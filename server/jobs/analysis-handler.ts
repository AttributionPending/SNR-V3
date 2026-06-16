/**
 * Analysis job handler — runs in the worker process. This is the two-phase LLM
 * pipeline that used to run inline inside the POST /analyze HTTP request (V2).
 * Instead of writing Server-Sent Events to a response, it writes progress events
 * to job_events (via JobEventWriter); the API process tails those and forwards
 * them to the browser, so the streaming UX is unchanged.
 *
 * Persistence (analysis_results, session status, threat-actor auto-link, audit)
 * is identical to V2.
 */
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { getDb, appendAuditLog, loadMergedSettings } from '../db/database.js';
import { readSecret } from '../lib/secrets.js';
import { analyzeWithClaude } from '../lib/claude.js';
import { parseSections } from '../lib/sections.js';
import { validateAndDeduplicateIOCs } from '../lib/ioc-validator.js';
import { validateAttackFlow } from '../lib/attack-flow.js';
import { autoLinkThreatActor } from '../lib/threat-actor-linker.js';
import { analysisRunsTotal, analysisDurationSeconds, jobsProcessedTotal } from '../lib/metrics.js';
import logger from '../lib/logger.js';
import { JobEventWriter } from './events.js';
import type { AnalysisJobData } from './queue.js';

/**
 * Execute an analysis job and stream its progress to job_events under `jobId`.
 * Resolves when the job is done (success or handled failure). Throws only on
 * unexpected errors so pg-boss can retry.
 */
export async function runAnalysisJob(jobId: string, p: AnalysisJobData): Promise<void> {
  const db = getDb();
  const now = Date.now();
  const startedAt = Date.now();
  const metricKind = p.auditAction === 'analysis_rerun' ? 'rerun' : 'analyze';
  const writer = new JobEventWriter(jobId);

  try {
    const settings = await loadMergedSettings(p.teamId);

    await writer.status('Phase 1 of 2 — Extracting ATT&CK techniques and IOCs…', 1);

    const audienceKey = p.audience.replace(/-/g, '_');
    let audiencePromptOverride = settings[`audience_prompt_${audienceKey}`] || undefined;
    let resolvedAudience = p.audience;

    // If no built-in override found, check custom audiences
    if (!audiencePromptOverride && !['purple_team', 'soc', 'red_team', 'dr', 'general'].includes(audienceKey)) {
      try {
        const customList = JSON.parse(settings['custom_audiences'] || '[]') as Array<{ id: string; label: string; prompt: string }>;
        const custom = customList.find((a) => a.id === p.audience);
        if (custom) {
          audiencePromptOverride = custom.prompt || undefined;
          resolvedAudience = custom.label;
        }
      } catch { /* ignore parse error */ }
    }

    const sections = parseSections(settings.report_sections || '');

    const result = await analyzeWithClaude(
      {
        siem: p.siemClean || undefined,
        log: p.logClean || undefined,
        text: p.textClean || undefined,
        audience: resolvedAudience,
        sections,
        orgEvaluationCriteria: settings.org_evaluation_criteria || undefined,
        orgDetectionContext: settings.org_detection_context || undefined,
        audiencePromptOverride,
        systemPromptOverride: settings.system_prompt_override || undefined,
        phase1InstructionsOverride: settings.phase1_instructions_override || undefined,
        phase2TemplateOverride: settings.phase2_template_override || undefined,
        providerSettings: settings,
      },
      (chunk, phase) => {
        if (chunk === '' && phase === 'phase2') {
          void writer.status('Phase 2 of 2 — Generating stakeholder brief…', 2);
        } else if (chunk) {
          writer.pushChunk(chunk);
        }
      }
    );

    if (!result.incident_summary?.title || !result.incident_summary?.severity) {
      throw new Error(
        'The model returned an incomplete analysis — missing incident_summary. ' +
        'This usually means the model cannot produce SNR\'s required JSON schema. ' +
        'Try a larger model (33B+) or use the Anthropic API.'
      );
    }

    if (result.iocs && result.iocs.length > 0) {
      const before = result.iocs.length;
      result.iocs = validateAndDeduplicateIOCs(result.iocs);
      const invalidCount = result.iocs.filter((i) => i.validation && !i.validation.valid).length;
      const deduped = before - result.iocs.length;
      if (deduped > 0 || invalidCount > 0) {
        logger.info(
          { iocsBefore: before, iocsAfter: result.iocs.length, duplicatesRemoved: deduped, invalidCount },
          `IOC validation: ${deduped} duplicates merged, ${invalidCount} invalid flagged`,
        );
      }
    }

    result.attack_flow = validateAttackFlow(result.attack_flow, result.attack_chain ?? []);

    const latestVersion = ((await db.prepare('SELECT MAX(version) as v FROM analysis_results WHERE session_id = ?').get(p.sessionId)) as { v: number | null }).v ?? 0;
    const newVersion = latestVersion + 1;

    await db.prepare('INSERT INTO analysis_results (id, session_id, version, result_json, created_at) VALUES (?,?,?,?,?)')
      .run(uuidv4(), p.sessionId, newVersion, JSON.stringify(result), now);

    await db.prepare('UPDATE sessions SET status = ?, updated_at = ?, severity = ?, version = ? WHERE id = ?')
      .run('complete', now, result.incident_summary.severity, newVersion, p.sessionId);

    // Auto-link threat actor (additive, failure-safe)
    try {
      await autoLinkThreatActor(db, p.sessionId, result, p.teamId, p.userId);
    } catch (err) {
      logger.warn({ err, session_id: p.sessionId }, 'Threat actor auto-link failed (non-fatal)');
    }

    const techniques = result.attack_chain.map((t) => t.sub_technique_id ?? t.technique_id);

    appendAuditLog({
      analyst_name: p.displayName,
      user_id: p.userId ?? undefined,
      session_id: p.sessionId,
      action: p.auditAction,
      input_hash: p.inputHash,
      techniques_identified: techniques,
      details: `severity=${result.incident_summary.severity}, audience=${p.audience}`,
    });

    analysisRunsTotal.inc({ result: 'success', kind: metricKind });
    analysisDurationSeconds.observe((Date.now() - startedAt) / 1000);
    jobsProcessedTotal.inc({ result: 'success' });

    await writer.complete({ result, version: newVersion });
    await writer.drain();
    await fireWebhook(p, { status: 'complete', version: newVersion });
  } catch (err) {
    // Mark the session failed so it doesn't sit in 'analyzing' forever and the
    // UI can offer a retry. Stream an error event for any attached client.
    try {
      await db.prepare('UPDATE sessions SET status = ?, updated_at = ? WHERE id = ?')
        .run('failed', Date.now(), p.sessionId);
    } catch { /* best-effort */ }
    analysisRunsTotal.inc({ result: 'failed', kind: metricKind });
    analysisDurationSeconds.observe((Date.now() - startedAt) / 1000);
    jobsProcessedTotal.inc({ result: 'failed' });
    const message = err instanceof Error ? err.message : 'Analysis failed';
    logger.warn({ err, session_id: p.sessionId }, 'Analysis job failed');
    await writer.error(message);
    await writer.drain();
    await fireWebhook(p, { status: 'failed', error: message });
  }
}

/**
 * POST a completion notification to the submission's callback URL, if any.
 * Best-effort and failure-safe. Signs the body with HMAC-SHA256 using
 * SNR_WEBHOOK_SECRET (header X-SNR-Signature) when that secret is configured.
 */
async function fireWebhook(
  p: AnalysisJobData,
  outcome: { status: 'complete' | 'failed'; version?: number; error?: string },
): Promise<void> {
  if (!p.webhookUrl) return;
  try {
    const payload = JSON.stringify({
      sessionId: p.sessionId,
      teamId: p.teamId,
      ...outcome,
      ts: Date.now(),
    });
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    const secret = readSecret('SNR_WEBHOOK_SECRET');
    if (secret) {
      headers['x-snr-signature'] =
        'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');
    }
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 10_000);
    await fetch(p.webhookUrl, { method: 'POST', headers, body: payload, signal: ctrl.signal });
    clearTimeout(t);
    logger.info({ sessionId: p.sessionId, status: outcome.status }, 'Webhook delivered');
  } catch (err) {
    logger.warn({ err, sessionId: p.sessionId }, 'Webhook delivery failed (non-fatal)');
  }
}
