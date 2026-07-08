/**
 * Pure merge helpers for the Analyst Workbench AI-assist actions. Kept out of the
 * component so the dedupe rules are unit-testable.
 *
 * "Suggest from notes" merges an AI-extracted technical result into the analyst's
 * current draft without clobbering their work: new techniques/IOCs/rules are
 * appended (deduped), and empty actor/assets/flow are seeded.
 */
import type { AnalysisResult } from '@/types';

type Technical = Omit<AnalysisResult, 'email_content'>;

/** A blank result to seed a new authored report. (Kept here — a light module —
 *  so App can create one without statically importing the heavy Workbench.) */
export function blankResult(): AnalysisResult {
  return {
    incident_summary: { title: '', severity: 'Medium', confidence: 'Medium', description: '', analyst_notes: '' },
    attack_chain: [],
    iocs: [],
    detection_rules: [],
    threat_actor: { name: null, aliases: [], motivation: null, attribution_confidence: null, intrusion_set: null, campaign_name: null, malware_families: [] },
    affected_assets: [],
    email_content: { subject: '', severity_badge: 'Medium' },
  };
}

export interface MergeCounts {
  techniques: number;
  iocs: number;
  rules: number;
  flowAdded: boolean;
}

const techKey = (x: { technique_id: string; sub_technique_id?: string | null }) =>
  `${x.technique_id}|${x.sub_technique_id ?? ''}`.toUpperCase();
const iocKey = (x: { type: string; value: string }) => `${x.type}|${x.value}`.toLowerCase();
const ruleKey = (x: { rule_name: string }) => x.rule_name.toLowerCase();

/** Merge an AI-extracted technical result into a draft (append + dedupe). */
export function mergeExtracted(draft: AnalysisResult, t: Partial<Technical>): { result: AnalysisResult; counts: MergeCounts } {
  const existTech = new Set(draft.attack_chain.map(techKey));
  const existIoc = new Set(draft.iocs.map(iocKey));
  const existRule = new Set(draft.detection_rules.map(ruleKey));

  const newTech = (t.attack_chain ?? []).filter((x) => x.technique_id && !existTech.has(techKey(x)));
  const newIocs = (t.iocs ?? []).filter((x) => x.value && !existIoc.has(iocKey(x)));
  const newRules = (t.detection_rules ?? []).filter((x) => x.rule_name && !existRule.has(ruleKey(x)));
  const flowAdded = !draft.attack_flow?.nodes?.length && !!t.attack_flow?.nodes?.length;

  const result: AnalysisResult = {
    ...draft,
    attack_chain: [...draft.attack_chain, ...newTech].map((x, i) => ({ ...x, order: i })),
    iocs: [...draft.iocs, ...newIocs],
    detection_rules: [...draft.detection_rules, ...newRules],
    affected_assets: draft.affected_assets.length ? draft.affected_assets : (t.affected_assets ?? []),
    threat_actor: draft.threat_actor.name ? draft.threat_actor : (t.threat_actor ?? draft.threat_actor),
    attack_flow: draft.attack_flow?.nodes?.length ? draft.attack_flow : t.attack_flow,
  };
  return { result, counts: { techniques: newTech.length, iocs: newIocs.length, rules: newRules.length, flowAdded } };
}

/** Append AI-generated detection rules to a draft (deduped by name). */
export function mergeRules(draft: AnalysisResult, rules: AnalysisResult['detection_rules']): { result: AnalysisResult; added: number } {
  const exist = new Set(draft.detection_rules.map(ruleKey));
  const add = rules.filter((r) => r.rule_name && !exist.has(ruleKey(r)));
  return { result: { ...draft, detection_rules: [...draft.detection_rules, ...add] }, added: add.length };
}
