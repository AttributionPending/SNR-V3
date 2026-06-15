import jsPDF from 'jspdf';
import type { AnalysisResult, BriefSection } from '../types';
import { DEFAULT_SECTIONS, AUTO_TYPES } from './sections';

const MARGIN = 20;
const PAGE_WIDTH = 210; // A4
const CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN;
const LINE_HEIGHT = 5;

function stripMarkdown(text: string): string {
  return text
    .replace(/#{1,6}\s+/g, '')         // headings
    .replace(/\*\*(.*?)\*\*/g, '$1')   // bold
    .replace(/\*(.*?)\*/g, '$1')       // italic
    .replace(/`(.*?)`/g, '$1')         // inline code
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1'); // links → text only
}

export function exportPdf(
  result: AnalysisResult,
  tlp: string,
  emailOverrides?: Record<string, unknown>,
  sections?: BriefSection[],
): void {
  const doc = new jsPDF();
  let y = MARGIN;

  function checkPage(needed: number) {
    if (y + needed > 280) {
      doc.addPage();
      y = MARGIN;
    }
  }

  function heading(text: string) {
    checkPage(12);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(text, MARGIN, y);
    y += 8;
    doc.setDrawColor(0, 188, 212); // cyan
    doc.line(MARGIN, y, MARGIN + CONTENT_WIDTH, y);
    y += 6;
  }

  function subheading(text: string) {
    checkPage(10);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text(text, MARGIN, y);
    y += 6;
  }

  function body(text: string) {
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');

    // Split into paragraphs on blank lines, then render each paragraph
    const paragraphs = stripMarkdown(text).split(/\n{2,}/);
    for (const para of paragraphs) {
      const trimmed = para.trim();
      if (!trimmed) continue;

      // Handle bullet / numbered list items within a paragraph
      const sublines = trimmed.split('\n');
      for (const subline of sublines) {
        const line = subline.trim();
        if (!line) continue;

        // Detect bullet or numbered list items
        const bulletMatch = line.match(/^[-*•]\s+(.*)/);
        const numberMatch = line.match(/^(\d+)[.)]\s+(.*)/);
        const indent = bulletMatch || numberMatch ? 6 : 0;
        const prefix = bulletMatch ? '• ' : numberMatch ? `${numberMatch[1]}. ` : '';
        const content = bulletMatch ? bulletMatch[1] : numberMatch ? numberMatch[2] : line;

        doc.setFont('helvetica', 'normal');
        const wrapped = doc.splitTextToSize(content, CONTENT_WIDTH - indent);
        for (let i = 0; i < wrapped.length; i++) {
          checkPage(LINE_HEIGHT);
          if (i === 0 && prefix) {
            doc.text(prefix, MARGIN + indent - 5, y);
          }
          doc.text(wrapped[i], MARGIN + indent, y);
          y += LINE_HEIGHT;
        }
      }
      y += 2; // paragraph spacing
    }
  }

  function labelValue(label: string, value: string) {
    checkPage(LINE_HEIGHT);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.text(`${label}: `, MARGIN, y);
    const labelWidth = doc.getTextWidth(`${label}: `);
    doc.setFont('helvetica', 'normal');
    doc.text(value, MARGIN + labelWidth, y);
    y += LINE_HEIGHT + 1;
  }

  const email = emailOverrides
    ? { ...result.email_content, ...emailOverrides }
    : result.email_content ?? {};

  // ── Title ──
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 188, 212);
  const titleLines = doc.splitTextToSize(result.incident_summary.title, CONTENT_WIDTH);
  for (const line of titleLines) {
    doc.text(line, MARGIN, y);
    y += 8;
  }
  doc.setTextColor(0, 0, 0);
  y += 2;

  // ── Metadata ──
  labelValue('Severity', result.incident_summary.severity);
  labelValue('Confidence', result.incident_summary.confidence);
  labelValue('TLP', tlp);
  labelValue('Generated', new Date().toISOString().slice(0, 19).replace('T', ' '));
  y += 4;

  // ── Render sections in configured order (same as email/report) ──
  const activeSections = (sections ?? DEFAULT_SECTIONS).filter(s => s.enabled);

  for (const section of activeSections) {
    // ── ATT&CK Techniques (auto section) ──
    if (section.type === 'techniques') {
      if (!result.attack_chain?.length) continue;
      heading(section.label);
      for (const tech of result.attack_chain) {
        checkPage(15);
        subheading(`${tech.technique_id} — ${tech.technique_name}`);
        labelValue('Tactic', tech.tactic);
        labelValue('Confidence', tech.confidence);
        labelValue('Detection', tech.detection_coverage);
        body(tech.evidence);
        y += 2;
      }
      continue;
    }

    // ── IOCs (auto section) ──
    if (section.type === 'iocs') {
      if (!result.iocs?.length) continue;
      heading(section.label);

      // Table header
      checkPage(10);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.text('Type', MARGIN, y);
      doc.text('Value', MARGIN + 25, y);
      doc.text('Confidence', MARGIN + 130, y);
      y += LINE_HEIGHT;
      doc.line(MARGIN, y - 1, MARGIN + CONTENT_WIDTH, y - 1);

      doc.setFont('helvetica', 'normal');
      for (const ioc of result.iocs) {
        checkPage(LINE_HEIGHT);
        doc.text(ioc.type, MARGIN, y);
        const valLines = doc.splitTextToSize(ioc.value, 100);
        doc.text(valLines[0], MARGIN + 25, y);
        doc.text(ioc.confidence, MARGIN + 130, y);
        y += LINE_HEIGHT;
        for (let i = 1; i < valLines.length; i++) {
          checkPage(LINE_HEIGHT);
          doc.text(valLines[i], MARGIN + 25, y);
          y += LINE_HEIGHT;
        }
      }
      y += 4;
      continue;
    }

    // ── Text sections from email_content ──
    const content = email[section.key] as string | undefined;
    if (!content || typeof content !== 'string' || !content.trim()) continue;
    heading(section.label);
    body(content);
  }

  // ── Detection Rules ──
  if (result.detection_rules?.length) {
    heading('Detection Rules');
    for (const rule of result.detection_rules) {
      checkPage(15);
      subheading(`[${rule.rule_type.toUpperCase()}] ${rule.rule_name}`);
      labelValue('Confidence', rule.confidence);
      labelValue('Source', rule.source);
      if (rule.related_technique) {
        labelValue('Technique', rule.related_technique);
      }
      body(rule.description);

      // Rule content in monospace
      doc.setFontSize(7);
      doc.setFont('courier', 'normal');
      const ruleLines = doc.splitTextToSize(rule.rule_content, CONTENT_WIDTH);
      for (const rl of ruleLines) {
        checkPage(4);
        doc.text(rl, MARGIN, y);
        y += 4;
      }
      doc.setFont('helvetica', 'normal');
      y += 4;
    }
  }

  // ── Footer on each page ──
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(128, 128, 128);
    doc.text(`TLP:${tlp}`, MARGIN, 290);
    doc.text(`SNR — Signal to Noise`, PAGE_WIDTH / 2, 290, { align: 'center' });
    doc.text(`Page ${i}/${pageCount}`, PAGE_WIDTH - MARGIN, 290, { align: 'right' });
    doc.setTextColor(0, 0, 0);
  }

  // Save
  const filename = `SNR-Report-${result.incident_summary.title.slice(0, 40).replace(/[^a-zA-Z0-9]/g, '_')}.pdf`;
  doc.save(filename);
}
