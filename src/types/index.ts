export interface DetectionRule {
  rule_type: 'sigma' | 'yara' | 'suricata';
  rule_name: string;
  rule_content: string;
  description: string;
  source: 'extracted' | 'generated';
  confidence: 'High' | 'Medium' | 'Low';
  related_technique: string | null;
}

export interface AnalysisResult {
  incident_summary: {
    title: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
    confidence: 'High' | 'Medium' | 'Low';
    description: string;
    analyst_notes: string;
  };
  attack_chain: AttackTechnique[];
  iocs: IOC[];
  detection_rules: DetectionRule[];
  threat_actor: {
    name: string | null;
    aliases: string[];
    motivation: string | null;
    attribution_confidence: string | null;
    intrusion_set?: string | null;
    campaign_name?: string | null;
    malware_families?: string[];
  };
  affected_assets: AffectedAsset[];
  /** Optional MITRE Attack Flow causal graph. Absent on legacy/sparse analyses. */
  attack_flow?: AttackFlow;
  email_content: EmailContent;
}

export type AttackFlowNodeType = 'action' | 'asset' | 'tool' | 'malware' | 'operator_and' | 'operator_or';

export interface AttackFlowNode {
  id: string;
  type: AttackFlowNodeType;
  name: string;
  technique_id: string | null;
  description: string;
}

export interface AttackFlowEdge {
  source: string;
  target: string;
  label: string;
}

export interface AttackFlow {
  nodes: AttackFlowNode[];
  edges: AttackFlowEdge[];
}

export interface AttackTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  tactic_id: string;
  sub_technique_id: string | null;
  sub_technique_name: string | null;
  evidence: string;
  confidence: 'High' | 'Medium' | 'Low';
  detection_coverage: 'Likely Detected' | 'Detection Gap' | 'Unknown';
  detection_recommendation: string;
  order: number;
}

export interface IOCValidation {
  valid: boolean;
  warnings: string[];
}

export interface IOC {
  type: 'ipv4' | 'ipv6' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'email' | 'filename' | 'registry' | 'user_agent';
  value: string;
  context: string;
  confidence: 'High' | 'Medium' | 'Low';
  /** Set by server-side validation. Absent on legacy data. */
  validation?: IOCValidation;
  /** Number of duplicate IOCs that were merged into this entry. */
  duplicateCount?: number;
}

export interface AffectedAsset {
  hostname: string | null;
  ip: string | null;
  role: string;
  compromise_confidence: 'High' | 'Medium' | 'Low';
}

export interface EmailContent {
  subject: string;
  severity_badge: string;
  [key: string]: unknown;
}

export interface BriefSection {
  key: string;
  label: string;
  description: string;
  type: 'text' | 'bullets' | 'numbered' | 'techniques' | 'iocs';
  enabled: boolean;
}

export interface Session {
  id: string;
  name: string;
  incident_id: string | null;
  created_at: number;
  updated_at: number;
  severity: string | null;
  audience: string | null;
  version: number;
  status: 'pending' | 'analyzing' | 'complete' | 'error' | 'failed';
  tags?: string[];
  /** 'workbench' = analyst-authored original research; 'analysis' = AI-derived. */
  origin?: 'analysis' | 'workbench';
}

export type AudienceType = 'purple_team' | 'soc' | 'red_team' | 'dr' | 'general';
export type TLPLevel = 'CLEAR' | 'GREEN' | 'AMBER' | 'AMBER+STRICT' | 'RED';

export interface CustomAudience {
  id: string;
  label: string;
  prompt: string;
}

export const AUDIENCE_LABELS: Record<AudienceType, string> = {
  purple_team: 'Purple Team',
  soc: 'SOC',
  red_team: 'Red Team',
  dr: 'Detection & Response',
  general: 'General',
};

export const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'bg-red-900 text-red-200 border-red-700',
  High: 'bg-red-800 text-red-200 border-red-600',
  Medium: 'bg-orange-900 text-orange-200 border-orange-700',
  Low: 'bg-green-900 text-green-200 border-green-700',
  Informational: 'bg-blue-900 text-blue-200 border-blue-700',
};

export const CONFIDENCE_COLORS: Record<string, string> = {
  High: '#ff6b35',
  Medium: '#ffd166',
  Low: '#06d6a0',
};

export const COVERAGE_COLORS: Record<string, string> = {
  'Likely Detected': 'text-green-400',
  'Detection Gap': 'text-red-400',
  'Unknown': 'text-yellow-400',
};

// ── Auth types ────────────────────────────────────────────────────────────────

export type UserRole = 'admin' | 'analyst' | 'viewer';
export type TeamRole = 'lead' | 'member';

export interface AuthUser {
  id: string;
  email: string;
  displayName: string;
  role: UserRole;
}

export interface AuthTeam {
  id: string;
  name: string;
  role: TeamRole;
}

export interface UserRecord {
  id: string;
  email: string;
  displayName: string;
  role: UserRole;
  createdAt: number;
  lastLoginAt: number | null;
  disabled: boolean;
  teams: Array<{ id: string; name: string; role: string }>;
}

export interface TeamRecord {
  id: string;
  name: string;
  description: string;
  createdAt: number;
  memberCount: number;
}

export interface TeamDetail {
  id: string;
  name: string;
  description: string;
  members: Array<{
    userId: string;
    email: string;
    displayName: string;
    userRole: string;
    teamRole: string;
    joinedAt: number;
  }>;
}

// ── Threat Actor Grouping ───────────────────────────────────────────────────

export interface ThreatActorSummary {
  id: string;
  name: string;
  aliases: string[];
  motivation: string | null;
  attribution_confidence: string | null;
  intrusion_set: string | null;
  campaign_name: string | null;
  malware_families: string[];
  description: string;
  session_count: number;
  latest_session_at: number | null;
  created_at: number;
}

export interface LinkedSession {
  id: string;
  name: string;
  severity: string | null;
  audience: string | null;
  created_at: number;
  link_type: 'auto' | 'manual';
}

export interface AggregatedTTP {
  technique_id: string;
  technique_name: string;
  tactic: string;
  session_count: number;
  sessions: Array<{ id: string; name: string }>;
}

export interface AggregatedIOC {
  type: string;
  value: string;
  context: string;
  confidence: string;
  session_count: number;
  first_seen: number;
  last_seen: number;
}

export interface ThreatActorDetail extends ThreatActorSummary {
  sessions: LinkedSession[];
  aggregated_ttps: AggregatedTTP[];
  aggregated_iocs: AggregatedIOC[];
}
