import { X, Shield } from 'lucide-react';
import { Button } from './ui/button';
import { cn } from '@/lib/utils';
import type { AttackTechnique } from '@/types';
import { CONFIDENCE_COLORS } from '@/types';

interface Props {
  technique: AttackTechnique;
  onClose: () => void;
}

export default function TechniqueDetail({ technique, onClose }: Props) {
  const confidenceColor = CONFIDENCE_COLORS[technique.confidence] ?? '#888';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-navy-800 border border-border rounded-xl max-w-lg w-full max-h-[80vh] overflow-y-auto shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between p-4 border-b border-border">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Shield className="w-4 h-4 text-muted-foreground" />
              <span className="text-xs font-mono text-cyan-400">
                {technique.sub_technique_id ?? technique.technique_id}
              </span>
              <span className="text-xs text-muted-foreground">·</span>
              <span className="text-xs text-muted-foreground">{technique.tactic}</span>
            </div>
            <h2 className="text-sm font-semibold text-foreground">
              {technique.sub_technique_name ?? technique.technique_name}
            </h2>
          </div>
          <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close">
            <X className="w-4 h-4" />
          </Button>
        </div>

        <div className="p-4 space-y-4">
          {/* Confidence */}
          <div className="rounded-lg p-3 border"
            style={{ borderColor: confidenceColor + '44', backgroundColor: confidenceColor + '11' }}>
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Confidence</div>
            <div className="text-sm font-semibold" style={{ color: confidenceColor }}>
              {technique.confidence}
            </div>
          </div>

          {/* Evidence */}
          <div>
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5">Evidence from Input</div>
            <div className="bg-navy-950 rounded-lg p-3 border border-border/50">
              <code className="text-xs text-cyan-300 leading-relaxed whitespace-pre-wrap break-all">
                {technique.evidence}
              </code>
            </div>
          </div>

          {/* Detection Recommendation */}
          <div>
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5">Detection Recommendation</div>
            <div className="bg-secondary/30 rounded-lg p-3 border border-border/50">
              <p className="text-xs text-foreground/80 leading-relaxed">{technique.detection_recommendation}</p>
            </div>
          </div>

          {/* Link to ATT&CK */}
          <div className="pt-1">
            <a
              href={`https://attack.mitre.org/techniques/${(technique.sub_technique_id ?? technique.technique_id).replace('.', '/')}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-cyan-400 hover:text-cyan-300 underline underline-offset-2"
            >
              View {technique.sub_technique_id ?? technique.technique_id} on MITRE ATT&CK →
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
