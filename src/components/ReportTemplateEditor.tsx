import { useEditor, EditorContent, Extension } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import { Markdown } from 'tiptap-markdown';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import { Decoration, DecorationSet } from '@tiptap/pm/view';
import * as DropdownMenu from '@radix-ui/react-dropdown-menu';
import {
  Bold, Italic, List, ListOrdered, Minus,
  Undo2, Redo2, ChevronDown, Plus, RotateCcw,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { DEFAULT_REPORT_TEMPLATE } from '@/lib/reportTemplate';
import type { BriefSection } from '@/types';

// ── Token definitions ──────────────────────────────────────────────────────

const FIELD_TOKENS = [
  'date', 'tlp', 'report_id', 'analyst_name', 'org_name',
  'confidence', 'severity', 'summary', 'affected_assets',
  'ioc_count', 'technique_count', 'threat_actor_name',
  'threat_actor_aliases', 'threat_actor_motivation',
  'threat_actor_confidence', 'initial_access', 'motivation',
] as const;

const BLOCK_TOKENS = [
  'SECTIONS', 'ATTACK_TABLE', 'ATTACK_CHAIN', 'IOC_TABLE', 'EMAIL_IOCS',
  'AFFECTED_ASSETS_TABLE', 'THREAT_ACTOR', 'CAMPAIGN_TIMELINE',
  'OBSERVATIONS', 'ACTIONS', 'NEXT_STEPS',
] as const;

type FieldToken = typeof FIELD_TOKENS[number];
type BlockToken = typeof BLOCK_TOKENS[number];

// ── Token decoration ProseMirror plugin ──────────────────────────────────

const FIELD_RE = /\{([a-z_]+)\}/g;
const BLOCK_RE = /\{\{([A-Z_]+(?::[a-z0-9_]+)?)\}\}/g;

const TokenDecoration = Extension.create({
  name: 'tokenDecoration',
  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('tokenDecoration'),
        props: {
          decorations(state) {
            const decorations: Decoration[] = [];
            state.doc.descendants((node, pos) => {
              if (!node.isText || !node.text) return;
              const text = node.text;
              let m: RegExpExecArray | null;

              FIELD_RE.lastIndex = 0;
              while ((m = FIELD_RE.exec(text)) !== null) {
                const isKnown = (FIELD_TOKENS as readonly string[]).includes(m[1]);
                decorations.push(
                  Decoration.inline(pos + m.index, pos + m.index + m[0].length, {
                    class: isKnown ? 'token-chip-field' : 'token-chip-field token-chip-unknown',
                  })
                );
              }

              BLOCK_RE.lastIndex = 0;
              while ((m = BLOCK_RE.exec(text)) !== null) {
                const isKnown = (BLOCK_TOKENS as readonly string[]).includes(m[1] as BlockToken) || m[1].startsWith('SECTION:');
                decorations.push(
                  Decoration.inline(pos + m.index, pos + m.index + m[0].length, {
                    class: isKnown ? 'token-chip-block' : 'token-chip-block token-chip-unknown',
                  })
                );
              }
            });
            return DecorationSet.create(state.doc, decorations);
          },
        },
      }),
    ];
  },
});

// ── ToolbarButton ─────────────────────────────────────────────────────────

interface ToolbarButtonProps {
  onClick: () => void;
  active?: boolean;
  disabled?: boolean;
  title: string;
  children: React.ReactNode;
}

function ToolbarButton({ onClick, active, disabled, title, children }: ToolbarButtonProps) {
  return (
    <button
      type="button"
      onMouseDown={(e) => {
        e.preventDefault(); // Prevent editor blur
        onClick();
      }}
      title={title}
      disabled={disabled}
      className={cn(
        'flex items-center justify-center w-7 h-7 rounded text-xs transition-colors',
        active
          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
          : 'text-muted-foreground hover:text-foreground hover:bg-secondary/60',
        disabled && 'opacity-40 cursor-not-allowed'
      )}
    >
      {children}
    </button>
  );
}

function Separator() {
  return <div className="w-px h-5 bg-border/60 mx-0.5 self-center flex-shrink-0" />;
}

// ── ReportTemplateEditor ──────────────────────────────────────────────────

interface ReportTemplateEditorProps {
  value: string;
  onChange: (v: string) => void;
  /** Live Brief Sections — drives the {{SECTION:key}} dropdown entries */
  sections?: BriefSection[];
}

export default function ReportTemplateEditor({ value, onChange, sections = [] }: ReportTemplateEditorProps) {
  const sectionTokens = sections.filter((s) => s.type === 'text' || s.type === 'bullets' || s.type === 'numbered');
  const editor = useEditor({
    extensions: [
      StarterKit.configure({
        codeBlock: false,
        heading: { levels: [1, 2, 3, 4] },
      }),
      Markdown.configure({
        html: false,
        tightLists: true,
        bulletListMarker: '-',
      }),
      TokenDecoration,
    ],
    content: value !== '' ? value : DEFAULT_REPORT_TEMPLATE,
    editorProps: {
      attributes: {
        class: 'snr-editor-content',
        spellcheck: 'false',
      },
    },
    onUpdate: ({ editor: ed }) => {
      const mdStorage = (ed.storage as unknown as Record<string, { getMarkdown: () => string }>)['markdown'];
      const md = mdStorage.getMarkdown();
      // Preserve "empty string = use built-in default" semantic
      onChange(md === DEFAULT_REPORT_TEMPLATE ? '' : md);
    },
  });

  const getMarkdown = (): string => {
    if (!editor) return '';
    const mdStorage = (editor.storage as unknown as Record<string, { getMarkdown: () => string }>)['markdown'];
    return mdStorage.getMarkdown();
  };

  const charCount = getMarkdown().length;

  return (
    <div className="border border-cyan-500/30 rounded-lg overflow-hidden bg-navy-950">

      {/* ── Toolbar ── */}
      <div className="flex flex-wrap items-center gap-0.5 p-2 border-b border-border bg-navy-900/60">

        {/* Format */}
        <ToolbarButton
          onClick={() => editor?.chain().focus().toggleBold().run()}
          active={editor?.isActive('bold')}
          title="Bold"
        >
          <Bold className="w-3.5 h-3.5" />
        </ToolbarButton>
        <ToolbarButton
          onClick={() => editor?.chain().focus().toggleItalic().run()}
          active={editor?.isActive('italic')}
          title="Italic"
        >
          <Italic className="w-3.5 h-3.5" />
        </ToolbarButton>

        <Separator />

        {/* Headings */}
        {([1, 2, 3, 4] as const).map((level) => (
          <ToolbarButton
            key={level}
            onClick={() => editor?.chain().focus().toggleHeading({ level }).run()}
            active={editor?.isActive('heading', { level })}
            title={`Heading ${level}`}
          >
            <span className="font-bold text-[10px] leading-none">H{level}</span>
          </ToolbarButton>
        ))}

        <Separator />

        {/* Lists */}
        <ToolbarButton
          onClick={() => editor?.chain().focus().toggleBulletList().run()}
          active={editor?.isActive('bulletList')}
          title="Bullet list"
        >
          <List className="w-3.5 h-3.5" />
        </ToolbarButton>
        <ToolbarButton
          onClick={() => editor?.chain().focus().toggleOrderedList().run()}
          active={editor?.isActive('orderedList')}
          title="Numbered list"
        >
          <ListOrdered className="w-3.5 h-3.5" />
        </ToolbarButton>
        <ToolbarButton
          onClick={() => editor?.chain().focus().setHorizontalRule().run()}
          title="Horizontal rule (---)"
        >
          <Minus className="w-3.5 h-3.5" />
        </ToolbarButton>

        <Separator />

        {/* History */}
        <ToolbarButton
          onClick={() => editor?.chain().focus().undo().run()}
          disabled={!editor?.can().undo()}
          title="Undo"
        >
          <Undo2 className="w-3.5 h-3.5" />
        </ToolbarButton>
        <ToolbarButton
          onClick={() => editor?.chain().focus().redo().run()}
          disabled={!editor?.can().redo()}
          title="Redo"
        >
          <Redo2 className="w-3.5 h-3.5" />
        </ToolbarButton>

        <Separator />

        {/* Insert Token dropdown */}
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button
              type="button"
              className="flex items-center gap-1 h-7 px-2 rounded text-[11px] text-cyan-400/80 hover:text-cyan-300 hover:bg-secondary/60 border border-cyan-500/20 transition-colors"
            >
              <Plus className="w-3 h-3" />
              Insert Token
              <ChevronDown className="w-3 h-3" />
            </button>
          </DropdownMenu.Trigger>

          <DropdownMenu.Portal>
            <DropdownMenu.Content
              className="z-[200] min-w-[220px] bg-navy-800 border border-border rounded-lg shadow-xl p-1 max-h-80 overflow-y-auto"
              sideOffset={4}
              align="start"
            >
              <DropdownMenu.Label className="px-2 py-1 text-[9px] uppercase tracking-widest text-muted-foreground/50">
                Field Tokens
              </DropdownMenu.Label>
              {FIELD_TOKENS.map((token) => (
                <DropdownMenu.Item
                  key={token}
                  onSelect={() => {
                    editor?.chain().focus().insertContent(`{${token}}`).run();
                  }}
                  className="flex items-center px-2 py-1.5 rounded text-xs cursor-pointer hover:bg-secondary/60 focus:bg-secondary/60 outline-none"
                >
                  <span className="token-chip-field font-mono text-[10px]">{`{${token}}`}</span>
                </DropdownMenu.Item>
              ))}

              <DropdownMenu.Separator className="h-px bg-border/60 my-1" />

              <DropdownMenu.Label className="px-2 py-1 text-[9px] uppercase tracking-widest text-muted-foreground/50">
                Block Tokens
              </DropdownMenu.Label>
              {BLOCK_TOKENS.map((token) => (
                <DropdownMenu.Item
                  key={token}
                  onSelect={() => {
                    editor?.chain().focus().insertContent(`{{${token}}}`).run();
                  }}
                  className="flex items-center px-2 py-1.5 rounded text-xs cursor-pointer hover:bg-secondary/60 focus:bg-secondary/60 outline-none"
                >
                  <span className="token-chip-block font-mono text-[10px]">{`{{${token}}}`}</span>
                </DropdownMenu.Item>
              ))}

              {sectionTokens.length > 0 && (
                <>
                  <DropdownMenu.Separator className="h-px bg-border/60 my-1" />
                  <DropdownMenu.Label className="px-2 py-1 text-[9px] uppercase tracking-widest text-muted-foreground/50">
                    Individual Sections
                  </DropdownMenu.Label>
                  {sectionTokens.map((s) => (
                    <DropdownMenu.Item
                      key={s.key}
                      onSelect={() => editor?.chain().focus().insertContent(`\n{{SECTION:${s.key}}}\n`).run()}
                      className="flex items-center gap-2 px-2 py-1.5 rounded text-xs cursor-pointer hover:bg-secondary/60 focus:bg-secondary/60 outline-none"
                    >
                      <span className="token-chip-block font-mono text-[10px]">{`{{SECTION:${s.key}}}`}</span>
                      <span className="text-[10px] text-muted-foreground/50 truncate">{s.label}</span>
                    </DropdownMenu.Item>
                  ))}
                </>
              )}
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>

        {/* Reset to Default — right-aligned */}
        <button
          type="button"
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => {
            editor?.commands.setContent(DEFAULT_REPORT_TEMPLATE);
            onChange('');
          }}
          className="flex items-center gap-1 h-7 px-2 rounded text-[11px] text-muted-foreground hover:text-red-400 hover:bg-secondary/60 transition-colors ml-auto"
          title="Reset to built-in default template"
        >
          <RotateCcw className="w-3 h-3" />
          Reset
        </button>
      </div>

      {/* ── Editor content ── */}
      <div className="overflow-y-auto" style={{ maxHeight: '560px' }}>
        <EditorContent editor={editor} />
      </div>

      {/* ── Status bar ── */}
      <div className="px-3 py-1.5 border-t border-border/60 flex items-center justify-between bg-navy-900/40">
        <span className="text-[10px] text-muted-foreground/40">
          WYSIWYG — tokens highlighted in{' '}
          <span className="text-cyan-400/60">cyan</span>
          {' '}(field) and{' '}
          <span className="text-orange-400/60">orange</span>
          {' '}(block) · saved as markdown
        </span>
        <span className="text-[10px] text-muted-foreground/30 font-mono tabular-nums">
          {charCount.toLocaleString()} chars
        </span>
      </div>
    </div>
  );
}
