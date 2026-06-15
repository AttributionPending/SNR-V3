/**
 * EmailTemplateEditor — WYSIWYG token editor for the email body layout.
 * Mirrors ReportTemplateEditor's Tiptap + token-decoration pattern, with the
 * email token vocabulary and support for {{SECTION:key}} tokens built from the
 * live Brief Sections config. Value in/out is markdown; "" means use the
 * built-in default layout.
 */
import { useEditor, EditorContent, Extension } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import { Markdown } from 'tiptap-markdown';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import { Decoration, DecorationSet } from '@tiptap/pm/view';
import * as DropdownMenu from '@radix-ui/react-dropdown-menu';
import { Bold, Italic, List, ListOrdered, Minus, Undo2, Redo2, ChevronDown, Plus, RotateCcw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { DEFAULT_EMAIL_TEMPLATE, EMAIL_FIELD_TOKENS, EMAIL_BLOCK_TOKENS } from '@/lib/emailTemplate';
import type { BriefSection } from '@/types';

const FIELD_RE = /\{([a-z_]+)\}/g;
const BLOCK_RE = /\{\{([A-Z_]+(?::[a-z0-9_]+)?)\}\}/g;

const KNOWN_FIELDS = new Set<string>(EMAIL_FIELD_TOKENS);
const KNOWN_BLOCKS = new Set<string>(EMAIL_BLOCK_TOKENS);

const TokenDecoration = Extension.create({
  name: 'emailTokenDecoration',
  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('emailTokenDecoration'),
        props: {
          decorations(state) {
            const decorations: Decoration[] = [];
            state.doc.descendants((node, pos) => {
              if (!node.isText || !node.text) return;
              const text = node.text;
              let m: RegExpExecArray | null;

              FIELD_RE.lastIndex = 0;
              while ((m = FIELD_RE.exec(text)) !== null) {
                const known = KNOWN_FIELDS.has(m[1]);
                decorations.push(Decoration.inline(pos + m.index, pos + m.index + m[0].length, {
                  class: known ? 'token-chip-field' : 'token-chip-field token-chip-unknown',
                }));
              }
              BLOCK_RE.lastIndex = 0;
              while ((m = BLOCK_RE.exec(text)) !== null) {
                const tok = m[1];
                const known = KNOWN_BLOCKS.has(tok) || tok.startsWith('SECTION:');
                decorations.push(Decoration.inline(pos + m.index, pos + m.index + m[0].length, {
                  class: known ? 'token-chip-block' : 'token-chip-block token-chip-unknown',
                }));
              }
            });
            return DecorationSet.create(state.doc, decorations);
          },
        },
      }),
    ];
  },
});

function ToolbarButton({ onClick, active, disabled, title, children }: {
  onClick: () => void; active?: boolean; disabled?: boolean; title: string; children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onMouseDown={(e) => { e.preventDefault(); onClick(); }}
      title={title}
      disabled={disabled}
      className={cn(
        'flex items-center justify-center w-7 h-7 rounded text-xs transition-colors',
        active ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
          : 'text-muted-foreground hover:text-foreground hover:bg-secondary/60',
        disabled && 'opacity-40 cursor-not-allowed',
      )}
    >
      {children}
    </button>
  );
}

function Separator() {
  return <div className="w-px h-5 bg-border/60 mx-0.5 self-center flex-shrink-0" />;
}

interface Props {
  value: string;
  onChange: (v: string) => void;
  /** Live Brief Sections — drives the {{SECTION:key}} dropdown entries */
  sections?: BriefSection[];
}

export default function EmailTemplateEditor({ value, onChange, sections = [] }: Props) {
  const editor = useEditor({
    extensions: [
      StarterKit.configure({ codeBlock: false, heading: false }),
      Markdown.configure({ html: false, tightLists: true, bulletListMarker: '-' }),
      TokenDecoration,
    ],
    content: value !== '' ? value : DEFAULT_EMAIL_TEMPLATE,
    editorProps: { attributes: { class: 'snr-editor-content', spellcheck: 'false' } },
    onUpdate: ({ editor: ed }) => {
      const mdStorage = (ed.storage as unknown as Record<string, { getMarkdown: () => string }>)['markdown'];
      const md = mdStorage.getMarkdown();
      onChange(md === DEFAULT_EMAIL_TEMPLATE ? '' : md);
    },
  });

  const getMarkdown = (): string => {
    if (!editor) return '';
    const mdStorage = (editor.storage as unknown as Record<string, { getMarkdown: () => string }>)['markdown'];
    return mdStorage.getMarkdown();
  };
  const charCount = getMarkdown().length;

  // Configurable (non-auto) sections for {{SECTION:key}} insertion
  const sectionTokens = sections.filter((s) => s.type === 'text' || s.type === 'bullets' || s.type === 'numbered');

  return (
    <div className="border border-cyan-500/30 rounded-lg overflow-hidden bg-navy-950">
      {/* ── Toolbar ── */}
      <div className="flex flex-wrap items-center gap-0.5 p-2 border-b border-border bg-navy-900/60">
        <ToolbarButton onClick={() => editor?.chain().focus().toggleBold().run()} active={editor?.isActive('bold')} title="Bold">
          <Bold className="w-3.5 h-3.5" />
        </ToolbarButton>
        <ToolbarButton onClick={() => editor?.chain().focus().toggleItalic().run()} active={editor?.isActive('italic')} title="Italic">
          <Italic className="w-3.5 h-3.5" />
        </ToolbarButton>
        <Separator />
        <ToolbarButton onClick={() => editor?.chain().focus().toggleBulletList().run()} active={editor?.isActive('bulletList')} title="Bullet list">
          <List className="w-3.5 h-3.5" />
        </ToolbarButton>
        <ToolbarButton onClick={() => editor?.chain().focus().toggleOrderedList().run()} active={editor?.isActive('orderedList')} title="Numbered list">
          <ListOrdered className="w-3.5 h-3.5" />
        </ToolbarButton>
        <ToolbarButton onClick={() => editor?.chain().focus().setHorizontalRule().run()} title="Horizontal rule">
          <Minus className="w-3.5 h-3.5" />
        </ToolbarButton>
        <Separator />
        <ToolbarButton onClick={() => editor?.chain().focus().undo().run()} disabled={!editor?.can().undo()} title="Undo">
          <Undo2 className="w-3.5 h-3.5" />
        </ToolbarButton>
        <ToolbarButton onClick={() => editor?.chain().focus().redo().run()} disabled={!editor?.can().redo()} title="Redo">
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
            <DropdownMenu.Content className="z-[200] min-w-[240px] bg-navy-800 border border-border rounded-lg shadow-xl p-1 max-h-80 overflow-y-auto" sideOffset={4} align="start">
              <DropdownMenu.Label className="px-2 py-1 text-[9px] uppercase tracking-widest text-muted-foreground/50">Field Tokens</DropdownMenu.Label>
              {EMAIL_FIELD_TOKENS.map((token) => (
                <DropdownMenu.Item
                  key={token}
                  onSelect={() => editor?.chain().focus().insertContent(`{${token}}`).run()}
                  className="flex items-center px-2 py-1.5 rounded text-xs cursor-pointer hover:bg-secondary/60 focus:bg-secondary/60 outline-none"
                >
                  <span className="token-chip-field font-mono text-[10px]">{`{${token}}`}</span>
                </DropdownMenu.Item>
              ))}
              <DropdownMenu.Separator className="h-px bg-border/60 my-1" />
              <DropdownMenu.Label className="px-2 py-1 text-[9px] uppercase tracking-widest text-muted-foreground/50">Block Tokens</DropdownMenu.Label>
              {EMAIL_BLOCK_TOKENS.map((token) => (
                <DropdownMenu.Item
                  key={token}
                  onSelect={() => editor?.chain().focus().insertContent(`\n{{${token}}}\n`).run()}
                  className="flex items-center px-2 py-1.5 rounded text-xs cursor-pointer hover:bg-secondary/60 focus:bg-secondary/60 outline-none"
                >
                  <span className="token-chip-block font-mono text-[10px]">{`{{${token}}}`}</span>
                </DropdownMenu.Item>
              ))}
              {sectionTokens.length > 0 && (
                <>
                  <DropdownMenu.Separator className="h-px bg-border/60 my-1" />
                  <DropdownMenu.Label className="px-2 py-1 text-[9px] uppercase tracking-widest text-muted-foreground/50">Individual Sections</DropdownMenu.Label>
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

        {/* Reset to Default */}
        <button
          type="button"
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => { editor?.commands.setContent(DEFAULT_EMAIL_TEMPLATE); onChange(''); }}
          className="flex items-center gap-1 h-7 px-2 rounded text-[11px] text-muted-foreground hover:text-red-400 hover:bg-secondary/60 transition-colors ml-auto"
          title="Reset to built-in default layout"
        >
          <RotateCcw className="w-3 h-3" />
          Reset
        </button>
      </div>

      {/* ── Editor content ── */}
      <div className="overflow-y-auto" style={{ maxHeight: '420px' }}>
        <EditorContent editor={editor} />
      </div>

      {/* ── Status bar ── */}
      <div className="px-3 py-1.5 border-t border-border/60 flex items-center justify-between bg-navy-900/40">
        <span className="text-[10px] text-muted-foreground/40">
          Tokens in <span className="text-cyan-400/60">cyan</span> (field) and <span className="text-orange-400/60">orange</span> (block) · empty = default layout
        </span>
        <span className="text-[10px] text-muted-foreground/30 font-mono tabular-nums">{charCount.toLocaleString()} chars</span>
      </div>
    </div>
  );
}
