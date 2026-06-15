/**
 * RichTextEditor — compact Tiptap-based rich text editor for email brief sections.
 * Value in/out is markdown, so saved content stays compatible with the existing
 * analyst_overrides storage, ReactMarkdown preview, and EML markdown→HTML export.
 */
import { useEffect, useRef } from 'react';
import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import { Markdown } from 'tiptap-markdown';
import { Bold, Italic, Code, List, ListOrdered, Undo2, Redo2 } from 'lucide-react';
import { cn } from '@/lib/utils';

interface RichTextEditorProps {
  value: string;
  onChange: (markdown: string) => void;
  /** Placeholder-ish hint shown via title attr; Tiptap placeholder ext not installed */
  minHeight?: number;
  className?: string;
}

function ToolbarButton({ onClick, active, disabled, title, children }: {
  onClick: () => void;
  active?: boolean;
  disabled?: boolean;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onMouseDown={(e) => {
        e.preventDefault(); // keep editor focus
        onClick();
      }}
      title={title}
      disabled={disabled}
      className={cn(
        'flex items-center justify-center w-6 h-6 rounded text-xs transition-colors',
        active
          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
          : 'text-muted-foreground hover:text-foreground hover:bg-secondary/60',
        disabled && 'opacity-40 cursor-not-allowed',
      )}
    >
      {children}
    </button>
  );
}

export default function RichTextEditor({ value, onChange, minHeight = 80, className }: RichTextEditorProps) {
  // Track the last markdown emitted so external value syncs don't clobber typing
  const lastEmittedRef = useRef(value);

  const editor = useEditor({
    extensions: [
      StarterKit.configure({
        codeBlock: false,
        heading: false,
        horizontalRule: false,
        blockquote: false,
      }),
      Markdown.configure({
        html: false,
        tightLists: true,
        bulletListMarker: '-',
      }),
    ],
    content: value,
    editorProps: {
      attributes: {
        class: 'snr-editor-content snr-richtext-compact',
        spellcheck: 'false',
        style: `min-height: ${minHeight}px;`,
      },
    },
    onUpdate: ({ editor: ed }) => {
      const mdStorage = (ed.storage as unknown as Record<string, { getMarkdown: () => string }>)['markdown'];
      const md = mdStorage.getMarkdown();
      lastEmittedRef.current = md;
      onChange(md);
    },
  });

  // Sync external value changes (e.g. Reset button) into the editor
  useEffect(() => {
    if (!editor) return;
    if (value !== lastEmittedRef.current) {
      lastEmittedRef.current = value;
      editor.commands.setContent(value);
    }
  }, [value, editor]);

  return (
    <div className={cn('border border-border rounded-md overflow-hidden bg-navy-950 focus-within:border-cyan-500/40', className)}>
      <div className="flex items-center gap-0.5 px-1.5 py-1 border-b border-border/60 bg-navy-900/60">
        <ToolbarButton onClick={() => editor?.chain().focus().toggleBold().run()} active={editor?.isActive('bold')} title="Bold (Ctrl+B)">
          <Bold className="w-3 h-3" />
        </ToolbarButton>
        <ToolbarButton onClick={() => editor?.chain().focus().toggleItalic().run()} active={editor?.isActive('italic')} title="Italic (Ctrl+I)">
          <Italic className="w-3 h-3" />
        </ToolbarButton>
        <ToolbarButton onClick={() => editor?.chain().focus().toggleCode().run()} active={editor?.isActive('code')} title="Inline code">
          <Code className="w-3 h-3" />
        </ToolbarButton>
        <div className="w-px h-4 bg-border/60 mx-0.5" />
        <ToolbarButton onClick={() => editor?.chain().focus().toggleBulletList().run()} active={editor?.isActive('bulletList')} title="Bullet list">
          <List className="w-3 h-3" />
        </ToolbarButton>
        <ToolbarButton onClick={() => editor?.chain().focus().toggleOrderedList().run()} active={editor?.isActive('orderedList')} title="Numbered list">
          <ListOrdered className="w-3 h-3" />
        </ToolbarButton>
        <div className="w-px h-4 bg-border/60 mx-0.5" />
        <ToolbarButton onClick={() => editor?.chain().focus().undo().run()} disabled={!editor?.can().undo()} title="Undo">
          <Undo2 className="w-3 h-3" />
        </ToolbarButton>
        <ToolbarButton onClick={() => editor?.chain().focus().redo().run()} disabled={!editor?.can().redo()} title="Redo">
          <Redo2 className="w-3 h-3" />
        </ToolbarButton>
      </div>
      <EditorContent editor={editor} />
    </div>
  );
}
