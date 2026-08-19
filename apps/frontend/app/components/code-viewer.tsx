"use client";

import Editor from "@monaco-editor/react";
import { SpinnerIcon } from "@/app/components/icons";

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  py: "python",
  js: "javascript",
  jsx: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  ts: "typescript",
  tsx: "typescript",
  json: "json",
  yml: "yaml",
  yaml: "yaml",
  sh: "shell",
  bash: "shell",
  rb: "ruby",
  go: "go",
  rs: "rust",
  java: "java",
  php: "php",
  cs: "csharp",
  cpp: "cpp",
  cc: "cpp",
  c: "c",
  h: "c",
  md: "markdown",
  mdx: "markdown",
  toml: "toml",
  dockerfile: "dockerfile",
  sql: "sql",
};

function languageForFile(filePath: string | null | undefined): string {
  if (!filePath) return "plaintext";
  const base = filePath.split("/").pop() ?? filePath;
  if (base.toLowerCase() === "dockerfile") return "dockerfile";
  const ext = base.includes(".") ? base.split(".").pop()?.toLowerCase() : undefined;
  return (ext && LANGUAGE_BY_EXTENSION[ext]) || "plaintext";
}

/**
 * Markdown's Monaco grammar doesn't tokenize a leading YAML front-matter
 * block (`---\n...\n---`), so SKILL.md manifests render their metadata as
 * flat text. Split it off so it can be shown in its own YAML-mode pane.
 */
function splitFrontmatter(code: string): { frontmatter: string; bodyStartIndex: number } | null {
  const lines = code.split("\n");
  if (lines[0]?.trim() !== "---") return null;
  for (let i = 1; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed === "---" || trimmed === "...") {
      return { frontmatter: lines.slice(1, i).join("\n"), bodyStartIndex: i + 1 };
    }
  }
  return null;
}

function paneHeight(code: string): number {
  const lineHeight = 19;
  const lineCount = code.split("\n").length;
  return Math.min(320, Math.max(lineHeight * lineCount + 20, 48));
}

function ReadOnlyPane({
  code,
  language,
  startLine,
}: {
  code: string;
  language: string;
  startLine: number;
}) {
  return (
    <Editor
      height={paneHeight(code)}
      language={language}
      value={code}
      theme="vs"
      loading={
        <div className="flex h-full items-center justify-center gap-2 bg-card py-4 text-xs text-muted-foreground">
          <SpinnerIcon className="h-3.5 w-3.5 animate-spin" />
          Loading editor…
        </div>
      }
      options={{
        readOnly: true,
        domReadOnly: true,
        minimap: { enabled: false },
        lineNumbers: (lineNumber: number) => String(startLine + lineNumber - 1),
        fontSize: 12,
        fontFamily: "var(--font-geist-mono), ui-monospace, monospace",
        scrollBeyondLastLine: false,
        folding: false,
        contextmenu: false,
        renderLineHighlight: "none",
        overviewRulerLanes: 0,
        hideCursorInOverviewRuler: true,
        wordWrap: "on",
        padding: { top: 10, bottom: 10 },
        scrollbar: { alwaysConsumeMouseWheel: false },
        guides: { indentation: false },
      }}
    />
  );
}

export function CodeViewer({
  code,
  filePath,
  startLine = 1,
}: {
  code: string;
  filePath?: string | null;
  startLine?: number;
}) {
  const language = languageForFile(filePath);
  const frontmatter = language === "markdown" ? splitFrontmatter(code) : null;

  if (frontmatter) {
    const bodyLines = code.split("\n").slice(frontmatter.bodyStartIndex);
    return (
      <div className="overflow-hidden rounded-xl border border-border/60">
        <div className="border-b border-border bg-muted px-3 py-1.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
          Front matter
        </div>
        <ReadOnlyPane code={frontmatter.frontmatter} language="yaml" startLine={startLine + 1} />
        <div className="border-y border-border bg-muted px-3 py-1.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
          Markdown
        </div>
        <ReadOnlyPane
          code={bodyLines.join("\n")}
          language="markdown"
          startLine={startLine + frontmatter.bodyStartIndex}
        />
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-border/60">
      <ReadOnlyPane code={code} language={language} startLine={startLine} />
    </div>
  );
}
