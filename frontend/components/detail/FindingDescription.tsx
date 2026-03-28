"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { Components } from "react-markdown";

const mdComponents: Components = {
  a: ({ href, children, ...rest }) => (
    <a
      href={href}
      {...rest}
      target={href?.startsWith("http") ? "_blank" : undefined}
      rel={href?.startsWith("http") ? "noopener noreferrer" : undefined}
    >
      {children}
    </a>
  ),
  pre: ({ children }) => (
    <pre className="detail-panel-snippet detail-panel-description-pre">{children}</pre>
  ),
  code: ({ className, children, ...rest }) => {
    const isBlock = Boolean(className?.includes("language-"));
    if (isBlock) {
      return (
        <code className={className} {...rest}>
          {children}
        </code>
      );
    }
    return (
      <code className="detail-panel-inline-code" {...rest}>
        {children}
      </code>
    );
  },
  table: ({ children }) => (
    <div className="detail-panel-md-table-wrap">
      <table className="detail-panel-md-table">{children}</table>
    </div>
  ),
};

/**
 * Renders scanner-sourced finding descriptions: Markdown/GFM (headers, lists,
 * fenced code, emphasis) and plain text with inline `code` / **bold** still parse sensibly.
 */
export function FindingDescription({ text }: { text: string }) {
  const trimmed = text?.trim() ?? "";
  if (!trimmed) {
    return <p className="detail-panel-prose">—</p>;
  }

  return (
    <div className="detail-panel-prose detail-panel-description-md">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
        {trimmed}
      </ReactMarkdown>
    </div>
  );
}
