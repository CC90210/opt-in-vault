import "server-only";

import { createHash } from "node:crypto";

const MAX_TEMPLATE_LENGTH = 100_000;
const MAX_RENDERED_LENGTH = 200_000;
const MAX_VARIABLE_LENGTH = 10_000;
const MAX_SPINTAX_GROUPS = 1_000;

export class TemplateRenderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TemplateRenderError";
  }
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function deterministicChoice(seed: string, index: number, length: number): number {
  const digest = createHash("sha256")
    .update("opt-in-vault:spintax:v1\0")
    .update(seed)
    .update("\0")
    .update(String(index))
    .digest();
  return digest.readUInt32BE(0) % length;
}

function renderSpintax(template: string, seed: string): string {
  let groupIndex = 0;
  const rendered = template.replace(/\{([^{}|]+(?:\|[^{}|]+)+)\}/g, (_, body: string) => {
    if (groupIndex >= MAX_SPINTAX_GROUPS) {
      throw new TemplateRenderError("Template contains too many spintax groups");
    }
    const choices = body.split("|");
    const choice = choices[deterministicChoice(seed, groupIndex, choices.length)];
    groupIndex += 1;
    return choice;
  });
  if (/(?<!\{)\{[^{}]*\|[^{}]*\}(?!\})/.test(rendered)) {
    throw new TemplateRenderError("Template contains unsupported nested spintax");
  }
  return rendered;
}

export function renderTemplate(
  template: string,
  variables: Readonly<Record<string, string | number | null | undefined>>,
  options: { seed: string; format: "text" | "html" },
): string {
  if (!options.seed || template.length > MAX_TEMPLATE_LENGTH) {
    throw new TemplateRenderError("Template or render seed is invalid");
  }

  const withSpintax = renderSpintax(template, options.seed);
  const rendered = withSpintax.replace(
    /\{\{\s*([A-Za-z][A-Za-z0-9_]*)\s*\}\}|(?<!\{)\{\s*([A-Za-z][A-Za-z0-9_]*)\s*\}(?!\})/g,
    (_, doubleBraceKey: string | undefined, singleBraceKey: string | undefined) => {
      const key = doubleBraceKey ?? singleBraceKey;
      if (!key) {
        throw new TemplateRenderError("Template variable is invalid");
      }
      const value = variables[key];
      if (value === undefined || value === null) {
        throw new TemplateRenderError(`Missing template variable: ${key}`);
      }
      const stringValue = String(value);
      if (stringValue.length > MAX_VARIABLE_LENGTH) {
        throw new TemplateRenderError(`Template variable is too long: ${key}`);
      }
      return options.format === "html" ? escapeHtml(stringValue) : stringValue;
    },
  );

  if (/\{\{[^{}]+\}\}/.test(rendered)) {
    throw new TemplateRenderError("Template contains an invalid variable expression");
  }
  if (rendered.length > MAX_RENDERED_LENGTH) {
    throw new TemplateRenderError("Rendered message exceeds the size limit");
  }
  return rendered;
}

export function validateSubject(subject: string): string {
  const normalized = subject.trim();
  if (
    !normalized ||
    normalized.length > 998 ||
    /[\r\n\u0000]/.test(normalized)
  ) {
    throw new TemplateRenderError("Email subject is invalid");
  }
  return normalized;
}
