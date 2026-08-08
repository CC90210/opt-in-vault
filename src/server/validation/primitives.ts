import "server-only";

import { Buffer } from "node:buffer";

import { z } from "zod";

export const MAX_EMAIL_BODY_BYTES = 200_000;
export const MAX_HEADER_VALUE_BYTES = 998;
export const MAX_SPINTAX_CHARS = 100_000;
export const MAX_SPINTAX_BYTES = 100_000;
export const MAX_SPINTAX_DEPTH = 3;
export const MAX_SPINTAX_GROUPS = 100;
export const MAX_SPINTAX_ALTERNATIVES = 20;

export const idSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/, "Invalid identifier.");

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .max(254)
  .email();

export const webUrlSchema = z
  .string()
  .max(2_048)
  .url()
  .refine((value) => {
    const url = new URL(value);
    return (
      (url.protocol === "https:" || url.protocol === "http:") &&
      url.username.length === 0 &&
      url.password.length === 0
    );
  }, "URL must use HTTP(S) and must not contain credentials.");

export const headerValueSchema = z
  .string()
  .max(MAX_HEADER_VALUE_BYTES)
  .refine(
    (value) => !/[\u0000-\u001f\u007f]/.test(value),
    "Header values cannot contain control bytes.",
  )
  .refine(
    (value) => Buffer.byteLength(value, "utf8") <= MAX_HEADER_VALUE_BYTES,
    `Header values cannot exceed ${MAX_HEADER_VALUE_BYTES} UTF-8 bytes.`,
  );

export const emailBodySchema = z
  .string()
  .max(MAX_EMAIL_BODY_BYTES)
  .refine(
    (value) => Buffer.byteLength(value, "utf8") <= MAX_EMAIL_BODY_BYTES,
    `Email bodies cannot exceed ${MAX_EMAIL_BODY_BYTES} UTF-8 bytes.`,
  )
  .refine((value) => !value.includes("\u0000"), "Email bodies cannot contain null bytes.");

function hasSafeSpintaxComplexity(value: string): boolean {
  const frames: Array<{
    alternatives: number;
    contentStart: number;
    currentAlternativeStart: number;
    hasNestedGroup: boolean;
  }> = [];
  let groups = 0;

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "\\") {
      index += 1;
      continue;
    }
    if (character === "{") {
      groups += 1;
      if (frames.length > 0) {
        frames[frames.length - 1].hasNestedGroup = true;
      }
      frames.push({
        alternatives: 1,
        contentStart: index + 1,
        currentAlternativeStart: index + 1,
        hasNestedGroup: false,
      });
      if (groups > MAX_SPINTAX_GROUPS || frames.length > MAX_SPINTAX_DEPTH) {
        return false;
      }
      continue;
    }
    if (character === "|") {
      if (frames.length === 0) {
        continue;
      }
      const frame = frames[frames.length - 1];
      if (value.slice(frame.currentAlternativeStart, index).trim().length === 0) {
        return false;
      }
      frame.alternatives += 1;
      frame.currentAlternativeStart = index + 1;
      if (frame.alternatives > MAX_SPINTAX_ALTERNATIVES) {
        return false;
      }
      continue;
    }
    if (character === "}") {
      const frame = frames.pop();
      if (!frame || value.slice(frame.currentAlternativeStart, index).trim().length === 0) {
        return false;
      }
      if (frame.alternatives === 1) {
        const content = value.slice(frame.contentStart, index);
        if (frame.hasNestedGroup || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(content)) {
          return false;
        }
      }
    }
  }

  return frames.length === 0;
}

export const spintaxTemplateSchema = z
  .string()
  .max(MAX_SPINTAX_CHARS)
  .refine(
    (value) => Buffer.byteLength(value, "utf8") <= MAX_SPINTAX_BYTES,
    `Spintax cannot exceed ${MAX_SPINTAX_BYTES} UTF-8 bytes.`,
  )
  .refine((value) => !value.includes("\u0000"), "Spintax cannot contain null bytes.")
  .refine(hasSafeSpintaxComplexity, "Spintax is unbalanced or exceeds complexity limits.");
