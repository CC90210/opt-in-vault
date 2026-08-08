import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import {
  MAX_EMAIL_BODY_BYTES,
  MAX_HEADER_VALUE_BYTES,
  MAX_SPINTAX_BYTES,
  MAX_SPINTAX_DEPTH,
  emailBodySchema,
  emailSchema,
  headerValueSchema,
  idSchema,
  spintaxTemplateSchema,
  webUrlSchema,
} from "./primitives";

describe("boundary validation", () => {
  it("normalizes emails and accepts bounded opaque IDs", () => {
    expect(emailSchema.parse("  USER@Example.COM ")).toBe("user@example.com");
    expect(idSchema.parse("tenant_01-abc")).toBe("tenant_01-abc");
    expect(idSchema.safeParse("../tenant").success).toBe(false);
    expect(emailSchema.safeParse("not an email").success).toBe(false);
  });

  it("accepts only HTTP(S) URLs without embedded credentials", () => {
    expect(webUrlSchema.parse("https://example.com/consent?a=1")).toBe(
      "https://example.com/consent?a=1",
    );
    expect(webUrlSchema.safeParse("ftp://example.com/file").success).toBe(false);
    expect(webUrlSchema.safeParse("https://user:pass@example.com").success).toBe(false);
  });

  it("rejects CRLF and control-byte header injection", () => {
    expect(headerValueSchema.parse("A normal subject")).toBe("A normal subject");
    expect(headerValueSchema.safeParse("Subject\r\nBcc: victim@example.com").success).toBe(
      false,
    );
    expect(headerValueSchema.safeParse("hello\0world").success).toBe(false);
    expect(headerValueSchema.safeParse("hello\u000bworld").success).toBe(false);
    expect(headerValueSchema.safeParse("a".repeat(MAX_HEADER_VALUE_BYTES)).success).toBe(true);
    expect(headerValueSchema.safeParse("é".repeat(MAX_HEADER_VALUE_BYTES)).success).toBe(false);
  });

  it("enforces email body and spintax complexity limits", () => {
    expect(emailBodySchema.safeParse("a".repeat(MAX_EMAIL_BODY_BYTES)).success).toBe(true);
    expect(emailBodySchema.safeParse("a".repeat(MAX_EMAIL_BODY_BYTES + 1)).success).toBe(
      false,
    );
    expect(emailBodySchema.safeParse("\u0800".repeat(MAX_EMAIL_BODY_BYTES)).success).toBe(
      false,
    );
    expect(
      spintaxTemplateSchema.safeParse("{Hi|Hey} {first_name}").success,
    ).toBe(true);
    expect(spintaxTemplateSchema.safeParse("Hello {friend|there").success).toBe(false);

    const tooDeep = `${"{".repeat(MAX_SPINTAX_DEPTH + 1)}a|b${"}".repeat(
      MAX_SPINTAX_DEPTH + 1,
    )}`;
    expect(spintaxTemplateSchema.safeParse(tooDeep).success).toBe(false);
    expect(
      spintaxTemplateSchema.safeParse(`{${Array.from({ length: 21 }, (_, i) => i).join("|")}}`)
        .success,
    ).toBe(false);
    expect(spintaxTemplateSchema.safeParse("é".repeat(MAX_SPINTAX_BYTES)).success).toBe(false);
  });
});
