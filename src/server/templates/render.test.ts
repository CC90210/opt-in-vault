import {
  renderTemplate,
  TemplateRenderError,
  validateSubject,
} from "./render";

describe("template renderer", () => {
  it("renders spintax deterministically for the same immutable seed", () => {
    const template = "{Hi|Hey|Hello} {{first_name}} from {OASIS|our team}";
    const variables = { first_name: "Ada" };

    const first = renderTemplate(template, variables, {
      seed: "job-123",
      format: "text",
    });
    const replay = renderTemplate(template, variables, {
      seed: "job-123",
      format: "text",
    });

    expect(replay).toBe(first);
    expect(first).toContain("Ada");
    expect(first).not.toMatch(/[{}]/);
  });

  it("supports the documented single-brace merge syntax without treating it as spintax", () => {
    expect(
      renderTemplate("{Hi|Hey} {first_name} from {company_name}", {
        first_name: "Ada",
        company_name: "Analytical Engines",
      }, {
        seed: "job-single-braces",
        format: "text",
      }),
    ).toMatch(/^(Hi|Hey) Ada from Analytical Engines$/);
  });

  it("escapes variables in HTML and rejects missing or oversized values", () => {
    expect(
      renderTemplate("Hello {{first_name}}", { first_name: "<Ada & Co>" }, {
        seed: "job-1",
        format: "html",
      }),
    ).toBe("Hello &lt;Ada &amp; Co&gt;");
    expect(() =>
      renderTemplate("Hi {{missing}}", {}, { seed: "job-1", format: "text" }),
    ).toThrow(TemplateRenderError);
    expect(() =>
      renderTemplate("{{value}}", { value: "x".repeat(10_001) }, {
        seed: "job-1",
        format: "text",
      }),
    ).toThrow(TemplateRenderError);
  });

  it("rejects CRLF and empty or oversized subjects", () => {
    expect(validateSubject("A useful subject")).toBe("A useful subject");
    expect(() => validateSubject("Hello\r\nBcc: victim@example.com")).toThrow(
      TemplateRenderError,
    );
    expect(() => validateSubject(" ")).toThrow(TemplateRenderError);
    expect(() => validateSubject("x".repeat(999))).toThrow(TemplateRenderError);
  });
});
