import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const css = readFileSync(fileURLToPath(new URL("./globals.css", import.meta.url)), "utf8");

function declarations(selector: string): Map<string, string> {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`${escaped}\\s*\\{([^}]*)\\}`).exec(css);
  expect(match, `missing CSS rule for ${selector}`).not.toBeNull();
  return new Map(
    match![1]
      .split(";")
      .map((declaration) => declaration.trim())
      .filter(Boolean)
      .map((declaration) => {
        const separator = declaration.indexOf(":");
        return [
          declaration.slice(0, separator).trim(),
          declaration.slice(separator + 1).trim(),
        ];
      }),
  );
}

function customProperty(name: string): string {
  const value = declarations(":root").get(name);
  expect(value, `missing ${name}`).toBeDefined();
  return value!;
}

function resolveColor(value: string): string {
  const variable = /var\((--[^)]+)\)/.exec(value)?.[1];
  const resolved = variable ? customProperty(variable) : value;
  const hex = /#[0-9a-f]{3,6}/i.exec(resolved)?.[0];
  expect(hex, `missing hex color in ${value}`).toBeDefined();
  return hex!;
}

function luminance(hex: string): number {
  const expanded = hex.length === 4
    ? `#${[...hex.slice(1)].map((character) => character.repeat(2)).join("")}`
    : hex;
  const channels = expanded
    .slice(1)
    .match(/.{2}/g)!
    .map((channel) => Number.parseInt(channel, 16) / 255)
    .map((channel) =>
      channel <= 0.04045
        ? channel / 12.92
        : ((channel + 0.055) / 1.055) ** 2.4,
    );
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}

function contrast(first: string, second: string): number {
  const light = Math.max(luminance(first), luminance(second));
  const dark = Math.min(luminance(first), luminance(second));
  return (light + 0.05) / (dark + 0.05);
}

describe("dashboard accessibility colors", () => {
  it("keeps the skip-link text above normal-text contrast", () => {
    const skip = declarations(".skip-link");
    expect(
      contrast(resolveColor(skip.get("color")!), resolveColor(skip.get("background")!)),
    ).toBeGreaterThanOrEqual(4.5);
  });

  it("keeps the default focus indicator distinct from the paper surface", () => {
    const focus = declarations(":focus-visible");
    expect(
      contrast(resolveColor(focus.get("outline")!), customProperty("--paper")),
    ).toBeGreaterThanOrEqual(3);
    expect(css).toMatch(/\.vault-rail\s+:focus-visible\s*\{[^}]*outline-color:/);
  });

  it("keeps inactive and active navigation codes readable", () => {
    const inactive = declarations(".nav-link > span");
    const active = declarations(".nav-link-active > span");
    const activeLink = declarations(".nav-link-active");

    expect(
      contrast(resolveColor(inactive.get("color")!), customProperty("--vault")),
    ).toBeGreaterThanOrEqual(4.5);
    expect(
      contrast(
        resolveColor(active.get("color")!),
        resolveColor(activeLink.get("background")!),
      ),
    ).toBeGreaterThanOrEqual(4.5);
  });
});
