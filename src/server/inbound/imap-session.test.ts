import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  options: vi.fn(),
  assertSafe: vi.fn(async () => ({
    hostname: "imap.example.com",
    tlsServername: "imap.example.com",
    port: 993,
    connectionAddress: "203.0.113.42",
    addresses: ["203.0.113.42"],
  })),
}));

vi.mock("server-only", () => ({}));
vi.mock("imapflow", () => ({
  ImapFlow: class {
    constructor(options: unknown) {
      mocks.options(options);
    }
  },
}));
vi.mock("@/server/security/network", () => ({
  assertSafeEgressTarget: mocks.assertSafe,
}));

import { createPinnedImapSession } from "./imap-client";

describe("pinned IMAP transport", () => {
  it("requires implicit TLS on port 993 and connects to the pinned address", async () => {
    await createPinnedImapSession({
      hostname: "imap.example.com",
      port: 993,
      secure: true,
      username: "sender@example.com",
      password: "secret",
    });

    expect(mocks.assertSafe).toHaveBeenCalledWith(
      { hostname: "imap.example.com", port: 993 },
      { allowedPorts: new Set([993]) },
    );
    expect(mocks.options).toHaveBeenCalledWith(
      expect.objectContaining({
        host: "203.0.113.42",
        servername: "imap.example.com",
        port: 993,
        secure: true,
        disableCompression: true,
        connectionTimeout: 10_000,
        greetingTimeout: 10_000,
        socketTimeout: 30_000,
        maxLineLength: 65_536,
        maxLiteralSize: 1_000_001,
        tls: expect.objectContaining({ servername: "imap.example.com" }),
      }),
    );
  });

  it.each([
    { port: 143, secure: true },
    { port: 993, secure: false },
  ])("rejects downgrade-capable IMAP configuration", async ({ port, secure }) => {
    mocks.assertSafe.mockClear();
    await expect(
      createPinnedImapSession({
        hostname: "imap.example.com",
        port,
        secure,
        username: "sender@example.com",
        password: "secret",
      }),
    ).rejects.toThrow(/tls|993/i);
    expect(mocks.assertSafe).not.toHaveBeenCalled();
  });
});
