import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import {
  assertSafeEgressTarget,
  EgressTargetError,
  isPublicIpAddress,
} from "./network";

describe("egress network policy", () => {
  it.each([
    "0.0.0.0",
    "10.0.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "192.168.1.1",
    "192.88.99.2",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "fc00::1",
    "fe80::1",
    "ff02::1",
    "2001:db8::1",
    "::ffff:127.0.0.1",
    "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
    "2002:7f00:0001::",
    "2001:100::1",
    "3ffe::1",
    "3fff::1",
  ])("rejects non-public IP address %s", (address) => {
    expect(isPublicIpAddress(address)).toBe(false);
  });

  it.each(["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])(
    "accepts public IP address %s",
    (address) => {
      expect(isPublicIpAddress(address)).toBe(true);
    },
  );

  it.each(["2001:1::1", "2001:3::1", "2001:4:112::1", "2001:20::1", "2001:30::1"])(
    "allows the explicitly global 2001::/23 carveout %s",
    (address) => {
      expect(isPublicIpAddress(address)).toBe(true);
    },
  );

  it("allows an approved port only when every DNS result is public", async () => {
    const lookup = vi.fn().mockResolvedValue([
      { address: "8.8.8.8", family: 4 as const },
      { address: "2606:4700:4700::1111", family: 6 as const },
    ]);

    await expect(
      assertSafeEgressTarget({ hostname: "smtp.example.com", port: 587 }, { lookup }),
    ).resolves.toEqual({
      hostname: "smtp.example.com",
      port: 587,
      addresses: ["8.8.8.8", "2606:4700:4700::1111"],
      connectionAddress: "8.8.8.8",
      tlsServername: "smtp.example.com",
    });
  });

  it("returns a frozen pinned connection contract after exactly one DNS lookup", async () => {
    const lookup = vi
      .fn()
      .mockResolvedValueOnce([{ address: "8.8.8.8", family: 4 as const }])
      .mockResolvedValueOnce([{ address: "127.0.0.1", family: 4 as const }]);

    const target = await assertSafeEgressTarget(
      { hostname: "smtp.example.com", port: 587 },
      { lookup },
    );

    expect(lookup).toHaveBeenCalledTimes(1);
    expect(target.connectionAddress).toBe("8.8.8.8");
    expect(target.addresses[0]).toBe(target.connectionAddress);
    expect(target.tlsServername).toBe("smtp.example.com");
    expect(Object.isFrozen(target)).toBe(true);
    expect(Object.isFrozen(target.addresses)).toBe(true);
  });

  it("rejects unapproved ports, local hostnames, empty DNS, and mixed private DNS", async () => {
    const publicLookup = vi
      .fn()
      .mockResolvedValue([{ address: "8.8.8.8", family: 4 as const }]);
    const mixedLookup = vi.fn().mockResolvedValue([
      { address: "8.8.8.8", family: 4 as const },
      { address: "127.0.0.1", family: 4 as const },
    ]);
    const emptyLookup = vi.fn().mockResolvedValue([]);

    await expect(
      assertSafeEgressTarget(
        { hostname: "smtp.example.com", port: 22 },
        { lookup: publicLookup },
      ),
    ).rejects.toBeInstanceOf(EgressTargetError);
    await expect(
      assertSafeEgressTarget(
        { hostname: "localhost", port: 587 },
        { lookup: publicLookup },
      ),
    ).rejects.toBeInstanceOf(EgressTargetError);
    await expect(
      assertSafeEgressTarget(
        { hostname: "smtp.example.com", port: 587 },
        { lookup: emptyLookup },
      ),
    ).rejects.toBeInstanceOf(EgressTargetError);
    await expect(
      assertSafeEgressTarget(
        { hostname: "smtp.example.com", port: 587 },
        { lookup: mixedLookup },
      ),
    ).rejects.toBeInstanceOf(EgressTargetError);
  });

  it("checks IP literals without performing a second DNS lookup", async () => {
    const lookup = vi.fn();

    await expect(
      assertSafeEgressTarget({ hostname: "169.254.169.254", port: 587 }, { lookup }),
    ).rejects.toBeInstanceOf(EgressTargetError);
    expect(lookup).not.toHaveBeenCalled();
  });
});
