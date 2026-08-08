import "server-only";

import { lookup as nodeLookup } from "node:dns/promises";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

export const APPROVED_EGRESS_PORTS = new Set([465, 587, 993]);
const MAX_RESOLVED_ADDRESSES = 16;

type LookupAddress = { address: string; family: 4 | 6 };
type LookupFunction = (
  hostname: string,
  options: { all: true; verbatim: true },
) => Promise<readonly LookupAddress[]>;

declare const pinnedEgressTargetBrand: unique symbol;

/**
 * A DNS result that is safe only when the transport connects to
 * `connectionAddress` (or another member of `addresses`). `hostname` and
 * `tlsServername` are identity values for TLS verification and must never be
 * resolved again for the socket connection.
 */
export type PinnedEgressTarget = Readonly<{
  hostname: string;
  tlsServername: string;
  port: number;
  connectionAddress: string;
  addresses: readonly [string, ...string[]];
  readonly [pinnedEgressTargetBrand]: true;
}>;

export class EgressTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EgressTargetError";
  }
}

function parseIpv4(address: string): number {
  return address
    .split(".")
    .map(Number)
    .reduce((value, octet) => value * 256 + octet, 0);
}

function inIpv4Cidr(value: number, base: number, prefix: number): boolean {
  const shift = 32 - prefix;
  return Math.floor(value / 2 ** shift) === Math.floor(base / 2 ** shift);
}

function isPublicIpv4(address: string): boolean {
  const value = parseIpv4(address);
  const blocked: Array<[string, number]> = [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ];
  return !blocked.some(([base, prefix]) => inIpv4Cidr(value, parseIpv4(base), prefix));
}

function parseIpv6(address: string): bigint | null {
  let normalized = address.toLowerCase();
  if (normalized.includes(".")) {
    const lastColon = normalized.lastIndexOf(":");
    const ipv4 = normalized.slice(lastColon + 1);
    if (isIP(ipv4) !== 4) {
      return null;
    }
    const value = parseIpv4(ipv4);
    normalized = `${normalized.slice(0, lastColon)}:${(value >>> 16).toString(16)}:${(
      value & 0xffff
    ).toString(16)}`;
  }

  const halves = normalized.split("::");
  if (halves.length > 2) {
    return null;
  }
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    return null;
  }
  const groups = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[a-f0-9]{1,4}$/.test(group))) {
    return null;
  }

  return groups.reduce(
    (value, group) => (value << BigInt(16)) | BigInt(`0x${group}`),
    BigInt(0),
  );
}

function inIpv6Cidr(value: bigint, base: bigint, prefix: number): boolean {
  return value >> BigInt(128 - prefix) === base >> BigInt(128 - prefix);
}

function ipv6Constant(address: string): bigint {
  const value = parseIpv6(address);
  if (value === null) {
    throw new Error(`Invalid internal IPv6 constant: ${address}`);
  }
  return value;
}

const special2001Base = ipv6Constant("2001::");
const special2001ExactGlobal = new Set([
  ipv6Constant("2001:1::1"),
  ipv6Constant("2001:1::2"),
  ipv6Constant("2001:1::3"),
]);
const special2001GlobalCidrs: Array<readonly [bigint, number]> = [
  [ipv6Constant("2001:3::"), 32],
  [ipv6Constant("2001:4:112::"), 48],
  [ipv6Constant("2001:20::"), 28],
  [ipv6Constant("2001:30::"), 28],
];

function isGlobalSpecial2001(value: bigint): boolean {
  return (
    special2001ExactGlobal.has(value) ||
    special2001GlobalCidrs.some(([base, prefix]) => inIpv6Cidr(value, base, prefix))
  );
}

function isPublicIpv6(address: string): boolean {
  const value = parseIpv6(address);
  if (value === null) {
    return false;
  }

  const ipv4MappedBase = BigInt(0xffff) << BigInt(32);
  if (inIpv6Cidr(value, ipv4MappedBase, 96)) {
    const mapped = Number(value & BigInt(0xffffffff));
    const mappedAddress = [24, 16, 8, 0]
      .map((shift) => (mapped >>> shift) & 0xff)
      .join(".");
    return isPublicIpv4(mappedAddress);
  }

  const globalUnicastBase = BigInt(0x2000) << BigInt(112);
  if (!inIpv6Cidr(value, globalUnicastBase, 3)) {
    return false;
  }

  if (inIpv6Cidr(value, special2001Base, 23) && !isGlobalSpecial2001(value)) {
    return false;
  }

  const documentationBase = ipv6Constant("2001:db8::");
  const sixToFourBase = ipv6Constant("2002::");
  const formerSixBoneBase = ipv6Constant("3ffe::");
  const documentationV2Base = ipv6Constant("3fff::");
  return (
    !inIpv6Cidr(value, documentationBase, 32) &&
    !inIpv6Cidr(value, sixToFourBase, 16) &&
    !inIpv6Cidr(value, formerSixBoneBase, 16) &&
    !inIpv6Cidr(value, documentationV2Base, 20)
  );
}

export function isPublicIpAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    return isPublicIpv4(address);
  }
  if (family === 6) {
    return isPublicIpv6(address);
  }
  return false;
}

function normalizeHostname(hostname: string): string {
  if (
    typeof hostname !== "string" ||
    hostname.length === 0 ||
    hostname.length > 253 ||
    /[\s\u0000-\u001f\u007f/%]/.test(hostname)
  ) {
    throw new EgressTargetError("Egress hostname is invalid.");
  }

  let normalized = hostname;
  if (normalized.startsWith("[") && normalized.endsWith("]")) {
    normalized = normalized.slice(1, -1);
  }
  normalized = normalized.replace(/\.$/, "").toLowerCase();
  if (isIP(normalized)) {
    return normalized;
  }

  const ascii = domainToASCII(normalized);
  if (
    !ascii ||
    ascii === "localhost" ||
    ascii.endsWith(".localhost") ||
    ascii.endsWith(".local") ||
    ascii.endsWith(".internal")
  ) {
    throw new EgressTargetError("Local egress hostnames are not allowed.");
  }
  return ascii;
}

const defaultLookup: LookupFunction = async (hostname, options) =>
  nodeLookup(hostname, options) as Promise<LookupAddress[]>;

export async function assertSafeEgressTarget(
  target: { hostname: string; port: number },
  options: {
    allowedPorts?: ReadonlySet<number>;
    lookup?: LookupFunction;
  } = {},
): Promise<PinnedEgressTarget> {
  const allowedPorts = options.allowedPorts ?? APPROVED_EGRESS_PORTS;
  if (!Number.isInteger(target.port) || !allowedPorts.has(target.port)) {
    throw new EgressTargetError("Egress port is not approved.");
  }

  const hostname = normalizeHostname(target.hostname);
  if (isIP(hostname)) {
    if (!isPublicIpAddress(hostname)) {
      throw new EgressTargetError("Egress address is not public.");
    }
    return createPinnedTarget(hostname, target.port, [hostname]);
  }

  let resolved: readonly LookupAddress[];
  try {
    resolved = await (options.lookup ?? defaultLookup)(hostname, {
      all: true,
      verbatim: true,
    });
  } catch {
    throw new EgressTargetError("Egress hostname could not be resolved safely.");
  }

  const addresses = [...new Set(resolved.map(({ address }) => address))];
  if (
    addresses.length === 0 ||
    addresses.length > MAX_RESOLVED_ADDRESSES ||
    addresses.some((address) => !isPublicIpAddress(address))
  ) {
    throw new EgressTargetError("Every resolved egress address must be public.");
  }

  return createPinnedTarget(hostname, target.port, addresses);
}

function createPinnedTarget(
  hostname: string,
  port: number,
  addresses: string[],
): PinnedEgressTarget {
  const frozenAddresses = Object.freeze([...addresses]) as readonly [string, ...string[]];
  return Object.freeze({
    hostname,
    tlsServername: hostname,
    port,
    connectionAddress: frozenAddresses[0],
    addresses: frozenAddresses,
  }) as PinnedEgressTarget;
}
