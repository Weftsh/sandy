import { describe, expect, it } from "vitest";

import { checkSlotPool, formatCidr, overlaps, parseCidr } from "../src/verify-release/network.js";

describe("CIDR helpers", () => {
  it("parses and formats", () => {
    expect(formatCidr(parseCidr("10.200.0.0/16"))).toBe("10.200.0.0/16");
    expect(formatCidr(parseCidr("0.0.0.0/0"))).toBe("0.0.0.0/0");
    expect(formatCidr(parseCidr("255.255.255.255/32"))).toBe("255.255.255.255/32");
  });

  it("rejects malformed blocks and host bits", () => {
    for (const bad of ["10.0.0.0", "10.0.0.0/33", "256.0.0.0/8", "10.0.0/8", "::/0"]) expect(() => parseCidr(bad)).toThrow();
    expect(() => parseCidr("10.0.0.1/16")).toThrow(/host bits set; use 10.0.0.0\/16/);
  });

  it("detects overlap", () => {
    expect(overlaps(parseCidr("10.0.0.0/8"), parseCidr("10.200.0.0/16"))).toBe(true);
    expect(overlaps(parseCidr("10.200.0.0/16"), parseCidr("10.201.0.0/16"))).toBe(false);
    expect(overlaps(parseCidr("10.200.255.252/30"), parseCidr("10.200.255.255/32"))).toBe(true);
    expect(overlaps(parseCidr("192.168.0.0/16"), parseCidr("10.0.0.0/8"))).toBe(false);
  });
});

describe("checkSlotPool", () => {
  it("accepts the default pool next to a typical VPC", () => {
    expect(checkSlotPool("10.200.0.0/16", ["10.0.0.0/16"], 64)).toEqual([]);
  });

  it("rejects overlap, reserved ranges and pools too small for the sandbox limit", () => {
    expect(checkSlotPool("10.0.0.0/8", ["10.0.0.0/16"], 8)[0]).toMatch(/overlaps the VPC CIDR/);
    expect(checkSlotPool("169.254.0.0/20", ["10.0.0.0/16"], 8)[0]).toMatch(/reserved range/);
    expect(checkSlotPool("10.200.0.0/28", ["10.0.0.0/16"], 8)[0]).toMatch(/room for 4 sandboxes per host, fewer than MaxSandboxesPerHost \(8\)/);
    expect(checkSlotPool("nope", [], 8)[0]).toMatch(/SlotPoolCidr/);
  });
});
