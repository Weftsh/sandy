/**
 * Pure checks for the network and host settings the stack is about to use.
 */

export interface Cidr {
  network: number;
  prefix: number;
}

export function parseCidr(s: string): Cidr {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(s.trim());
  if (!m) throw new Error(`${JSON.stringify(s)} is not an IPv4 CIDR block`);
  const octets = m.slice(1, 5).map(Number);
  const prefix = Number(m[5]);
  if (octets.some((o) => o > 255) || prefix > 32) throw new Error(`${JSON.stringify(s)} is not an IPv4 CIDR block`);
  const addr = ((octets[0]! << 24) | (octets[1]! << 16) | (octets[2]! << 8) | octets[3]!) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  if ((addr & mask) >>> 0 !== addr) throw new Error(`${s} has host bits set; use ${formatCidr({ network: (addr & mask) >>> 0, prefix })}`);
  return { network: addr, prefix };
}

export function formatCidr(c: Cidr): string {
  const n = c.network;
  return `${n >>> 24}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}/${c.prefix}`;
}

function range(c: Cidr): [number, number] {
  const size = 2 ** (32 - c.prefix);
  return [c.network, c.network + size - 1];
}

export function overlaps(a: Cidr, b: Cidr): boolean {
  const [a0, a1] = range(a);
  const [b0, b1] = range(b);
  return a0 <= b1 && b0 <= a1;
}

/**
 * The host slot pool is carved into one /30 per sandbox and must not overlap
 * any VPC CIDR, or the host could not route to VPC addresses in it.
 */
export function checkSlotPool(slotPool: string, vpcCidrs: string[], maxSandboxes: number): string[] {
  const problems: string[] = [];
  let pool: Cidr;
  try {
    pool = parseCidr(slotPool);
  } catch (e) {
    return [`SlotPoolCidr: ${(e as Error).message}`];
  }
  for (const v of vpcCidrs) {
    if (overlaps(pool, parseCidr(v))) problems.push(`SlotPoolCidr ${slotPool} overlaps the VPC CIDR ${v}; choose a range outside the VPC`);
  }
  const reserved = [parseCidr("169.254.0.0/16"), parseCidr("127.0.0.0/8"), parseCidr("224.0.0.0/3")];
  if (reserved.some((r) => overlaps(pool, r))) problems.push(`SlotPoolCidr ${slotPool} overlaps a reserved range`);
  const slots = 2 ** (32 - pool.prefix) / 4;
  if (slots < maxSandboxes) {
    problems.push(`SlotPoolCidr ${slotPool} has room for ${slots} sandboxes per host, fewer than MaxSandboxesPerHost (${maxSandboxes})`);
  }
  return problems;
}

export interface SubnetFacts {
  subnetId: string;
  vpcId?: string;
  availabilityZone?: string;
}

export function checkSubnets(label: string, subnetIds: string[], found: SubnetFacts[], vpcId: string): string[] {
  const problems: string[] = [];
  for (const id of subnetIds) {
    const s = found.find((f) => f.subnetId === id);
    if (!s) problems.push(`${label}: subnet ${id} was not found`);
    else if (s.vpcId !== vpcId) problems.push(`${label}: subnet ${id} is in ${s.vpcId}, not ${vpcId}`);
  }
  const azs = new Set(found.filter((f) => subnetIds.includes(f.subnetId)).map((f) => f.availabilityZone));
  if (azs.size < 2) problems.push(`${label}: subnets must span at least two Availability Zones`);
  return problems;
}

export interface InstanceTypeFacts {
  instanceType: string;
  architectures: string[];
  bareMetal: boolean;
  /** EC2 `ProcessorInfo.SupportedFeatures`, e.g. `nested-virtualization`. */
  processorFeatures: string[];
}

/**
 * Hosts are x86_64. With nested virtualization (the launch template sets
 * CpuOptions.NestedVirtualization) every type must report the
 * `nested-virtualization` processor feature; in metal mode every type must be
 * bare metal.
 */
export function checkInstanceTypes(requested: string[], found: InstanceTypeFacts[], mode: "nested" | "metal"): string[] {
  const problems: string[] = [];
  if (requested.length === 0) return ["no host instance types were given"];
  for (const t of requested) {
    const f = found.find((x) => x.instanceType === t);
    if (!f) {
      problems.push(`instance type ${t} is not offered in this Region`);
      continue;
    }
    if (!f.architectures.includes("x86_64")) problems.push(`instance type ${t} is not x86_64`);
    if (mode === "metal" && !f.bareMetal) problems.push(`HostVirtualization is metal, but ${t} is not a bare-metal type`);
    if (mode === "nested") {
      if (f.bareMetal) problems.push(`${t} is bare metal; set HostVirtualization to metal`);
      else if (!f.processorFeatures.includes("nested-virtualization")) {
        problems.push(`${t} does not support nested virtualization; use a C8i, M8i or R8i type, or a .metal type with HostVirtualization=metal`);
      }
    }
  }
  return problems;
}
