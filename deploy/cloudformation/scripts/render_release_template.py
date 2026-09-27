#!/usr/bin/env python3
"""Fill the release values into weft-sandboxes.yaml.

The template in the repository carries placeholders (version 0.0.0-dev,
all-zero image digests, a placeholder AMI). The release workflow runs this
script to produce the published template:

  render_release_template.py \
      --template deploy/cloudformation/weft-sandboxes.yaml \
      --version 1.2.3 \
      --control-plane-image ghcr.io/weftsh/sandbox-control-plane@sha256:... \
      --gateway-image ghcr.io/weftsh/sandbox-egress-gateway@sha256:... \
      --amis amis.json \            # {"us-east-1": "ami-...", ...}
      --bootstrap-templates base=ghcr.io/weftsh/sandbox-base:1.2.3 \
      --out dist/release/weft-sandboxes.yaml

Every placeholder must be found exactly once, so a template change that
moves one fails the release instead of publishing a half-rendered template.
Plain text substitution keeps the template's comments and formatting.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$")
AMI_RE = re.compile(r"^ami-[0-9a-f]{8,17}$")
REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d+$")
ZERO_DIGEST = "sha256:" + "0" * 64


def replace_once(text: str, old: str, new: str, what: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"render: expected exactly one {what} ({old!r}), found {count}")
    return text.replace(old, new)


def replace_block(text: str, begin: str, end: str, body: str, what: str) -> str:
    pattern = re.compile(rf"(^[ \t]*# {re.escape(begin)}\n).*?(^[ \t]*# {re.escape(end)}\n)", re.S | re.M)
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise SystemExit(f"render: expected exactly one {what} block, found {len(matches)}")
    return pattern.sub(lambda m: m.group(1) + body + m.group(2), text)


def render(template: str, version: str, cp_image: str, gw_image: str, amis: dict[str, str], bootstrap: str) -> str:
    if not VERSION_RE.match(version):
        raise SystemExit(f"render: invalid version {version!r}")
    for name, image in (("control plane", cp_image), ("gateway", gw_image)):
        if not IMAGE_RE.match(image) or image.endswith(ZERO_DIGEST):
            raise SystemExit(f"render: the {name} image must be pinned by a real digest, got {image!r}")
    if not amis:
        raise SystemExit("render: no AMIs")
    for region, ami in amis.items():
        if not REGION_RE.match(region) or not AMI_RE.match(ami):
            raise SystemExit(f"render: invalid AMI entry {region}: {ami}")
    if "," in bootstrap and not all("=" in p for p in bootstrap.split(",")):
        raise SystemExit(f"render: invalid bootstrap templates {bootstrap!r}")

    out = replace_once(template, "(weft-sandboxes 0.0.0-dev)", f"(weft-sandboxes {version})", "description version")
    out = replace_once(out, 'Value: "0.0.0-dev"', f'Value: "{version}"', "Release.Version mapping")
    out = replace_once(
        out,
        f"ControlPlane: ghcr.io/weftsh/sandbox-control-plane@{ZERO_DIGEST}",
        f"ControlPlane: {cp_image}",
        "control plane image mapping",
    )
    out = replace_once(
        out,
        f"Gateway: ghcr.io/weftsh/sandbox-egress-gateway@{ZERO_DIGEST}",
        f"Gateway: {gw_image}",
        "gateway image mapping",
    )
    out = replace_once(
        out,
        "Default: base=ghcr.io/weftsh/sandbox-base:0.0.0-dev",
        f"Default: {bootstrap}",
        "BootstrapTemplates default",
    )

    regions = sorted(amis)
    ami_body = "  HostAmi:\n" + "".join(f"    {r}:\n      ImageId: {amis[r]}\n" for r in regions)
    out = replace_block(out, "BEGIN RELEASE AMIS", "END RELEASE AMIS", ami_body, "HostAmi mapping")
    region_list = ", ".join(json.dumps(r) for r in regions)
    rule_body = (
        "  SupportedRegion:\n"
        '    RuleCondition: !Equals [!Ref HostAmiId, ""]\n'
        "    Assertions:\n"
        f'      - Assert: !Contains [[{region_list}], !Ref "AWS::Region"]\n'
        "        AssertDescription: This release has no host AMI in this Region.\n"
    )
    out = replace_block(out, "BEGIN RELEASE REGIONS", "END RELEASE REGIONS", rule_body, "SupportedRegion rule")

    for leftover in ("0.0.0-dev", ZERO_DIGEST, "ami-00000000000000000"):
        if leftover in out:
            raise SystemExit(f"render: placeholder {leftover!r} is still present")
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--template", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--control-plane-image", required=True)
    ap.add_argument("--gateway-image", required=True)
    ap.add_argument("--amis", required=True, help="JSON file mapping Region to AMI ID")
    ap.add_argument("--bootstrap-templates", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    with open(args.template, encoding="utf-8") as f:
        template = f.read()
    with open(args.amis, encoding="utf-8") as f:
        amis = json.load(f)
    rendered = render(template, args.version, args.control_plane_image, args.gateway_image, amis, args.bootstrap_templates)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"rendered {args.out} for {args.version} in {', '.join(sorted(amis))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
