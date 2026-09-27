"""Tests for render_release_template.py (python3 -m unittest discover -s deploy/cloudformation/scripts)."""
from __future__ import annotations

import os
import unittest

import render_release_template as r

TEMPLATE = os.path.join(os.path.dirname(__file__), "..", "weft-sandboxes.yaml")
CP = "ghcr.io/weftsh/sandbox-control-plane@sha256:" + "a" * 64
GW = "ghcr.io/weftsh/sandbox-egress-gateway@sha256:" + "b" * 64
AMIS = {"us-east-1": "ami-0123456789abcdef0", "eu-west-1": "ami-0fedcba9876543210"}


def load() -> str:
    with open(TEMPLATE, encoding="utf-8") as f:
        return f.read()


class RenderTest(unittest.TestCase):
    def test_fills_every_placeholder(self) -> None:
        out = r.render(load(), "1.2.3", CP, GW, AMIS, "base=ghcr.io/weftsh/sandbox-base:1.2.3")
        self.assertIn("(weft-sandboxes 1.2.3)", out)
        self.assertIn('Value: "1.2.3"', out)
        self.assertIn(f"ControlPlane: {CP}", out)
        self.assertIn(f"Gateway: {GW}", out)
        self.assertIn("    eu-west-1:\n      ImageId: ami-0fedcba9876543210\n", out)
        self.assertIn('!Contains [["eu-west-1", "us-east-1"], !Ref "AWS::Region"]', out)
        self.assertIn("Default: base=ghcr.io/weftsh/sandbox-base:1.2.3", out)
        for placeholder in ("0.0.0-dev", "sha256:" + "0" * 64, "ami-00000000000000000"):
            self.assertNotIn(placeholder, out)

    def test_refuses_bad_inputs(self) -> None:
        template = load()
        with self.assertRaises(SystemExit):
            r.render(template, "v1.2.3", CP, GW, AMIS, "base=x")
        with self.assertRaises(SystemExit):
            r.render(template, "1.2.3", "ghcr.io/weftsh/sandbox-control-plane:1.2.3", GW, AMIS, "base=x")
        with self.assertRaises(SystemExit):
            r.render(template, "1.2.3", CP, GW, {"us-east-1": "ami-nope"}, "base=x")
        with self.assertRaises(SystemExit):
            r.render(template, "1.2.3", CP, GW, {}, "base=x")

    def test_refuses_an_already_rendered_template(self) -> None:
        out = r.render(load(), "1.2.3", CP, GW, AMIS, "base=x")
        with self.assertRaises(SystemExit):
            r.render(out, "1.2.4", CP, GW, AMIS, "base=x")


if __name__ == "__main__":
    unittest.main()
