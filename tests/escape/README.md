# Escape-attempt suite

Runs hostile code inside real sandboxes and checks that it cannot reach
anything it should not: the instance metadata service, the host agent, other
sandboxes, or the internet outside its egress policy. It is a release gate:
every release must pass it on a Firecracker host.

```sh
source .weft/dev/e2b.env                 # or point E2B_* at a real stack
pip install -r packages/compat-tests/python/requirements.txt
pytest tests/escape                      # network escapes (any runtime)
WEFT_ESCAPE_RUNTIME=firecracker pytest tests/escape   # adds microVM boundary checks
sudo tests/escape/host_checks.sh         # on a Firecracker host: jails, namespaces, UIDs, seccomp
```

Tests marked `vm` need the Firecracker runtime; the development namespace
runtime shares the host kernel, so they are skipped there.

Set `WEFT_ESCAPE_HOST_IP` to the host's VPC address to also probe the host
agent's ports from inside a sandbox.
