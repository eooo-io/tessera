#!/usr/bin/env python3
"""Minimal Guardian v1 stdio reference client; Python standard library only."""
import argparse, json, subprocess, sys

def request(proc, payload):
    proc.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("Guardian closed stdout before replying")
    return json.loads(line)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--guardian", required=True)
    parser.add_argument("--vault", required=True)
    parser.add_argument("--pairing", required=True)
    parser.add_argument("--passphrase-file", required=True)
    args = parser.parse_args()
    proc = subprocess.Popen(
        [args.guardian, "--vault", args.vault, "--pairing", args.pairing,
         "--passphrase-file", args.passphrase_file],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
        text=True, bufsize=1)
    init = request(proc, {"jsonrpc":"2.0", "id":1, "method":"initialize",
        "params":{"capabilities":{"experimental":{"tessera.guardian":
        {"contractVersion":"tessera.guardian.v1"}}}}})
    advertised = init.get("result", {}).get("capabilities", {}).get(
        "experimental", {}).get("tessera.guardian", {}).get("contractVersion")
    if advertised != "tessera.guardian.v1":
        raise RuntimeError(f"incompatible initialize response: {init}")
    print(json.dumps(init, indent=2))
    print(json.dumps(request(proc, {"jsonrpc":"2.0", "id":2, "method":"ping"}), indent=2))
    print(json.dumps(request(proc, {"jsonrpc":"2.0", "id":3, "method":"tools/list"}), indent=2))
    proc.stdin.close()
    if proc.wait() != 0:
        raise RuntimeError("Guardian exited non-zero")

if __name__ == "__main__":
    main()
