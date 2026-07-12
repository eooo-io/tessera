#!/usr/bin/env python3
"""Minimal Guardian v1 Streamable HTTP client; Python standard library only."""
import argparse, json, urllib.request

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="MCP endpoint")
    parser.add_argument("--token", required=True, help="Owner-authorized OAuth token")
    parser.add_argument("--origin", required=True)
    args = parser.parse_args()

    def request(payload):
        req = urllib.request.Request(args.url, json.dumps(payload).encode(), method="POST",
            headers={"Authorization": f"Bearer {args.token}", "Origin": args.origin,
                     "Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream",
                     "MCP-Protocol-Version": "2025-11-25"})
        with urllib.request.urlopen(req) as response:
            return json.load(response)

    init = request({"jsonrpc":"2.0", "id":1, "method":"initialize",
        "params":{"capabilities":{"experimental":{"tessera.guardian":
        {"contractVersion":"tessera.guardian.v1"}}}}})
    advertised = init.get("result", {}).get("capabilities", {}).get(
        "experimental", {}).get("tessera.guardian", {}).get("contractVersion")
    if advertised != "tessera.guardian.v1":
        raise RuntimeError(f"incompatible initialize response: {init}")
    print(json.dumps(init, indent=2))
    print(json.dumps(request({"jsonrpc":"2.0", "id":2, "method":"ping"}), indent=2))
    print(json.dumps(request({"jsonrpc":"2.0", "id":3, "method":"tools/list"}), indent=2))

if __name__ == "__main__":
    main()
