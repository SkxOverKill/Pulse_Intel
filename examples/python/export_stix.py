#!/usr/bin/env python3
"""Export indicators from Pulse Intelligence as a STIX 2.1 bundle.

Fetches `GET /api/v1/indicators?format=stix` with a scoped API key and writes
the STIX 2.1 bundle to a file (or stdout). The response is validated against
the STIX bundle shape before anything is written, so a misconfigured key or
endpoint fails loudly instead of producing an empty feed file for the SOAR
queue to choke on.

Example:
    set PULSE_BASE_URL=https://your-pulse-host.example
    set PULSE_API_KEY=pulse_your_key
    python examples/python/export_stix.py --severity HIGH -o pulse-indicators.stix.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def fetch_bundle(base_url: str, api_key: str, params: dict[str, str]) -> dict:
    url = f"{base_url.rstrip('/')}/api/v1/indicators?{urlencode(params)}"
    request = Request(url, headers={"Authorization": f"Bearer {api_key}"})
    with urlopen(request, timeout=60) as response:
        body = response.read().decode("utf-8")
        status = response.status
        content_type = response.headers.get_content_type()
    try:
        bundle = json.loads(body)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"server returned {content_type}, not JSON "
            f"(HTTP {status}): check the API key and format"
        ) from exc
    if bundle.get("type") != "bundle" or bundle.get("spec_version") != "2.1":
        raise SystemExit("response is not a STIX 2.1 bundle")
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.getenv("PULSE_BASE_URL"))
    parser.add_argument("--api-key", default=os.getenv("PULSE_API_KEY"))
    parser.add_argument("--severity", default="HIGH")
    parser.add_argument("--type", default="")
    parser.add_argument("--output", "-o", default="-")
    args = parser.parse_args()

    if not args.base_url or not args.api_key:
        parser.error("set PULSE_BASE_URL and PULSE_API_KEY, or pass --base-url and --api-key")

    params = {"format": "stix", "severity": args.severity}
    if args.type:
        params["type"] = args.type

    bundle = fetch_bundle(args.base_url, args.api_key, params)
    text = json.dumps(bundle, indent=2) + "\n"

    if args.output == "-":
        sys.stdout.write(text)
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)

    print(f"wrote {len(bundle.get('objects', []))} STIX objects", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
