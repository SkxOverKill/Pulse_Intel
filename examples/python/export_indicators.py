#!/usr/bin/env python3
"""Export indicators from Pulse Intelligence using a scoped API key."""

from __future__ import annotations

import argparse
import csv
import os
import sys
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import json


def request_json(base_url: str, api_key: str, params: dict[str, str]) -> dict:
    url = f"{base_url.rstrip('/')}/api/v1/indicators?{urlencode(params)}"
    request = Request(url, headers={"Authorization": f"Bearer {api_key}"})
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.getenv("PULSE_BASE_URL"))
    parser.add_argument("--api-key", default=os.getenv("PULSE_API_KEY"))
    parser.add_argument("--severity", default="HIGH")
    parser.add_argument("--type", default="")
    parser.add_argument("--page-size", default="500")
    args = parser.parse_args()

    if not args.base_url or not args.api_key:
        parser.error("set PULSE_BASE_URL and PULSE_API_KEY, or pass --base-url and --api-key")

    params = {"severity": args.severity, "pageSize": args.page_size}
    if args.type:
        params["type"] = args.type

    payload = request_json(args.base_url, args.api_key, params)
    writer = csv.DictWriter(
        sys.stdout,
        fieldnames=["type", "value", "severity", "confidence", "source", "lastSeen"],
    )
    writer.writeheader()
    for indicator in payload["data"]:
        writer.writerow({key: indicator.get(key) for key in writer.fieldnames})

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
