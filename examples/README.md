# Integration Examples

These examples show how to consume Pulse Intelligence data from analyst tools and SOAR
automation. Everything calls the public API with a scoped key and exports indicators into
common analyst workflows.

## Prerequisites

- Create an API key in the app under `/settings` with **only the `indicators:read` scope**.
  A scoped key is enough for every example here and limits blast radius if it leaks.
- Set `PULSE_BASE_URL` to your host and `PULSE_API_KEY` to the key. Never commit real keys —
  use an env file or your CI secret store.
- The API is rate limited per key (120 requests / 60 seconds by default). Export scripts use
  one request each, so this only matters if you are looping.

## Python

### `examples/python/export_indicators.py` — CSV export

Downloads the JSON view of `/api/v1/indicators` and writes a CSV to stdout.

```bash
set PULSE_BASE_URL=https://your-pulse-host.example
set PULSE_API_KEY=pulse_your_key
python examples/python/export_indicators.py --severity HIGH > high-indicators.csv
```

### `examples/python/export_stix.py` — STIX 2.1 bundle export

Fetches `GET /api/v1/indicators?format=stix` and writes the STIX 2.1 bundle to a file.
The response is validated against the STIX bundle shape before anything is written.

```bash
python examples/python/export_stix.py --severity HIGH -o pulse-indicators.stix.json
```

## cURL

### `examples/curl/export_indicators.sh` — raw format downloads

One-liner downloads for any export format the API supports (`csv`, `stix`, `misp`, `snort`,
`json`). Non-JSON formats are full-set exports capped at 50,000 rows server-side; `json` is
paginated at 100 rows per page.

```bash
bash examples/curl/export_indicators.sh csv  > pulse-indicators.csv
bash examples/curl/export_indicators.sh stix > pulse-indicators.stix.json
```

## Splunk

`examples/splunk/pulse_indicator_lookup.spl` is a lookup-oriented SPL starter query for
normalized Pulse indicator exports.

## Microsoft Sentinel

`examples/sentinel/pulse_high_confidence_iocs.kql` is a KQL starter query for high-confidence
network and hash indicators after importing Pulse data into a `PulseIndicators` table.

## Verification Notes

- **CSV**: the first line is the header `type,value,confidence,severity,tlp,tags,source,firstSeen,lastSeen`; `head -n 5` should show it.
- **STIX**: the file must parse as JSON with `"type": "bundle"` and `"spec_version": "2.1"`:
  `jq -e '.type == "bundle" and .spec_version == "2.1"' pulse-indicators.stix.json`
- **Whitelisted indicators never appear in any format** — including your own whitelists. If a
  whitelisted value shows up, that is a bug; if you want to confirm the export pipeline works,
  check for a known high-confidence feed indicator instead.
- **Expired indicators are also excluded** (the API only serves active indicators by default).
- **401 / 403**: wrong key or missing `indicators:read` scope. **400**: bad `format` value.
- The API reference lives in `docs/API.md` and `docs/openapi.yaml`.
