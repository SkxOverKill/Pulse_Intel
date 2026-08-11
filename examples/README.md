# Integration Examples

These examples show how to consume Pulse Intelligence data from analyst tools and automation.

## Python

`examples/python/export_indicators.py` downloads JSON from `/api/v1/indicators` and writes a
CSV to stdout.

```bash
set PULSE_BASE_URL=https://your-pulse-host.example
set PULSE_API_KEY=pulse_your_key
python examples/python/export_indicators.py --severity HIGH > high-indicators.csv
```

## Splunk

`examples/splunk/pulse_indicator_lookup.spl` is a lookup-oriented SPL starter query for
normalized Pulse indicator exports.

## Microsoft Sentinel

`examples/sentinel/pulse_high_confidence_iocs.kql` is a KQL starter query for high-confidence
network and hash indicators after importing Pulse data into a `PulseIndicators` table.
