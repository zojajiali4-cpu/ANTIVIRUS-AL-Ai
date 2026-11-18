# Optional cloud hash reputation

## Purpose and trust boundary

The Android client can request a reputation lookup for a selected file's SHA-256 digest. This action is **disabled until the user confirms it for that scan result**.

The lookup sends a single 64-character SHA-256 value to `POST /v1/hash/reputation`. It does not send file bytes, filename, content URI, or filesystem path. The API provider and its infrastructure may process normal connection metadata, including the client IP, for rate limiting and abuse prevention.

The online result is displayed separately from the local scan verdict. It must not silently promote an unknown/no-match local result to "clean" or override a local signed-feed match.

## API contract

Request:

```json
{"sha256":"<64 lowercase hexadecimal characters>"}
```

A known record returns:

```json
{
  "ok": true,
  "found": true,
  "classification": "MALWARE",
  "indicator": {
    "sha256": "<digest>",
    "classification": "MALWARE",
    "family_id": "SOURCE.FAMILY",
    "source": "SOURCE_NAME",
    "updated_at": 1800000000
  },
  "scope": "HASH_ONLY_REPUTATION",
  "disclaimer": "Only the submitted SHA-256 digest was queried. A no-match is not proof of safety."
}
```

An absent record returns `found=false` and `classification=UNKNOWN`. If the D1 database is not available, the service returns HTTP 503. The client displays this as an unavailable service, not as a no-match.

The Worker applies a per-IP rate limit when the D1 rate-limit table is present. The request body is bounded and the SHA-256 field is validated on both client and server.

## Current activation status

The repository contains the Worker route and D1 schema, but code presence is not proof of a deployed service or populated database. A production deployment, operational reputation data, source provenance, retention policy, privacy review and monitoring are separate requirements.

Until those are completed, the app must clearly report a service error or unknown result. Do not advertise a production malware-reputation service merely because the endpoint compiles.

## Data quality requirements

Before inserting reputation indicators:

- Keep source, first-seen/update time and provenance.
- Admit only records covered by a source's redistribution terms and commercial-use permissions.
- Validate the SHA-256 format and one of `MALWARE`, `PUA`, or `SUSPICIOUS`.
- Keep false-positive correction and removal procedures.
- Never create a trusted/clean allowlist from absence of a malicious indicator.
- Test with synthetic hashes and documented benign fixtures; never place live malware samples in the repository or test pipeline.

## Release checklist

1. Confirm ownership and access controls for the Cloudflare Worker and D1 database.
2. Apply `cloud-api/schema.sql` and verify the required tables exist.
3. Provision an authorized, reviewed reputation-data ingestion process with source provenance.
4. Configure rate limiting and operational monitoring.
5. Publish the service privacy notice and retention policy, including network metadata.
6. Verify known synthetic match, unknown digest, invalid digest, missing database, rate limiting and timeout behavior.
7. Confirm no scan path invokes this endpoint without the user's separate consent.
8. Keep the local verdict and cloud reputation result visibly distinct.
