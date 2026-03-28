# VAT ingest parsers

Parsers convert scanner-native output into **`VatFindingSchema`** (see `app/schemas/vat.py`). Registration lives in `app/parsers/__init__.py` (`PARSER_REGISTRY`, `ParserDescriptor`).

## Adding a new scanner — checklist

1. **Parser class** — Implement `IngestParser` (`app/parsers/base.py`): `parse(raw) -> list[VatFindingSchema]` (or project canonical types that map to it).
2. **Register** — Add a `ParserDescriptor` entry in `__init__.py` (`parser_id`, file extensions, `strong_fields`, asset extractors as needed).
3. **Identity (optional)** — If the tool needs non-default fingerprinting, extend `resolve_fingerprint_strategy` / strategies in `app/services/ingest_identity.py` (most parsers use `DefaultFingerprintStrategy`).
4. **Fixtures** — Add minimal real or anonymized samples under `backend/tests/fixtures/` or `tests/integration/fixtures/`.
5. **Tests** — Parser unit tests for canonical fields; golden `fingerprint_id` / `correlation_key` if the integration is security-sensitive (see `tests/test_correlation_golden_keys.py`).
6. **Docs** — If the scanner emits SARIF, ensure `partial_fingerprints` / `rule_id` / `file_path` populate per `docs/implementation-plan-dedup-correlation-hardening.md` §4.5–4.6.

## Related

- [`docs/correlation-field-matrix.md`](../../../docs/correlation-field-matrix.md) — which fields feed fingerprint vs correlation vs grouping.
- [`docs/correlation-linking-architecture.md`](../../../docs/correlation-linking-architecture.md) — cross-source linking after ingest.
