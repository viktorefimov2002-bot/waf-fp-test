# Benign and false-positive corpus sources

The project separates three kinds of input:

1. curated false-positive strings known to resemble attack syntax;
2. normal HTTP parameter values collected from benign datasets;
3. application-specific values exported from the protected service.

The standard FP runner uses the original semantic values only. These importers do not generate encoded mutations.

## 1. MGM WAF Payload Collection

Existing command:

```bash
go run ./cmd/corpus-sync-mgm
```

This remains the highest-signal source because its files are explicitly named `false-positives.txt` and grouped by attack family.

## 2. HTTPParamsDataset normal rows

HTTPParamsDataset contains HTTP parameter examples with a class/label column. Import only rows marked normal or benign; anomalous rows are intentionally skipped.

Obtain a local copy of the source dataset and run:

```bash
go run ./cmd/corpus-import-httpparams \
  --input sources/HttpParamsDataset/payload_test_lexical.csv \
  --output corpora/httpparams/all.jsonl
```

The importer auto-detects common payload columns (`payload`, `value`, `param`, `parameter`, `query`) and label columns (`label`, `class`, `type`, `is_anomaly`, `anomaly`). Override them when the mirror uses another schema:

```bash
go run ./cmd/corpus-import-httpparams \
  --input sources/HttpParamsDataset/data.csv \
  --value-column payload \
  --label-column label \
  --normal-label 0 \
  --output corpora/httpparams/all.jsonl
```

Generated entries use:

- category: `benign-http-param`;
- source: `Morzeux/HttpParamsDataset`;
- tags: `benign`, `http-parameter`, `dataset`.

The importer accepts textual normal labels such as `normal`, `benign`, and `false` in addition to the configured value.

## 3. HTTP CSIC 2010 normal traffic

HTTP CSIC 2010 includes normal and anomalous HTTP traffic. Use only the normal/training files. The importer recursively selects files whose names contain `normal` or `training`, then extracts values from query strings and form-like request bodies.

```bash
go run ./cmd/corpus-import-csic \
  --input-dir sources/HTTP-CSIC-2010 \
  --output corpora/csic/all.jsonl
```

Generated entries use:

- category: `benign-http-param`;
- source: `HTTP CSIC 2010`;
- tags: `benign`, `normal-traffic`, `http-parameter`.

The importer deliberately extracts parameter values rather than replaying the historic application requests. The original CSIC endpoints and business flow are not expected to exist on the tested service.

## Recommended use

Run the sources separately first:

```text
MGM curated FP corpus
HTTPParams normal parameter corpus
CSIC normal traffic parameter corpus
internal/application-specific corpus
```

Separate runs preserve signal quality:

- MGM answers: “does the WAF block known FP-like strings?”
- HTTPParams/CSIC answer: “does the WAF block ordinary parameter values from benign traffic?”
- application-specific corpora answer: “does the WAF block values actually used by this service?”

Do not treat every normal dataset value as a pre-confirmed false positive. It becomes a confirmed FP only after the differential WAF/origin check and recheck succeed.

## Sources not imported automatically

### OWASP CRS regression tests

CRS regression tests are primarily rule tests, not a clean portable benign corpus. Some negative cases and false-positive fixes are useful when a Rule ID is already known, but blindly flattening all expected-allow test data would mix protocol fixtures, rule-specific assumptions, and malicious payloads. They are better suited to the future rule-aware analysis stage.

### CRS regex exclusions and application exclusion packages

These files document known collision patterns and scoped exclusions. They are valuable for understanding a specific rule but are not equivalent to complete benign input values. The project therefore does not turn regex fragments or exclusion rules into synthetic payloads.

### Attack payload repositories

PayloadsAllTheThings, SecLists attack lists, go-ftw positive attack tests, and similar repositories are useful for WAF coverage and bypass testing, not for building a false-positive corpus. They should stay outside the standard FP workflow.

## Licensing and provenance

The import commands operate on local source copies and do not vendor third-party datasets into this repository. Before publishing generated corpora, verify the license and redistribution terms of the exact source or mirror you used. Keep the generated `source` and `source_reference` fields intact.
