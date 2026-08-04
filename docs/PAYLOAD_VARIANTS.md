# Normalization diagnostics

Payload variants are not part of the standard false-positive methodology.

The standard command `cmd/waf-fp` always tests the original semantic value from the benign corpus. Each placement still performs the transport serialization required by HTTP: query and form encoding, JSON escaping, safe cookie representation, and path serialization. Those transport details do not create a new semantic payload.

Use variants only after a false positive has already been found and you need to understand whether normalization or a Seclang transformation chain affects the match.

## Standard FP run

```yaml
payload_variants:
  transforms: [raw]
```

Run with:

```bash
go run ./cmd/waf-fp --config config.yaml
```

`cmd/waf-fp` rejects configurations containing non-raw variants. This prevents normalization experiments from being mixed into the normal FP baseline.

## Separate normalization lab

Use the dedicated command:

```bash
go run ./cmd/waf-normalization-test \
  --config examples/config.normalization-lab.yaml
```

The diagnostic command requires `raw` plus at least one transformed variant and refuses baseline comparison or `fail_on_new_fp`.

A normalization run should normally use:

- a small corpus containing selected confirmed FP values;
- one relevant endpoint/profile;
- one or a small number of placements;
- no baseline comparison;
- a separate output such as `normalization-results.jsonl`.

## Supported transformations

- `raw`: original corpus value;
- `url`: query escaping of the semantic value;
- `double-url`: URL escaping applied twice;
- `base64`: standard Base64 with padding;
- `base64url`: URL-safe Base64 without padding;
- `html`: HTML entity escaping;
- `unicode`: non-ASCII/control runes represented with `\\uXXXX` sequences;
- `lower`: Unicode-aware lowercase conversion;
- `upper`: Unicode-aware uppercase conversion;
- `space-plus`: replaces literal spaces with `+`.

These transformations answer a diagnostic question: whether different normalized representations activate the same or different WAF behavior. They do not by themselves prove a false positive and should not be used to generate exclusion recommendations without reviewing the actual rule, target, and transformation chain.

## Relationship to Seclang

For a Seclang rule, the operator or regular expression normally evaluates the value after the configured `t:` transformations. The same regex can therefore match plain and encoded input when the transformation chain normalizes both to the same value.

The useful FP workflow is:

```text
confirmed raw FP
-> obtain Rule ID or rule text when possible
-> inspect targets, operator and t: transformations
-> reproduce the transformation locally or with the normalization lab
-> prepare a narrow target/endpoint exclusion or rule correction
```

The lab exists only for the third and fourth steps. It is not a general request-fuzzing stage.

## Result fields

Diagnostic results retain:

- `payload`: original benign corpus value;
- `variant`: transformation name;
- `variant_value`: transformed value supplied to the request builder;
- `wire_value`: value used by the placement implementation.

Keep normalization outputs separate from `results.jsonl` and from the standard FP baseline.
