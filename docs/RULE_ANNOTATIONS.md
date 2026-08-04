# Optional rule correlation

`waf-fp-test` can be used without WAF logs, Rule IDs, or an integration with a log storage system. The runner records the request test ID in `X-WAF-FP-Test-ID` and produces `results.jsonl` independently.

When rule metadata becomes available later, use `results-annotate` to attach it without changing the original results.

## Recommended workflow

```text
run waf-fp
-> receive results.jsonl
-> generate rule-annotations.template.jsonl
-> fill rule information only for results you can correlate
-> run results-annotate with the filled template
-> receive results.enriched.jsonl and rule-annotations.md
```

## 1. Generate a fillable template

After `results.jsonl` has been created, run:

```bash
go run ./cmd/results-annotate \
  --generate-template \
  --results results.jsonl \
  --template-output rule-annotations.template.jsonl
```

By default the template contains only:

- `CONFIRMED_FP`;
- `BLOCKED_BENIGN_CANDIDATE`.

A custom verdict list may be supplied:

```bash
go run ./cmd/results-annotate \
  --generate-template \
  --results results.jsonl \
  --template-verdicts CONFIRMED_FP,FLAKY_FP \
  --template-output rule-annotations.template.jsonl
```

Each generated line already contains the exact `test_id`, `payload_id`, `placement`, optional future `profile`, and a readable `context` copied from `results.jsonl`.

Example generated record:

```json
{"match":{"test_id":"waf-fp-...","payload_id":"mgm-sqli-d6a23b83af12b926","placement":"json"},"context":{"payload":"union was a great select","category":"sqli","verdict":"CONFIRMED_FP","method":"POST"},"rule":{"rule_id":"","rule_name":"","rule_text":"","matched_field":"","matched_data":"","source":"","notes":"","tags":[]},"_help":{"required":"fill at least one of rule.rule_id, rule.rule_name, or rule.rule_text","optional":"matched_field, matched_data, source, notes, tags; match and context are generated from results.jsonl"}}
```

Do not modify `match` unless you intentionally want to broaden or change the link. `context` and `_help` exist only to make manual editing easier and are ignored by the enrichment logic.

## 2. Fill only known rule information

For each result you can correlate, fill at least one required field:

- `rule.rule_id`; or
- `rule.rule_name`; or
- `rule.rule_text`.

All other rule fields are optional:

- `matched_field`;
- `matched_data`;
- `source`;
- `notes`;
- `tags`.

Example with a known Rule ID:

```json
{"match":{"test_id":"waf-fp-...","payload_id":"mgm-sqli-d6a23b83af12b926","placement":"json"},"context":{"payload":"union was a great select","category":"sqli","verdict":"CONFIRMED_FP","method":"POST"},"rule":{"rule_id":"942100","rule_name":"SQL injection detector","rule_text":"","matched_field":"ARGS:fp_param","matched_data":"union was a great select","source":"manual-waf-log-review","notes":"Found by X-WAF-FP-Test-ID","tags":["sqli","crs"]},"_help":{"required":"fill at least one of rule.rule_id, rule.rule_name, or rule.rule_text","optional":"matched_field, matched_data, source, notes, tags; match and context are generated from results.jsonl"}}
```

Records whose `rule_id`, `rule_name`, and `rule_text` all remain empty are ignored. You do not need to delete unfilled template lines.

When no Rule ID is known, a copied rule name or full Seclang rule is enough:

```json
{"match":{"test_id":"waf-fp-..."},"rule":{"rule_id":"","rule_name":"Custom XML detector","rule_text":"SecRule REQUEST_BODY ...","matched_field":"","matched_data":"","source":"copied-from-waf-config","notes":"Rule has no stable ID","tags":[]}}
```

## 3. Apply the filled template

The generated template can be used directly as the annotations file:

```bash
go run ./cmd/results-annotate \
  --results results.jsonl \
  --annotations rule-annotations.template.jsonl \
  --output results.enriched.jsonl \
  --report rule-annotations.md
```

The command does not overwrite `results.jsonl`. It creates:

- `results.enriched.jsonl`, where matching records contain `rule_metadata`;
- `rule-annotations.md`, a concise table of applied links.

It also reports completed annotations that did not match any result. This helps detect stale test IDs, incorrect placements, or payload IDs from another corpus version.

If no template record has any required rule field filled, the command stops with a clear error instead of producing an empty enrichment report.

## Manual matching without a generated template

A hand-written annotation may still match one exact result by `test_id`:

```json
{"match":{"test_id":"waf-fp-..."},"rule":{"rule_id":"942100","rule_name":"SQL injection detector","source":"waf-log","notes":"Correlated manually by X-WAF-FP-Test-ID"}}
```

Or match by `payload_id`, optionally narrowed by `placement` and future `profile`:

```json
{"match":{"payload_id":"mgm-sqli-d6a23b83af12b926","placement":"json"},"rule":{"rule_id":"942100","matched_field":"ARGS:query","matched_data":"union was a great select","source":"manual-log-correlation"}}
```

Rule metadata remains optional. Without it, the project can still detect and reproduce WAF/origin differences, but it should not claim that a specific Seclang rule caused the block.
