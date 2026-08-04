# Request modes and control requests

## Generic mode (default)

Generic mode requires no knowledge of the protected application's business logic. It uses `target.path`, the configured placements, and default names such as `fp_param`.

```yaml
request:
  mode: generic
  payloads: corpora/mgm/all.jsonl
  placements: [query, form, json, header, cookie, path]
```

This remains the recommended first broad run.

## Profiles mode

Profiles describe real application endpoints and fields. Store one JSON object per line in a JSONL file:

```json
{"name":"product-search","path":"/api/products/search","method":"POST","placement":"json","field":"query","headers":{"Accept":"application/json"},"control":true,"control_value":"running shoes"}
```

Configure it with:

```yaml
request:
  mode: profiles
  profiles: examples/request-profiles.jsonl
  payloads: corpora/mgm/all.jsonl
```

Supported methods: `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`.

Supported placements: `query`, `form`, `json`, `header`, `cookie`, and `path`.

Required profile fields:

- `name`;
- `path`;
- `method`;
- `placement`;
- `field`, except for `path`; for a header profile, `header` may provide the target header name.

Optional fields:

- `header`: header name for header placement;
- `headers`: fixed headers added to every request for this profile;
- `control`: enable a control request for this profile;
- `control_value`: neutral value used by the control request.

## Both mode

`both` executes the generic matrix and all configured profiles in the same run:

```yaml
request:
  mode: both
  profiles: examples/request-profiles.jsonl
  payloads: corpora/mgm/all.jsonl
  placements: [query, form, json, header, cookie, path]
```

## Control requests

Control requests are optional. A control request uses the same endpoint, method, field, placement, and fixed headers as the payload request, but sends a neutral control value.

Enable controls globally:

```yaml
validation:
  control_request: true
  control_value: waf-fp-control
```

Or enable them only in selected profiles with `"control": true`.

The result contains:

```json
{
  "control": {
    "enabled": true,
    "value": "running shoes",
    "waf": {"status_code": 200},
    "origin": {"status_code": 200},
    "context_validated": true
  }
}
```

`context_validated=true` currently means the control request completed without transport errors and neither route matched a configured block signal. It does not prove that every business operation was semantically successful.

## Result request metadata

Every result now records the exact request context:

- `request_mode`;
- `profile` (`generic` for the default matrix);
- `request_path`;
- `request_field`;
- `method`;
- `placement`;
- `wire_value`.

For cookie placement, `wire_value` contains the percent-encoded value actually placed into the Cookie header. For other placements, it currently equals the corpus value.
