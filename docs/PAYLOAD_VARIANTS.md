# Payload representation variants

The corpus remains the source of the original benign payloads. Variants do not invent new semantic payloads; they create deterministic representations of each existing value before it is inserted into a request.

## Configuration

The previous behavior is preserved by default:

```yaml
payload_variants:
  transforms: [raw]
```

A broader first pass can be enabled explicitly:

```yaml
payload_variants:
  transforms: [raw, url, double-url, base64, base64url, html, unicode]
```

Case and whitespace variants are more semantic and should normally be enabled separately:

```yaml
payload_variants:
  transforms: [raw, lower, upper, space-plus]
```

## Supported transformations

- `raw`: original corpus value;
- `url`: Go query escaping of the value, for example `A B&` becomes `A+B%26`;
- `double-url`: applies the same URL escaping twice;
- `base64`: standard Base64 with padding;
- `base64url`: URL-safe Base64 without padding;
- `html`: HTML entity escaping such as `<` to `&lt;`;
- `unicode`: non-ASCII/control runes represented with `\\uXXXX` sequences;
- `lower`: Unicode-aware lower-case conversion;
- `upper`: Unicode-aware upper-case conversion;
- `space-plus`: replaces literal spaces with `+` without changing other bytes.

## Important transport distinction

A variant is produced before placement serialization. The HTTP placement may add its own encoding afterwards.

For example, the variant:

```text
url value: A+B%26
```

inserted into a query parameter is serialized by the HTTP client as a parameter value, so the percent sign itself is escaped on the wire. This intentionally exercises a second decoding layer. The result records both:

- `payload`: original corpus value;
- `variant`: transformation name;
- `variant_value`: transformed representation supplied to the request builder;
- `wire_value`: representation used by the placement implementation (cookie additionally percent-encodes invalid cookie octets).

A future raw-wire request mode may provide byte-exact control over complete query strings and request bodies. The current variant stage deliberately remains safe and standards-compliant for Go `net/http`.

## Test count

The number of primary tests is approximately:

```text
corpus entries × distinct generated variants × request cases
```

Equivalent values are de-duplicated per payload. For example, `lower` produces the same value as `raw` for an already lower-case string, so it does not create a duplicate test.

Rechecks and optional control requests add extra HTTP requests but do not create extra result records.

## Recommended presets

Minimal regression:

```yaml
payload_variants:
  transforms: [raw]
```

Encoding-focused run:

```yaml
payload_variants:
  transforms: [raw, url, double-url, base64, base64url, html, unicode]
```

Text-normalization run:

```yaml
payload_variants:
  transforms: [raw, lower, upper, space-plus]
```

Do not enable every transformation automatically for large corpora without considering runtime. With 112 payloads, six generic placements, and seven distinct variants, the upper bound is 4,704 result records before per-payload de-duplication.
