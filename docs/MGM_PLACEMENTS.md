# MGM source-aware request placements

Generic runs of the `mgm-sp/WAF-Payload-Collection` corpus do not send every attack family into every request location.

The project follows the intent of the source repository's false-positive Nuclei templates:

| MGM category | Generic placements used by waf-fp | Rationale |
|---|---|---|
| `sqli` | `query`, `form` | MGM sends SQLi-like false-positive values as request parameters. |
| `xss` | `query`, `form` | MGM sends XSS-like false-positive values as request parameters. |
| `cmdexe` | `query`, `form` | MGM sends command-execution-like false-positive values as request parameters. |
| `traversal` | `query`, `form` | MGM sends traversal/file-inclusion-like false-positive values as request parameters. |
| `xxe` | `xml` | XXE requires XML input to reach an XML parser; the MGM template sends the value as an XML request body with `Content-Type: application/xml`. |
| `log4shell` | `header` (`User-Agent`) | MGM tests the value through `User-Agent`, a common logging input. |
| `shellshock` | `header` (`User-Agent`), `form` | MGM tests both CGI-style header input and a form value. |

This policy is applied only when both conditions are true:

1. `source == "mgm-sp/WAF-Payload-Collection"`;
2. the request case is the built-in `generic` profile.

Explicit application profiles are never filtered. For example, if an application accepts an XML document inside a JSON field and then parses that field as XML, a profile may intentionally use `placement: json` for an XXE-related test.

## XML placement

`xml` sends the corpus value as the raw request body using `POST` and:

```http
Content-Type: application/xml; charset=utf-8
```

No extra XML wrapper is generated; the MGM value is sent as provided by the source corpus.

## Why this matters

A WAF may inspect suspicious byte sequences in locations where the corresponding application vulnerability is not realistically reachable. Treating such a block as an equally useful FP result creates noise. Source-aware placements keep the generic MGM run focused on the request context the original corpus intended to exercise.
