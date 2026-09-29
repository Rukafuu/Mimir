# Mímir CCP/0.1 — Context Capability Protocol

## Status

Initial, local-only MVP contract. It specifies a semantic-context authorization boundary, not a connector or identity standard.

## Principles

- A capability authorizes named **semantic scopes**, never raw source access.
- Every request declares a purpose and bounded TTL.
- Policies are evaluated before token issuance; an applicable `deny` overrides every `allow`.
- A context response includes only facts whose keys match a granted scope.
- Token use and issuance are auditable.

## Resources

`Source` is a connector-provided collection of mock facts. Future connectors should implement an adapter that yields semantic keys such as `employment.current`, without exposing provider-specific records.

`Policy` has `effect` (`allow` or `deny`), `scope`, and `purpose`. CCP/0.1 supports exact matching plus `*` as the all-values wildcard.

`Capability` is an opaque bearer token bound to scopes, purpose, and an expiry. It is only valid at the local daemon and is never returned again by audit APIs.

## HTTP profile

All requests and responses use JSON. The daemon is intended to bind to loopback only.

| Endpoint | Meaning |
| --- | --- |
| `POST /v1/sources` | Register a mock semantic fact source |
| `POST /v1/policies` | Add an allow/deny policy |
| `POST /v1/access-requests` | Request a scoped, purposeful temporary capability |
| `GET /v1/context` | Redeem `Authorization: Bearer <capability>` for the minimal view |
| `GET /v1/audit` | Read issuance and access events |

## Deliberate CCP/0.1 limits

There is no user authentication, encrypted persistence, token revocation endpoint, source provenance per field, wildcard-prefix matching, or external connector implementation yet. Those are next-stage design work, not implied security guarantees.
