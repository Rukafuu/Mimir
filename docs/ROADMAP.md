# Mímir roadmap

Mímir should earn trust before it reaches for more context. The next work is therefore sequenced around enforceable boundaries, rather than connector count.

## Current — CCP/0.1 MVP

- Local `mimird` HTTP daemon.
- Mock semantic sources, purpose-bound TTL capabilities, allow/deny policy decisions, and in-memory audit events.
- No provider credentials or external connector code.

## Milestone 1 — durable local trust boundary

**Goal:** make the local daemon safe to restart and easy to inspect.

- Persist encrypted state locally, with an explicit key-management design.
- Add capability revocation, token identifiers separate from secrets, and expiry cleanup.
- Make audit records append-only with export and human-readable inspection.
- Add schema validation and structured error codes to the HTTP profile.

**Gate:** threat model reviewed; restart, revocation, expiry, and audit-tampering tests pass.

## Milestone 2 — consent and provenance

**Goal:** distinguish an authorized fact from a raw provider record.

- Define the connector adapter interface and normalized fact/provenance envelope.
- Add a local consent workflow for policy creation and access requests.
- Support field-level transformations such as redaction and coarse-graining.
- Build one fixture-only connector implementation; do not connect a real account yet.

**Gate:** each returned field can explain its semantic scope, source class, transformation, and governing policy.

## Milestone 3 — CCP interoperability

**Goal:** make capabilities intelligible to cooperating local agents without leaking context.

- Version discovery and capability introspection endpoints.
- Stable scope registry, purpose vocabulary, and compatibility tests.
- Signed or sender-constrained capability design, following a review of local threat assumptions.
- Reference client plus conformance suite.

**Gate:** independent client implementation passes CCP conformance fixtures.

## Milestone 4 — first real connector

**Goal:** introduce one provider only after the boundary is proven.

- Choose a low-risk, read-only source with narrow semantic mapping.
- Store refresh credentials outside Mímir's fact store.
- Add explicit reconnect, revoke, and data-deletion paths.
- Run adversarial connector and policy tests before inviting external users.

**Gate:** connector security review, privacy review, and documented user recovery path.

## Decisions to make next

1. Local persistence: encrypted SQLite vs. an OS-backed secret store plus a database.
2. Identity boundary: per-OS-user daemon or an explicit local user/session model.
3. Capability form: opaque server-side tokens first, then whether CCP needs portable signed capabilities.
4. First user: developer agents, personal desktop workflows, or a team-managed environment.
