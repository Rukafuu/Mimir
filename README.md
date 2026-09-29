# Mímir

<p align="center">
  <img src="assets/mimir-mark.png" alt="Mímir mark: an observing eye within a Norse-inspired knot" width="260" />
</p>

**Mímir** is a local context kernel for AI systems. Its daemon, `mimird`, turns context into narrowly scoped, time-limited semantic capabilities. An agent asks for `employment.current` for a declared purpose; it never receives credentials or unfiltered provider data.

The name honors Mímir, the Norse guardian of wisdom. The mark is an observing eye held inside a carved knot: knowledge is valuable, but never unbounded.

## Architecture

```text
mock connector/source -> semantic facts -> policy engine -> capability -> minimal view
                                          \-> audit trail
```

The service uses standard-library Go only. All MVP state is in memory and is reset when `contextd` stops. `internal/kernel` is transport-independent domain logic; `internal/httpapi` is the HTTP adapter; future Gmail/Calendar adapters belong behind the `Source` contract rather than inside policy or token code.

## Run

```powershell
go run ./cmd/mimird
```

It listens on `http://127.0.0.1:8787` by default. Use `-listen` to choose another loopback address.

## Walkthrough

Register only mock facts:

```powershell
curl.exe -X POST http://127.0.0.1:8787/v1/sources -H "Content-Type: application/json" -d '{"id":"mock-profile","facts":{"employment.current":{"company":"Mímir","role":"Founder"},"finances.balance":100}}'
```

Allow precisely one semantic scope and purpose:

```powershell
curl.exe -X POST http://127.0.0.1:8787/v1/policies -H "Content-Type: application/json" -d '{"id":"salary-negotiation","effect":"allow","scope":"employment.current","purpose":"salary_negotiation"}'
```

Request a 20-minute capability (copy `token` from the response):

```powershell
curl.exe -X POST http://127.0.0.1:8787/v1/access-requests -H "Content-Type: application/json" -d '{"scopes":["employment.current"],"purpose":"salary_negotiation","ttl":"20m"}'
curl.exe http://127.0.0.1:8787/v1/context -H "Authorization: Bearer YOUR_TOKEN"
curl.exe http://127.0.0.1:8787/v1/audit
```

The context response contains `employment.current` but not `finances.balance`.

## Verify

```powershell
go test ./...
go vet ./...
```

See [CCP/0.1](docs/CCP-0.1.md) for the initial protocol boundary and intentional limitations, and [the roadmap](docs/ROADMAP.md) for the next guarded milestones.
