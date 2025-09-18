# Repository Guidelines

## Project Structure & Module Organization
- Go module entrypoint `cmd/system-api/main.go`; runtime config in repo root (`systemapi-config.toml`, TLS fixtures).
- Core HTTP handlers, middleware, config loaders in `systemapi/`; shared logging/version helpers in `common/`; TLS primitives in `crypto/`.
- Tests live beside code (`systemapi/server_test.go`); docs and measurement fixtures under `docs/`; build artifacts land in `build/`.

## Build, Test, and Development Commands
- Use tabs instead of spaces for indentation.
- Always run `make fmt` and `make lint` (and `make test`) before committing.
- `make run` starts the API with the default config; pass `GOFLAGS` or `--config` for overrides.
- `make build` emits `build/system-api` with version metadata from `common.Version`.
- `make test`, `make test-race`, and `make cover` cover the unit suite, race detector, and coverage report respectively.
- `make fmt` then `make lint` ensure gofmt, gofumpt, gci, go vet, staticcheck, and golangci-lint all pass before review.

## Coding Style & Naming Conventions
- Code is gofmt/gofumpt formatted with tabs; prefer explicit names (`eventStore`, `tlsCertPath`) and singular file names.
- Document exported symbols with concise GoDoc comments and keep configuration passed through structs instead of globals.
- Secrets, ports, and paths should be injected via config or env; never hardcode sensitive values.

## Testing Guidelines
- Mirror the table-driven patterns in `systemapi/server_test.go` when adding cases; colocate new `*_test.go` files.
- Iterate with `go test ./systemapi -run <Name>` as needed, then finish with `make test-race` before pushing.
- Add coverage for authentication, TLS, and upload branches when touched; store ad hoc fixtures under `docs/` or temp dirs.
- Validate new config keys by asserting defaults, validation errors, and hot-reload behavior where relevant.

## Commit & Pull Request Guidelines
- Use imperative commit subjects similar to `git log` (`Add TLS reload hook`, optional `(#123)` suffix for PRs).
- PR descriptions should summarize behavior, list verification commands, and reference BuilderNet tickets or incidents.
- Attach screenshots or curl transcripts when API responses change; call out config updates in both the PR and `README.md`.
- Confirm `make fmt`, `make lint`, and `make test` in PR checklists; ensure reviewers can reproduce your steps quickly.

## Security & Configuration Tips
- Maintain `basic-auth-hash.txt` outside version control; rotate secrets through the `/api/v1/set-basic-auth` endpoint.
- Regenerate local certificates with the `cmd/tls-gen` helpers before shipping TLS changes.
- Keep `systemapi-config.toml` modifications minimal and documented so operators can diff with their deployments.
- Run `make clean` to clear generated binaries and temporary TLS assets before packaging artifacts.
