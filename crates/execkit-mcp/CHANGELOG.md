# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0](https://github.com/blinkingbit-oss/execkit/compare/v0.7.2...v0.8.0) - 2026-06-25

### Added

- *(mcp)* viewer transcript search, legend filter, copy-id, auto-refresh
- *(mcp)* viewer status bar persistently shows the selected session's details
- *(mcp)* viewer history relative times refresh every 30s (no manual refresh needed)
- *(mcp)* viewer UX - bottom status bar, command-count labels, color legend, action feedback
- *(mcp)* viewer session screenshot - canvas to PNG
- *(mcp)* viewer session export - txt/log/md/json
- *(mcp)* viewer history panel - browse past sessions from the audit dir
- *(mcp)* GET /sessions + /session/<id> - dir history, id-validated, no traversal
- *(mcp)* viewer 3-dots menu - rename/pin/keep + persisted sidebar width
- *(mcp)* GET/POST /state route - token-gated, validated, no-store
- *(mcp)* viewer metadata store (validated, capped, 0600 display-only state)
- *(mcp)* viewer sidebar redesign - transport groups, labels, active, resize, branding
- *(mcp)* stable+configurable auto-start web endpoint; link by default, opt-in open, reconnect recovery
- *(mcp)* EXECKIT_MCP_WATCH_WEB auto-starts the browser viewer
- *(mcp)* watch --serve [--open] - browser-view any audit log
- *(mcp)* web viewer browser-open helper (per-OS, best-effort)
- *(mcp)* web viewer page - session sidebar + transcript panes
- *(mcp)* web viewer HTTP/SSE core - token-gated, loopback, replay+live
- *(mcp)* web viewer scaffolding - URL token + SSE wire JSON

### Fixed

- *(mcp)* viewer export/screenshot filenames + add blinking favicon
- *(mcp)* viewer history addresses past sessions by unique file key
- *(mcp)* valid export/screenshot downloads - defer object-URL revoke, append anchor
- *(mcp)* inline session rename in the sidebar (replace the prompt dialog)
- *(mcp)* history title respects alias; clear history selection on reconnect
- *(mcp)* viewer history - fix stale live-sel on hist click; avoid DOM thrash per SSE event
- *(mcp)* cap /state body pre-fill to Content-Length; hermetic HOME in test
- *(mcp)* web viewer resets state on (re)connect so reconnect replay does not duplicate
- *(mcp)* web viewer renderTranscript scopes the session; dedupe disconnect note
- *(mcp)* web viewer title tracks the selected session as it streams

### Other

- *(mcp)* document the browser viewer UX (sidebar command counts, colors, status bar, history, actions)
- *(mcp)* use sort_by_key for /sessions ordering (clippy 1.96 unnecessary_sort_by)
- *(mcp)* cargo fmt the viewer-ux changes (incl. alpha-ordered module decl)
- *(mcp)* stabilize web_viewer e2e - non-discarding harness, token I/O off the executor, settle before tool calls
- Merge pull request #29 from blinkingbit-oss/feat/docs-site
- link the docs site from crates.io and PyPI metadata

## [0.7.2](https://github.com/blinkingbit-oss/execkit/compare/v0.7.1...v0.7.2) - 2026-06-19

### Added

- *(mcp)* operator onboarding CLI (--version, --help, setup, doctor) + robust ~ resolution ([#27](https://github.com/blinkingbit-oss/execkit/pull/27))

## [0.7.1](https://github.com/blinkingbit-oss/execkit/compare/v0.7.0...v0.7.1) - 2026-06-18

### Added

- *(mcp)* per-session audit files, retention, watch dir/follow, and live notifications ([#25](https://github.com/blinkingbit-oss/execkit/pull/25))

## [0.7.0](https://github.com/blinkingbit-oss/execkit/compare/v0.6.1...v0.7.0) - 2026-06-17

### Added

- *(mcp)* execkit-mcp watch - live read-only session viewer ([#21](https://github.com/blinkingbit-oss/execkit/pull/21))

## [0.6.1](https://github.com/blinkingbit-oss/execkit/compare/v0.6.0...v0.6.1) - 2026-06-17

### Fixed

- *(release)* re-cut 0.6.x so the execkit-mcp binaries build

## [0.6.0](https://github.com/blinkingbit-oss/execkit/compare/v0.5.0...v0.6.0) - 2026-06-17

### Added

- *(python)* ship execkit-mcp as a pip-installable bin-wheel; 0.6 docs

### Other

- deflake mcp_e2e harness (background reader + best-effort cap drain) ([#17](https://github.com/blinkingbit-oss/execkit/pull/17))

## [0.5.0](https://github.com/blinkingbit-oss/execkit/compare/v0.4.3...v0.5.0) - 2026-06-13

### Added

- *(mcp)* reap idle sessions on create (EXECKIT_MCP_SESSION_TTL, default 30m)

### Other

- *(mcp)* widen active-session TTL margin to 3s (CI flake guard)
- *(mcp)* document EXECKIT_MCP_SESSION_TTL
- *(mcp)* SessionEntry with last_used + spawn_blocking destroy drop

## [0.4.3](https://github.com/blinkingbit-oss/execkit/compare/v0.4.2...v0.4.3) - 2026-06-08

### Other

- document MAX_SESSIONS + checkpoint tools + docker; MSRV + lean-build test

## [0.4.2](https://github.com/blinkingbit-oss/execkit/compare/v0.4.1...v0.4.2) - 2026-06-08

### Fixed

- *(security)* exclude .execkit, validate token, redaction coverage, docker -- , document destructive restore
- *(security)* atomic session cap (close TOCTOU that bypassed MAX_SESSIONS)

## [0.4.1](https://github.com/blinkingbit-oss/execkit/compare/v0.4.0...v0.4.1) - 2026-06-07

### Fixed

- *(checkpoint)* require explicit workspace; configurable + broader ignores

## [0.4.0](https://github.com/blinkingbit-oss/execkit/compare/v0.3.1...v0.4.0) - 2026-06-07

### Added

- *(mcp)* output budget params on session_create/session_exec

### Fixed

- *(budget)* guard HeadTail against untrusted extreme counts (final review)

### Other

- output budgets (README, QUICKSTART, mcp README) + truncated doc
- *(budget)* MCP e2e for output budgets (shape + report + bad regex)

## [0.3.0](https://github.com/blinkingbit-oss/execkit/compare/v0.2.0...v0.3.0) - 2026-06-07

### Added

- *(mcp)* checkpoint/restore tools + auto_snapshot/workspace/paths

### Other

- checkpoints feature + git-on-remote prerequisite

## [0.2.0](https://github.com/blinkingbit-oss/execkit/compare/v0.1.3...v0.2.0) - 2026-06-06

### Added

- Docker transport (Session::docker + MCP transport=docker)

## [0.1.3](https://github.com/blinkingbit-oss/execkit/compare/v0.1.2...v0.1.3) - 2026-06-05

### Other

- *(mcp)* assert server advertises execkit-mcp identity

## [0.1.2](https://github.com/blinkingbit-oss/execkit/compare/execkit-mcp-v0.1.1...execkit-mcp-v0.1.2) - 2026-06-05

### Fixed

- *(mcp)* advertise execkit-mcp identity, not rmcp's

### Other

- *(mcp)* accurate per-client setup (claude mcp add, Cursor, Gemini)
