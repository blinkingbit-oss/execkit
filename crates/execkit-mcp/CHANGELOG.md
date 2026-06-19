# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
