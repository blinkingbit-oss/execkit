# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0](https://github.com/blinkingbit-oss/execkit/compare/execkit-v0.5.0...execkit-v0.6.0) - 2026-06-17

### Added

- *(python)* ship execkit-mcp as a pip-installable bin-wheel; 0.6 docs

## [0.5.0](https://github.com/blinkingbit-oss/execkit/compare/execkit-v0.4.3...execkit-v0.5.0) - 2026-06-13

### Added

- [**breaking**] ShellExited error + non_exhaustive Error (0.5.0)

### Other

- bump dependency examples 0.4 -> 0.5 for the 0.5.0 release

## [0.4.3](https://github.com/blinkingbit-oss/execkit/compare/execkit-v0.4.2...execkit-v0.4.3) - 2026-06-08

### Fixed

- correct MSRV to 1.88; defer ShellExited (breaking) to keep v0.4.3 a patch
- drop now-unused Session.token field (dead-code; -D warnings CI gate)
- reap local shell on drop; checkpoints() degrades to empty list
- temp-file leak, exit-vs-timeout, TMPDIR, cached markers; docs 0.4

### Other

- document MAX_SESSIONS + checkpoint tools + docker; MSRV + lean-build test

## [0.4.2](https://github.com/blinkingbit-oss/execkit/compare/execkit-v0.4.1...execkit-v0.4.2) - 2026-06-08

### Fixed

- *(security)* exclude .execkit, validate token, redaction coverage, docker -- , document destructive restore
- *(security)* framing integrity - unspoofable cwd, unforgeable stderr path, strip C0
- *(security)* make secret excludes un-negatable by untrusted ignores
- *(security)* fail closed on unreadable known_hosts (no silent host-key bypass)
- *(security)* validate checkpoint id is a hex SHA (blocks git option injection)

## [0.4.1](https://github.com/blinkingbit-oss/execkit/compare/execkit-v0.4.0...execkit-v0.4.1) - 2026-06-07

### Fixed

- *(checkpoint)* clearer error on restore before any snapshot + doc fix
- *(checkpoint)* require explicit workspace; configurable + broader ignores

## [0.4.0](https://github.com/blinkingbit-oss/execkit/compare/execkit-v0.3.1...execkit-v0.4.0) - 2026-06-07

### Added

- *(budget)* session exec_budgeted + with_output_budget + report wiring
- *(budget)* ExecResult.budget report field + re-exports
- *(budget)* apply() pipeline + StreamReport/BudgetReport
- *(budget)* line-keep subset + gap-marker rendering
- *(budget)* grep line-index selection with context merge
- *(budget)* Budget/Grep/Keep types + Error::Budget

### Fixed

- *(budget)* guard HeadTail against untrusted extreme counts (final review)
- *(budget)* bound untrusted grep pattern (length cap + compiled-size limit)

### Other

- output budgets (README, QUICKSTART, mcp README) + truncated doc

## [0.3.1](https://github.com/blinkingbit-oss/execkit/compare/execkit-v0.3.0...execkit-v0.3.1) - 2026-06-07

### Other

- accuracy pass for v0.3.0

## [0.3.0](https://github.com/blinkingbit-oss/execkit/compare/execkit-v0.2.0...execkit-v0.3.0) - 2026-06-07

### Added

- *(checkpoint)* auto-snapshot before changing remote commands
- *(checkpoint)* remote-only checkpoint/restore/list API + lazy git init
- *(checkpoint)* Checkpointer config, git command builders, parsers
- *(checkpoint)* conservative read-only command classifier
- *(checkpoint)* error variant + checkpoint types + module skeleton

### Fixed

- *(checkpoint)* close <(...) bypass, drop uniq, re-check poison (pre-merge review)
- *(checkpoint)* tighten read-only classifier (final review)
- *(checkpoint)* run git in the work-tree (-C) + space-delimited log

### Other

- drop stray em-dashes in source comments
- reflect six MCP tools (checkpoint/restore) in README
- checkpoints feature + git-on-remote prerequisite
- *(checkpoint)* Docker integration (roundtrip, auto-skip, multi-path)
- rustfmt the checkpoint module + session refactor
- *(session)* extract run_framed; hold an optional Checkpointer
- fix stale version refs after 0.2.0 bump

## [0.2.0](https://github.com/blinkingbit-oss/execkit/compare/execkit-v0.1.3...execkit-v0.2.0) - 2026-06-06

### Added

- Docker transport (Session::docker + MCP transport=docker)

### Fixed

- *(docker)* reap in-container process tree on session drop
- *(docker)* validate container ref + end-of-options marker

### Other

- no-Rust install (prebuilt installer) + structured-result demo
- rustfmt wrap long line in ssh_smoke test
- *(ssh)* CI regression test for RSA key auth (rsa-sha2)

## [0.1.3](https://github.com/blinkingbit-oss/execkit/compare/execkit-v0.1.2...execkit-v0.1.3) - 2026-06-05

### Other

- *(ssh)* use russh 'ring' crypto backend instead of aws-lc-rs
- *(dist)* prebuilt binaries via cargo-dist (6 unix targets)

## [0.1.2](https://github.com/blinkingbit-oss/execkit/compare/execkit-v0.1.1...execkit-v0.1.2) - 2026-06-05

### Fixed

- *(ssh)* RSA key auth (rsa-sha2) + use a clean POSIX shell

### Other

- rustfmt wrap long line in output.rs
