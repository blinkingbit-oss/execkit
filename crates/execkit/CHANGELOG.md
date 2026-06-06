# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
