# Release setup (one-time)

The `release-plz` workflow automates: version bump -> CHANGELOG -> git tag ->
GitHub Release -> `cargo publish`. It activates once these prerequisites are met.

## Prerequisites

1. **A publishable crate exists.** There must be a `Cargo.toml` with the required
   publish metadata (`name`, `version`, `description`, `license = "Apache-2.0"`,
   `repository`, `readme`). release-plz does nothing until a real crate is present.

2. **Repo is on GitHub**, with the `main` branch as default.

3. **Reserve the crate name** on crates.io (publish a `0.0.0` placeholder, or just
   ensure `execkit` is free): `cargo publish` once manually for the first version, OR
   set up Trusted Publishing (below) which can claim it.

4. **crates.io auth - choose one:**

   **Option A - Trusted Publishing via OIDC (recommended, no stored secret):**
   - On crates.io -> your crate -> *Settings -> Trusted Publishing* -> add a GitHub
     publisher: owner/repo + workflow file `release-plz.yml` + (optional) environment.
   - The workflow's `release` job already requests `id-token: write` and uses
     `rust-lang/crates-io-auth-action`. Nothing else to store.
   - Note: Trusted Publishing requires the crate to already exist, so do the first
     publish with a token (Option B), then switch to OIDC.

   **Option B - Stored token (simplest for the very first publish):**
   - `cargo login` locally -> create a crates.io API token (scope: publish-update).
   - Add it as a GitHub repo secret named `CARGO_REGISTRY_TOKEN`.
   - In `release-plz.yml`, comment out the OIDC auth step and switch the
     `CARGO_REGISTRY_TOKEN` env to `${{ secrets.CARGO_REGISTRY_TOKEN }}`.

5. **Let the Action open PRs:** Settings -> Actions -> General -> Workflow permissions
   -> enable "Allow GitHub Actions to create and approve pull requests".

## How a release happens after setup

1. Push commits to `main` using **Conventional Commits** (`feat:`, `fix:`, etc.).
2. release-plz opens/updates a **Release PR** with the bumped version + changelog.
3. **Merge the Release PR** -> the `release` job publishes to crates.io and creates
   the GitHub Release. That's it.

> **On a minor bump (e.g. 0.2 -> 0.3):** release-plz updates `Cargo.toml` and the
> changelog, but NOT README prose. Hand-update the dependency examples in
> `README.md` + `docs/QUICKSTART.md` (`execkit = "0.x"`), since `^0.2` won't pull
> `0.3`. The "Early `0.x` release" banner is version-agnostic on purpose.

## Prebuilt binaries (cargo-dist) + the tag-trigger PAT

`execkit-mcp` ships prebuilt binaries for 6 targets via cargo-dist
(`dist-workspace.toml` + `.github/workflows/release.yml`). On the release tag,
release-plz creates the GitHub Release as a **draft**; cargo-dist then builds the
binaries, uploads them to the draft, and publishes it.

**Gotcha:** a tag pushed with the default `GITHUB_TOKEN` does **not** trigger
other workflows (GitHub's anti-recursion rule). So cargo-dist never fires and the
Release is left an empty draft. Give release-plz a token that *can* trigger
workflows:

1. Create a **fine-grained PAT** on this repo with `Contents: read/write` +
   `Workflows: read/write` (or a classic PAT with `repo` + `workflow`; a GitHub
   App token is even better for orgs).
2. Add it as a repo secret named **`RELEASE_PLZ_TOKEN`** (Settings -> Secrets and
   variables -> Actions). `release-plz.yml` already prefers it over `GITHUB_TOKEN`.

**Fallback if the PAT isn't set:** the crate still publishes, but the Release sits
as an empty draft. Build its binaries by re-pushing the tag yourself (a *user*
push triggers cargo-dist):

```bash
git push origin :refs/tags/vX.Y.Z   # delete the tag
git push origin vX.Y.Z              # re-push -> triggers cargo-dist
```

## Pre-release checklist

Run this before merging the Release PR (step 3 above). CI enforces most of it; the
items marked (manual) are what a human must confirm.

### Code and tests
- [ ] `cargo fmt --all --check` clean
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- [ ] `cargo clippy -p execkit --no-default-features --all-targets -- -D warnings` clean (lean local+Docker build, no SSH)
- [ ] `cargo test --workspace` green
- [ ] Real-infra e2e green - the CI jobs `ssh-e2e`, `ssh-rsa-key-e2e`, `docker-e2e`, `checkpoints-e2e` (or run locally with containers + the matching `EXECKIT_TEST_*` env)
- [ ] CI is green on `main` for the release commit (every job)

### Review (manual)
- [ ] Substantive changes have had a code review
- [ ] Any command built from agent/untrusted input was checked for shell injection - values go through `shq`/validation (the agent is the adversary)
- [ ] New attack surface got a security pass

### Docs (manual - release-plz does NOT edit prose)
- [ ] Dependency version examples in `README.md` + `docs/QUICKSTART.md` match the new version. CRITICAL on a minor bump: `execkit = "0.x"` means `^0.x` and excludes the next minor, so `"0.2"` will not pull `0.3`.
- [ ] `crates/execkit/src/lib.rs` module doc and the MCP tool list/table reflect the current transports, tools, and API
- [ ] New features are documented; limitations and honest non-goals are stated
- [ ] No non-ASCII typography (em-dashes, ellipses, arrows): the repo-wide grep over `git ls-files` returns 0
- [ ] `cargo doc -p execkit --no-deps --all-features` is warning-clean (no broken/private intra-doc links)
- [ ] The generated CHANGELOG entry reads correctly (release-plz builds it from Conventional Commits)

### Security and hygiene
- [ ] `cargo audit --ignore RUSTSEC-2023-0071` clean (no NEW advisories; revisit the ignore when russh updates)
- [ ] No secrets/tokens committed; planning and dev docs stay in gitignored `_internal/`
- [ ] `cargo package -p execkit --list` and `-p execkit-mcp --list` contain only intended files (no internal docs leak)

### Release mechanics
- [ ] Commits use Conventional Commits (only `feat:`/`fix:` bump the version; `docs:`/`chore:`/`ci:` do not)
- [ ] `RELEASE_PLZ_TOKEN` is set so cargo-dist auto-builds binaries (otherwise do the manual tag re-push above)
- [ ] Merge the Release PR

### Post-release verification
- [ ] crates.io shows the new version for BOTH `execkit` and `execkit-mcp`
- [ ] The GitHub Release is **published (not a draft)** with all 6 binaries + `execkit-mcp-installer.sh`
- [ ] docs.rs built the new version
- [ ] (optional) smoke the PUBLISHED `execkit-mcp` against a real container and SSH host
- [ ] Rotate/revoke any test credentials used during verification

## Add the other registries later

- v0.2 PyPI: `maturin generate-ci github` + a PyPI Trusted Publisher.
- v0.3 npm: `napi new` template + `NPM_TOKEN`.
- v0.4 Go: just push a `vX.Y.Z` tag.
