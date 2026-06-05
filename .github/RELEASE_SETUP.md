# Release setup (one-time)

The `release-plz` workflow automates: version bump → CHANGELOG → git tag →
GitHub Release → `cargo publish`. It activates once these prerequisites are met.

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
   - On crates.io → your crate → *Settings → Trusted Publishing* → add a GitHub
     publisher: owner/repo + workflow file `release-plz.yml` + (optional) environment.
   - The workflow's `release` job already requests `id-token: write` and uses
     `rust-lang/crates-io-auth-action`. Nothing else to store.
   - Note: Trusted Publishing requires the crate to already exist, so do the first
     publish with a token (Option B), then switch to OIDC.

   **Option B - Stored token (simplest for the very first publish):**
   - `cargo login` locally → create a crates.io API token (scope: publish-update).
   - Add it as a GitHub repo secret named `CARGO_REGISTRY_TOKEN`.
   - In `release-plz.yml`, comment out the OIDC auth step and switch the
     `CARGO_REGISTRY_TOKEN` env to `${{ secrets.CARGO_REGISTRY_TOKEN }}`.

5. **Let the Action open PRs:** Settings → Actions → General → Workflow permissions
   → enable "Allow GitHub Actions to create and approve pull requests".

## How a release happens after setup

1. Push commits to `main` using **Conventional Commits** (`feat:`, `fix:`, etc.).
2. release-plz opens/updates a **Release PR** with the bumped version + changelog.
3. **Merge the Release PR** → the `release` job publishes to crates.io and creates
   the GitHub Release. That's it.

## Add the other registries later

- v0.2 PyPI: `maturin generate-ci github` + a PyPI Trusted Publisher.
- v0.3 npm: `napi new` template + `NPM_TOKEN`.
- v0.4 Go: just push a `vX.Y.Z` tag.
