# Package-name reservations

Minimal placeholder packages that reserve the `execkit` / `execkit-mcp` names on
**npm** for future installers. They are NOT part of the Rust crates and are never
published to crates.io. Each is an honest placeholder linking to the repo.

> **PyPI is no longer placeholders.** Both `execkit` (the native PyO3 SDK, from
> `crates/execkit-py`) and `execkit-mcp` (the server binary as a maturin bin-wheel,
> from `crates/execkit-mcp`) are real packages, built and published by
> `.github/workflows/wheels.yml` on a release tag via Trusted Publishing.

## Publish (one-time, to claim each npm name)

npm (needs `npm login`):

    cd packaging/npm/execkit        && npm publish --access public
    cd packaging/npm/execkit-mcp    && npm publish --access public

Replace the placeholders with real wrappers when you build them.
