# Package-name reservations

Minimal placeholder packages that reserve the `execkit-mcp` name on PyPI and the
`execkit` / `execkit-mcp` names on npm for future installers. They are NOT part of
the Rust crates and are never published to crates.io. Each is an honest placeholder
linking to the repo.

> The PyPI `execkit` name is no longer a placeholder: it is the real Python SDK,
> built natively from `crates/execkit-py` (PyO3 + maturin) and published by
> `.github/workflows/wheels.yml` on a release tag via Trusted Publishing.

## Publish (one-time, to claim each name)

PyPI (needs a PyPI account + token; then set up a Trusted Publisher for automation):

    cd packaging/pypi/execkit-mcp   && python -m build && twine upload dist/*

npm (needs `npm login`):

    cd packaging/npm/execkit        && npm publish --access public
    cd packaging/npm/execkit-mcp    && npm publish --access public

Replace the placeholders with the real SDK / wrapper when you build them.
