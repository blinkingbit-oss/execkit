# Package-name reservations

Minimal placeholder packages that reserve the `execkit` / `execkit-mcp` names on
PyPI and npm for future SDKs / installers. They are NOT part of the Rust crates and
are never published to crates.io. Each is an honest placeholder linking to the repo.

## Publish (one-time, to claim each name)

PyPI (needs a PyPI account + token; then set up a Trusted Publisher for automation):

    cd packaging/pypi/execkit       && python -m build && twine upload dist/*
    cd packaging/pypi/execkit-mcp   && python -m build && twine upload dist/*

npm (needs `npm login`):

    cd packaging/npm/execkit        && npm publish --access public
    cd packaging/npm/execkit-mcp    && npm publish --access public

Replace the placeholders with the real SDK / wrapper when you build them.
