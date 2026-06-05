<!-- Thanks for contributing! Keep PRs small and focused. -->

## What & why

<!-- What does this change, and why? Link any related issue (Fixes #123). -->

## Checklist

- [ ] `cargo fmt --all` and clippy clean (`-D warnings`), default **and** `--no-default-features`
- [ ] `cargo test --workspace` passes (added/updated a test for new behavior)
- [ ] SSH/MCP e2e run if I touched those paths
- [ ] Docs/README/CHANGELOG updated if user-facing
- [ ] Commits signed off (`git commit -s`, DCO)
- [ ] No new tool argument lets an (untrusted) caller pick arbitrary host paths,
      credentials, or hosts - dangerous config stays operator-controlled

## Notes for reviewers

<!-- Anything tricky, trade-offs, or areas you'd like extra eyes on. -->
