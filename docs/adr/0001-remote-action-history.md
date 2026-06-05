# ADR 0001 — Remote action history (time-travel for agent changes)

- **Status:** Accepted (design) — targets v0.4; not in MVP
- **Date:** 2026-06-03
- **Context docs:** [`../../ROADMAP.md`](../../ROADMAP.md), [`../../FEATURE_VISION.md`](../../FEATURE_VISION.md), [`../../README.md`](../../README.md)

## Context

execkit lets an AI agent run commands on remote targets (SSH, Docker, K8s). Those
targets typically have **no version control**, so an agent's destructive or wrong
actions there are unrecoverable. This is the un-versioned blast radius the policy
fence can only *prevent* — we also want to *recover*.

Explicitly **out of scope:** versioning the user's own project/codebase. That is
the user's git responsibility. This ADR covers **agent changes made on remote
environments only**.

We want: a backup of file-affecting actions (update / create / delete / move /
rename); the ability to return to any previous state; **non-destructive** history
(returning to a past state never deletes later history); branches; "test any
previous state and stick to it"; manual deletion of states.

## Decision

**Maintain a content-addressed history as a local (execkit-side) git mirror of a
bounded remote workspace, synced after each agent action. The remote stays a
dumb sync source and needs no special tooling.**

1. **Scope to a workspace root, never the whole remote FS.** Each session declares
   a workspace root on the remote (default: cwd; or an explicit path such as
   `/opt/app`). Only that subtree is tracked. This is the decision that makes the
   feature tractable.

2. **Local git mirror, via `gix` (gitoxide), unmodified.** Use git's object model
   as-is — it dissolves the "full-file vs diff" dilemma: content-addressed blobs
   dedupe unchanged files to a single copy, and packfiles delta-compress changed
   ones. We get snapshot simplicity with diff-level storage, plus a DAG, branches,
   and append-only (non-destructive) history for free. `git2` (libgit2) is the
   fallback if gitoxide write support is insufficient.

3. **Remote needs no git.** History is computed and stored on the execkit side under
   e.g. `~/.execkit/history/<host>/<workspace>/`, with a ref namespace
   (`refs/execkit/...`). The remote only needs standard shell utilities.

4. **Sync per action:**
   - **Change detection:** mtime+size sweep over the workspace (rsync's heuristic;
     `find`/`stat`). Optional "paranoid" full-hash mode.
   - **Pull changed/created files** over the existing SFTP channel (or a `tar`
     stream); deletions/renames surface as tree changes when the mirror is
     reconciled.
   - **Commit** the mirror; store the commit hash on the corresponding **audit-log
     entry** (audit log = the actions; git mirror = the resulting file states;
     cross-linked).

5. **Restore = gated push-back.** Restoring makes the remote workspace match a
   chosen commit. Because it mutates the remote, restore routes through the same
   **policy / human-in-the-loop gate** as any other action, and must **diff-and-warn**
   before overwriting (never blind-clobber concurrent external changes).

6. **History semantics map to native git:**
   | Requirement | Mechanism |
   |---|---|
   | Back to any state | checkout a commit |
   | Back doesn't delete forward | git DAG is non-destructive |
   | Test a state and stick to it | branch from that commit, continue |
   | Branches | native |
   | Manual state deletion | delete ref/branch + prune (append-only until gc) |

## Alternatives considered

- **Git *on the remote*** — rejected: needs tooling on every host, fails on minimal
  images, risks clobbering the remote's own git.
- **Full remote-filesystem backup** — rejected: absurd scope and storage.
- **Custom restic/borg-style chunk store (CDC + content-addressed chunks)** — the
  correct *model*, but overkill to build now; git's object store already provides
  dedup + delta. Revisit only if git's large-file behavior becomes the bottleneck.
- **Custom diff-only format** — rejected: reinvents git worse; brittle.

## Consequences

**Positive**
- Reuses a proven, embeddable store (gitoxide); minimal custom code (the novel part
  is change-detection + file pull/push).
- Remote-agnostic; works on minimal/locked-down hosts.
- Reinforces the "safe autonomy" thesis: prevent with the fence, recover with the
  history. Restore inherits the same safety gate.
- Audit-log ↔ commit linkage answers "what command caused this state / show its diff."

**Negative / limits (must be designed for and documented)**
1. **This is agent-action history, not a server backup.** Files changed by other
   processes/users between sweeps can be missed or race.
2. **Restore can clobber concurrent external changes** → must diff-and-warn.
3. **Large workspaces** inflate sweep cost → mitigate with scope + gitignore-style
   excludes + the mtime heuristic.
4. **Permissions** — SSH user needs read on the workspace (capture) and write
   (restore).
5. **Large binaries** — git's weak spot → size caps + excludes.
6. **Deleting a *middle* state isn't free** — deleting leaves/branches is cheap;
   surgically removing one mid-history state requires a rewrite (`rebase --onto`)
   that re-hashes its descendants. Document this honestly.

## Scope for first cut (v0.2 — simple/linear)

Per the "simplest thing first" decision, the first cut is **linear**, not the full
branching tree:

- One workspace root per session; SSH + local/container transports.
- Local git mirror (gitoxide); mtime+size change detection; SFTP/`tar` transfer.
- **Snapshot-before-risky-command → restore-last** (linear undo). Gated, diff-and-warn restore.
- Each checkpoint linked to its audit-log entry.

**Deferred to v0.4 (decide when we build it):** branches / navigable history tree /
manual mid-history prune (the non-destructive DAG described above), paranoid
full-hash mode, large-file/LFS handling, multi-workspace, automatic restore policies.

The git-as-store decision and the rationale above stand unchanged — only the
*navigation surface* is staged: linear now, branching later.
