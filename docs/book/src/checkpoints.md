# Checkpoints

On SSH and Docker sessions, execkit can snapshot the workspace before a changing
command and restore it on demand: a filesystem "undo" for agent actions.

It undoes **files only**, never side effects. A dropped database stays dropped, a
sent email stays sent, an installed package stays installed. For "the agent
mangled my source tree," that is exactly the recovery you want.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `session_checkpoint` | `session_id`, optional `label` | `{ "checkpoint_id": "..." }` |
| `session_checkpoints` | `session_id` | `[{ id, label, created }]` |
| `session_restore` | `session_id`, optional `checkpoint_id` | `{ restored_to, files_changed }` |

Omit `checkpoint_id` on restore to roll back to the most recent checkpoint.

## Enabling it

Two requirements:

1. **`git` on the remote host.** Checkpoints use a shadow git repo. If git is
   absent, auto-snapshot disables itself and checkpoint calls return a clear
   "install git on the remote" error.
2. **An explicit `workspace`** on `session_create`. Without it, checkpoints and
   auto-snapshot are off. execkit will **not** default to the cwd or `$HOME`,
   snapshotting a home directory is slow and would capture secrets. Set
   `workspace` to the project directory you want undo for (pass `$HOME`
   explicitly only if you truly mean it).

Control it via `session_create`:

- `workspace` (root; REQUIRED to enable checkpoints)
- `auto_snapshot` (default true; effective only with a workspace)
- `paths` (sub-directories under the root to track)
- `checkpoint_ignores` (extra gitignore-style patterns, added to the built-in
  defaults: `.git`, `node_modules`, build dirs, caches, `.ssh`, `.aws`, ...)

## Restore is destructive

> **Warning.** `session_restore` reverts tracked files **and deletes all
> untracked files and directories** anywhere under the workspace (via `git
> clean`), not only files created since the checkpoint. Do not restore if
> untracked files in the workspace must be preserved.
