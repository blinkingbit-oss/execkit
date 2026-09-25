# Output budgets

A noisy command can dump thousands of lines. That hurts twice: it costs the agent
context window, and the volume itself degrades the agent's reasoning. Output
budgets shape a command's output before it reaches the model.

Pass `budget` to `session_exec`, or `output_budget` to `session_create` for a
session default:

```jsonc
// keep only the last 200 lines of a noisy build
{ "session_id": "a3f9-1_local", "command": "npm run build",
  "budget": { "keep": { "mode": "tail", "n": 200 } } }

// grep a 50k-line log for errors, with 2 lines of context around each
{ "session_id": "a3f9-1_local", "command": "cat big.log",
  "budget": { "grep": { "pattern": "error|fail", "context": 2 } } }
```

Keep modes are `tail`, `head`, and `head_tail`; `grep` is a separate filter; both honor a `max_chars` cap.

Shaping is line-based, applied client-side, and runs **after** secret redaction.
It never changes the exit code or any side effect of the command, only what text
comes back. When a budget is applied, the result carries a `budget` report so the
agent knows the output was shaped:

```jsonc
"budget": {
  "stdout": { "mode": "tail", "lines_total": 4123, "lines_kept": 200 },
  "stderr": { "mode": "tail", "lines_total": 12, "lines_kept": 12 }
}
```

## How much output a budget sees

With a budget, execkit reads up to 8 MiB of each stream before shaping it, so
`grep` finds a match anywhere in a large log and `lines_total` is the real count.
Output past 8 MiB is compacted: execkit keeps the first and last 4 MiB and puts a
`[execkit: N bytes elided]` line where the middle was.

Without a budget, output is capped at about 100,000 characters per stream and the
result has `truncated: true`. Over MCP it also carries a `hint` suggesting a
budget:

```jsonc
// session_exec {"session_id":"a3f9-1_local","command":"seq 1 200000"}
{ "stdout": "1\n2\n3\n...", "truncated": true, "timed_out": false,
  "hint": "output was truncated; pass budget (grep/keep/max_chars) to shape it" }
```

Use budgets liberally on commands you expect to be loud (builds, installs, big
log reads); the agent keeps the signal without the noise.
