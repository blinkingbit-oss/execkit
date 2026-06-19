# Output budgets

A noisy command can dump thousands of lines. That hurts twice: it costs the agent
context window, and the volume itself degrades the agent's reasoning. Output
budgets shape a command's output before it reaches the model.

Pass `budget` to `session_exec`, or `output_budget` to `session_create` for a
session default:

```jsonc
// keep only the last 200 lines of a noisy build
{ "session_id": "1_local", "command": "npm run build",
  "budget": { "keep": { "mode": "tail", "n": 200 } } }

// grep a 50k-line log for errors, with 2 lines of context around each
{ "session_id": "1_local", "command": "cat big.log",
  "budget": { "grep": { "pattern": "error|fail", "context": 2 } } }
```

Modes include `tail`, `head`, `head_tail`, and `grep`, plus a `max_chars` cap.

Shaping is line-based, applied client-side, and runs **after** secret redaction.
It never changes the exit code or any side effect of the command, only what text
comes back. When a budget is applied, the result carries a `budget` report so the
agent knows the output was shaped:

```jsonc
"budget": { "stdout": { "mode": "tail", "lines_total": 4123, "lines_kept": 200 } }
```

Use budgets liberally on commands you expect to be loud (builds, installs, big
log reads); the agent keeps the signal without the noise.
