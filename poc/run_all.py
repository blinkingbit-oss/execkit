"""execkit feasibility PoC — run every risk probe and print a verdict table."""
import importlib
import sys

RISKS = [
    ("R1", "Command boundary detection", "r1_command_boundary"),
    ("R2", "stdout/stderr split", "r2_stdout_stderr_split"),
    ("R3", "Clean output (ANSI strip)", "r3_ansi_strip"),
    ("R4", "Persistent session state", "r4_session_state"),
    ("R5", "Interactive process control", "r5_interactive_repl"),
    ("R6", "Multi-transport (Docker)", "r6_docker_transport"),
]


def main():
    print("=" * 70)
    print("execkit — feasibility PoC")
    print("=" * 70)
    summary = []
    for rid, title, mod in RISKS:
        print(f"\n### {rid} — {title}")
        m = importlib.import_module(mod)
        rs = m.run()
        passed = all(p for _, p, _ in rs)
        skipped = any("SKIP" in d for _, _, d in rs) and not passed
        for label, p, detail in rs:
            tag = "SKIP" if ("SKIP" in detail) else ("PASS" if p else "FAIL")
            print(f"  [{tag}] {label:36} {detail}")
        summary.append((rid, title, "PASS" if passed else ("SKIP" if skipped else "FAIL")))

    print("\n" + "=" * 70)
    print("VERDICT")
    print("=" * 70)
    for rid, title, verdict in summary:
        print(f"  {rid}  {verdict:5}  {title}")
    hard = [v for r, _, v in summary if r in ("R1", "R2")]
    print("\nCritical risks (R1 boundary, R2 split):",
          "FEASIBLE" if all(v == "PASS" for v in hard) else "NEEDS WORK")
    return 0 if all(v in ("PASS", "SKIP") for _, _, v in summary) else 1


if __name__ == "__main__":
    sys.exit(main())
