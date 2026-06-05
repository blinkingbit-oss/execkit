"""Run the flashy-feature security PoCs — each verifies the GATE holds."""
import importlib
import sys

FLASHY = [
    ("F1", "Self-healing reconnect + host-key re-verify (MITM caught)", "f1_reconnect_hostkey"),
    ("F3", "Snapshot/replay: redacted, encrypted, dry-run default", "f3_snapshot_replay"),
    ("F4", "Fork/observe: isolation, no session bleed", "f4_fork_isolation"),
    ("F5", "Capability gate: no agent self-escalation", "f5_capability_no_escalation"),
    ("F6", "Native file primitive: path-traversal blocked", "f6_path_traversal"),
]


def main():
    print("=" * 72)
    print("execkit — flashy-feature SECURITY PoC (does the gate hold?)")
    print("=" * 72)
    summary = []
    for fid, title, mod in FLASHY:
        print(f"\n### {fid} — {title}")
        rs = importlib.import_module(mod).run()
        passed = all(p for _, p, _ in rs)
        for label, p, detail in rs:
            print(f"  [{'PASS' if p else 'FAIL'}] {label:40} {detail}")
        summary.append((fid, title, "PASS" if passed else "FAIL"))

    print("\n" + "=" * 72)
    print("VERDICT — flashy features are safe ONLY if their gate holds")
    print("=" * 72)
    for fid, title, verdict in summary:
        print(f"  {fid}  {verdict:5}  {title}")
    print("\n  F2  CUT    Cross-host federated sessions (no PoC — surface > value)")
    return 0 if all(v == "PASS" for _, _, v in summary) else 1


if __name__ == "__main__":
    sys.exit(main())
