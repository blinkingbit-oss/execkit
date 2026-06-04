"""
FLASHY GATE — Native file primitives must honor the permission fence.

A `read_file` primitive that bypasses the shell must NOT become a path-traversal
hole. Verifies the jail holds against `..`, absolute escapes, and symlink tricks.
"""
import os
import sys

from _policy import Policy

JAIL = "/tmp/nexum_jail"


def read_file(policy: Policy, path: str):
    ok, rp = policy.check_path(path)
    if not ok:
        return {"allowed": False, "resolved": rp}
    with open(rp) as f:
        return {"allowed": True, "resolved": rp, "content": f.read()}


def run():
    results = []
    os.makedirs(JAIL, exist_ok=True)
    with open(os.path.join(JAIL, "ok.txt"), "w") as f:
        f.write("inside the jail")
    # a secret living OUTSIDE the jail that an attacker would try to reach
    with open("/tmp/nexum_secret_outside.txt", "w") as f:
        f.write("TOP SECRET")
    # symlink inside the jail pointing out (classic traversal trick)
    link = os.path.join(JAIL, "escape_link")
    if not os.path.lexists(link):
        os.symlink("/tmp/nexum_secret_outside.txt", link)

    policy = Policy(allow_paths=[JAIL])

    # 1. legit read inside jail
    r = read_file(policy, os.path.join(JAIL, "ok.txt"))
    results.append(("read inside jail", r["allowed"] and r.get("content") == "inside the jail",
                    f"allowed={r['allowed']}"))

    # 2. absolute escape blocked
    r = read_file(policy, "/etc/passwd")
    results.append(("absolute escape blocked", not r["allowed"], f"resolved={r['resolved']}"))

    # 3. ../ traversal blocked
    r = read_file(policy, os.path.join(JAIL, "../../etc/passwd"))
    results.append(("../ traversal blocked", not r["allowed"], f"resolved={r['resolved']}"))

    # 4. symlink traversal blocked (realpath resolves the link target)
    r = read_file(policy, link)
    results.append(("symlink traversal blocked", not r["allowed"], f"resolved={r['resolved']}"))

    return results


if __name__ == "__main__":
    rs = run()
    ok = all(p for _, p, _ in rs)
    for label, passed, detail in rs:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label:30} {detail}")
    print(f"F6 {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
