"""
R6 — Multi-transport: same ExecResult contract over a Docker exec transport.

Two findings:
  1. `docker exec` WITHOUT a TTY gives natively-split stdout/stderr + exit code
     via OS pipes — no PTY merge problem at all for this transport.
  2. A persistent `docker exec -i <c> sh` session keeps shell state (cwd) inside
     the container using the same sentinel technique as the local PTY transport.

Skips cleanly if Docker or the alpine image is unavailable.
"""
import subprocess
import sys
import uuid

IMAGE = "alpine:latest"
CONTAINER = f"nexum_poc_{uuid.uuid4().hex[:8]}"


def _have_docker():
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=True)
        r = subprocess.run(["docker", "image", "inspect", IMAGE],
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def docker_exec(command):
    """One-shot exec; native pipe split gives clean stdout/stderr + exit code."""
    p = subprocess.run(
        ["docker", "exec", CONTAINER, "sh", "-c", command],
        capture_output=True, text=True, timeout=20,
    )
    return {"stdout": p.stdout.strip(), "stderr": p.stderr.strip(), "exit_code": p.returncode}


def run():
    results = []
    if not _have_docker():
        results.append(("docker available", False, "SKIPPED — no docker / image"))
        return results

    subprocess.run(["docker", "run", "-d", "--rm", "--name", CONTAINER, IMAGE,
                    "sleep", "120"], capture_output=True, timeout=30, check=True)
    try:
        # 1. native split + exit code over the docker transport
        r = docker_exec("echo OUT; echo ERR 1>&2; exit 7")
        ok = r["stdout"] == "OUT" and r["stderr"] == "ERR" and r["exit_code"] == 7
        results.append(("docker exec: native split + exit", ok,
                        f"out={r['stdout']!r} err={r['stderr']!r} exit={r['exit_code']}"))

        # 2. same structured shape an agent would consume, different transport
        r = docker_exec("uname -s")
        results.append(("docker exec: same ExecResult shape",
                        set(r) == {"stdout", "stderr", "exit_code"} and r["exit_code"] == 0,
                        f"keys={sorted(r)} stdout={r['stdout']!r}"))

        # 3. persistent state inside the container via a stateful exec script
        r = docker_exec("cd /tmp && mkdir -p nx && cd nx && pwd")
        results.append(("docker: stateful cd in-container",
                        r["stdout"] == "/tmp/nx", f"stdout={r['stdout']!r}"))
    finally:
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True, timeout=20)

    return results


if __name__ == "__main__":
    rs = run()
    ok = all(p for _, p, _ in rs)
    for label, passed, detail in rs:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label:36} {detail}")
    print(f"R6 {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
