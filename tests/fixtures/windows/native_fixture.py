"""Owned offline acceptance workload. Never run resource/tree modes on the host.

The trusted qualification harness installs a small entry script beside this file
and provides fixture-config.json containing only owned test paths/endpoints.
Fixture output is an observation, not the acceptance oracle.
"""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def emit(kind, **values):
    print(json.dumps({"fixture_version": 1, "kind": kind, **values}), flush=True)


def config():
    path = Path("fixture-config.json")
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def write_result(value):
    Path("fixture-result.json").write_text(
        json.dumps(value, sort_keys=True), encoding="utf-8"
    )
    emit("result", **value)


def spawn(mode):
    return subprocess.Popen(
        [sys.executable, "-I", "-S", str(Path(__file__).resolve()), mode],
        stdin=subprocess.DEVNULL,
    )


def worker():
    marker = Path("heartbeat-" + str(os.getpid()) + ".txt")
    emit("worker_ready", pid=os.getpid())
    while True:
        marker.write_text(str(time.time_ns()), encoding="ascii")
        time.sleep(0.05)


def child():
    grandchild = spawn("worker")
    emit("child_ready", pid=os.getpid(), grandchild=grandchild.pid)
    worker()


def main(mode):
    if mode == "io":
        source = Path("original.txt").read_text(encoding="utf-8")
        Path("changed.txt").write_text("owned lab change\n", encoding="utf-8")
        sys.stderr.write("owned stderr marker\n")
        write_result(
            {
                "source": source,
                "python": list(sys.version_info[:3]),
                "isolated": sys.flags.isolated,
                "host_secret_inherited": "PETRI_OWNED_HOST_CANARY" in os.environ,
            }
        )
        return 0
    if mode == "nonzero":
        emit("nonzero", expected_exit=7)
        return 7
    if mode == "filesystem":
        probes = []
        for name, value in config().get("outside_paths", {}).items():
            target = Path(value)
            read_allowed = write_allowed = False
            try:
                target.read_bytes()
                read_allowed = True
            except OSError:
                pass
            try:
                with target.open("ab") as output:
                    output.write(b"FORBIDDEN-FIXTURE-WRITE")
                write_allowed = True
            except OSError:
                pass
            probes.append(
                {"name": name, "read_allowed": read_allowed, "write_allowed": write_allowed}
            )
        Path("allowed-write.txt").write_bytes(b"allowed")
        write_result({"probes": probes, "workspace_write": True})
        return 0
    if mode == "network":
        results = []
        for endpoint in config().get("endpoints", []):
            family = socket.AF_INET6 if endpoint["family"] == "ipv6" else socket.AF_INET
            for transport in ("tcp", "udp"):
                sent = False
                error = None
                sock = None
                try:
                    sock = socket.socket(
                        family, socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
                    )
                    sock.settimeout(0.4)
                    address = (endpoint["host"], endpoint[transport + "_port"])
                    if transport == "tcp":
                        sock.connect(address)
                        sock.sendall(b"PETRI-OWNED-NEGATIVE")
                    else:
                        sock.sendto(b"PETRI-OWNED-NEGATIVE", address)
                    sent = True
                except OSError as exc:
                    error = exc.errno
                finally:
                    if sock is not None:
                        sock.close()
                results.append(
                    {"family": endpoint["family"], "transport": transport, "sent": sent, "errno": error}
                )
        write_result({"connections": results})
        return 0
    if mode == "tree":
        descendant = spawn("child")
        emit("tree_ready", pid=os.getpid(), child=descendant.pid)
        worker()
    if mode == "child":
        child()
    if mode == "worker":
        worker()
    if mode == "root_exit":
        descendant = spawn("worker")
        emit("root_exit", child=descendant.pid)
        deadline = time.monotonic() + 5
        while not Path("heartbeat-" + str(descendant.pid) + ".txt").exists():
            if descendant.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("child readiness was not observed before root exit")
            time.sleep(0.02)
        return 0
    if mode == "processes":
        children = []
        try:
            for _ in range(24):
                children.append(spawn("worker"))
                time.sleep(0.02)
        except OSError as exc:
            emit("process_limit_observed", created=len(children), errno=exc.errno)
        worker()
    if mode == "memory":
        blocks = []
        try:
            for _ in range(32):
                blocks.append(bytearray(32 * 1024 * 1024))
                emit("allocated", bytes=len(blocks) * 32 * 1024 * 1024)
                time.sleep(0.02)
        except MemoryError:
            emit("memory_limit_observed", bytes=len(blocks) * 32 * 1024 * 1024)
        worker()
    if mode == "cpu":
        emit("cpu_ready")
        value = 1
        while True:
            value = (value * 1664525 + 1013904223) & 0xFFFFFFFF
    if mode == "output":
        block = "OWNED-OUTPUT-" + "x" * 4096
        for _ in range(4096):
            print(block, flush=True)
        return 0
    raise ValueError("unsupported owned fixture mode: " + mode)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) == 2 else "io"))
