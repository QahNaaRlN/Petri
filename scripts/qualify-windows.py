#!/usr/bin/env python3
"""Opt-in, owned-data Windows native qualification. No external Python packages.

Run through tests/windows_native.rs to create the source with embedded libgit2.
The input toolchain manifest must be pinned independently, not inferred from a
test that just downloaded arbitrary tools. This harness retains all artifacts.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import threading
import time


PROTOCOL = "petri.control/v1"
DEFAULT_CASES = "io,nonzero,filesystem,network,tree,stop,root_exit,controller_crash,guardian_crash,checkpoint,output,processes,memory,cpu"


class Unverified(RuntimeError):
    """A missing prerequisite is never an isolation PASS."""


class WindowsObjects:
    """Trusted observer handles; never terminate a process selected by a PID file."""

    def __init__(self):
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        self.api.OpenProcess.restype = ctypes.c_void_p
        self.api.OpenJobObjectW.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
        self.api.OpenJobObjectW.restype = ctypes.c_void_p
        self.api.QueryInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
        self.api.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        self.api.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
        self.api.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.api.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.api.CloseHandle.argtypes = [ctypes.c_void_p]
        self.members = []

    def capture_tree(self, execution, workspace):
        class Accounting(ctypes.Structure):
            _fields_ = [(name, ctypes.c_int64) for name in ("user", "kernel", "period_user", "period_kernel")] + [(name, ctypes.c_uint32) for name in ("faults", "total", "active", "terminated")]

        job = self.api.OpenJobObjectW(0x0004, False, execution["binding"]["job_name"])
        if not job:
            raise Unverified("external observer cannot open the owned Job for membership verification")
        try:
            information = Accounting()
            require(self.api.QueryInformationJobObject(job, 1, ctypes.byref(information), ctypes.sizeof(information), None), "external Job accounting query failed")
            pids = {int(path.stem.removeprefix("heartbeat-")) for path in workspace.glob("heartbeat-*.txt")}
            require(len(pids) == 3 and information.active == 3, "crash fixture needs exactly three positively observed Job members")
            require(execution["binding"]["pid"] in pids, "bound root process is not a fixture member")
            for pid in sorted(pids):
                handle = self.api.OpenProcess(0x00100000 | 0x0400, False, pid)
                if not handle:
                    raise Unverified("cannot retain an owned fixture process observation handle")
                self.members.append((pid, handle))
                member = ctypes.c_int()
                require(self.api.IsProcessInJob(handle, job, ctypes.byref(member)) and member.value, "fixture PID did not belong to the recorded private Job")
            return {"active_job_members_before": information.active, "retained_member_pids": sorted(pids), "job_observer_closed_before_injection": True}
        finally:
            # Essential: a surviving observer Job handle would defeat the
            # guardian's KILL_ON_JOB_CLOSE crash behavior under test.
            require(self.api.CloseHandle(job), "observer Job handle did not close; crash injection refused")

    def owned_guardian(self, controller, executable):
        class ProcessEntry(ctypes.Structure):
            _fields_ = [("size", ctypes.c_uint32), ("usage", ctypes.c_uint32), ("pid", ctypes.c_uint32), ("heap", ctypes.c_size_t), ("module", ctypes.c_uint32), ("threads", ctypes.c_uint32), ("parent", ctypes.c_uint32), ("priority", ctypes.c_int32), ("flags", ctypes.c_uint32), ("exe", ctypes.c_wchar * 260)]

        require(controller.poll() is None, "owned controller exited before guardian selection")
        self.api.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        self.api.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        self.api.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ProcessEntry)]
        self.api.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ProcessEntry)]
        snapshot = self.api.CreateToolhelp32Snapshot(0x00000002, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise Unverified("cannot independently enumerate the owned controller child")
        candidates = []
        try:
            entry = ProcessEntry()
            entry.size = ctypes.sizeof(entry)
            exists = self.api.Process32FirstW(snapshot, ctypes.byref(entry))
            while exists:
                if entry.parent == controller.pid:
                    candidates.append(entry.pid)
                exists = self.api.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            self.api.CloseHandle(snapshot)
        require(len(candidates) == 1, "owned controller must have exactly one independently selected guardian child")
        handle = self.api.OpenProcess(0x00100000 | 0x1000 | 0x0001, False, candidates[0])
        if not handle:
            raise Unverified("cannot retain the owned guardian process handle")
        try:
            size = ctypes.c_uint32(32768)
            path = ctypes.create_unicode_buffer(size.value)
            require(self.api.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)), "guardian executable identity query failed")
            require(Path(path.value).resolve() == executable.resolve(), "guardian child executable differs from the owned Petri binary")
            require(controller.poll() is None, "controller ownership ended during guardian validation")
            return handle, candidates[0]
        except Exception:
            self.api.CloseHandle(handle)
            raise

    def wait_zero(self, seconds):
        deadline = time.monotonic() + seconds
        for _, handle in self.members:
            remaining = max(0, int((deadline - time.monotonic()) * 1000))
            require(self.api.WaitForSingleObject(handle, remaining) == 0, "a retained owned process remained alive after crash stop deadline")

    def close(self):
        for _, handle in self.members:
            self.api.CloseHandle(handle)
        self.members.clear()


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for data in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def windows_facts():
    if sys.platform != "win32":
        raise Unverified("native Windows qualification requires a real Windows host")
    import winreg

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    token = ctypes.c_void_p()
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    advapi.OpenProcessToken.restype = ctypes.c_int
    advapi.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    advapi.GetTokenInformation.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise Unverified("cannot independently inspect the qualification account token")
    try:
        values = {}
        for name, info_class in (("elevation_type", 18), ("elevated", 20)):
            value = ctypes.c_uint32()
            length = ctypes.c_uint32()
            if not advapi.GetTokenInformation(token, info_class, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(length)):
                raise Unverified("cannot read " + name + " from the host token")
            values[name] = value.value
    finally:
        kernel.CloseHandle(token)
    values["is_user_admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    if values["elevated"] or values["elevation_type"] != 1 or values["is_user_admin"]:
        raise Unverified("qualification requires a standard non-admin account, not an elevated or split admin token")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
        for name in ("ProductName", "DisplayVersion", "CurrentBuildNumber", "UBR"):
            values[name] = winreg.QueryValueEx(key, name)[0]
    values["machine"] = platform.machine()
    values["platform"] = platform.platform()
    if int(values["CurrentBuildNumber"]) != 26100 or values["DisplayVersion"] != "24H2":
        raise Unverified("first qualification profile is Windows 11 24H2 build 26100 with actual UBR recorded")
    if values["machine"].lower() not in ("amd64", "x86_64"):
        raise Unverified("first qualification profile requires x64")
    return values


class Endpoints:
    """Owned IPv4/IPv6 TCP/UDP listeners with independent positive controls."""

    def __init__(self):
        self.stop = threading.Event()
        self.sockets = []
        self.threads = []
        self.messages = []
        self.lock = threading.Lock()
        self.endpoints = []

    def __enter__(self):
        try:
            for name, family, host in (("ipv4", socket.AF_INET, "127.0.0.1"), ("ipv6", socket.AF_INET6, "::1")):
                endpoint = {"family": name, "host": host}
                for transport, kind in (("tcp", socket.SOCK_STREAM), ("udp", socket.SOCK_DGRAM)):
                    server = socket.socket(family, kind)
                    self.sockets.append(server)
                    server.bind((host, 0))
                    server.settimeout(0.1)
                    if kind == socket.SOCK_STREAM:
                        server.listen(8)
                    endpoint[transport + "_port"] = server.getsockname()[1]
                    thread = threading.Thread(target=self.listen, args=(server, name, transport), daemon=True)
                    thread.start()
                    self.threads.append(thread)
                self.endpoints.append(endpoint)
            self.control("before")
            return self
        except (OSError, AssertionError) as error:
            self.__exit__(None, None, None)
            raise Unverified("mandatory dual-stack positive control unavailable: " + str(error)) from error

    def listen(self, server, family, transport):
        while not self.stop.is_set():
            try:
                if transport == "tcp":
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(0.5)
                        data = connection.recv(1024)
                else:
                    data, _ = server.recvfrom(1024)
                with self.lock:
                    self.messages.append({"family": family, "transport": transport, "payload": data.decode("ascii", errors="replace")})
            except socket.timeout:
                continue
            except OSError:
                return

    def control(self, stage):
        expected = []
        for endpoint in self.endpoints:
            family = socket.AF_INET6 if endpoint["family"] == "ipv6" else socket.AF_INET
            for transport, kind in (("tcp", socket.SOCK_STREAM), ("udp", socket.SOCK_DGRAM)):
                message = "PETRI-POSITIVE-" + stage + "-" + endpoint["family"] + "-" + transport
                with socket.socket(family, kind) as client:
                    client.settimeout(1)
                    address = (endpoint["host"], endpoint[transport + "_port"])
                    if transport == "tcp":
                        client.connect(address)
                        client.sendall(message.encode("ascii"))
                    else:
                        client.sendto(message.encode("ascii"), address)
                expected.append(message)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with self.lock:
                received = {message["payload"] for message in self.messages}
            if all(message in received for message in expected):
                return
            time.sleep(0.01)
        raise Unverified("positive endpoint counters did not observe every mandatory " + stage + " control")

    def __exit__(self, *_):
        self.stop.set()
        for server in self.sockets:
            server.close()
        for thread in self.threads:
            thread.join(timeout=1)


class Qualification:
    def __init__(self, args):
        self.args = args
        self.output = args.output.resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        self.home = self.output / "state"
        self.sequence = 0
        self.sequence_lock = threading.Lock()
        self.report = {"schema": "petri.windows-qualification/v1", "assigned_suite": "UNVERIFIED", "full_specification": "UNVERIFIED", "native_execution_observed": False, "cases": [], "limitations": ["This suite is not full AC-WIN-N01/W01..W14 qualification.", "No GUI, ConPTY, live-provider, full hostile-alias, journal-fault or full crash-recovery qualification is claimed.", "Network case covers owned dual-stack loopback endpoints; LAN/external/DNS matrix remains UNVERIFIED."]}

    def invoke(self, *arguments, expected_codes=(0,), on_started=None, controller_crash=False):
        with self.sequence_lock:
            self.sequence += 1
            sequence = self.sequence
        stem = self.output / ("command-%03d" % sequence)
        command = [str(self.args.petri.resolve()), "--home", str(self.home), "windows", *map(str, arguments)]
        environment = dict(os.environ)
        environment["PETRI_OWNED_HOST_CANARY"] = "owned-test-value-must-not-be-inherited"
        started = time.monotonic()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        if on_started is not None:
            on_started(process)
        try:
            stdout, stderr = process.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            process.terminate()  # retained handle of this exact owned controller
            stdout, stderr = process.communicate(timeout=10)
            raise AssertionError("owned controller exceeded harness deadline; evidence retained, no automatic rerun")
        Path(str(stem) + ".stdout.json").write_bytes(stdout)
        Path(str(stem) + ".stderr.txt").write_bytes(stderr)
        write_json(Path(str(stem) + ".invocation.json"), {"argv": command, "exit_code": process.returncode, "elapsed_seconds": time.monotonic() - started})
        require(len(stdout) <= 4 * 1024 * 1024, "controller response exceeded harness bound")
        if controller_crash and process.returncode != 0 and not stdout:
            return {"owned_controller_terminated": True, "exit_code": process.returncode}
        try:
            envelope = json.loads(stdout)
        except (ValueError, UnicodeError) as error:
            raise AssertionError("controller stdout is not exactly one JSON envelope") from error
        require(envelope.get("protocol") == PROTOCOL, "wrong controller protocol")
        require(envelope.get("status") in ("ok", "error"), "missing closed response status")
        require(bool(envelope.get("request_id")) and bool(envelope.get("operation_id")), "response lacks operation/request identity")
        require(process.returncode in expected_codes, "unexpected CLI exit %d: %s" % (process.returncode, envelope))
        require(envelope["status"] == "ok", "controller refused operation: " + str(envelope.get("error")))
        return envelope["result"]

    def run(self):
        self.report["host"] = windows_facts()
        python = self.args.python_home.resolve() / "python.exe"
        if not python.is_file() or not self.args.toolchain_manifest.is_file():
            raise Unverified("prepared python.exe and independent toolchain manifest are required")
        version = subprocess.check_output([str(python), "-I", "-S", "-c", "import json,sys;print(json.dumps(list(sys.version_info[:3])))"], timeout=10)
        version = json.loads(version)
        if version[:2] != [3, 12]:
            raise Unverified("first native profile requires exact prepared CPython 3.12; observed " + str(version))
        self.report["inputs"] = {"python_version": version, "python_executable_sha256": sha256(python), "toolchain_manifest_sha256": sha256(self.args.toolchain_manifest), "petri_sha256": sha256(self.args.petri), "fixture_sha256": sha256(self.args.source / "native_fixture.py"), "harness_sha256": sha256(__file__)}
        source_before = sha256(self.args.source / "original.txt")
        doctor = self.invoke("doctor", expected_codes=(0, 3))
        self.report["probe"] = doctor
        if not doctor.get("supported", False):
            raise Unverified("native backend probe is unsupported: " + str(doctor))
        tool = self.invoke("tool", "import", self.args.python_home, "--manifest", self.args.toolchain_manifest)
        tool_id = tool.get("id") or tool.get("tool", {}).get("id")
        require(bool(tool_id), "tool import did not return a content identity")
        self.report["tool"] = tool
        for case in self.args.cases.split(","):
            self.run_case(case, tool_id)
        require(sha256(self.args.source / "original.txt") == source_before, "source original changed")
        require((self.args.source / "untracked.txt").read_bytes() == b"owned untracked canary", "source untracked changed")
        self.report["assigned_suite"] = "PASS"

    def run_case(self, case, tool_id):
        require(case in DEFAULT_CASES.split(","), "unknown qualification case")
        record = {"case": case, "status": "RUNNING"}
        self.report["cases"].append(record)
        lab = self.invoke("create", "--repo", self.args.source, "--tool", tool_id, "--task", "owned offline qualification " + case)
        lab_value = lab.get("lab", lab)
        lab_id = lab_value.get("lab_id") or lab_value.get("id")
        workspace_value = lab.get("workspace") or lab_value.get("workspace")
        require(bool(lab_id) and bool(workspace_value), "create must return lab identity and workspace path")
        workspace = Path(workspace_value)
        require(workspace.is_dir(), "created workspace is absent")
        require(not (workspace / "untracked.txt").exists(), "untracked source silently exported")
        record["lab_id"] = lab_id
        outside = self.output / ("outside-" + case + ".txt")
        controller = self.home / ("owned-controller-canary-" + case)
        controller.parent.mkdir(parents=True, exist_ok=True)
        outside.write_bytes(b"owned outside canary")
        controller.write_bytes(b"owned controller canary")
        canaries = {"outside": outside, "controller": controller, "source": self.args.source / "original.txt"}
        baseline = {name: sha256(path) for name, path in canaries.items()}
        cfg = {"outside_paths": {name: str(path.resolve()) for name, path in canaries.items()}}
        if case == "network":
            with Endpoints() as endpoints:
                cfg["endpoints"] = endpoints.endpoints
                write_json(workspace / "fixture-config.json", cfg)
                execution, terminal, native_report = self.execute(lab_id, case)
                endpoints.control("after")
                with endpoints.lock:
                    observations = list(endpoints.messages)
                record["endpoint_observations"] = observations
                require(not any(item["payload"] == "PETRI-OWNED-NEGATIVE" for item in observations), "sandbox traffic reached an owned endpoint")
        elif case in ("controller_crash", "guardian_crash"):
            write_json(workspace / "fixture-config.json", cfg)
            record.update(self.crash_case(lab_id, workspace, case))
            for name, path in canaries.items():
                require(sha256(path) == baseline[name], "crash case changed forbidden " + name)
            record["status"] = "PASS"
            write_json(self.output / "report.json", self.report)
            return
        elif case == "stop":
            write_json(workspace / "fixture-config.json", cfg)
            execution, terminal, native_report = self.stop_case(lab_id, workspace)
        else:
            write_json(workspace / "fixture-config.json", cfg)
            execution, terminal, native_report = self.execute(lab_id, "io" if case == "checkpoint" else case)
        record["execution"] = execution
        record["terminal"] = terminal
        record["native_report"] = native_report
        for name, path in canaries.items():
            require(sha256(path) == baseline[name], "forbidden write changed " + name)
        if case in ("io", "filesystem", "network", "checkpoint"):
            require(terminal["windows_exit_code"] == 0, "success fixture did not exit zero")
            observed = json.loads((workspace / "fixture-result.json").read_text(encoding="utf-8"))
            record["fixture_observation"] = observed
            if case == "io":
                require(observed["isolated"] == 1 and not observed["host_secret_inherited"], "Python mode/environment is not isolated")
                require((workspace / "changed.txt").read_bytes() == b"owned lab change\r\n" or (workspace / "changed.txt").read_bytes() == b"owned lab change\n", "allowed workspace write absent")
            if case == "filesystem":
                require(observed["workspace_write"], "positive writable-workspace control absent")
                require(len(observed["probes"]) == len(canaries), "outside-path probe coverage incomplete")
                require(all(not item["read_allowed"] and not item["write_allowed"] for item in observed["probes"]), "host/source/control read or write was allowed")
            if case == "checkpoint":
                value = self.invoke("result", lab_id, "--execution", execution["execution_id"])
                events = Path(value["artifacts"]["events"])
                audit = events.read_bytes()
                checkpoint = self.invoke("checkpoint", lab_id, "owned stopped checkpoint")
                original = (workspace / "changed.txt").read_bytes()
                (workspace / "changed.txt").write_bytes(b"owned post-checkpoint mutation")
                (workspace / "later.txt").write_bytes(b"must disappear on restore")
                self.invoke("restore", lab_id, checkpoint["checkpoint_id"])
                require((workspace / "changed.txt").read_bytes() == original and not (workspace / "later.txt").exists(), "stopped checkpoint did not restore the owned workspace")
                require(events.read_bytes() == audit, "restore rewound or replaced execution audit")
                record["checkpoint"] = checkpoint
                record["restored_diff"] = self.invoke("diff", lab_id)
        elif case == "nonzero":
            require(terminal["windows_exit_code"] == 7, "full fixture exit status was not preserved")
        elif case == "stop":
            require(terminal["outcome"] == "Cancelled", "explicit stop did not produce cancellation")
            require(native_report["stop_reason"] == "user_stop", "explicit stop was replaced by another termination reason")
        elif case in ("tree", "processes", "memory", "cpu", "output"):
            expected_reason = {"tree": "wall_time", "processes": "process_limit", "memory": "memory_limit", "cpu": "cpu_time", "output": "output_limit"}[case]
            require(native_report.get("stop_reason") == expected_reason, "wrong independent guardian stop reason for " + case)
            require(terminal["outcome"] == ("TimedOut" if case == "tree" else "BudgetExceeded"), "budget was replaced by an unrelated timeout/failure")
            if case == "cpu":
                require(terminal["user_cpu_100ns"] >= 10_000 * 10_000, "CPU-time threshold was not observed")
        if case in ("tree", "stop", "root_exit"):
            heartbeats = list(workspace.glob("heartbeat-*.txt"))
            require(len(heartbeats) >= (3 if case in ("tree", "stop") else 1), "child/grandchild readiness positive control absent")
            before = {str(path): sha256(path) for path in heartbeats}
            time.sleep(0.25)
            require(before == {str(path): sha256(path) for path in heartbeats}, "descendant still produced effects after confirmed stop")
        record["status"] = "PASS"
        write_json(self.output / "report.json", self.report)

    def crash_case(self, lab_id, workspace, case):
        controller = []
        completed = []
        errors = []
        started = threading.Event()

        def on_started(process):
            controller.append(process)
            started.set()

        def launch():
            try:
                completed.append(self.invoke("run", lab_id, "--script", "native_fixture.py", "--wallclock-ms", "20000", "--", "tree", expected_codes=(0, 9), on_started=on_started, controller_crash=case == "controller_crash"))
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=launch, daemon=True)
        thread.start()
        require(started.wait(timeout=5), "owned run controller did not start")
        execution = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if errors:
                raise errors[0]
            value = self.invoke("status", lab_id)
            current = value.get("execution")
            if current and current.get("phase") == "Running" and len(list(workspace.glob("heartbeat-*.txt"))) == 3:
                execution = current
                break
            if completed:
                raise AssertionError("owned crash fixture exited before positive readiness")
            time.sleep(0.05)
        require(execution is not None, "owned crash fixture lacks Running and three-member readiness")
        self.report["native_execution_observed"] = True
        observer = WindowsObjects()
        guardian = None
        try:
            proof = observer.capture_tree(execution, workspace)
            if case == "controller_crash":
                require(controller[0].poll() is None, "owned controller already exited")
                controller[0].terminate()  # Popen retains this exact process handle
                proof["injection"] = "terminate_owned_controller_handle"
            else:
                guardian, guardian_pid = observer.owned_guardian(controller[0], self.args.petri)
                require(observer.api.TerminateProcess(guardian, 0xE0000001), "owned guardian termination failed")
                proof["injection"] = "terminate_verified_owned_guardian_handle"
                proof["guardian_pid"] = guardian_pid
            observer.wait_zero(3)
            proof["all_retained_job_member_handles_signalled"] = True
            before = {str(path): sha256(path) for path in workspace.glob("heartbeat-*.txt")}
            time.sleep(0.25)
            require(before == {str(path): sha256(path) for path in workspace.glob("heartbeat-*.txt")}, "crashed execution still produces heartbeat effects")
            thread.join(timeout=10)
            require(not thread.is_alive(), "owned controller did not finish after crash injection")
            if errors:
                raise errors[0]
            require(len(completed) == 1, "crash must produce exactly one controller observation")
            if case == "controller_crash":
                require(completed[0].get("owned_controller_terminated") is True, "controller crash lacks the expected lost-response observation")
            deadline = time.monotonic() + 10
            while True:
                status = self.invoke("status", lab_id, "--execution", execution["execution_id"])
                durable = status["execution"]
                if durable["phase"] == "Terminal" or time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
            require(durable["execution_id"] == execution["execution_id"], "crash recovery silently substituted execution identity")
            require(durable["phase"] == "Terminal", "crash did not settle to an inspectable terminal/unknown outcome")
            if case == "controller_crash":
                require((durable.get("result") or {}).get("stop", {}).get("confirmed") is True, "live guardian failed to persist the observed stop after controller loss")
                require(durable["result"]["stop"]["active_processes"] == 0, "live guardian did not observe zero")
            else:
                require(durable.get("outcome") == "Unknown", "guardian loss without terminal receipt must remain Unknown")
                require((durable.get("result") or {}).get("stop", {}).get("confirmed") is not True and durable.get("stop_state") == "Unconfirmed", "missing guardian receipt fabricated a durable zero")
            return {"execution": durable, "external_crash_stop_proof": proof, "controller_observation": completed[0], "durable_and_external_proofs_are_separate": True}
        finally:
            if guardian:
                observer.api.CloseHandle(guardian)
            observer.close()

    def stop_case(self, lab_id, workspace):
        completed = []
        errors = []

        def execute():
            try:
                completed.append(self.execute(lab_id, "tree", wallclock_ms=20_000))
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=execute, daemon=True)
        thread.start()
        deadline = time.monotonic() + 15
        execution_id = None
        while time.monotonic() < deadline:
            if errors:
                raise errors[0]
            status = self.invoke("status", lab_id)
            execution = status.get("execution")
            if execution and execution.get("phase") == "Running" and len(list(workspace.glob("heartbeat-*.txt"))) >= 3:
                execution_id = execution["execution_id"]
                break
            if completed:
                raise AssertionError("tree exited before explicit stop readiness")
            time.sleep(0.05)
        require(execution_id is not None, "explicit stop lacks a Running child/grandchild positive control")
        self.invoke("stop", lab_id, "--execution", execution_id, expected_codes=(0, 9))
        thread.join(timeout=10)
        require(not thread.is_alive(), "explicit stop did not finish the original run controller")
        if errors:
            raise errors[0]
        require(len(completed) == 1, "stop did not produce exactly one execution result")
        return completed[0]

    def execute(self, lab_id, case, wallclock_ms=None):
        arguments = ["run", lab_id, "--script", "native_fixture.py"]
        if wallclock_ms is not None:
            arguments.extend(["--wallclock-ms", str(wallclock_ms)])
        elif case in ("tree", "processes", "memory"):
            arguments.extend(["--wallclock-ms", "5000"])
        arguments.extend(["--", case])
        value = self.invoke(*arguments, expected_codes=(0, 7, 8, 9))
        execution = value.get("execution", value)
        require(execution.get("phase") == "Terminal", "execution did not reach a terminal recorded phase")
        require(bool(execution.get("execution_id")), "execution identity missing")
        terminal = execution.get("result")
        require(isinstance(terminal, dict), "terminal result missing")
        require(terminal.get("stop", {}).get("confirmed") is True, "process tree stop was not confirmed")
        require(terminal["stop"].get("active_processes") == 0, "confirmed stop lacks observed zero active processes")
        require(execution.get("binding", {}).get("lpac") is True, "actual LPAC binding was not observed")
        self.report["native_execution_observed"] = True
        native_report = value.get("report")
        require(isinstance(native_report, dict), "independent native guardian report missing")
        require(native_report.get("tree_stopped") is True, "guardian did not confirm tree stop")
        return execution, terminal, native_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--petri", required=True, type=Path)
    parser.add_argument("--python-home", required=True, type=Path)
    parser.add_argument("--toolchain-manifest", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory; retained on PASS/FAIL/UNVERIFIED")
    parser.add_argument("--cases", default=DEFAULT_CASES)
    args = parser.parse_args()
    qualification = Qualification(args)
    code = 0
    try:
        qualification.run()
    except Unverified as error:
        qualification.report["assigned_suite"] = "UNVERIFIED"
        qualification.report["error"] = str(error)
        code = 2
    except Exception as error:
        qualification.report["assigned_suite"] = "FAIL"
        qualification.report["error"] = type(error).__name__ + ": " + str(error)
        code = 1
    write_json(qualification.output / "report.json", qualification.report)
    print(json.dumps({"assigned_suite": qualification.report["assigned_suite"], "full_specification": "UNVERIFIED", "report": str(qualification.output / "report.json")}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
