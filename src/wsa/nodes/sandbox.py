from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from wsa.state import ScanState

logger = logging.getLogger(__name__)

DOCKER_IMAGES = {
    "jsp": "tomcat:10-jdk17",
    "php": "php:8.3-cli",
}

STRACE_SYSCALLS = {"execve", "connect", "open", "openat", "write", "clone", "socket"}


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _run_in_container(file_path: str, tech_stack: str, timeout: int = 10) -> dict:
    image = DOCKER_IMAGES.get(tech_stack)
    if not image:
        return {"skipped": True, "reason": f"unsupported stack: {tech_stack}"}

    report: dict = {
        "executed": False,
        "process_creation": False,
        "command_execution": False,
        "file_write": False,
        "network_access": False,
        "suspicious_syscalls": [],
        "exit_code": None,
        "stderr": "",
    }

    src = Path(file_path)
    if not src.exists():
        return {"skipped": True, "reason": "file not found"}

    with tempfile.TemporaryDirectory(prefix="wsa_sandbox_") as tmpdir:
        dest = Path(tmpdir) / src.name
        dest.write_bytes(src.read_bytes())

        if tech_stack == "php":
            cmd = [
                "docker", "run", "--rm",
                "--network=none",
                "--memory=128m", "--cpus=0.5",
                "--read-only",
                "-v", f"{tmpdir}:/app:ro",
                image, "php", "-r",
                f"error_reporting(0); include '/app/{src.name}';",
            ]
        elif tech_stack == "jsp":
            cmd = [
                "docker", "run", "--rm",
                "--network=none",
                "--memory=256m", "--cpus=0.5",
                "-v", f"{tmpdir}:/usr/local/tomcat/webapps/ROOT:ro",
                image, "bash", "-c",
                f"timeout {timeout} catalina.sh run 2>&1 | head -50",
            ]
        else:
            return {"skipped": True, "reason": f"no sandbox config for {tech_stack}"}

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 5,
            )
            report["executed"] = True
            report["exit_code"] = proc.returncode
            report["stderr"] = proc.stderr[:2000]

            output = proc.stdout + proc.stderr
            if any(kw in output.lower() for kw in ("exec(", "system(", "runtime.exec", "processbuilder")):
                report["command_execution"] = True
                report["suspicious_syscalls"].append("command_execution_detected")
            if any(kw in output.lower() for kw in ("fwrite", "file_put_contents", "fileoutputstream")):
                report["file_write"] = True
                report["suspicious_syscalls"].append("file_write_detected")
            if any(kw in output.lower() for kw in ("socket", "curl", "urlconnection", "fsockopen")):
                report["network_access"] = True
                report["suspicious_syscalls"].append("network_access_detected")
            if proc.returncode != 0 and "fatal" in output.lower():
                report["process_creation"] = True

        except subprocess.TimeoutExpired:
            report["executed"] = True
            report["suspicious_syscalls"].append("execution_timeout")
        except Exception as e:
            logger.warning("Sandbox execution failed: %s", e)
            report["stderr"] = str(e)

    return report


def sandbox_node(state: ScanState) -> dict:
    tech_stack = state.get("tech_stack", "unknown")

    if tech_stack not in DOCKER_IMAGES:
        logger.info("Sandbox skipped: unsupported tech_stack=%s", tech_stack)
        return {"sandbox_report": {"skipped": True, "reason": f"unsupported: {tech_stack}"}}

    if not _docker_available():
        logger.warning("Docker not available, sandbox degraded")
        return {"sandbox_report": {"skipped": True, "reason": "docker not available"}}

    file_path = state.get("file_path", "")
    report = _run_in_container(file_path, tech_stack)
    return {"sandbox_report": report}
