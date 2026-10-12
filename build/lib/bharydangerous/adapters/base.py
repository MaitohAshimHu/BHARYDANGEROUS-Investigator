"""Secure subprocess adapter base for external forensic utilities."""
import os
import shutil
import subprocess
from typing import List, Optional, Tuple
from bharydangerous.core.constants import SUBPROCESS_TIMEOUT_SECONDS

class SubprocessResult:
    def __init__(self, exit_code: int, stdout: str, stderr: str, timed_out: bool = False):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

def is_tool_available(tool_name: str) -> bool:
    """Check if binary exists in PATH."""
    return shutil.which(tool_name) is not None

def run_command_safely(
    cmd: List[str],
    cwd: Optional[str] = None,
    timeout_seconds: int = SUBPROCESS_TIMEOUT_SECONDS,
    max_output_bytes: int = 10 * 1024 * 1024,  # 10 MB limit
) -> SubprocessResult:
    """
    Execute external command safely.
    Strictly forbids shell=True.
    Enforces timeout and limits memory consumed by stdout/stderr.
    """
    if not cmd or not isinstance(cmd, list):
        raise ValueError("Command must be a non-empty list of arguments.")

    # Validate that executable exists
    binary = shutil.which(cmd[0])
    if not binary:
        return SubprocessResult(
            exit_code=127,
            stdout="",
            stderr=f"Executable '{cmd[0]}' not found in PATH.",
        )

    # Use resolved executable path
    safe_cmd = [binary] + cmd[1:]

    try:
        proc = subprocess.Popen(
            safe_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            shell=False,
            env=os.environ.copy(),
        )
        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout_seconds)
            # Bound output size
            if len(stdout_bytes) > max_output_bytes:
                stdout_bytes = stdout_bytes[:max_output_bytes] + b"\n...[TRUNCATED: Output exceeded size limit]..."
            if len(stderr_bytes) > max_output_bytes:
                stderr_bytes = stderr_bytes[:max_output_bytes] + b"\n...[TRUNCATED: Stderr exceeded size limit]..."

            return SubprocessResult(
                exit_code=proc.returncode,
                stdout=stdout_bytes.decode("utf-8", errors="replace"),
                stderr=stderr_bytes.decode("utf-8", errors="replace"),
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_bytes, stderr_bytes = proc.communicate()
            return SubprocessResult(
                exit_code=-1,
                stdout=stdout_bytes.decode("utf-8", errors="replace"),
                stderr=f"Command timed out after {timeout_seconds}s.",
                timed_out=True,
            )
    except Exception as exc:
        return SubprocessResult(
            exit_code=1,
            stdout="",
            stderr=f"Subprocess execution error: {exc}",
        )
