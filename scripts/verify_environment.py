#!/usr/bin/env python3
"""Environment and dependency verification diagnostic script for BHARYDANGEROUS-Investigator."""
import sys

def main():
    print("=" * 70)
    print("BHARYDANGEROUS-Investigator - Environment Diagnostics")
    print("=" * 70)

    # 1. Python version
    major, minor = sys.version_info.major, sys.version_info.minor
    print(f"Python Version: {major}.{minor}.{sys.version_info.micro}")
    if (major, minor) < (3, 11):
        print("[-] ERROR: Python 3.11+ is required.")
        sys.exit(1)
    else:
        print("[+] Python 3.11+ requirement satisfied.")

    # 2. Package import checks
    modules = [
        ("typer", "CLI Framework"),
        ("rich", "Terminal Interface"),
        ("pydantic", "Schema Validation"),
        ("jinja2", "Report Generation"),
        ("defusedxml", "Secure XML Parsing"),
        ("sqlite3", "Relational Evidence DB"),
    ]

    missing = []
    for mod_name, desc in modules:
        try:
            __import__(mod_name)
            print(f"[+] Module '{mod_name}' ({desc}): Available")
        except ImportError:
            print(f"[-] Module '{mod_name}' ({desc}): MISSING")
            missing.append(mod_name)

    # Optional AI SDK
    try:
        __import__("google.genai")
        print("[+] Module 'google-genai' (Gemini AI SDK): Available")
    except ImportError:
        print("[*] Module 'google-genai' (Gemini AI SDK): Optional (Not Installed)")

    # 3. Check CLI application entry point
    try:
        from bharydangerous.cli.app import app
        print("[+] BHARYDANGEROUS-Investigator CLI package is successfully importable.")
    except Exception as exc:
        print(f"[-] Package import error: {exc}")
        sys.exit(1)

    print("=" * 70)
    if missing:
        print(f"FAILED: Missing core dependencies: {', '.join(missing)}")
        print("Run: pip install -e .")
        sys.exit(1)
    else:
        print("SUCCESS: Environment is fully verified and ready for forensic operations.")
        print("Run 'bdinvestigator --help' or 'bdinvestigator doctor' to start.")
        sys.exit(0)

if __name__ == "__main__":
    main()
