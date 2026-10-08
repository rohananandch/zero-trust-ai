"""
Zero Trust AI System Orchestrator
Launches all microservices and the Streamlit dashboard in synchronized subprocesses:
1. Port 8000: Policy Engine & Administrator (Control Plane)
2. Port 8001: Policy Enforcement Point Gateway (Data Plane)
3. Port 8002: Protected Enterprise Database Resource
4. Port 8501: Interactive Streamlit SOC Dashboard
"""

import subprocess
import sys
import os
import time
import requests
import signal

PYTHON_EXE = os.path.join(os.path.dirname(__file__), ".venv", "Scripts", "python.exe")
if not os.path.exists(PYTHON_EXE):
    PYTHON_EXE = sys.executable

PROCESSES = []

def start_service(name: str, cmd: list, cwd: str):
    print(f"[+] Launching {name}...")
    p = subprocess.Popen(cmd, cwd=cwd)
    PROCESSES.append((name, p))
    return p

def wait_for_health(url: str, timeout: int = 15):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=1)
            if r.status_code == 200:
                return True
        except:
            time.sleep(0.5)
    return False

def shutdown_all(sig=None, frame=None):
    print("\n[!] Shutting down all Zero Trust microservices...")
    for name, p in PROCESSES:
        try:
            print(f"    Stopping {name} (PID: {p.pid})...")
            p.terminate()
            p.wait(timeout=2)
        except Exception:
            p.kill()
    print("[*] All services stopped cleanly.")
    sys.exit(0)

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    signal.signal(signal.SIGINT, shutdown_all)

    print("=" * 70)
    print("      LAUNCHING ZERO TRUST ARCHITECTURE (NIST SP 800-207)      ")
    print("=" * 70)

    # 1. Start Control Plane (Policy Engine) on Port 8000
    start_service(
        "Control Plane (Policy Engine : 8000)",
        [PYTHON_EXE, "-m", "uvicorn", "control_plane.policy_engine:app", "--host", "127.0.0.1", "--port", "8000"],
        root_dir
    )

    # 2. Start Protected Resource (Secure Vault) on Port 8002
    start_service(
        "Protected Resource (: 8002)",
        [PYTHON_EXE, "-m", "uvicorn", "protected_service.secure_api:app", "--host", "127.0.0.1", "--port", "8002"],
        root_dir
    )

    # 3. Start Data Plane (PEP Gateway) on Port 8001
    start_service(
        "Data Plane (PEP Gateway : 8001)",
        [PYTHON_EXE, "-m", "uvicorn", "data_plane.gateway_pep:app", "--host", "127.0.0.1", "--port", "8001"],
        root_dir
    )

    # Health Checks
    print("\n[*] Waiting for microservices to initialize...")
    pe_ok = wait_for_health("http://127.0.0.1:8000")
    vault_ok = wait_for_health("http://127.0.0.1:8002")
    pep_ok = wait_for_health("http://127.0.0.1:8001")

    if pe_ok and vault_ok and pep_ok:
        print("[OK] All backend microservices are healthy and communicating!")
    else:
        print("[!] Warning: Some services took longer than expected to report health.")

    # 4. Start Streamlit Visual SOC Dashboard on Port 8501
    start_service(
        "Visual SOC Dashboard (: 8501)",
        [PYTHON_EXE, "-m", "streamlit", "run", "dashboard/app.py", "--server.port", "8501", "--server.headless", "true"],
        root_dir
    )

    print("\n" + "=" * 70)
    print("                  ZERO TRUST ENVIRONMENT IS LIVE!                  ")
    print("=" * 70)
    print("Control Plane (Policy Engine) : http://127.0.0.1:8000/docs")
    print("Data Plane (PEP Gateway)       : http://127.0.0.1:8001/docs")
    print("Protected Backend Vault        : http://127.0.0.1:8002/docs")
    print("Visual Security Dashboard      : http://127.0.0.1:8501")
    print("=" * 70)
    print("Press Ctrl+C at any time in this terminal to stop all services.")
    print("=" * 70 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown_all()

if __name__ == "__main__":
    main()
