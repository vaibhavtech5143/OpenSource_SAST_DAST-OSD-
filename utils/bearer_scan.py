#!/usr/bin/env python3
"""
Bearer-based SAST Scanner using Docker

Runs Bearer CLI via container, exports results to output dir, and removes the
container after completion. Supports JSON and SARIF outputs.
"""
import os
import sys
import json
import csv
import tempfile
import subprocess
import time
import signal
import platform
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any


def run_command(cmd: List[str]) -> Tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=True,
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        # Ensure proper decoding on Windows
        stderr = e.stderr if isinstance(e.stderr, str) else ""
        stdout = e.stdout if isinstance(e.stdout, str) else ""
        return False, f"Command failed with code {e.returncode}: {stderr or stdout}"


def ensure_output_dir(output_dir: str) -> None:
    try:
        os.makedirs(output_dir, exist_ok=True)
        test_file = os.path.join(output_dir, ".permission_test")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(test_file)
    except Exception as e:
        print(f"[!] Error accessing output directory {output_dir}: {e}")
        sys.exit(1)


def run_bearer_scan(repo_path: str, output_dir: str, extra_args: Optional[List[str]] = None, timeout: int = 1800) -> bool:
    # Global flag to track if we're shutting down
    global _shutdown_flag
    _shutdown_flag = False
    
    # Signal handler for graceful shutdown
    def signal_handler(signum, frame):
        global _shutdown_flag
        print("\n[!] Received termination signal. Cleaning up...")
        _shutdown_flag = True
    
    # Set up signal handlers
    if platform.system() == 'Windows':
        signal.signal(signal.SIGBREAK, signal_handler)  # For Windows
    signal.signal(signal.SIGINT, signal_handler)  # For Ctrl+C
    """Run Bearer CLI scan via Docker with enhanced configuration and timeouts.
    
    Args:
        repo_path: Path to the repository to scan
        output_dir: Directory to save scan results
        extra_args: Additional arguments to pass to Bearer
        timeout: Maximum time in seconds to allow the scan to run (default: 1800s/30min)
        
    Returns:
        bool: True if scan completed successfully, False otherwise
    """
    print(f"\n[i] Starting Bearer SAST scan with {timeout}s timeout...")
    start_time = time.time()

    # Convert paths to absolute and ensure they use forward slashes for Docker
    repo_abs = Path(repo_path).absolute()
    out_abs = Path(output_dir).absolute()
    ensure_output_dir(str(out_abs))
    
    # Use the .bearer.yml from the project root if it exists
    project_bearer_yml = Path(__file__).parent.parent / ".bearer.yml"
    
    # Create a temporary directory for scan artifacts
    with tempfile.TemporaryDirectory() as temp_dir:
        # Use project's .bearer.yml if it exists, otherwise create a default one
        if project_bearer_yml.exists():
            config_path = project_bearer_yml
            print(f"[i] Using project's .bearer.yml from {config_path}")
        else:
            # Create a minimal .bearer.yml in temp dir
            config_path = Path(temp_dir) / ".bearer.yml"
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write("""
                version: v1
                rules:
                  all: true
                scan:
                  languages:
                    - javascript
                    - typescript
                    - python
                    - go
                    - java
                    - c
                    - c++
                    - c#
                    - ruby
                    - php
                    - swift
                    - rust
                    
                exclude_paths:
                  - '**/node_modules/**'
                  - '**/test/**'
                  - '**/dist/**'
                  - '**/build/**'
                  - '**/*.min.js'
                  - '**/assets/private/three.js'
                """)

        # Output file paths
        json_out = out_abs / "bearer_findings.json"
        
        # Ensure output directory has proper permissions
        os.chmod(str(out_abs), 0o777)
        
        # Build the Docker command with resource limits and user permissions
        cmd = [
            "docker", "run", "--rm",
            "--memory", "4g",  # Limit memory usage
            "--cpus", "2",     # Limit CPU usage
            "--user", "0:0",   # Run as root to avoid permission issues
            "-v", f"{repo_abs}:/scan:ro",
            "-v", f"{out_abs}:/output",
            "-v", f"{config_path}:/.bearer.yml:ro",
            "bearer/bearer:latest-amd64",
            "scan", "/scan",
            "--format", "json",
            "--output", f"/output/{json_out.name}",
            "--debug"
        ]
        
        if extra_args:
            cmd.extend(extra_args)
        
        print(f"[i] Running command: {' '.join(cmd)}")
        
        try:
            # Start the process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Function to read output in a non-blocking way
            def read_output(stream, prefix='', stop_event=None):
                while not (_shutdown_flag or (stop_event and stop_event.is_set())):
                    try:
                        line = stream.readline()
                        if not line:
                            break
                        print(f"{prefix}{line}", end='', flush=True)
                    except (UnicodeDecodeError, ValueError):
                        # Skip binary files or encoding issues
                        continue
                    except Exception as e:
                        print(f"\n[!] Error reading output: {e}")
                        break
            
            # Create an event to signal threads to stop
            import threading
            stop_event = threading.Event()
            
            # Start output reader threads as daemon threads
            stdout_thread = threading.Thread(
                target=read_output, 
                args=(process.stdout, '', stop_event),
                daemon=True
            )
            stderr_thread = threading.Thread(
                target=read_output, 
                args=(process.stderr, '[stderr] ', stop_event),
                daemon=True
            )
            
            stdout_thread.start()
            stderr_thread.start()
            
            # Wait for process to complete with timeout
            try:
                start_time = time.time()
                while True:
                    if _shutdown_flag:
                        print("\n[!] Shutting down due to user interrupt...")
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                        stop_event.set()
                        return False
                        
                    remaining = timeout - (time.time() - start_time)
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(cmd, timeout)
                        
                    try:
                        if process.poll() is not None:  # Process has finished
                            break
                        time.sleep(0.1)  # Small sleep to prevent busy waiting
                    except Exception as e:
                        print(f"\n[!] Error checking process status: {e}")
                        break
                        
            except subprocess.TimeoutExpired:
                print(f"\n[!] Scan timed out after {timeout} seconds")
                process.kill()
                stop_event.set()
                return False
                
            # Wait for output threads to finish with a timeout
            stop_event.set()  # Signal threads to stop
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            
            # Force cleanup if threads are still alive
            if stdout_thread.is_alive() or stderr_thread.is_alive():
                print("\n[!] Warning: Some output threads did not terminate cleanly")
            
            # Check for errors
            if process.returncode not in (0, 1):  # 0 = success, 1 = findings found
                error = process.stderr.read()
                print(f"[!] Bearer scan failed with error: {error}")
                return False
                
            # Convert JSON to CSV if scan completed successfully
            if json_out.exists() and json_out.stat().st_size > 0:
                csv_path = out_abs / "bearer_findings.csv"
                bearer_json_to_csv(str(json_out), str(csv_path))
            
            elapsed = time.time() - start_time
            print(f"\n[i] Bearer scan completed in {elapsed:.1f} seconds")
            print(f"[i] Results saved to: {json_out}")
            
            return True
            
        except Exception as e:
            print(f"\n[!] Error running Bearer scan: {e}")
            import traceback
            traceback.print_exc()
            return False

    # Brief finding count if possible (jsonv2 or json formats vary; try best-effort)
    try:
        with open(json_out, "r", encoding="utf-8") as f:
            data = json.load(f)
        findings_count = 0
        if isinstance(data, dict):
            if "findings" in data and isinstance(data["findings"], list):
                findings_count = len(data["findings"])
            elif "results" in data and isinstance(data["results"], list):
                findings_count = len(data["results"])
        print(f"[i] Bearer reported {findings_count} findings")
    except Exception:
        pass

    return True


def bearer_json_to_csv(json_path: str, csv_path: str) -> bool:
    """Convert Bearer JSON results to a comprehensive CSV summary.
    
    Args:
        json_path: Path to the Bearer JSON results file
        csv_path: Path to save the CSV output
        
    Returns:
        bool: True if conversion was successful, False otherwise
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Initialize CSV rows list
        rows = []
        
        # Function to clean text for CSV
        def clean_text(text):
            if not isinstance(text, str):
                return str(text)
            # Remove newlines and extra spaces
            return ' '.join(str(text).replace('\n', ' ').split())
        
        # Process findings by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in data and isinstance(data[severity], list):
                for finding in data[severity]:
                    if not isinstance(finding, dict):
                        continue
                        
                    # Extract file path correctly
                    file_path = finding.get('filename') or finding.get('full_filename', '')
                    if file_path.startswith('/scan/'):
                        file_path = file_path[6:]  # Remove /scan/ prefix
                    
                    # Safely extract line number
                    line_number = ''
                    if 'line_number' in finding:
                        line_number = finding['line_number']
                    elif 'source' in finding:
                        source = finding['source']
                        if isinstance(source, dict):
                            start = source.get('start', {})
                            if isinstance(start, dict):
                                line_number = start.get('line', '')
                            else:
                                line_number = str(start)
                        else:
                            line_number = str(source)
                    
                    row = {
                        'Severity': severity.upper(),
                        'Rule ID': clean_text(finding.get('id', '')),
                        'Title': clean_text(finding.get('title', '')),
                        'File': file_path.replace('\\', '/'),
                        'Line': line_number,
                        'CWE IDs': ', '.join(str(cwe) for cwe in finding.get('cwe_ids', []) if cwe),
                        'Category': ', '.join(str(cat) for cat in finding.get('category_groups', []) if cat),
                        'Description': clean_text(finding.get('description', ''))[:1000],
                        'Remediation': clean_text(finding.get('remediation', finding.get('remediations', '')))[:1000],
                        'Documentation': finding.get('documentation_url', '')
                    }
                    rows.append(row)

        if not rows:
            print(f"[i] No security findings in {json_path}")
            return True

        # Define field order for CSV
        fieldnames = [
            'Severity', 'Rule ID', 'Title', 'File', 'Line', 
            'CWE IDs', 'Category', 'Description', 'Remediation', 'Documentation'
        ]
        
        # Write to CSV with proper encoding and error handling
        try:
            with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:  # utf-8-sig for Excel compatibility
                writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
                writer.writeheader()
                for row in rows:
                    try:
                        writer.writerow(row)
                    except Exception as e:
                        print(f"[!] Error writing row to CSV: {e}")
                        continue
        except Exception as e:
            print(f"[!] Error writing to CSV file {csv_path}: {e}")
            return False

        print(f"[i] Exported {len(rows)} security findings to {csv_path}")
        return True
        
    except Exception as e:
        print(f"[!] Error converting Bearer JSON to CSV: {e}")
        import traceback
        traceback.print_exc()
        return False


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run SAST scan using Bearer (Docker)")
    parser.add_argument("repository_path", help="Path to the repository to scan")
    parser.add_argument("output_directory", help="Directory to save scan results")
    parser.add_argument(
        "--bearer-arg",
        dest="bearer_args",
        nargs="*",
        default=[],
        help="Additional args passed to Bearer CLI (e.g., --skip-rule=RULE_ID)",
    )

    args = parser.parse_args()

    # Check Docker
    ok, msg = run_command(["docker", "--version"])
    if not ok:
        print("[!] Docker is not installed or not running. Please start Docker and try again.")
        sys.exit(1)

    ensure_output_dir(args.output_directory)

    if not run_bearer_scan(args.repository_path, args.output_directory, args.bearer_args):
        print("[!] Bearer scan failed")
        sys.exit(1)

    print("\n" + "=" * 50)
    print(f"{'BEARER SCAN COMPLETED':^50}")
    print("=" * 50)
    print(f"\n[✔] Results saved to: {os.path.abspath(args.output_directory)}")


if __name__ == "__main__":
    main()


