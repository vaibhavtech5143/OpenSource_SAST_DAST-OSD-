import os
import json
import csv
import subprocess
from typing import Tuple, List, Dict, Any


def convert_windows_path_for_docker(path: str) -> str:
    """Convert Windows paths to Docker-compatible format."""
    if os.name == 'nt':
        # Convert backslashes to forward slashes
        path = path.replace('\\', '/')
        # Convert drive letters to Docker format
        for drive in ['A:', 'B:', 'C:', 'D:', 'E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:', 'L:', 'M:', 'N:', 'O:', 'P:', 'Q:', 'R:', 'S:', 'T:', 'U:', 'V:', 'W:', 'X:', 'Y:', 'Z:']:
            if path.startswith(drive):
                path = path.replace(drive, f'/{drive[0].lower()}')
                break
        return path
    return path


def check_trivy_version() -> str:
    """Check the Trivy version in the Docker image."""
    try:
        cmd = ['docker', 'run', '--rm', 'aquasec/trivy:latest', '--version']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            version_line = result.stdout.strip().split('\n')[0]
            return version_line  # e.g., "Version: 0.55.0"
        return "Unknown"
    except Exception as e:
        print(f"[!] Failed to check Trivy version: {e}")
        return "Unknown"


def run_trivy_config_in_docker(repo_path: str, output_dir: str, timeout_seconds: int = 600) -> Tuple[bool, List[Dict[str, Any]]]:
    """Run Trivy config (IaC/CI-CD) scan using Docker against a filesystem path.

    Saves JSON results to output_dir and returns (success, findings_list).
    success is True when exit code is 0 or 1 (1 means issues found).
    """
    # Check Trivy version for debugging
    print(f"[i] Trivy version: {check_trivy_version()}")

    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, 'trivy_config_results.json')

    # Convert paths for Docker on Windows
    docker_repo_path = convert_windows_path_for_docker(os.path.abspath(repo_path))
    docker_output_dir = convert_windows_path_for_docker(os.path.abspath(output_dir))

    # Ensure output directory has proper permissions
    try:
        os.chmod(output_dir, 0o777)
    except:
        pass  # Ignore permission errors on some systems

    cmd = [
        'docker', 'run', '--rm',
        '--user', '0:0',  # Run as root to avoid permission issues
        '-v', f'{docker_repo_path}:/workspace',
        '-v', f'{docker_output_dir}:/output',
        'aquasec/trivy:latest',
        '--quiet',
        'config', '/workspace',
        '--format', 'json',
        '--output', '/output/trivy_config_results.json',
        '--timeout', f'{timeout_seconds}s',
    ]

    print(f"[i] Running command: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    # Debug: Always print output for troubleshooting
    if result.stdout.strip():
        print(f"[i] Trivy stdout: {result.stdout.strip()}")
    if result.stderr.strip():
        print(f"[i] Trivy stderr: {result.stderr.strip()}")

    if result.returncode not in (0, 1):
        # 0/1 are normal; others are failures
        err = result.stderr.strip() or result.stdout.strip()
        if "unknown flag" in err.lower():
            print(f"[!] Trivy config scan failed: Invalid flag detected. Ensure Trivy version supports the command.")
        else:
            print(f"[!] Trivy config scan failed: {err}")
        return False, []

    # Check if output file exists
    if not os.path.exists(output_file):
        print(f"[!] Trivy output file not created: {output_file} (scan may have found no targets)")
        # Trivy may not write file if no IaC/config files detected; treat as success with no findings
        return True, []

    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to parse Trivy config results: {e}")
        return False, []

    # Flatten findings
    findings: List[Dict[str, Any]] = []
    results_list = data if isinstance(data, list) else data.get('Results', []) if isinstance(data, dict) else []
    for result_obj in results_list:
        target = result_obj.get('Target', '')
        for mis in result_obj.get('Misconfigurations', []) or []:
            findings.append({
                'type': 'misconfiguration',
                'target': target,
                'id': mis.get('ID', ''),
                'title': mis.get('Title', ''),
                'severity': mis.get('Severity', 'UNKNOWN'),
                'description': mis.get('Description', ''),
                'message': mis.get('Message', ''),
                'resolution': mis.get('Resolution', ''),
            })
        for sec in result_obj.get('Secrets', []) or []:
            findings.append({
                'type': 'secret',
                'target': target,
                'rule_id': sec.get('RuleID', ''),
                'severity': sec.get('Severity', 'UNKNOWN'),
                'title': sec.get('Title', ''),
                'match': sec.get('Match', ''),
                'file': sec.get('Location', {}).get('FilePath', sec.get('FilePath', '')),
            })

    return True, findings


def print_trivy_config_summary(findings: List[Dict[str, Any]]) -> None:
    if not findings:
        print('[+] No IaC/CI-CD misconfigurations or secrets found!')
        return
    by_sev: Dict[str, int] = {}
    for f in findings:
        by_sev[f.get('severity', 'UNKNOWN')] = by_sev.get(f.get('severity', 'UNKNOWN'), 0) + 1
    print("\n" + "="*50)
    print(f"{'IAC / CI-CD CONFIG SCAN':^50}")
    print("="*50)
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        if sev in by_sev:
            print(f"[{sev}] {by_sev[sev]} issues")
    print("\nFor details, open trivy_config_results.json in the results directory.")


def trivy_config_to_csv(json_path: str, csv_path: str) -> bool:
    """Convert Trivy config JSON to CSV summary (type, target, id/title, severity)."""
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read Trivy config JSON: {e}")
        return False

    rows: List[Dict[str, Any]] = []
    results_list = data if isinstance(data, list) else data.get('Results', []) if isinstance(data, dict) else []
    for result_obj in results_list:
        target = result_obj.get('Target', '')
        for mis in result_obj.get('Misconfigurations', []) or []:
            rows.append({
                'type': 'misconfiguration',
                'target': target,
                'id_or_rule': mis.get('ID', ''),
                'title': mis.get('Title', ''),
                'severity': mis.get('Severity', 'UNKNOWN'),
                'file': mis.get('Location', {}).get('FilePath', ''),
            })
        for sec in result_obj.get('Secrets', []) or []:
            rows.append({
                'type': 'secret',
                'target': target,
                'id_or_rule': sec.get('RuleID', ''),
                'title': sec.get('Title', ''),
                'severity': sec.get('Severity', 'UNKNOWN'),
                'file': sec.get('Location', {}).get('FilePath', sec.get('FilePath', '')),
            })

    if not rows:
        print("[i] No Trivy config findings to export as CSV")
        return True

    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['type', 'target', 'id_or_rule', 'title', 'severity', 'file'])
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
        print(f"[i] Trivy config CSV saved to {csv_path}")
        return True
    except Exception as e:
        print(f"[!] Failed writing Trivy config CSV: {e}")
        return False