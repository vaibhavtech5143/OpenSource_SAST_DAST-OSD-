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

def pull_gitleaks_image() -> bool:
    """Pull the latest Gitleaks Docker image."""
    try:
        print("[i] Pulling latest Gitleaks Docker image...")
        cmd = ['docker', 'pull', 'zricethezav/gitleaks:latest']
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] Gitleaks image pulled successfully")
            return True
        else:
            print(f"[!] Warning: Could not pull Gitleaks image: {result.stderr}")
            print("[i] Proceeding with existing image if available...")
            return True
    except Exception as e:
        print(f"[!] Error pulling Gitleaks image: {e}")
        return False

def run_gitleaks_in_docker(repo_path: str, output_dir: str, extra_args: List[str] = [], timeout_seconds: int = 600) -> Tuple[bool, List[Dict[str, Any]]]:
    """Run Gitleaks secret scan using Docker against a git repository path."""
    pull_gitleaks_image()
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, 'gitleaks_results.json')
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
        'zricethezav/gitleaks:latest',
        'detect',
        '--source', '/workspace',
        '--report-format', 'json',
        '--report-path', '/output/gitleaks_results.json',
        '--no-banner',
        '--verbose',
    ] + extra_args
    print(f"[i] Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout.strip():
        print(f"[i] Gitleaks stdout: {result.stdout.strip()}")
    if result.stderr.strip():
        print(f"[i] Gitleaks stderr: {result.stderr.strip()}")
    
    # Gitleaks exit codes:
    # 0: No secrets found (success)
    # 1: Secrets found (success - this is the expected behavior)
    # 2+: Actual errors (failure)
    if result.returncode > 1:
        err = result.stderr.strip() or result.stdout.strip()
        print(f"[!] Gitleaks scan failed with exit code {result.returncode}: {err}")
        return False, []
    elif result.returncode == 1:
        print(f"[+] Gitleaks completed successfully and found secrets (exit code 1)")
    else:
        print(f"[+] Gitleaks completed successfully with no secrets found (exit code 0)")
    if not os.path.exists(output_file):
        print(f"[!] Gitleaks output file not created: {output_file} (no secrets found or no git history)")
        return True, []
    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to parse Gitleaks results: {e}")
        return False, []
    findings: List[Dict[str, Any]] = []
    if isinstance(data, list):
        for leak in data:
            findings.append({
                'description': leak.get('Description', ''),
                'rule_id': leak.get('RuleID', ''),
                'secret': leak.get('Secret', ''),
                'file': leak.get('File', ''),
                'start_line': leak.get('StartLine', ''),
                'end_line': leak.get('EndLine', ''),
                'commit': leak.get('Commit', ''),
                'author': leak.get('Author', ''),
                'email': leak.get('Email', ''),
                'date': leak.get('Date', ''),
                'message': leak.get('Message', ''),
            })
    else:
        print("[!] Unexpected Gitleaks JSON format")
        return False, []
    return True, findings

def print_gitleaks_summary(findings: List[Dict[str, Any]]) -> None:
    if not findings:
        print('[+] No secrets detected by Gitleaks!')
        return
    total = len(findings)
    by_rule: Dict[str, int] = {}
    for f in findings:
        rule = f.get('rule_id', 'Unknown')
        by_rule[rule] = by_rule.get(rule, 0) + 1
    print("\n" + "="*50)
    print(f"{'GITLEAKS SECRET SCAN':^50}")
    print("="*50)
    print(f"[!] {total} potential secrets found")
    print("\nBy Rule:")
    for rule, count in sorted(by_rule.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {rule}: {count}")
    if total > 10:
        print(f"\n... and {total - 10} more details in gitleaks_results.json")
    else:
        for f in findings:
            print(f"\n  - {f['description']} in {f['file']} (line {f['start_line']})")
    print("\nFor full details, open gitleaks_results.json in the results directory.")

def gitleaks_to_csv(json_path: str, csv_path: str) -> bool:
    """Convert Gitleaks JSON to CSV."""
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read Gitleaks JSON: {e}")
        return False
    
    rows: List[Dict[str, Any]] = []
    if isinstance(data, list):
        for leak in data:
            rows.append({
                'description': leak.get('Description', ''),
                'rule_id': leak.get('RuleID', ''),
                'secret': leak.get('Secret', ''),
                'file': leak.get('File', ''),
                'start_line': leak.get('StartLine', ''),
                'end_line': leak.get('EndLine', ''),
                'commit': leak.get('Commit', ''),
                'author': leak.get('Author', ''),
                'email': leak.get('Email', ''),
                'date': leak.get('Date', ''),
                'fingerprint': leak.get('Fingerprint', ''),
                'entropy': leak.get('Entropy', '')
            })
    else:
        print("[!] Unexpected Gitleaks JSON format for CSV conversion")
        return False
    
    if not rows:
        print("[i] No Gitleaks findings to convert to CSV")
        return True
    
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['description', 'rule_id', 'secret', 'file', 'start_line', 'end_line', 
                         'commit', 'author', 'email', 'date', 'fingerprint', 'entropy']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"[+] Successfully converted {len(rows)} Gitleaks findings to CSV: {csv_path}")
        return True
    except Exception as e:
        print(f"[!] Failed to write Gitleaks CSV: {e}")
        return False