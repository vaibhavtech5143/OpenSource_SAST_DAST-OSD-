#!/usr/bin/env python3
"""
Semgrep-based SAST Scanner with Docker support
"""
import os
import sys
import subprocess
import json
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import shutil

def run_command(cmd: List[str], cwd: Optional[str] = None) -> Tuple[bool, str]:
    """Run a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, f"Command failed with code {e.returncode}: {e.stderr}"

def ensure_output_dir(output_dir: str) -> None:
    """Ensure the output directory exists and is writable."""
    try:
        os.makedirs(output_dir, exist_ok=True)
        # Test write permission
        test_file = os.path.join(output_dir, '.permission_test')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
    except Exception as e:
        print(f"[!] Error accessing output directory {output_dir}: {e}")
        sys.exit(1)

# Default rulesets to use for scanning
DEFAULT_RULESETS = [
    'p/owasp-top-ten',          # OWASP Top 10 vulnerabilities
    'p/r2c-security-audit',     # r2c security audit rules
    'p/default',                # Semgrep's default rules
    # Additional security rules
    'p/security-audit',         # Security best practices
    'p/secrets',                # Secrets detection
    'p/ci',                     # CI/CD security
    'p/jwt',                    # JWT security
    'p/docker',                 # Docker security
    'p/cryptography',           # Cryptography best practices
    'p/flask',                  # Flask security
    'p/django',                 # Django security
    'p/command-injection',      # Command injection
    'p/sql-injection',          # SQL injection
    'p/xss',                    # Cross-Site Scripting (XSS)
    'p/deserialization',        # Insecure deserialization
    'p/insecure-transport',     # Insecure transport
    'p/ssrf'                    # Server-Side Request Forgery
]

def run_semgrep_scan(repo_path: str, output_dir: str, custom_rules: List[str] = None, use_default_rules: bool = True) -> bool:
    """Run Semgrep SAST scan using Docker.
    
    Args:
        repo_path: Path to the repository to scan
        output_dir: Directory to save scan results
        custom_rules: List of paths to custom rule files or Semgrep registry entries
        use_default_rules: Whether to include the default security rulesets
    """
    print("\n[i] Starting Semgrep SAST scan...")
    
    # Normalize paths for Docker volume mounting
    repo_path = os.path.abspath(repo_path)
    output_path = os.path.abspath(output_dir)
    
    # Create a temporary file for Semgrep output
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False, dir=output_dir) as tmp_file:
        output_file = tmp_file.name
    
    try:
        # Build the base command
        cmd = [
            'docker', 'run', '--rm',
            '-v', f'{repo_path}:/src',
            '-v', f'{output_path}:/output',
            'returntocorp/semgrep',
            'semgrep', 'scan',
            '--json',
            '--output', f'/output/{os.path.basename(output_file)}',
            '--error',  # Exit 1 if findings are found
            '--metrics', 'off',  # Disable metrics
        ]
        
        # Add rules configuration
        rules_to_use = []
        
        # Add default rules if enabled
        if use_default_rules:
            rules_to_use.extend(DEFAULT_RULESETS)
            print("[i] Using security rulesets:", ", ".join(DEFAULT_RULESETS))
        
        # Add custom rules if provided
        if custom_rules:
            rules_to_use.extend(custom_rules)
            print("[i] Using custom rules:", ", ".join(custom_rules))
        
        # If no rules specified, use auto mode
        if not rules_to_use:
            print("[i] No rules specified, using Semgrep's auto mode")
            cmd.extend(['--config', 'auto'])
        else:
            # Add each rule or ruleset
            for rule in rules_to_use:
                cmd.extend(['--config', rule])
        
        # Add the source directory
        cmd.append('/src')
        
        success, output = run_command(cmd)
        
        # Process results
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                try:
                    results = json.load(f)
                    findings = results.get('results', [])
                    if findings:
                        print(f"[!] Found {len(findings)} potential security issues")
                        # Save detailed results
                        with open(os.path.join(output_dir, 'semgrep_findings.json'), 'w') as f_out:
                            json.dump(results, f_out, indent=2)
                        print(f"[i] Detailed findings saved to {os.path.join(output_dir, 'semgrep_findings.json')}")
                    else:
                        print("[✔] No security issues found by Semgrep")
                except json.JSONDecodeError:
                    print("[!] Error parsing Semgrep results")
            os.remove(output_file)
        
        return success
        
    except Exception as e:
        print(f"[!] Error running Semgrep: {str(e)}")
        return False

def scan_docker_images(repo_path: str, output_dir: str) -> None:
    """Scan Dockerfiles and container images in the repository."""
    print("\n[i] Scanning for Docker images...")
    
    # Find all Dockerfiles in the repository
    dockerfiles = []
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.lower() == 'dockerfile':
                dockerfiles.append(os.path.join(root, file))
    
    if not dockerfiles:
        print("[i] No Dockerfiles found in the repository")
        return
    
    print(f"[i] Found {len(dockerfiles)} Dockerfiles")
    
    for dockerfile in dockerfiles:
        print(f"\n[i] Scanning Dockerfile: {os.path.relpath(dockerfile, repo_path)}")
        
        # Run Hadolint (Dockerfile linter)
        cmd = [
            'docker', 'run', '--rm',
            '-v', f'{os.path.dirname(dockerfile)}:/src',
            '-w', '/src',
            'hadolint/hadolint',
            'hadolint',
            '--no-fail',
            '--format', 'json',
            os.path.basename(dockerfile)
        ]
        
        success, output = run_command(cmd)
        if success and output.strip():
            try:
                findings = json.loads(output)
                if findings:
                    print(f"[!] Found {len(findings)} issues in {os.path.basename(dockerfile)}")
                    output_file = os.path.join(
                        output_dir,
                        f"hadolint_{os.path.basename(os.path.dirname(dockerfile))}.json"
                    )
                    with open(output_file, 'w') as f:
                        json.dump(findings, f, indent=2)
                    print(f"[i] Hadolint results saved to {output_file}")
            except json.JSONDecodeError:
                print(f"[!] Error parsing Hadolint output: {output}")

def main():
    import argparse
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Run SAST scan using Semgrep')
    parser.add_argument('repository_path', help='Path to the repository to scan')
    parser.add_argument('output_directory', help='Directory to save scan results')
    parser.add_argument('--rules', '-r', nargs='+', default=[],
                      help='Custom Semgrep rules or rulesets to use (e.g., "p/security-audit" or "path/to/rules.yaml")')
    parser.add_argument('--no-default-rules', action='store_true',
                      help='Disable the default security rulesets')
    
    args = parser.parse_args()
    
    print("=" * 50)
    print(f"{'SEMGREP SAST SCANNER':^50}")
    print("=" * 50)
    
    # Check if Docker is running
    success, _ = run_command(['docker', '--version'])
    if not success:
        print("[!] Docker is not installed or not running. Please start Docker and try again.")
        sys.exit(1)
    
    # Ensure output directory exists and is writable
    ensure_output_dir(args.output_directory)
    
    # Run Semgrep SAST scan
    if not run_semgrep_scan(
        args.repository_path, 
        args.output_directory, 
        custom_rules=args.rules,
        use_default_rules=not args.no_default_rules
    ):
        print("[!] Semgrep scan failed")
    
    # Scan Dockerfiles
    scan_docker_images(args.repository_path, args.output_directory)
    
    print("\n" + "=" * 50)
    print(f"{'SCAN COMPLETED':^50}")
    print("=" * 50)
    print(f"\n[✔] Results saved to: {os.path.abspath(args.output_directory)}")
    
    print("\n[i] Usage tips:")
    print("  - Use --rules to add custom rules: --rules p/security-audit path/to/rules.yaml")
    print("  - Use --no-default-rules to disable default security rules")
    print("  - View available rules: https://semgrep.dev/explore")

if __name__ == "__main__":
    main()
