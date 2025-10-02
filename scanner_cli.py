#!/usr/bin/env python3
"""
Simple CLI wrapper for the security scanner Docker container
Usage: python3 scanner_cli.py --repo <repo_url> [--target <target_url>]
"""

import os
import sys
import argparse
import subprocess
import tempfile
import shutil
from pathlib import Path

def clone_repository(repo_url, branch="main", target_dir="/workspace/repo"):
    """Clone a git repository"""
    try:
        # Remove existing directory if it exists
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)
        
        # Clone the repository
        print(f"[i] Cloning {repo_url} (branch: {branch}) to {target_dir}")
        
        cmd = ["git", "clone", "--branch", branch, "--depth", "1", repo_url, target_dir]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            print(f"[!] Git clone failed: {result.stderr}")
            return False, None
        
        print(f"[✔] Repository cloned successfully")
        return True, target_dir
        
    except subprocess.TimeoutExpired:
        print("[!] Git clone timed out after 5 minutes")
        return False, None
    except Exception as e:
        print(f"[!] Error cloning repository: {e}")
        return False, None

def run_security_scanner(repo_path, target_url=None, output_dir="/workspace/output"):
    """Run the Python security scanner directly"""
    try:
        print(f"[i] Running Python security scanner on: {repo_path}")
        
        # Use the existing Python scanner with mock inputs
        scanner_script = "/app/scanner.py"
        
        if not os.path.exists(scanner_script):
            print(f"[!] Python scanner not found: {scanner_script}")
            return False
        
        # Create mock input for the interactive scanner
        mock_inputs = [
            repo_path,  # Repository path (use already cloned repo)
            "main",     # Branch
            ".",        # Target folder (use current since already cloned)
            "755",      # Permissions
            "3",        # Skip container scanning 
            "N",        # Skip Trivy config
            "y",        # Run Gitleaks
        ]
        
        if target_url:
            mock_inputs.extend([
                "y",        # Run DAST
                target_url  # Target URL
            ])
        else:
            mock_inputs.append("n")  # Skip DAST
        
        # Join inputs with newlines
        input_data = "\n".join(mock_inputs) + "\n"
        
        print(f"[i] Running: python3 {scanner_script}")
        print(f"[i] Using cloned repository at: {repo_path}")
        
        # Set environment variables
        env = os.environ.copy()
        env['PYTHONPATH'] = '/app'
        env['OUTPUT_DIR'] = output_dir
        
        # Override the default output directory for the Python scanner
        # by modifying the mock inputs to use our custom output directory
        mock_inputs[0] = repo_path  # Keep the repo path
        # Add output directory override as an environment variable
        env['SCANNER_OUTPUT_DIR'] = output_dir
        
        # Run the Python scanner
        result = subprocess.run(
            ["python3", scanner_script], 
            input=input_data,
            cwd="/app",
            env=env,
            text=True,
            capture_output=True,
            timeout=3600  # 1 hour timeout
        )
        
        # Print output for debugging
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"[stderr] {result.stderr}")
        
        if result.returncode == 0:
            print("[✔] Security scanner completed successfully")
            
            # Copy results from default location to custom output directory
            default_output = "/app/output"
            if output_dir != default_output and os.path.exists(default_output):
                print(f"[i] Copying results from {default_output} to {output_dir}")
                try:
                    # Copy all files and directories from default output to custom output
                    import shutil
                    if os.path.exists(output_dir):
                        shutil.rmtree(output_dir)
                    shutil.copytree(default_output, output_dir)
                    print(f"[✔] Results copied successfully to {output_dir}")
                except Exception as e:
                    print(f"[!] Error copying results: {e}")
            
            return True
        else:
            print(f"[!] Security scanner failed with exit code: {result.returncode}")
            return False
            
    except subprocess.TimeoutExpired:
        print("[!] Security scanner timed out after 1 hour")
        return False
    except Exception as e:
        print(f"[!] Error running security scanner: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='SAST/DAST Security Scanner CLI')
    parser.add_argument('--repo', required=True, help='Repository URL (https or git@...)')
    parser.add_argument('--branch', default='main', help='Branch name (default: main)')
    parser.add_argument('--target', help='Target URL for DAST scanning (optional)')
    parser.add_argument('--output', default='/workspace/output', help='Output directory on host machine (default: /workspace/output)')
    parser.add_argument('--output-name', help='Custom output folder name (default: output)')
    parser.add_argument('--clone-dir', default='/workspace/repo', help='Directory to clone repository (default: /workspace/repo)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("              SAST/DAST SECURITY SCANNER (CLI)")
    print("=" * 60)
    print()
    
    print(f"[i] Repository: {args.repo}")
    print(f"[i] Branch: {args.branch}")
    print(f"[i] Clone directory: {args.clone_dir}")
    
    # Handle custom output directory naming
    if args.output_name:
        # Use custom output folder name in the workspace
        final_output_dir = f"/workspace/{args.output_name}"
        host_output_path = f"./{args.output_name}"
    else:
        # Use the provided output path or default
        final_output_dir = args.output
        host_output_path = args.output.replace('/workspace/', './')
    
    print(f"[i] Output directory (container): {final_output_dir}")
    print(f"[i] Output directory (host): {host_output_path}")
    
    if args.target:
        print(f"[i] DAST target: {args.target}")
    print()
    
    # Create output directory
    output_dir = Path(final_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Clone repository
    success, repo_path = clone_repository(args.repo, args.branch, args.clone_dir)
    if not success:
        print("[!] Failed to clone repository")
        sys.exit(1)
    
    # Run security scanner
    success = run_security_scanner(repo_path, args.target, str(output_dir))
    if not success:
        print("[!] Security scanner failed")
        sys.exit(1)
    
    print()
    print("=" * 60)
    print("                    SCAN COMPLETE")
    print("=" * 60)
    print()
    print(f"[✔] Results saved to container: {output_dir}")
    print(f"[✔] Results available on host: {host_output_path}")
    print(f"[i] Repository analyzed: {repo_path}")
    
    # Show output structure
    if output_dir.exists():
        print("\nOutput structure:")
        for item in sorted(output_dir.iterdir()):
            if item.is_dir():
                file_count = len(list(item.glob("*")))
                print(f"  📁 {item.name}/ ({file_count} files)")
            else:
                print(f"  📄 {item.name}")

if __name__ == "__main__":
    main()