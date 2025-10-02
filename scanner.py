import os
import sys
import tempfile
import subprocess
import time
import json
import traceback
from typing import Dict, List, Tuple

from utils.clone_repo import clone_repo, ask
from utils.language_utils import analyze_repo_languages
from utils.sast_runner import run_sast, sast_to_csv
from utils.trivy_scanner import print_trivy_summary, trivy_to_csv
from utils.trivy_config import run_trivy_config_in_docker, print_trivy_config_summary, trivy_config_to_csv
from utils.nuclei_scanner import run_nuclei_dast, nuclei_to_csv
from utils.bearer_scan import run_bearer_scan, bearer_json_to_csv
from utils.gitleaks_scanner import run_gitleaks_in_docker, print_gitleaks_summary, gitleaks_to_csv

def check_docker_installed() -> bool:
    """Check if Docker is installed and running."""
    try:
        result = subprocess.run(['docker', '--version'], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE,
                               text=True)
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def check_dependencies() -> Tuple[bool, List[str]]:
    """Check if required tools are installed."""
    missing = ['git']
    
    try:
        subprocess.run(['git', '--version'], 
                       stdout=subprocess.PIPE, 
                       stderr=subprocess.PIPE,
                       check=True)
        missing.remove('git')
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    
    if not check_docker_installed():
        missing.append('docker')
    
    return len(missing) == 0, missing

def run_trivy_in_docker(image_name: str, output_dir: str, timeout: int = 600) -> Tuple[bool, List[Dict]]:
    """Run Trivy in a Docker container with verbose output and timeout."""
    print(f"[i] Starting Trivy scan for {image_name}...")
    start_time = time.time()
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        cmd = [
            'docker', 'run', '--rm',
            '-v', f'{os.path.abspath(output_dir)}:/output',
            'aquasec/trivy:latest',
            '--debug',
            'image',
            '--format', 'json',
            '--output', '/output/trivy_scan_results.json',
            '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
            '--timeout', f'{timeout}s',
            image_name
        ]
        
        print(f"[i] Running command: {' '.join(cmd)}")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        def stream_output(pipe, prefix):
            for line in iter(pipe.readline, ''):
                if line.strip():
                    print(f"{prefix}{line.strip()}")
        
        import threading
        stdout_thread = threading.Thread(target=stream_output, args=(process.stdout, '[Trivy] '))
        stderr_thread = threading.Thread(target=stream_output, args=(process.stderr, '[Trivy ERROR] '))
        
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()
        
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f"[!] Trivy scan timed out after {timeout} seconds")
            process.kill()
            return False, []
            
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        
        if process.returncode not in (0, 1):
            print(f"[!] Trivy scan failed with exit code {process.returncode}")
            return False, []
            
        results_file = os.path.join(output_dir, 'trivy_scan_results.json')
        if not os.path.exists(results_file):
            print(f"[!] Trivy results file not found: {results_file}")
            return False, []
            
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
                
            findings = []
            for result in results.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    findings.append({
                        'target': result.get('Target', ''),
                        'vulnerability_id': vuln.get('VulnerabilityID', ''),
                        'pkg_name': vuln.get('PkgName', ''),
                        'installed_version': vuln.get('InstalledVersion', ''),
                        'fixed_version': vuln.get('FixedVersion', ''),
                        'severity': vuln.get('Severity', 'UNKNOWN'),
                        'title': vuln.get('Title', ''),
                        'description': vuln.get('Description', ''),
                        'references': vuln.get('References', [])
                    })
            
            scan_time = time.time() - start_time
            print(f"[i] Trivy scan completed in {scan_time:.2f} seconds")
            print(f"[i] Found {len(findings)} vulnerabilities")
            
            return True, findings
            
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[!] Error parsing Trivy results: {str(e)}")
            return False, []
            
    except Exception as e:
        print(f"[!] Error running Trivy in Docker: {str(e)}")
        traceback.print_exc()
        return False, []

def scan_container_images(output_dir: str) -> None:
    """Scan container images using Trivy."""
    try:
        while True:
            image_name = input("\nEnter Docker image name to scan (e.g., nginx:latest) or leave empty to skip: ").strip()
            if not image_name:
                print("[i] Skipping container scanning")
                break
                
            print(f"[i] Using Trivy in Docker...")
            success, findings = run_trivy_in_docker(image_name, output_dir)
            
            if success:
                print("\n" + "=" * 50)
                print(f"CONTAINER SCAN RESULTS FOR {image_name}")
                print("=" * 50)
                print_trivy_summary(findings)
                
                output_file = os.path.join(output_dir, f'trivy_{image_name.replace("/", "_").replace(":", "_")}.json')
                with open(output_file, 'w') as f:
                    json.dump(findings, f, indent=2)
                print(f"\n[i] Detailed results saved to {output_file}")
            
            if input("\nScan another image? (y/N): ").strip().lower() != 'y':
                break
    except Exception as e:
        print(f"[!] Error during container image scanning: {e}")
        traceback.print_exc()

def ensure_tool_output_dir(base_dir: str, tool_name: str) -> str:
    """Create and return a tool-specific output directory."""
    tool_dir = os.path.join(base_dir, tool_name)
    os.makedirs(tool_dir, exist_ok=True)
    return tool_dir

def find_repo_root(target: str) -> str:
    """Find the root directory of the cloned repository by locating the .git folder."""
    target = os.path.abspath(target)
    
    if os.path.exists(os.path.join(target, '.git')) and os.path.isdir(os.path.join(target, '.git')):
        return target
    
    for subdir in os.listdir(target):
        subdir_path = os.path.join(target, subdir)
        if os.path.isdir(subdir_path) and os.path.exists(os.path.join(subdir_path, '.git')):
            return os.path.abspath(subdir_path)
    
    print(f"[i] No .git directory found in {target} or its subdirectories. Using {target} for scanning.")
    return target

def main():
    print("\n" + "="*50)
    print(f"{'SECURITY SCANNER':^50}")
    print("="*50)
    
    deps_ok, missing = check_dependencies()
    if not deps_ok:
        print("\n[!] Missing required tools. Please install:")
        for tool in missing:
            print(f"  - {tool}")
        print("\nFor Trivy installation: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
        sys.exit(1)

    print("\n[i] Repository Configuration")
    print("-" * 30)
    repo_url = ask("Repository URL (https or git@...)", required=True)
    branch = ask("Branch name (leave empty for default)", default="main")
    target = ask("Target folder path (where repo will be cloned)", default=".")
    perm = ask("Permissions (numeric, e.g. 755)", default="755")

    target = os.path.abspath(target)
    
    # Use the output directory in the current working directory
    base_output_dir = os.path.join(os.getcwd(), "output")
    os.makedirs(base_output_dir, exist_ok=True)
    # Ensure proper permissions for all subdirectories
    try:
        os.chmod(base_output_dir, 0o777)
    except:
        pass
    print(f"[i] Results will be saved to: {base_output_dir}")
    
    bearer_dir = ensure_tool_output_dir(base_output_dir, 'bearer')
    trivy_dir = ensure_tool_output_dir(base_output_dir, 'trivy')
    trivy_config_dir = ensure_tool_output_dir(base_output_dir, 'trivy_config')
    nuclei_dir = ensure_tool_output_dir(base_output_dir, 'nuclei')
    sast_dir = ensure_tool_output_dir(base_output_dir, 'sast')
    gitleaks_dir = ensure_tool_output_dir(base_output_dir, 'gitleaks')

    try:
        print("\n[i] Cloning repository...")
        clone_repo(repo_url, branch, target, perm)

        target_path = find_repo_root(target)
        print(f"[i] Using repository root for scanning: {target_path}")

        temp_csv = os.path.join(tempfile.gettempdir(), "repo_files.csv")
        print("\n[i] Analyzing repository languages...")
        percentages, files_by_lang, _ = analyze_repo_languages(target_path, temp_csv)
        print("\n[i] Languages detected with file count percentages:")
        for lang, pct in percentages.items():
            print(f"  - {lang}: {pct}% ({len(files_by_lang[lang])} files)")

        print("\n" + "="*50)
        print(f"{'RUNNING STATIC APPLICATION SECURITY TESTING (SAST)':^50}")
        print("="*50)
        
        print("\n[i] Running Bearer scan (Docker)...")
        try:
            bearer_success = run_bearer_scan(target_path, bearer_dir, extra_args=[])
            
            if bearer_success:
                bearer_json = os.path.join(bearer_dir, 'bearer_findings.json')
                bearer_csv = os.path.join(bearer_dir, 'bearer_findings.csv')
                
                if os.path.exists(bearer_json):
                    print(f"[i] Converting Bearer results to CSV: {bearer_csv}")
                    csv_success = bearer_json_to_csv(bearer_json, bearer_csv)
                    if csv_success:
                        print(f"[i] Successfully converted Bearer JSON to CSV: {bearer_csv}")
                    else:
                        print("[!] Failed to convert Bearer JSON to CSV")
                else:
                    print(f"[!] Bearer JSON file not found: {bearer_json}")
            else:
                print("[!] Bearer scan completed with errors")
                
        except Exception as e:
            print(f"[!] Error during Bearer scan or CSV conversion: {e}")
            traceback.print_exc()

        try:
            print("\n[i] Running regex-based SAST scan...")
            sast_results = run_sast(files_by_lang, target_path)
            
            if sast_results:
                sast_json = os.path.join(sast_dir, 'sast_results.json')
                sast_csv = os.path.join(sast_dir, 'sast_results.csv')
                
                with open(sast_json, 'w') as f:
                    json.dump(sast_results, f, indent=2)
                
                if sast_to_csv(sast_results, sast_csv):
                    print(f"[i] SAST results saved to: {sast_csv}")
                else:
                    print("[!] Failed to convert SAST results to CSV")
            else:
                print("[i] No SAST findings to report")
                
        except Exception as e:
            print(f"[!] Error during SAST scan: {e}")
            traceback.print_exc()

        print("\n" + "="*50)
        print(f"{'RUNNING CONTAINER SECURITY SCANNING':^50}")
        print("="*50)
        
        print("\n[i] Scanning for Dockerfiles in the project...")
        dockerfile_found = False
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.lower() in ['dockerfile', 'dockerfile.dev', 'dockerfile.prod'] or file.lower().startswith('dockerfile.'):
                    dockerfile_path = os.path.join(root, file)
                    dockerfile_found = True
                    
                    print(f"\n[i] Found Dockerfile: {os.path.relpath(dockerfile_path, target_path)}")
                    
                    try:
                        from utils.trivy_scanner import scan_dockerfile
                        
                        dockerfile_dir = os.path.join(base_output_dir, 'dockerfile_scan')
                        success, findings = scan_dockerfile(dockerfile_path, dockerfile_dir, dockerfile_context=root)
                        
                        if success:
                            print(f"[+] Dockerfile scan completed! Found {len(findings)} security issues")
                            if findings:
                                print_trivy_summary(findings)
                            
                            dockerfile_json = os.path.join(dockerfile_dir, 'trivy_dockerfile_scan_results.json')
                            dockerfile_csv = os.path.join(dockerfile_dir, 'trivy_dockerfile_scan_results.csv')
                            
                            if os.path.exists(dockerfile_json):
                                if trivy_to_csv(dockerfile_json, dockerfile_csv):
                                    print(f"[i] Dockerfile scan results saved to: {dockerfile_csv}")
                                else:
                                    print("[!] Failed to convert Dockerfile results to CSV")
                        else:
                            print(f"[!] Failed to scan Dockerfile: {dockerfile_path}")
                            
                    except Exception as e:
                        print(f"[!] Error scanning Dockerfile {dockerfile_path}: {e}")
                        traceback.print_exc()
        
        if not dockerfile_found:
            print("[i] No Dockerfiles found in the project directory")
        
        print("\n" + "-"*40)
        print("Docker Image Vulnerability Scanning")
        print("-"*40)
        
        local_images = []
        try:
            result = subprocess.run(['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'], 
                                   capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                local_images = [img.strip() for img in result.stdout.split('\n') if img.strip() and img.strip() != '<none>:<none>']
        except Exception as e:
            print(f"[!] Could not list local Docker images: {e}")
        
        if local_images:
            print(f"\n[i] Found {len(local_images)} local Docker images:")
            for i, img in enumerate(local_images): 
                print(f"  {i+1}. {img}")
            if len(local_images) > 10:
                print(f"  ... and {len(local_images) - 10} more")
            
            scan_choice = ask("\nChoose scanning option:\n1. Scan a local image\n2. Scan a public image from registry\n3. Skip image scanning\nChoice (1/2/3)", default="3")
            
            if scan_choice == "1":
                print("\nAvailable local images:")
                for i, img in enumerate(local_images):
                    print(f"  {i+1}. {img}")
                
                try:
                    img_choice = int(ask(f"Select image number (1-{len(local_images)})", default="1")) - 1
                    if 0 <= img_choice < len(local_images):
                        image_name = local_images[img_choice]
                    else:
                        print("[!] Invalid selection")
                        image_name = None
                except ValueError:
                    print("[!] Invalid input")
                    image_name = None
                    
            elif scan_choice == "2":
                image_name = ask("Enter public Docker image name (e.g., nginx:latest, ubuntu:18.04): ", default="")
                if not image_name:
                    image_name = None
            else:
                image_name = None
        else:
            print("[i] No local Docker images found")
            image_name = ask("Enter public Docker image name to scan (e.g., nginx:latest) or leave empty to skip: ", default="")
            if not image_name:
                image_name = None
        
        if image_name:
            try:
                from utils.trivy_scanner import scan_docker_image
                
                print(f"\n[i] Scanning Docker image: {image_name}")
                success, findings = scan_docker_image(image_name, trivy_dir)
                
                if success:
                    print(f"[+] Image scan completed! Found {len(findings)} vulnerabilities")
                    if findings:
                        print_trivy_summary(findings)
                    
                    trivy_json = os.path.join(trivy_dir, 'trivy_image_scan_results.json')
                    trivy_csv = os.path.join(trivy_dir, 'trivy_image_scan_results.csv')
                    
                    if os.path.exists(trivy_json):
                        if trivy_to_csv(trivy_json, trivy_csv):
                            print(f"[i] Image scan results saved to: {trivy_csv}")
                        else:
                            print("[!] Failed to convert image scan results to CSV")
                else:
                    print(f"[!] Failed to scan Docker image: {image_name}")
                    
            except Exception as e:
                print(f"[!] Error during Docker image scanning: {e}")
                traceback.print_exc()
        else:
            print("[i] Skipping Docker image scanning")

        print("\n" + "="*50)
        print(f"{'RUNNING IAC / CI-CD CONFIG SCANNING':^50}")
        print("="*50)
        try:
            ok_cfg, cfg_findings = run_trivy_config_in_docker(target_path, trivy_config_dir)
            if ok_cfg:
                if cfg_findings:
                    print_trivy_config_summary(cfg_findings)
                    trivy_config_json = os.path.join(trivy_config_dir, 'trivy_config_results.json')
                    trivy_config_csv = os.path.join(trivy_config_dir, 'trivy_config_results.csv')
                    
                    with open(os.path.join(trivy_config_dir, 'trivy_config_findings_flattened.json'), 'w') as f:
                        json.dump(cfg_findings, f, indent=2)
                    
                    if os.path.exists(trivy_config_json):
                        if trivy_config_to_csv(trivy_config_json, trivy_config_csv):
                            print(f"[i] Trivy config results saved to: {trivy_config_csv}")
                        else:
                            print("[!] Failed to convert Trivy config results to CSV")
                    else:
                        print(f"[!] Trivy config JSON file not found: {trivy_config_json}")
                else:
                    print("[i] No IaC/CI-CD misconfigurations or secrets found!")
            else:
                print("[!] Trivy config scan failed")
        except Exception as e:
            print(f"[!] Error during IaC/CI-CD config scanning: {e}")
            traceback.print_exc()

        try:
            confirm_gitleaks = ask("Run secret scanning with Gitleaks? (y/N)", default="N").strip().lower() == 'y'
        except Exception:
            confirm_gitleaks = False
            
        if confirm_gitleaks:
            print("\n" + "="*50)
            print(f"{'RUNNING GITLEAKS SECRET SCAN':^50}")
            print("="*50)
            try:
                is_git_repo = os.path.exists(os.path.join(target_path, '.git'))
                extra_args = ['--no-git'] if not is_git_repo else []
                ok_gitleaks, gitleaks_findings = run_gitleaks_in_docker(target_path, gitleaks_dir, extra_args=extra_args)
                if ok_gitleaks:
                    print_gitleaks_summary(gitleaks_findings)
                    
                    flattened_json = os.path.join(gitleaks_dir, 'gitleaks_findings_flattened.json')
                    with open(flattened_json, 'w') as f:
                        json.dump(gitleaks_findings, f, indent=2)
                    
                    original_json = os.path.join(gitleaks_dir, 'gitleaks_results.json')
                    gitleaks_csv = os.path.join(gitleaks_dir, 'gitleaks_results.csv')
                    if os.path.exists(original_json):
                        if gitleaks_to_csv(original_json, gitleaks_csv):
                            print(f"[i] Gitleaks CSV saved to {gitleaks_csv}")
                        else:
                            print(f"[!] Failed to convert Gitleaks JSON to CSV")
                    else:
                        print(f"[!] Gitleaks JSON file not found: {original_json}")
                else:
                    print("[!] Gitleaks scan failed")
            except Exception as e:
                print(f"[!] Error during Gitleaks secret scanning: {e}")
                traceback.print_exc()

        try:
            confirm_dast = ask("Run DAST with Nuclei? (y/N)", default="N").strip().lower() == 'y'
        except Exception:
            confirm_dast = False
            
        if confirm_dast:
            try:
                url = ask("Target URL for DAST (e.g., https://example.com)", default="").strip()
                if url:
                    print("\n" + "="*50)
                    print(f"{'RUNNING DAST WITH NUCLEI':^50}")
                    print("="*50)
                    ok_nuclei, nuclei_path = run_nuclei_dast(url, nuclei_dir)
                    if ok_nuclei and nuclei_path and os.path.exists(nuclei_path):
                        try:
                            nuclei_csv = os.path.join(nuclei_dir, 'nuclei_results.csv')
                            if nuclei_to_csv(nuclei_path, nuclei_csv):
                                print(f"[i] Nuclei results saved to: {nuclei_csv}")
                            else:
                                print("[!] Failed to convert Nuclei results to CSV")
                        except Exception as e:
                            print(f"[!] Error processing Nuclei results: {e}")
                            traceback.print_exc()
                    else:
                        print("[!] Nuclei scan failed or no results found")
            except Exception as e:
                print(f"[!] Error running Nuclei: {e}")
                traceback.print_exc()

        print("\n" + "="*50)
        print(f"{'SCAN SUMMARY':^50}")
        print("="*50)
        print(f"\n[✔] Scan completed. Results saved to: {os.path.abspath(base_output_dir)}")
        print("\nTool-specific results:")
        for tool in ['bearer', 'sast', 'dockerfile_scan', 'trivy', 'trivy_config', 'gitleaks', 'nuclei']:
            tool_dir = os.path.join(base_output_dir, tool)
            if os.path.exists(tool_dir):
                if tool == 'dockerfile_scan':
                    print(f"  - Dockerfile Security: {os.path.abspath(tool_dir)}")
                elif tool == 'trivy':
                    print(f"  - Container Images: {os.path.abspath(tool_dir)}")
                else:
                    print(f"  - {tool.capitalize()}: {os.path.abspath(tool_dir)}")

    except Exception as e:
        print(f"\n[!] Error during scanning: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()