import json
import subprocess
import os
import csv
import tempfile
import shutil
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum

class ScanType(Enum):
    """Enumeration of supported Trivy scan types."""
    IMAGE = "image"
    DOCKERFILE = "dockerfile"
    GIT_REPO = "repo"
    FILESYSTEM = "fs"

def run_trivy_scan(target: str, output_dir: str, scan_type: ScanType = ScanType.IMAGE, use_docker: bool = True, **kwargs) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Run Trivy scan on the specified target.
    
    Args:
        target: Target to scan (image name, git URL, dockerfile path, or filesystem path)
        output_dir: Directory to save the scan results
        scan_type: Type of scan to perform (IMAGE, DOCKERFILE, GIT_REPO, FILESYSTEM)
        use_docker: If True, run Trivy in a Docker container (default: True)
        **kwargs: Additional arguments (e.g., dockerfile_context for Dockerfile scans)
        
    Returns:
        Tuple of (success, findings) where success is a boolean and findings is a list of vulnerabilities
    """
    try:
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate appropriate output filename based on scan type
        filename_prefix = {
            ScanType.IMAGE: 'trivy_image_scan',
            ScanType.DOCKERFILE: 'trivy_dockerfile_scan', 
            ScanType.GIT_REPO: 'trivy_repo_scan',
            ScanType.FILESYSTEM: 'trivy_fs_scan'
        }.get(scan_type, 'trivy_scan')
        
        output_file = os.path.join(output_dir, f'{filename_prefix}_results.json')
        
        if use_docker:
            # Run Trivy using Docker container
            success, findings = run_trivy_with_docker(target, output_file, scan_type, **kwargs)
        else:
            # Run Trivy directly (original method)
            success, findings = run_trivy_direct(target, output_file, scan_type, **kwargs)
            
        return success, findings
            
    except Exception as e:
        print(f"[!] Error during Trivy scan: {str(e)}")
        return False, []

def run_trivy_with_docker(target: str, output_file: str, scan_type: ScanType, **kwargs) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Run Trivy scan using Docker container.
    
    Args:
        target: Target to scan (image name, git URL, dockerfile path, etc.)
        output_file: Path to save the scan results
        scan_type: Type of scan to perform
        **kwargs: Additional arguments
        
    Returns:
        Tuple of (success, findings)
    """
    try:
        print(f"[i] Running Trivy {scan_type.value} scan using Docker container for: {target}")
        
        # Get absolute path for output file (Windows path handling)
        output_file = os.path.abspath(output_file)
        output_dir = os.path.dirname(output_file)
        output_filename = os.path.basename(output_file)
        
        # Use the actual Windows output directory for volume mounting
        docker_output_dir = output_dir
            
        # Pull latest Trivy image
        print("[i] Pulling latest Trivy Docker image...")
        pull_cmd = ['docker', 'pull', 'aquasec/trivy:latest']
        pull_result = subprocess.run(pull_cmd, capture_output=True, text=True)
        
        if pull_result.returncode != 0:
            print(f"[!] Warning: Could not pull latest Trivy image: {pull_result.stderr}")
            print("[i] Proceeding with existing image if available...")
        
        # Build Docker command based on scan type
        docker_cmd = build_docker_command(target, scan_type, docker_output_dir, output_filename, **kwargs)
        
        if not docker_cmd:
            print(f"[!] Failed to build Docker command for scan type: {scan_type}")
            return False, []
        
        print(f"[i] Running command: {' '.join(docker_cmd[:10])}...")  # Show first part of command
        
        # Run Trivy in Docker container
        result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=600)  # Increased timeout for repo scans
        
        print(f"[i] Trivy scan completed with exit code: {result.returncode}")
        
        if result.returncode not in (0, 1):  # 0: success, 1: vulnerabilities found
            print(f"[!] Error running Trivy scan: {result.stderr}")
            if result.stdout:
                print(f"[!] Stdout: {result.stdout}")
            return False, []
        
        # Clean up temporary directories if created
        if 'temp_dir' in kwargs:
            try:
                shutil.rmtree(kwargs['temp_dir'])
                print(f"[i] Cleaned up temporary directory: {kwargs['temp_dir']}")
            except Exception as e:
                print(f"[!] Warning: Could not clean up temp directory: {e}")
            
        # Load and parse results
        return parse_trivy_results(output_file)
            
    except subprocess.TimeoutExpired:
        print("[!] Trivy scan timed out after 10 minutes")
        return False, []
    except Exception as e:
        print(f"[!] Error running Trivy with Docker: {str(e)}")
        return False, []

def convert_windows_path_for_docker(path: str) -> str:
    """
    Convert Windows paths to Docker-compatible format.
    
    Args:
        path: Windows file path
        
    Returns:
        Docker-compatible path
    """
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

def build_docker_command(target: str, scan_type: ScanType, docker_output_dir: str, output_filename: str, **kwargs) -> Optional[List[str]]:
    """
    Build Docker command based on scan type.
    
    Args:
        target: Target to scan
        scan_type: Type of scan
        docker_output_dir: Docker-compatible output directory path
        output_filename: Name of output file
        **kwargs: Additional arguments
        
    Returns:
        Docker command as list of strings, or None if invalid
    """
    # Extract actual output directory from the docker_output_dir parameter
    # Note: docker_output_dir is the output directory, not the file
    # We need to determine the actual Windows directory for permissions
    if docker_output_dir.startswith('/'):
        # This is already a Docker-compatible path, convert back to Windows for permissions
        if docker_output_dir.startswith('/c/'):
            actual_output_dir = docker_output_dir.replace('/c/', 'C:/').replace('/', '\\')
        else:
            actual_output_dir = docker_output_dir.replace('/', '\\')
    else:
        actual_output_dir = docker_output_dir
    
    # Ensure output directory exists and has proper permissions
    try:
        os.makedirs(actual_output_dir, exist_ok=True)
        os.chmod(actual_output_dir, 0o777)
    except:
        pass  # Ignore permission errors on some systems
    
    base_cmd = [
        'docker', 'run', '--rm',
        '--user', '0:0',  # Run as root to avoid permission issues
        '-v', f'{actual_output_dir}:/tmp/output',
    ]
    
    if scan_type == ScanType.IMAGE:
        # Add Docker socket for image scanning
        base_cmd.extend(['-v', '/var/run/docker.sock:/var/run/docker.sock'])
        
        trivy_cmd = [
            'aquasec/trivy:latest',
            'image',
            '--format', 'json',
            '--output', f'/tmp/output/{output_filename}',
            '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
            '--quiet',
            target
        ]
        
    elif scan_type == ScanType.DOCKERFILE:
        # For Dockerfile scanning, we need to mount the context directory
        dockerfile_context = kwargs.get('dockerfile_context', os.path.dirname(target))
        dockerfile_context_abs = os.path.abspath(dockerfile_context)
        dockerfile_relative_path = os.path.relpath(target, dockerfile_context)
        
        base_cmd.extend(['-v', f'{dockerfile_context_abs}:/tmp/context'])
        
        trivy_cmd = [
            'aquasec/trivy:latest',
            'config',
            '--format', 'json',
            '--output', f'/tmp/output/{output_filename}',
            '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
            f'/tmp/context/{dockerfile_relative_path}'
        ]
        
    elif scan_type == ScanType.GIT_REPO:
        # For Git repo scanning, we'll clone to temp dir and scan filesystem
        temp_dir = setup_git_repo_for_scan(target)
        if not temp_dir:
            return None
            
        # Store temp_dir in kwargs for cleanup
        kwargs['temp_dir'] = temp_dir
        
        base_cmd.extend(['-v', f'{temp_dir}:/tmp/repo'])
        
        trivy_cmd = [
            'aquasec/trivy:latest',
            'fs',
            '--format', 'json',
            '--output', f'/tmp/output/{output_filename}',
            '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
            '--quiet',
            '/tmp/repo'
        ]
        
    elif scan_type == ScanType.FILESYSTEM:
        # For filesystem scanning
        target_abs = os.path.abspath(target)
        base_cmd.extend(['-v', f'{target_abs}:/tmp/target:ro'])
        
        trivy_cmd = [
            'aquasec/trivy:latest',
            'fs',
            '--format', 'json',
            '--output', f'/tmp/output/{output_filename}',
            '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
            '--quiet',
            '/tmp/target'
        ]
        
    else:
        print(f"[!] Unsupported scan type: {scan_type}")
        return None
    
    return base_cmd + trivy_cmd

def setup_git_repo_for_scan(repo_url: str) -> Optional[str]:
    """
    Clone a Git repository to a temporary directory for scanning.
    
    Args:
        repo_url: Git repository URL
        
    Returns:
        Path to temporary directory containing cloned repo, or None if failed
    """
    try:
        print(f"[i] Cloning repository: {repo_url}")
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix="trivy_git_scan_")
        
        # Clone repository
        clone_cmd = ['git', 'clone', '--depth', '1', repo_url, temp_dir]
        result = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            print(f"[!] Failed to clone repository: {result.stderr}")
            try:
                shutil.rmtree(temp_dir)
            except:
                pass
            return None
            
        print(f"[i] Repository cloned to: {temp_dir}")
        return temp_dir
        
    except subprocess.TimeoutExpired:
        print("[!] Git clone timed out after 5 minutes")
        return None
    except Exception as e:
        print(f"[!] Error cloning repository: {str(e)}")
        return None

def run_trivy_direct(target: str, output_file: str, scan_type: ScanType, **kwargs) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Run Trivy scan directly (requires local Trivy installation).
    
    Args:
        target: Target to scan
        output_file: Path to save the scan results
        scan_type: Type of scan to perform
        **kwargs: Additional arguments
        
    Returns:
        Tuple of (success, findings)
    """
    try:
        # Build command based on scan type
        if scan_type == ScanType.IMAGE:
            cmd = [
                'trivy', 'image',
                '--format', 'json',
                '--output', output_file,
                '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                target
            ]
        elif scan_type == ScanType.DOCKERFILE:
            cmd = [
                'trivy', 'config',
                '--format', 'json',
                '--output', output_file,
                '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                target
            ]
        elif scan_type == ScanType.FILESYSTEM:
            cmd = [
                'trivy', 'fs',
                '--format', 'json',
                '--output', output_file,
                '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                target
            ]
        elif scan_type == ScanType.GIT_REPO:
            # For direct mode, we'll clone and scan the filesystem
            temp_dir = setup_git_repo_for_scan(target)
            if not temp_dir:
                return False, []
                
            try:
                cmd = [
                    'trivy', 'fs',
                    '--format', 'json',
                    '--output', output_file,
                    '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                    temp_dir
                ]
            finally:
                # Clean up after scan
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    print(f"[!] Warning: Could not clean up temp directory: {e}")
        else:
            print(f"[!] Unsupported scan type for direct mode: {scan_type}")
            return False, []
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode not in (0, 1):  # 0: success, 1: vulnerabilities found
            print(f"[!] Error running Trivy scan: {result.stderr}")
            return False, []
            
        return parse_trivy_results(output_file)
            
    except Exception as e:
        print(f"[!] Error running Trivy directly: {str(e)}")
        return False, []

def parse_trivy_results(output_file: str) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Parse Trivy scan results from JSON file.
    
    Args:
        output_file: Path to the JSON results file
        
    Returns:
        Tuple of (success, findings)
    """
    try:
        if not os.path.exists(output_file):
            print(f"[!] Results file not found: {output_file}")
            return False, []
            
        with open(output_file, 'r', encoding='utf-8') as f:
            results = json.load(f)
            
        # Extract vulnerabilities
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
        
        print(f"[i] Found {len(findings)} vulnerabilities in scan results")
        return True, findings
        
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[!] Error parsing Trivy results: {str(e)}")
        return False, []
    except Exception as e:
        print(f"[!] Error reading results file: {str(e)}")
        return False, []

def print_trivy_summary(findings: List[Dict[str, Any]]) -> None:
    """Print a summary of Trivy findings to the console."""
    if not findings:
        print("[+] No container vulnerabilities found!")
        return
        
    # Group by severity
    by_severity = {}
    for finding in findings:
        by_severity.setdefault(finding['severity'], []).append(finding)
    
    # Print summary
    print("\n" + "="*50)
    print(f"{'CONTAINER VULNERABILITY SCAN':^50}")
    print("="*50)
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if severity in by_severity:
            print(f"\n[{severity}] {len(by_severity[severity])} issues")
            for finding in by_severity[severity][:5]:  # Show top 5 per severity
                print(f"  - {finding['vulnerability_id']} in {finding['pkg_name']} ({finding['installed_version']})")
                print(f"    {finding['title']}")
            if len(by_severity[severity]) > 5:
                print(f"  ... and {len(by_severity[severity]) - 5} more")

    print("\nFor detailed results, check the trivy_scan_results.json file")


def trivy_to_csv(json_path: str, csv_path: str) -> bool:
    """
    Convert Trivy JSON results to CSV format.
    
    Args:
        json_path: Path to the Trivy JSON results file
        csv_path: Path to save the CSV output
        
    Returns:
        bool: True if conversion was successful, False otherwise
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # Handle both direct list format and dictionary format
        if isinstance(data, list):
            results_list = data
        elif isinstance(data, dict):
            results_list = data.get('Results', [])
        else:
            print("[!] Unknown JSON format in Trivy results")
            return False
            
        # Extract all unique field names from findings
        fieldnames = set()
        findings = []
        
        # Process each result and its vulnerabilities/misconfigurations
        for result in results_list:
            # Handle vulnerabilities
            for vuln in result.get('Vulnerabilities', []):
                finding = {
                    'target': result.get('Target', ''),
                    'class': result.get('Class', ''),
                    'type': result.get('Type', ''),
                    'finding_type': 'vulnerability',
                    'vulnerability_id': vuln.get('VulnerabilityID', ''),
                    'pkg_name': vuln.get('PkgName', ''),
                    'installed_version': vuln.get('InstalledVersion', ''),
                    'fixed_version': vuln.get('FixedVersion', ''),
                    'severity': vuln.get('Severity', 'UNKNOWN'),
                    'title': vuln.get('Title', ''),
                    'description': vuln.get('Description', '').replace('\n', ' ').replace('\r', ''),
                    'cvss_score': vuln.get('CVSS', {}).get('nvd', {}).get('V3Score', ''),
                    'cwe_ids': ', '.join(vuln.get('CweIDs', [])),
                    'references': ' | '.join(vuln.get('References', [])),
                    'published_date': vuln.get('PublishedDate', ''),
                    'last_modified_date': vuln.get('LastModifiedDate', '')
                }
                
                # Add any additional fields that might be present
                for key in vuln.keys():
                    if key not in finding and not isinstance(vuln[key], (dict, list)):
                        finding[key] = vuln[key]
                
                fieldnames.update(finding.keys())
                findings.append(finding)
            
            # Handle misconfigurations (for Dockerfile and config scans)
            for misconf in result.get('Misconfigurations', []):
                finding = {
                    'target': result.get('Target', ''),
                    'class': result.get('Class', ''),
                    'type': result.get('Type', ''),
                    'finding_type': 'misconfiguration',
                    'vulnerability_id': misconf.get('ID', ''),
                    'avd_id': misconf.get('AVDID', ''),
                    'severity': misconf.get('Severity', 'UNKNOWN'),
                    'title': misconf.get('Title', ''),
                    'description': misconf.get('Description', '').replace('\n', ' ').replace('\r', ''),
                    'message': misconf.get('Message', ''),
                    'resolution': misconf.get('Resolution', ''),
                    'references': ' | '.join(misconf.get('References', [])),
                    'status': misconf.get('Status', ''),
                    'namespace': misconf.get('Namespace', ''),
                    'primary_url': misconf.get('PrimaryURL', '')
                }
                
                # Add any additional fields
                for key in misconf.keys():
                    if key not in finding and not isinstance(misconf[key], (dict, list)):
                        finding[key] = misconf[key]
                
                fieldnames.update(finding.keys())
                findings.append(finding)
        
        if not findings:
            print("[i] No vulnerabilities found to export to CSV")
            return True
            
        # Ensure consistent field order
        field_order = [
            'target', 'class', 'type', 'vulnerability_id', 'pkg_name', 
            'installed_version', 'fixed_version', 'severity', 'title',
            'description', 'cvss_score', 'cwe_ids', 'references',
            'published_date', 'last_modified_date'
        ]
        
        # Add any extra fields that weren't in our default order
        extra_fields = [f for f in sorted(fieldnames) if f not in field_order]
        field_order.extend(extra_fields)
        
        # Write to CSV
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=field_order, quoting=csv.QUOTE_MINIMAL)
            writer.writeheader()
            for finding in findings:
                writer.writerow(finding)
                
        print(f"[i] Exported {len(findings)} vulnerabilities to {csv_path}")
        return True
        
    except Exception as e:
        print(f"[!] Error converting Trivy JSON to CSV: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

# Convenience functions for different scan types
def scan_docker_image(image_name: str, output_dir: str, use_docker: bool = True) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Scan a Docker image for vulnerabilities.
    
    Args:
        image_name: Name of the Docker image to scan
        output_dir: Directory to save scan results
        use_docker: Whether to use Docker-based scanning
        
    Returns:
        Tuple of (success, findings)
    """
    return run_trivy_scan(image_name, output_dir, ScanType.IMAGE, use_docker)

def scan_dockerfile(dockerfile_path: str, output_dir: str, dockerfile_context: Optional[str] = None, use_docker: bool = True) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Scan a Dockerfile for security issues.
    
    Args:
        dockerfile_path: Path to the Dockerfile
        output_dir: Directory to save scan results
        dockerfile_context: Context directory for the Dockerfile (defaults to Dockerfile directory)
        use_docker: Whether to use Docker-based scanning
        
    Returns:
        Tuple of (success, findings)
    """
    kwargs = {}
    if dockerfile_context:
        kwargs['dockerfile_context'] = dockerfile_context
    
    return run_trivy_scan(dockerfile_path, output_dir, ScanType.DOCKERFILE, use_docker, **kwargs)

def scan_git_repository(repo_url: str, output_dir: str, use_docker: bool = True) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Scan a Git repository for vulnerabilities.
    
    Args:
        repo_url: Git repository URL (e.g., https://github.com/user/repo.git)
        output_dir: Directory to save scan results
        use_docker: Whether to use Docker-based scanning
        
    Returns:
        Tuple of (success, findings)
    """
    return run_trivy_scan(repo_url, output_dir, ScanType.GIT_REPO, use_docker)

def scan_filesystem(path: str, output_dir: str, use_docker: bool = True) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Scan a filesystem path for vulnerabilities.
    
    Args:
        path: Filesystem path to scan
        output_dir: Directory to save scan results
        use_docker: Whether to use Docker-based scanning
        
    Returns:
        Tuple of (success, findings)
    """
    return run_trivy_scan(path, output_dir, ScanType.FILESYSTEM, use_docker)
