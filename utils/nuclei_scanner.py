import os
import subprocess
import json
import csv
import re
from datetime import datetime
from typing import Tuple

def run_nuclei_dast(target_url: str, output_dir: str) -> Tuple[bool, str]:
    """Run Nuclei DAST scan via Docker against a target URL.

    Uses volume mounts for output. Saves results as JSONL to a file in output_dir. 
    Returns (success, output_path).
    """
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, 'nuclei_results.jsonl')

    # Convert paths for Docker (Windows compatibility)
    docker_output_dir = os.path.abspath(output_dir)

    # Pull the latest Nuclei image
    try:
        print("[i] Pulling latest Nuclei Docker image...")
        pull_cmd = ['docker', 'pull', 'projectdiscovery/nuclei:latest']
        pull_result = subprocess.run(pull_cmd, capture_output=True, text=True, timeout=300)
        if pull_result.returncode != 0:
            print(f"[!] Warning: Could not pull Nuclei image: {pull_result.stderr.strip()}")
            print("[i] Proceeding with existing image if available...")
    except Exception as e:
        print(f"[!] Error pulling Nuclei image: {e}")
        return False, ""

    # Ensure output directory has proper permissions
    try:
        os.chmod(output_dir, 0o777)
    except:
        pass  # Ignore permission errors on some systems
    
    # Build Docker command with volume mounts
    cmd = [
        'docker', 'run', '--rm',
        '--user', '0:0',  # Run as root to avoid permission issues
        '-v', f'{docker_output_dir}:/app',
        'projectdiscovery/nuclei:latest',
        '-u', target_url,
        '-jsonl', '/app/nuclei_results.jsonl',
        '-silent',
        '-timeout', '10',
        '-c', '50',
    ]

    print(f"[i] Running command: {' '.join(cmd)}")

    try:
        # Use explicit encoding and error handling to avoid Unicode issues
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=600,
            encoding='utf-8',
            errors='replace'  # Replace problematic characters instead of crashing
        )
    except subprocess.TimeoutExpired:
        print("[!] Nuclei scan timed out after 600 seconds")
        return False, ""
    except Exception as e:
        print(f"[!] Error running Nuclei Docker command: {e}")
        return False, ""

    if result.returncode not in (0, 1):
        # Handle potential None values from subprocess output
        stderr_text = result.stderr.strip() if result.stderr else ""
        stdout_text = result.stdout.strip() if result.stdout else ""
        err = stderr_text or stdout_text or "Unknown error"
        print(f"[!] Nuclei scan failed with exit code {result.returncode}: {err}")
        return False, ""

    # Check if the output file exists in the mounted volume
    host_out_file = os.path.join(output_dir, 'nuclei_results.jsonl')
    try:
        if os.path.exists(host_out_file):
            print(f"[i] Nuclei results saved to {host_out_file}")
        else:
            # Fallback: write stdout if it contains JSONL
            stdout_content = result.stdout.strip() if result.stdout else ""
            if stdout_content:
                with open(out_file, 'w', encoding='utf-8') as f:
                    f.write(stdout_content)
                print(f"[i] Nuclei results (from stdout) saved to {out_file}")
            else:
                print("[i] No Nuclei findings; empty results file created")
                with open(out_file, 'w', encoding='utf-8') as f:
                    f.write('')  # Create empty file instead of JSON array
        return True, out_file
    except Exception as e:
        print(f"[!] Failed to write Nuclei results: {e}")
        return False, ""

def nuclei_to_csv(json_path: str, csv_path: str) -> bool:
    """
    Convert Nuclei JSONL results to CSV format.
    
    Args:
        json_path: Path to the Nuclei JSONL results file
        csv_path: Path to save the CSV output
        
    Returns:
        bool: True if conversion was successful, False otherwise
    """
    try:
        findings = []
        with open(json_path, 'r', encoding='utf-8') as f:
            try:
                # Try to parse as a single JSON array
                data = json.load(f)
                if isinstance(data, list):
                    findings = data
                else:
                    findings = [data]
            except json.JSONDecodeError:
                # Parse as JSONL
                f.seek(0)
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        if not findings:
            print("[i] No findings to export to CSV")
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                f.write('template,severity,host,name,description,timestamp\n')
            return True

        # Define preferred field order for CSV
        field_order = [
            'template', 'type', 'name', 'author', 'severity', 'description',
            'host', 'matched', 'extracted_results', 'ip', 'timestamp',
            'matcher_name', 'extractor_name', 'curl_command', 'template_url',
            'template_id', 'info_name', 'info_author', 'info_severity',
            'info_description', 'info_reference', 'info_tags', 'info_metadata',
            'request', 'response', 'extracted_data', 'metadata', 'curl-command'
        ]

        all_fields = set()
        processed_findings = []

        for finding in findings:
            processed = {}
            def flatten_dict(d, parent_key='', sep='_'):
                for k, v in d.items():
                    new_key = f"{parent_key}{sep}{k}" if parent_key else k
                    if isinstance(v, dict):
                        flatten_dict(v, new_key, sep)
                    elif isinstance(v, list):
                        processed[new_key] = str(v)
                    else:
                        processed[new_key] = str(v) if v is not None else ''
            
            flatten_dict(finding)
            all_fields.update(processed.keys())
            processed_findings.append(processed)

        field_order = [f for f in field_order if f in all_fields]
        remaining_fields = sorted(f for f in all_fields if f not in field_order)
        field_order.extend(remaining_fields)

        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=field_order, quoting=csv.QUOTE_MINIMAL)
            writer.writeheader()
            for finding in processed_findings:
                row = {field: finding.get(field, '') for field in field_order}
                row['timestamp'] = row.get('timestamp', datetime.now().isoformat())
                writer.writerow(row)

        print(f"[i] Exported {len(processed_findings)} findings to {csv_path}")
        return True

    except Exception as e:
        print(f"[!] Error converting Nuclei results to CSV: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def _parse_nuclei_text_output(text_file, csv_path: str) -> bool:
    """Parse Nuclei text output and convert to CSV."""
    try:
        findings = []
        current_finding = {}
        patterns = {
            'template': r'\[([^]]+)\](?=\s*\[)',
            'severity': r'\[([a-zA-Z]+)\](?=\s+\[|$)',
            'host': r'https?://[^\s\]]+',
            'name': r'\]\s+([^\[]+)'
        }

        for line in text_file:
            line = line.strip()
            if not line:
                if current_finding:
                    findings.append(current_finding)
                    current_finding = {}
                continue

            template_match = re.search(patterns['template'], line)
            if template_match:
                current_finding['template'] = template_match.group(1).strip()

            severity_match = re.search(patterns['severity'], line, re.IGNORECASE)
            if severity_match:
                current_finding['severity'] = severity_match.group(1).upper()

            host_match = re.search(patterns['host'], line)
            if host_match:
                current_finding['host'] = host_match.group(0)

            name_match = re.search(patterns['name'], line)
            if name_match:
                current_finding['name'] = name_match.group(1).strip()

            if line and 'details' not in current_finding:
                current_finding['details'] = line
            elif line and 'details' in current_finding and line not in current_finding['details']:
                current_finding['details'] += '\n' + line

        if current_finding:
            findings.append(current_finding)

        if not findings:
            print("[i] No findings to export to CSV from text output")
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                f.write('template,severity,host,name,details,timestamp\n')
            return True

        fieldnames = ['template', 'severity', 'host', 'name', 'details', 'timestamp']
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
            writer.writeheader()
            for finding in findings:
                for field in fieldnames:
                    if field not in finding:
                        finding[field] = ''
                finding['timestamp'] = datetime.now().isoformat()
                writer.writerow(finding)

        print(f"[i] Exported {len(findings)} findings from text output to {csv_path}")
        return True

    except Exception as e:
        print(f"[!] Error parsing Nuclei text output: {str(e)}")
        import traceback
        traceback.print_exc()
        return False