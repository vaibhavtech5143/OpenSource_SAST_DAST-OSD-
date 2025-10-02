#!/bin/bash
# Multi-tool security scanner for SAST/DAST analysis
# Usage: ./security_scanner.sh <repository_path> [target_url]
# Optional target_url enables Nuclei DAST scanning

set -e

REPO_PATH=${1:-.}
REPORT_FILE="./security_report.json"

# Detect execution environment for proper Docker volume mounting
DOCKER_SOCKET="/var/run/docker.sock"
INSIDE_DOCKER_CONTAINER=""

# Check if we're running inside a Docker containe
if [ -f /.dockerenv ] || grep -q 'docker\|lxc' /proc/1/cgroup 2>/dev/null; then
    INSIDE_DOCKER_CONTAINER="true"
    echo "Detected execution inside Docker container"
fi

# Function to get absolute path that works in both environments
get_absolute_path() {
    local path="$1"
    if [ "$INSIDE_DOCKER_CONTAINER" = "true" ]; then
        # Inside Docker, use simple absolute path resolution
        cd "$path" && pwd
    else
        # On host, use realpath if available, otherwise fallback
        if command -v realpath >/dev/null 2>&1; then
            realpath "$path"
        else
            cd "$path" && pwd
        fi
    fi
}

# Function to create Docker volume mount string
create_volume_mount() {
    local host_path="$1"
    local container_path="$2"
    
    if [ "$INSIDE_DOCKER_CONTAINER" = "true" ]; then
        # Inside Docker container, use simpler bind mount
        echo "-v $host_path:$container_path"
    else
        # On host system, use full path
        local abs_path=$(get_absolute_path "$host_path")
        echo "-v $abs_path:$container_path"
    fi
}

# Function to run Docker with fallback options
run_docker_with_fallback() {
    local docker_cmd="$1"
    
    # First try the normal command
    if eval "$docker_cmd"; then
        return 0
    fi
    
    # If that fails and we're in Docker-in-Docker, try without Docker socket mount
    if [ "$INSIDE_DOCKER_CONTAINER" = "true" ]; then
        echo "Docker command failed, trying without Docker socket mount..."
        local fallback_cmd=$(echo "$docker_cmd" | sed 's/-v [^[:space:]]*docker\.sock[^[:space:]]* //g')
        if eval "$fallback_cmd"; then
            return 0
        fi
    fi
    
    # If still failing, try with host networking
    echo "Docker command failed, trying with host networking..."
    local network_cmd=$(echo "$docker_cmd" | sed 's/docker run/docker run --network=host/')
    eval "$network_cmd" || return 1
}

echo "=== Starting Security Scan of $REPO_PATH ==="#!/bin/bash
# Multi-tool security scanner for SAST/DAST analysis
# Usage: ./security_scanner.sh <repository_path> [target_url]
# Optional target_url enables Nuclei DAST scanning

set -e

REPO_PATH=${1:-"./test_repo"}
REPORT_FILE="./security_report.json"

echo "=== Starting Security Scan of $REPO_PATH ==="

# Debug output
echo "Environment debug:"
echo "- INSIDE_DOCKER_CONTAINER: $INSIDE_DOCKER_CONTAINER"
echo "- Docker socket exists: $([ -S "$DOCKER_SOCKET" ] && echo "yes" || echo "no")"
echo "- Working directory: $(pwd)"
echo "- REPO_PATH absolute: $(get_absolute_path "$REPO_PATH" 2>/dev/null || echo "failed to resolve")"

# Initialize report structure
cat > "$REPORT_FILE" << 'EOJSON'
{
  "scan_timestamp": "",
  "repository_path": "",
  "tools_used": [],
  "summary": {
    "total_vulnerabilities": 0,
    "high_severity": 0,
    "medium_severity": 0,
    "low_severity": 0
  },
  "findings": []
}
EOJSON

# Update timestamp and repo path using Python
python3 -c "
import json
from datetime import datetime

with open('$REPORT_FILE', 'r') as f:
    report = json.load(f)

report['scan_timestamp'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
report['repository_path'] = '$REPO_PATH'

with open('$REPORT_FILE', 'w') as f:
    json.dump(report, f, indent=2)
"

echo "--- Running Bearer (SAST Security Scanning) ---"

# Create output directories
BEARER_OUTPUT_DIR="./output/bearer"
mkdir -p "$BEARER_OUTPUT_DIR"

# Get volume mount strings for Beare
REPO_MOUNT=$(create_volume_mount "$REPO_PATH" "/src")
OUTPUT_MOUNT=$(create_volume_mount "$BEARER_OUTPUT_DIR" "/output")

# Additional Docker options for Docker-in-Docke
DOCKER_OPTS=""
if [ "$INSIDE_DOCKER_CONTAINER" = "true" ] && [ -S "$DOCKER_SOCKET" ]; then
    DOCKER_OPTS="-v $DOCKER_SOCKET:$DOCKER_SOCKET"
fi

# Run Bearer for SAST analysis
BEARER_CMD="docker run --rm --user 0:0 $REPO_MOUNT $OUTPUT_MOUNT $DOCKER_OPTS bearer/bearer:latest scan /src --format json --output /output/bearer_results.json --quiet --skip-path \"/src/.git\" 2>/dev/null"

if run_docker_with_fallback "$BEARER_CMD" || true; then

if [ -f "$OUTPUT_DIR/bearer_findings.json" ] && [ -s "$OUTPUT_DIR/bearer_findings.json" ]; then
    echo "Bearer found security issues, processing results..."
    
    # Process Bearer results and add to main report
    python3 -c "
import json
import sys

try:
    with open('$OUTPUT_DIR/bearer_findings.json', 'r') as f:
        bearer_data = json.load(f)
    
    findings = []
    for severity in ['critical', 'high', 'medium', 'low']:
        if severity in bearer_data:
            for finding in bearer_data[severity]:
                findings.append({
                    'tool_name': 'bearer',
                    'severity': severity.upper(),
                    'vulnerability_type': 'sast_finding',
                    'file_path': finding.get('filename', ''),
                    'line_number': finding.get('line_number', 0),
                    'rule_id': finding.get('id', ''),
                    'description': finding.get('title', '') + ': ' + finding.get('description', '')[:200]
                })
    
    with open('bearer_processed.json', 'w') as f:
        json.dump(findings, f)
        
    print(f'Processed {len(findings)} Bearer security findings')
except Exception as e:
    print(f'Error processing Bearer results: {e}', file=sys.stderr)
"
    
    # Merge into main report if processing succeeded
    if [ -f "bearer_processed.json" ]; then
        python3 -c "
import json

# Load main report
with open('$REPORT_FILE', 'r') as f:
    report = json.load(f)

# Load Bearer findings
with open('bearer_processed.json', 'r') as f:
    bearer_findings = json.load(f)

# Merge findings
report['findings'].extend(bearer_findings)
if 'bearer' not in report['tools_used']:
    report['tools_used'].append('bearer')

# Save updated report
with open('$REPORT_FILE', 'w') as f:
    json.dump(report, f, indent=2)
"
        rm bearer_processed.json
    fi
else
    echo "No security issues found by Bearer"
    python3 -c "
import json
with open('$REPORT_FILE', 'r') as f:
    report = json.load(f)
if 'bearer' not in report['tools_used']:
    report['tools_used'].append('bearer')
with open('$REPORT_FILE', 'w') as f:
    json.dump(report, f, indent=2)
"
fi

echo "--- Running Gitleaks (Secret Scanning) ---"

# Run Gitleaks for secret detection
GITLEAKS_OUTPUT_DIR="./output/gitleaks"
mkdir -p "$GITLEAKS_OUTPUT_DIR"

# Get volume mount strings for Gitleaks
REPO_MOUNT=$(create_volume_mount "$REPO_PATH" "/workspace")
OUTPUT_MOUNT=$(create_volume_mount "$GITLEAKS_OUTPUT_DIR" "/output")

GITLEAKS_CMD="docker run --rm --user 0:0 $REPO_MOUNT $OUTPUT_MOUNT $DOCKER_OPTS zricethezav/gitleaks:latest detect --source /workspace --report-format json --report-path /output/gitleaks_results.json --no-git"

run_docker_with_fallback "$GITLEAKS_CMD" || true

if [ -f "$GITLEAKS_OUTPUT_DIR/gitleaks_results.json" ] && [ -s "$GITLEAKS_OUTPUT_DIR/gitleaks_results.json" ]; then
    echo "Gitleaks found secrets, processing results..."
    
    # Process Gitleaks results and add to main report
    python3 -c "
import json
import sys

try:
    with open('$GITLEAKS_OUTPUT_DIR/gitleaks_results.json', 'r') as f:
        gitleaks_data = json.load(f)
    
    findings = []
    for finding in gitleaks_data:
        findings.append({
            'tool_name': 'gitleaks',
            'severity': 'HIGH',
            'vulnerability_type': 'secret_exposure',
            'file_path': finding.get('File', ''),
            'line_number': finding.get('StartLine', 0),
            'rule_id': finding.get('RuleID', ''),
            'description': 'Secret detected: ' + finding.get('Description', '') + ' at line ' + str(finding.get('StartLine', 0))
        })
    
    with open('gitleaks_processed.json', 'w') as f:
        json.dump(findings, f)
        
    print(f'Processed {len(findings)} Gitleaks secret findings')
except Exception as e:
    print(f'Error processing Gitleaks results: {e}', file=sys.stderr)
"
    
    # Merge into main report if processing succeeded
    if [ -f "gitleaks_processed.json" ]; then
        python3 -c "
import json

# Load main report
with open('$REPORT_FILE', 'r') as f:
    report = json.load(f)

# Load Gitleaks findings
with open('gitleaks_processed.json', 'r') as f:
    gitleaks_findings = json.load(f)

# Merge findings
report['findings'].extend(gitleaks_findings)
if 'gitleaks' not in report['tools_used']:
    report['tools_used'].append('gitleaks')

# Save updated report
with open('$REPORT_FILE', 'w') as f:
    json.dump(report, f, indent=2)
"
        rm gitleaks_processed.json
    fi
else
    echo "No secrets found by Gitleaks"
    python3 -c "
import json
with open('$REPORT_FILE', 'r') as f:
    report = json.load(f)
if 'gitleaks' not in report['tools_used']:
    report['tools_used'].append('gitleaks')
with open('$REPORT_FILE', 'w') as f:
    json.dump(report, f, indent=2)
"
fi

echo "--- Running Trivy (Container Security) ---"

# Run Trivy for container security analysis
TRIVY_OUTPUT_DIR="./output/trivy"
mkdir -p "$TRIVY_OUTPUT_DIR"

# Scan Dockerfile if it exists
if [ -f "$REPO_PATH/Dockerfile" ]; then
    echo "Scanning Dockerfile for security misconfigurations..."
    
    # Get volume mount strings for Trivy
    OUTPUT_MOUNT=$(create_volume_mount "$TRIVY_OUTPUT_DIR" "/tmp/output")
    CONTEXT_MOUNT=$(create_volume_mount "$REPO_PATH" "/tmp/context")
    
    TRIVY_CMD="docker run --rm --user 0:0 $OUTPUT_MOUNT $CONTEXT_MOUNT $DOCKER_OPTS aquasec/trivy:latest config --format json --output /tmp/output/trivy_dockerfile_results.json --severity CRITICAL,HIGH,MEDIUM,LOW /tmp/context/Dockerfile"
    
    run_docker_with_fallback "$TRIVY_CMD" || true
    
    if [ -f "$TRIVY_OUTPUT_DIR/trivy_dockerfile_results.json" ] && [ -s "$TRIVY_OUTPUT_DIR/trivy_dockerfile_results.json" ]; then
        echo "Trivy found Dockerfile issues, processing results..."
        
        # Process Trivy results
        python3 -c "
import json
import sys

try:
    with open('$TRIVY_OUTPUT_DIR/trivy_dockerfile_results.json', 'r') as f:
        trivy_data = json.load(f)
    
    findings = []
    for result in trivy_data.get('Results', []):
        for misconfig in result.get('Misconfigurations', []):
            findings.append({
                'tool_name': 'trivy',
                'severity': misconfig.get('Severity', 'UNKNOWN'),
                'vulnerability_type': 'docker_misconfiguration',
                'file_path': result.get('Target', ''),
                'rule_id': misconfig.get('ID', ''),
                'description': misconfig.get('Title', '') + ': ' + misconfig.get('Message', '')
            })
    
    with open('trivy_processed.json', 'w') as f:
        json.dump(findings, f)
        
    print(f'Processed {len(findings)} Trivy security findings')
except Exception as e:
    print(f'Error processing Trivy results: {e}', file=sys.stderr)
"
        
        # Merge into main report if processing succeeded
        if [ -f "trivy_processed.json" ]; then
            python3 -c "
import json

# Load main report
with open('$REPORT_FILE', 'r') as f:
    report = json.load(f)

# Load Trivy findings
with open('trivy_processed.json', 'r') as f:
    trivy_findings = json.load(f)

# Merge findings
report['findings'].extend(trivy_findings)
if 'trivy' not in report['tools_used']:
    report['tools_used'].append('trivy')

# Save updated report
with open('$REPORT_FILE', 'w') as f:
    json.dump(report, f, indent=2)
"
            rm trivy_processed.json
        fi
    else
        echo "No Dockerfile security issues found by Trivy"
        python3 -c "
import json
with open('$REPORT_FILE', 'r') as f:
    report = json.load(f)
if 'trivy' not in report['tools_used']:
    report['tools_used'].append('trivy')
with open('$REPORT_FILE', 'w') as f:
    json.dump(report, f, indent=2)
"
    fi
else
    echo "No Dockerfile found for Trivy scanning"
    python3 -c "
import json
with open('$REPORT_FILE', 'r') as f:
    report = json.load(f)
if 'trivy' not in report['tools_used']:
    report['tools_used'].append('trivy')
with open('$REPORT_FILE', 'w') as f:
    json.dump(report, f, indent=2)
"
fi

echo "--- Running Nuclei (DAST Security Scanning) ---"

# Run Nuclei for DAST analysis if URL is provided
NUCLEI_OUTPUT_DIR="./output/nuclei"
mkdir -p "$NUCLEI_OUTPUT_DIR"

# Check if a target URL is provided as second argument, otherwise use a default test
TARGET_URL=${2:-""}

if [ -n "$TARGET_URL" ]; then
    echo "Running Nuclei DAST scan against: $TARGET_URL"
    
    # Get volume mount strings for Nuclei
    OUTPUT_MOUNT=$(create_volume_mount "$NUCLEI_OUTPUT_DIR" "/app")
    
    NUCLEI_CMD="docker run --rm --user 0:0 $OUTPUT_MOUNT $DOCKER_OPTS projectdiscovery/nuclei:latest -u \"$TARGET_URL\" -jsonl /app/nuclei_results.jsonl -silent -timeout 10 -c 50"
    
    run_docker_with_fallback "$NUCLEI_CMD" || true
    
    if [ -f "$NUCLEI_OUTPUT_DIR/nuclei_results.jsonl" ] && [ -s "$NUCLEI_OUTPUT_DIR/nuclei_results.jsonl" ]; then
        echo "Nuclei found DAST issues, processing results..."
        
        # Process Nuclei results and add to main report
        python3 -c "
import json
import sys

try:
    findings = []
    with open('$NUCLEI_OUTPUT_DIR/nuclei_results.jsonl', 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('[WRN]'):
                try:
                    nuclei_finding = json.loads(line)
                    
                    findings.append({
                        'tool_name': 'nuclei',
                        'severity': nuclei_finding.get('info', {}).get('severity', 'info').upper(),
                        'vulnerability_type': 'dast_finding',
                        'file_path': nuclei_finding.get('host', ''),
                        'template_id': nuclei_finding.get('template-id', ''),
                        'description': nuclei_finding.get('info', {}).get('name', '') + ': ' + nuclei_finding.get('info', {}).get('description', '')
                    })
                except json.JSONDecodeError:
                    continue
    
    # Also create CSV output
    if findings:
        import csv
        csv_path = '$NUCLEI_OUTPUT_DIR/nuclei_results.csv'
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['tool_name', 'severity', 'vulnerability_type', 'file_path', 'template_id', 'description']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in findings:
                writer.writerow(finding)
        print(f'Created CSV report: {csv_path}')
    
    with open('nuclei_processed.json', 'w') as f:
        json.dump(findings, f)
        
    print(f'Processed {len(findings)} Nuclei DAST findings')
except Exception as e:
    print(f'Error processing Nuclei results: {e}', file=sys.stderr)
"
        
        # Merge into main report if processing succeeded
        if [ -f "nuclei_processed.json" ]; then
            python3 -c "
import json

# Load main report
with open('$REPORT_FILE', 'r') as f:
    report = json.load(f)

# Load Nuclei findings
with open('nuclei_processed.json', 'r') as f:
    nuclei_findings = json.load(f)

# Merge findings
report['findings'].extend(nuclei_findings)
if 'nuclei' not in report['tools_used']:
    report['tools_used'].append('nuclei')

# Save updated report
with open('$REPORT_FILE', 'w') as f:
    json.dump(report, f, indent=2)
"
            rm nuclei_processed.json
        fi
    else
        echo "No DAST issues found by Nuclei"
        python3 -c "
import json
with open('$REPORT_FILE', 'r') as f:
    report = json.load(f)
if 'nuclei' not in report['tools_used']:
    report['tools_used'].append('nuclei')
with open('$REPORT_FILE', 'w') as f:
    json.dump(report, f, indent=2)
"
    fi
else
    echo "No target URL provided for Nuclei DAST scanning (use: ./security_scanner.sh <repo_path> <target_url>)"
    python3 -c "
import json
with open('$REPORT_FILE', 'r') as f:
    report = json.load(f)
if 'nuclei' not in report['tools_used']:
    report['tools_used'].append('nuclei')
with open('$REPORT_FILE', 'w') as f:
    json.dump(report, f, indent=2)
"
fi

echo "--- Finalizing Security Report ---"

# Calculate summary statistics
python3 -c "
import json

try:
    with open('$REPORT_FILE', 'r') as f:
        report = json.load(f)
    
    findings = report.get('findings', [])
    total = len(findings)
    high = len([f for f in findings if f.get('severity') in ['CRITICAL', 'HIGH']])
    medium = len([f for f in findings if f.get('severity') == 'MEDIUM'])
    low = len([f for f in findings if f.get('severity') == 'LOW'])
    
    report['summary'] = {
        'total_vulnerabilities': total,
        'high_severity': high,
        'medium_severity': medium,
        'low_severity': low
    }
    
    with open('$REPORT_FILE', 'w') as f:
        json.dump(report, f, indent=2)
        
    print(f'Security scan completed: {total} total findings ({high} high, {medium} medium, {low} low severity)')
except Exception as e:
    print(f'Error finalizing report: {e}')
"

echo "=== Security Scan Complete ==="
echo "Report saved to: $REPORT_FILE"

# Show summary using Python
echo ""
echo "=== SCAN SUMMARY ==="
python3 -c "
import json
with open('$REPORT_FILE', 'r') as f:
    report = json.load(f)

summary = report.get('summary', {})
print(f\"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}\")
print(f\"High Severity: {summary.get('high_severity', 0)}\")
print(f\"Medium Severity: {summary.get('medium_severity', 0)}\")
print(f\"Low Severity: {summary.get('low_severity', 0)}\")
print()
print(f\"Tools Used: {', '.join(report.get('tools_used', []))}\")
"