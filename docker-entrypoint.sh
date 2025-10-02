#!/bin/bash
# Docker container entrypoint for SAST/DAST Security Scanner
# Usage examples:
#   docker run ... scanner --repo https://github.com/user/repo.git
#   docker run ... scanner --repo https://github.com/user/repo.git --target https://example.com
#   docker run ... scanner --help

set -e

# Default values
REPO_URL=""
TARGET_URL=""
OUTPUT_DIR="/workspace/output"
OUTPUT_NAME=""
BRANCH="main"
CLONE_DIR="/workspace/repo"

# Help function
show_help() {
    cat << EOF
SAST/DAST Security Scanner (Docker Version)

Usage: docker run [docker-options] <image> [scanner-options]

Scanner Options:
  --repo <url>          Repository URL (required)
  --branch <name>       Branch name (default: main)  
  --target <url>        Target URL for DAST scanning (optional)
  --output <dir>        Output directory (default: /workspace/output)
  --output-name <name>  Custom output folder name (default: output)
  --clone-dir <dir>     Clean directory (default: /workspace/repo)
  --skip-bearer         Skip Bearer SAST scanning
  --skip-sast           Skip regex-based SAST scanning
  --skip-trivy          Skip Trivy container scanning
  --skip-gitleaks       Skip Gitleaks secret scanning
  --skip-nuclei         Skip Nuclei DAST scanning
  --help               Show this help

Examples:
  # Basic SAST scan (results in ./output/)
  docker run -v \${PWD}:/workspace vaibhav2633/sast-dast-security-scanner \\
    --repo https://github.com/user/repo.git

  # SAST + DAST scan with custom output folder (results in ./my-scan-results/)
  docker run -v \${PWD}:/workspace vaibhav2633/sast-dast-security-scanner \\
    --repo https://github.com/user/repo.git --target https://example.com \\
    --output-name my-scan-results

  # SAST only with timestamped output folder
  docker run -v \${PWD}:/workspace vaibhav2633/sast-dast-security-scanner \\
    --repo https://github.com/user/repo.git --output-name scan-\$(date +%Y%m%d-%H%M%S)
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --repo)
            REPO_URL="$2"
            shift 2
            ;;
        --target)
            TARGET_URL="$2"
            shift 2
            ;;
        --branch)
            BRANCH="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --output-name)
            OUTPUT_NAME="$2"
            shift 2
            ;;
        --clone-dir)
            CLONE_DIR="$2"
            shift 2
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        --skip-bearer|--skip-sast|--skip-trivy|--skip-gitleaks|--skip-nuclei)
            # Pass through to Python script
            EXTRA_ARGS="$EXTRA_ARGS $1"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check required arguments
if [ -z "$REPO_URL" ]; then
    echo "Error: --repo is required"
    echo "Use --help for usage information"
    exit 1
fi

# Handle custom output directory
if [ -n "$OUTPUT_NAME" ]; then
    OUTPUT_DIR="/workspace/$OUTPUT_NAME"
    echo "Using custom output directory: $OUTPUT_NAME"
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build Python command
PYTHON_CMD="python3 /app/scanner_cli.py --repo '$REPO_URL' --branch '$BRANCH' --output '$OUTPUT_DIR' --clone-dir '$CLONE_DIR'"

if [ -n "$OUTPUT_NAME" ]; then
    PYTHON_CMD="$PYTHON_CMD --output-name '$OUTPUT_NAME'"
fi

if [ -n "$TARGET_URL" ]; then
    PYTHON_CMD="$PYTHON_CMD --target '$TARGET_URL'"
fi

if [ -n "$EXTRA_ARGS" ]; then
    PYTHON_CMD="$PYTHON_CMD $EXTRA_ARGS"
fi

echo "Starting SAST/DAST Security Scanner..."
echo "Repository: $REPO_URL"
echo "Branch: $BRANCH"
echo "Output (container): $OUTPUT_DIR"
if [ -n "$OUTPUT_NAME" ]; then
    echo "Output (host): ./$OUTPUT_NAME"
else
    echo "Output (host): ./output"
fi
if [ -n "$TARGET_URL" ]; then
    echo "DAST Target: $TARGET_URL"
fi
echo ""

# Execute the Python scanner
eval $PYTHON_CMD