# SAST/DAST Security Scanner

A comprehensive automation tool for security scanning that integrates multiple security engines to scan source code repositories for vulnerabilities before production deployment. This tool combines Static Application Security Testing (SAST), Dynamic Application Security Testing (DAST), container security, Infrastructure as Code (IaC) scanning, and secret detection.

## 🔒 Features

### SAST (Static Application Security Testing)
- **Bearer Integration**: Professional SAST scanning using Bearer CLI in Docker
- **Custom Regex Rules**: Multi-language vulnerability detection for OWASP Top 10
- **Language Support**: Python, JavaScript, Java, PHP, Go, C/C++, and more
- **Output Formats**: JSON and CSV reports with detailed findings

### Container Security Scanning
- **Trivy Integration**: Industry-standard vulnerability scanning for container images
- **Dockerfile Analysis**: Security best practices validation
- **Multi-OS Support**: Linux, Windows, and Alpine container scanning
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW vulnerability ratings

### DAST (Dynamic Application Security Testing)
- **Nuclei Integration**: Modern vulnerability scanner with extensive template library
- **Web Application Testing**: OWASP Top 10 dynamic vulnerability detection
- **Custom Templates**: Support for custom security test templates
- **Real-time Scanning**: Live application security assessment

### Infrastructure as Code (IaC) Security
- **Trivy Config Scan**: Kubernetes, Terraform, CloudFormation security validation
- **Misconfiguration Detection**: Security best practices enforcement
- **Compliance Checking**: CIS benchmarks and security standards validation

### Secret Detection
- **Gitleaks Integration**: Advanced secret and credential detection
- **Git History Scanning**: Deep repository history analysis
- **Custom Rules**: Configurable secret patterns and false positive reduction
- **Multiple Formats**: Support for various secret types (API keys, tokens, passwords)

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Docker (for containerized security tools)
- Git
- Internet connection (for pulling security databases)

### Installation & Usage

#### Quick Start (Recommended)

**Native Python Run (Recommended And Most Stable For Now):**

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Run the scanner (requires Docker for security tools)
python3 scanner.py
```

**Alternative: Docker Run (Still In Testing There Are Various Bugs If you can solve them fell free to use this approach):**

```bash
# Build the scanner
docker build -t sast-dast-scanner .

# Run with Docker-in-Docker support (Linux/macOS)
docker run --rm -it --privileged \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd):/app" \
  sast-dast-scanner python3 scanner.py

# Run with Docker-in-Docker support (Windows PowerShell)

## Docker CLI (Non-Interactive)

For automated CI/CD pipelines or scripts, use the non-interactive Docker CLI:

**Basic SAST scan (default output):**
```bash
docker run --rm -v $(pwd):/workspace -v /var/run/docker.sock:/var/run/docker.sock \
  sast-dast-scanner --repo https://github.com/user/repo.git
```

**SAST + DAST scan with custom output folder:**
```bash
docker run --rm -v $(pwd):/workspace -v /var/run/docker.sock:/var/run/docker.sock \
  sast-dast-scanner --repo https://github.com/user/repo.git --target https://example.com \
  --output-name my-security-scan
```

**Available CLI options:**
```bash
docker run --rm sast-dast-scanner --help
```

**Output Locations:**
- Default: Results saved to `./output/` directory
- Custom: Results saved to `./<custom-name>/` directory  
- All formats: CSV and JSON reports with detailed findings  
docker run --rm -it --privileged -v /var/run/docker.sock:/var/run/docker.sock -v "${PWD}:/app" sast-dast-scanner python3 scanner.py
```

**Using Provided Scripts:**

```bash
# Linux/macOS
chmod +x run_scanner.sh
./run_scanner.sh

# Windows PowerShell  
.\run_scanner.ps1
```

2. **Follow the interactive prompts:**
   - Repository URL (GitHub, GitLab, Bitbucket, etc.)
   - Branch selection (default: main)
   - Target directory for cloning
   - Scanning preferences (SAST, DAST, secrets, etc.)

3. **View comprehensive results in `output/`:**
   ```
   output/
   ├── bearer/          # SAST findings (JSON/CSV)
   ├── trivy/           # Container vulnerabilities
   ├── trivy_config/    # IaC misconfigurations
   ├── nuclei/          # DAST findings
   ├── gitleaks/        # Secret detection results
   └── sast/            # Custom SAST rules results
   ```

## 📊 Scan Results

### Output Formats
- **JSON**: Machine-readable detailed findings
- **CSV**: Spreadsheet-compatible vulnerability reports
- **Summary Reports**: Human-readable security summaries

### Key Metrics
- Vulnerability counts by severity
- OWASP Top 10 compliance status
- Container security posture
- Secret exposure risks
- IaC security score

## 🛠️ Supported Technologies

### Programming Languages
- Python, JavaScript/TypeScript, Java
- PHP, Go, Ruby, C/C++
- Kotlin, Swift, Rust, Scala

### Container Platforms
- Docker, Podman, Containerd
- Kubernetes, OpenShift
- AWS ECR, Azure ACR, Google GCR

### IaC Frameworks
- Terraform, CloudFormation
- Kubernetes YAML, Helm Charts
- Ansible, Puppet, Chef

### Repository Platforms
- GitHub, GitLab, Bitbucket
- Azure DevOps, AWS CodeCommit
- Local repositories

## ⚙️ Configuration

### Environment Variables
```bash
# Optional: Custom Bearer configuration
export BEARER_CONFIG_FILE=/path/to/.bearer.yml

# Optional: Custom Nuclei templates
export NUCLEI_TEMPLATES_DIR=/path/to/templates

# Optional: Gitleaks configuration
export GITLEAKS_CONFIG=/path/to/gitleaks.toml
```

### Custom Rules
- **Bearer**: Modify `.bearer.yml` for custom SAST rules
- **Nuclei**: Add custom templates to templates directory
- **Gitleaks**: Configure custom secret patterns
- **Custom SAST**: Edit `utils/sast_runner.py` for regex rules


## 📈 Security Benefits

- **Shift-Left Security**: Early vulnerability detection in development
- **Comprehensive Coverage**: Multiple security testing approaches
- **Automation Ready**: CI/CD pipeline integration
- **Industry Standards**: OWASP, CIS, NIST compliance checking
- **Cost Effective**: Open-source security tools integration
- **Rapid Deployment**: Docker-based tool isolation

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests for:
- New security tool integrations
- Enhanced vulnerability detection rules
- Improved reporting formats
- Bug fixes and performance improvements

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[Trivy](https://github.com/aquasecurity/trivy)** - Container and IaC security scanning
- **[Bearer](https://github.com/bearer/bearer)** - Static application security testing
- **[Nuclei](https://github.com/projectdiscovery/nuclei)** - Dynamic application security testing
- **[Gitleaks](https://github.com/zricethezav/gitleaks)** - Secret detection and prevention
- **[OWASP](https://owasp.org/)** - Security standards and best practices

---

**🔐 Secure your code before it reaches production!**
