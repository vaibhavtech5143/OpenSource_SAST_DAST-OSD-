import os
import subprocess
import json
import shutil
import csv
import re
import tempfile
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict

@dataclass
class Finding:
    check_id: str
    path: str
    start_line: int
    end_line: int
    message: str
    severity: str
    fix: Optional[str] = None
    category: Optional[str] = None
    confidence: str = "medium"

def get_owasp_fix_suggestion(category: str, code_snippet: str) -> str:
    """Generate fix suggestions based on OWASP category."""
    fixes = {
        "A1: Injection": "Use parameterized queries or prepared statements",
        "A2: Broken Authentication": "Store secrets in environment variables or secure vault",
        "A3: Sensitive Data Exposure": "Encrypt sensitive data at rest and in transit",
        "A4: XXE": "Disable external entity processing in XML parsers",
        "A5: Broken Access Control": "Implement proper access control checks",
        "A6: Security Misconfiguration": "Disable debug mode in production",
        "A7: XSS": "Use proper output encoding/escaping for user input",
        "A8: Insecure Deserialization": "Use safe serialization libraries",
        "A9: Known Vulnerabilities": "Update to the latest secure version",
        "A10: Insufficient Logging": "Remove sensitive data from logs"
    }
    return fixes.get(category, "Review and apply security best practices")

def scan_file_for_patterns(file_path: str, patterns: List[Tuple[re.Pattern, str, str, str]]) -> List[Finding]:
    """Scan a single file for security patterns."""
    findings = []
    
    def safe_extract_line(content: str, position: int) -> str:
        """Safely extract a line of text from content at given position."""
        try:
            line_start = content.rfind('\n', 0, position) + 1
            line_end = content.find('\n', position)
            if line_end == -1:
                line_end = len(content)
            return content[line_start:line_end].strip()
        except Exception as e:
            print(f"[!] Error extracting line from {file_path}: {str(e)}")
            return "[Error extracting line]"
    
    try:
        # Skip binary files and large files (>10MB)
        if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10MB
            print(f"[i] Skipping large file: {file_path}")
            return findings
            
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        for pattern, message, severity, category in patterns:
            try:
                for match in pattern.finditer(content):
                    try:
                        line_num = content.count('\n', 0, match.start()) + 1
                        line_content = safe_extract_line(content, match.start())
                        
                        findings.append(Finding(
                            check_id=f"OWASP-{category.split(':')[0]}",
                            path=file_path,
                            start_line=line_num,
                            end_line=line_num,
                            message=f"{message}. Found: {match.group(0)[:100]}",
                            severity=severity,
                            category=category,
                            fix=get_owasp_fix_suggestion(category, line_content)
                        ))
                    except Exception as match_error:
                        print(f"[!] Error processing match in {file_path}: {str(match_error)}")
                        continue
                        
            except Exception as pattern_error:
                print(f"[!] Error applying pattern in {file_path}: {str(pattern_error)}")
                continue
                
    except Exception as e:
        print(f"[!] Error scanning {file_path}: {str(e)}")
    
    return findings

def run_security_scan(repo_path: str, output_dir: str) -> Tuple[bool, List[Finding]]:
    """Run security scan with OWASP Top 10 patterns using Python's re module."""
    try:
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # OWASP Top 10 Security Rules
        owasp_rules = [
            # A1: Injection
            (re.compile(r'(?i)\b(SELECT|INSERT|UPDATE|DELETE|EXEC(?:UTE)?|CALL|UNION).*?\bFROM\b'), 
             "SQL Injection - Use parameterized queries", "HIGH", "A1: Injection"),
             
            # A2: Broken Authentication
            (re.compile(r'(?i)\b(password|pwd|secret|key|token|api[_-]?key|auth|credential)\s*[=:].*?[\'\"].{8,}[\'\"]'), 
             "Hardcoded Credentials - Use secure storage", "HIGH", "A2: Broken Authentication"),
             
            # A3: Sensitive Data Exposure
            (re.compile(r'(?i)\b(ssn|social[ -]?security|credit[ -]?card|cc[_-]?number|account[_-]?number)\b'), 
             "Potential Sensitive Data Exposure", "HIGH", "A3: Sensitive Data Exposure"),
             
            # A4: XML External Entities (XXE)
            (re.compile(r'(?i)\b(DocumentBuilderFactory|XMLInputFactory|SAXParserFactory|XMLReader|XInclude)\b'),
             "Potential XXE Vulnerability - Disable external entity processing", "HIGH", "A4: XXE"),
             
            # A5: Broken Access Control
            (re.compile(r'(?i)\b(checkAccess|isAdmin|hasPrivilege)\s*\('), 
             "Missing Access Control Check", "MEDIUM", "A5: Broken Access Control"),
             
            # A6: Security Misconfiguration
            (re.compile(r'(?i)(?:^|\s)(debug|DEBUG)\s*=\s*(?:True|true|\'true\'|"true")'), 
             "Debug Mode Enabled in Production", "HIGH", "A6: Security Misconfiguration"),
             
            # A7: Cross-Site Scripting (XSS)
            (re.compile(r'(?i)<\s*script\b|\b(?:inner|outer)HTML\s*=|\beval\s*\('), 
             "Potential XSS Vulnerability - Sanitize user input", "HIGH", "A7: XSS"),
             
            # A8: Insecure Deserialization
            (re.compile(r'(?i)\b(ObjectInputStream|readObject)\s*\('), 
             "Insecure Deserialization - Use safe serialization", "HIGH", "A8: Insecure Deserialization"),
             
            # A9: Using Components with Known Vulnerabilities
            (re.compile(r'(?i)\bjquery\s*[<>=]\s*[0-9]|\bstruts\s*[<>=]\s*2\.3\b'), 
             "Outdated Library with Known Vulnerabilities", "MEDIUM", "A9: Known Vulnerabilities"),
             
            # A10: Insufficient Logging
            (re.compile(r'(?i)\b(password|pwd|secret|key|token|api[_-]?key)\s*[=:].*?[\s\r\n]'), 
             "Potential Sensitive Data in Logs", "MEDIUM", "A10: Insufficient Logging")
        ]
        
        all_findings = []
        file_extensions = ('.py', '.js', '.java', '.c', '.cpp', '.cs', '.php', '.rb', '.go', '.ts')
        
        # Walk through the repository and scan relevant files
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.lower().endswith(file_extensions):
                    file_path = os.path.join(root, file)
                    findings = scan_file_for_patterns(file_path, owasp_rules)
                    all_findings.extend(findings)
        
        # Save findings to CSV
        if all_findings:
            csv_path = os.path.join(output_dir, 'owasp_security_findings.csv')
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'check_id', 'path', 'start_line', 'end_line',
                    'message', 'severity', 'category', 'fix', 'confidence'
                ])
                writer.writeheader()
                for finding in all_findings:
                    writer.writerow({
                        'check_id': finding.check_id,
                        'path': finding.path,
                        'start_line': finding.start_line,
                        'end_line': finding.end_line,
                        'message': finding.message,
                        'severity': finding.severity,
                        'category': finding.category,
                        'fix': finding.fix or '',
                        'confidence': finding.confidence
                    })
            print(f"[+] Security scan completed. Found {len(all_findings)} issues. Report saved to: {csv_path}")
        else:
            print("[+] No security issues found!")
        
        return True, all_findings
    except Exception as e:
        print(f"[!] Error during security scan: {str(e)}")
        return False, []

def print_findings_summary(findings: List[Finding]) -> None:
    """Print a summary of findings to the console."""
    if not findings:
        return
        
    # Group by severity
    by_severity = {}
    for finding in findings:
        by_severity.setdefault(finding.severity, []).append(finding)
    
    # Print summary
    print("\n" + "="*50)
    print(f"{'OWASP TOP 10 SECURITY FINDINGS':^50}")
    print("="*50)
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if severity in by_severity:
            print(f"\n[{severity}] {len(by_severity[severity])} issues")
            for finding in by_severity[severity][:5]:  # Show top 5 per severity
                print(f"  - {finding.message} in {finding.path}:{finding.start_line}")
            if len(by_severity[severity]) > 5:
                print(f"  ... and {len(by_severity[severity]) - 5} more")

def sast_to_csv(sast_results: List[Dict], csv_path: str) -> bool:
    """
    Convert SAST results to CSV format.
    
    Args:
        sast_results: List of SAST findings in dictionary format
        csv_path: Path to save the CSV file
        
    Returns:
        bool: True if conversion was successful, False otherwise
    """
    try:
        if not sast_results:
            print("[i] No SAST findings to export to CSV")
            return True
        
        # Define CSV field names
        fieldnames = [
            'check_id', 'path', 'start_line', 'end_line', 
            'severity', 'confidence', 'category', 'message', 'fix'
        ]
        
        # Write findings to CSV
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for finding in sast_results:
                # Ensure all fields are present in the finding
                row = {field: finding.get(field, '') for field in fieldnames}
                writer.writerow(row)
                
        print(f"[i] SAST results saved to CSV: {csv_path}")
        return True
        
    except Exception as e:
        print(f"[!] Error converting SAST results to CSV: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_sast(files_by_lang: Dict[str, List[str]], repo_path: str):
    """
    Run OWASP Top 10 security scan on the repository.
    
    Args:
        files_by_lang: Dictionary of files grouped by language (unused in this implementation)
        repo_path: Path to the repository root
        
    Returns:
        bool: True if scan completed successfully with no findings, False otherwise
    """
    try:
        # Get the directory where the current script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Create a temporary directory for scan results
        with tempfile.TemporaryDirectory() as temp_dir:
            # Run the security scan
            success, findings = run_security_scan(repo_path, temp_dir)
            
            if not success:
                print("[!] Security scan failed")
                return []
            
            # Print summary to console
            print_findings_summary(findings)
            
            # Convert findings to a serializable format
            findings_data = []
            for finding in findings:
                finding_dict = asdict(finding)
                # Convert any non-serializable fields to strings
                for key, value in finding_dict.items():
                    if not isinstance(value, (str, int, float, bool, type(None))):
                        finding_dict[key] = str(value)
                findings_data.append(finding_dict)
            
            # Save findings to CSV
            csv_path = os.path.join(temp_dir, 'owasp_security_findings.csv')
            if not sast_to_csv(findings_data, csv_path):
                print(f"[!] Error saving SAST results to CSV: {csv_path}")
                return False
            
            return findings_data
            
    except Exception as e:
        print(f"[!] Error during SAST scan: {e}")
        import traceback
        traceback.print_exc()
        return []
