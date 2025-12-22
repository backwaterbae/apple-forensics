# macOS Log Directory Analyzer - User Guide

## Overview

The **Log Directory Analyzer** is an intelligent forensic tool that automatically discovers, classifies, and analyzes log files in macOS systems. It's designed to scan entire log directories (like `~/Library/Logs`) and search for user-defined patterns, IOCs, and security indicators.

## Key Features

### Intelligent Log Discovery
- **Automatic Scanning**: Recursively scans directories for log files
- **Type Detection**: Automatically classifies logs (crash, diagnostic, application, system)
- **Smart Filtering**: Skips hidden files and non-log data
- **Multi-Directory**: Scan multiple directories in one pass

### Pattern Matching
- **Three Match Types**: Exact, Partial (case-insensitive), Regex
- **Metadata Support**: Attach categories, severity, descriptions to patterns
- **Flexible Signatures**: Compatible with existing signature files
- **Auto-Severity**: Automatically classifies findings by risk level

### Comprehensive Reporting
- **Multiple Formats**: CSV, JSON, Markdown
- **Severity Classification**: HIGH, MEDIUM, LOW
- **Category Grouping**: Organize findings by threat type
- **Timeline Ready**: ISO timestamps for correlation

## Installation

```bash
# No dependencies - uses Python 3 standard library
chmod +x log_directory_analyzer.py
```

## Quick Start

### 1. Create Example Pattern File

```bash
./log_directory_analyzer.py --create-example patterns.txt
```

### 2. Scan ~/Library/Logs (Default)

```bash
./log_directory_analyzer.py -p patterns.txt
```

### 3. Scan Specific Directory

```bash
./log_directory_analyzer.py -d /var/log -p patterns.txt
```

### 4. List Log Files Without Analyzing

```bash
./log_directory_analyzer.py --list-only
```

## Usage Examples

### Basic Usage

```bash
# Scan default location with patterns
./log_directory_analyzer.py -p security_patterns.txt

# Scan multiple directories
./log_directory_analyzer.py \
  -d ~/Library/Logs /Library/Logs /var/log \
  -p patterns.txt

# Non-recursive scan (single directory level)
./log_directory_analyzer.py \
  -d ~/Library/Logs \
  -p patterns.txt \
  --no-recursive
```

### Output Control

```bash
# Save reports to specific directory
./log_directory_analyzer.py \
  -p patterns.txt \
  -o /cases/case-001/analysis/

# Generate only CSV output
./log_directory_analyzer.py \
  -p patterns.txt \
  -f csv

# Generate only Markdown report
./log_directory_analyzer.py \
  -p patterns.txt \
  -f md
```

### Advanced Analysis

```bash
# Verbose output for debugging
./log_directory_analyzer.py \
  -p patterns.txt \
  -v

# Multiple pattern files
./log_directory_analyzer.py \
  -p exploits.txt malware.txt network_iocs.txt

# Combine with existing signatures
./log_directory_analyzer.py \
  -p signatures_enhanced.txt signatures_macos.txt \
  -d ~/Library/Logs
```

## Pattern File Format

### Basic Patterns

```
# Comments start with #

# Exact match (case-sensitive)
EXACT:kernel panic
EXACT:Exception Type:

# Partial match (case-insensitive)
PARTIAL:authentication fail
PARTIAL:permission denied

# Regex pattern
REGEX:error.*code\s+\d+
REGEX:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
```

### Patterns with Metadata

```
# Pattern with category and severity
PARTIAL:malware|CATEGORY:Security|SEVERITY:HIGH

# Full metadata
EXACT:CVE-2024-|CATEGORY:Vulnerability|SEVERITY:HIGH|DESC:Recent CVE reference

# Multiple metadata fields
PARTIAL:sudo|CATEGORY:Security|SEVERITY:MEDIUM|DESC:Privilege escalation attempt
```

### Metadata Fields

- **CATEGORY** (or **CAT**): Organize findings (Security, Malware, Network, etc.)
- **SEVERITY** (or **SEV**): Override auto-severity (HIGH, MEDIUM, LOW)
- **DESCRIPTION** (or **DESC**): Explain what the pattern indicates

## Log Type Detection

The analyzer automatically detects these log types:

### By Extension
- `.crash` → crash report
- `.ips` → iOS/macOS crash format
- `.panic` → kernel panic
- `.spin` → spindump report
- `.diag` → diagnostic report
- `.log` → application log

### By Content
- **Crash Reports**: "Incident Identifier", "Exception Type"
- **Diagnostic**: "Diagnostic Report", "sysdiagnose"
- **Spindump**: "spindump.*report", "Heavy format"
- **System**: "kernel[", "com.apple."

## Common Log Locations

### User Logs
```bash
~/Library/Logs              # User application logs
~/Library/Logs/CrashReporter # User crash reports
~/Library/Logs/DiagnosticReports # User diagnostics
```

### System Logs
```bash
/Library/Logs               # System-wide application logs
/var/log                    # System logs (requires sudo)
/private/var/log            # System logs (alternative path)
```

### Specific Applications
```bash
~/Library/Logs/Firefox
~/Library/Logs/Google/Chrome
~/Library/Logs/Adobe
~/Library/Logs/Steam
```

## Output Formats

### CSV Report
Machine-readable format for SIEM integration or spreadsheet analysis:

```csv
timestamp,log_file,log_type,line_number,match_type,pattern,context,severity,category,full_line,log_timestamp
2025-12-22T10:30:00,system.log,application,1234,partial,authentication fail,"Dec 21 10:31:22 MacBook kernel[0]: Authen...",HIGH,Security,"Dec 21 10:31:22 MacBook kernel[0]: Authentication failed for user: admin",Dec 21 10:31:22
```

### JSON Report
Structured data with complete metadata:

```json
{
  "analysis_timestamp": "2025-12-22T10:30:00",
  "total_log_files": 47,
  "total_findings": 23,
  "severity_summary": {
    "HIGH": 5,
    "MEDIUM": 12,
    "LOW": 6
  },
  "findings": [
    {
      "timestamp": "2025-12-22T10:30:00.123456",
      "log_file": "system.log",
      "log_type": "application",
      "line_number": 1234,
      "match_type": "partial",
      "pattern": "authentication fail",
      "context": "Dec 21 10:31:22 MacBook kernel[0]: Authen...",
      "severity": "HIGH",
      "category": "Security",
      "full_line": "Dec 21 10:31:22 MacBook kernel[0]: Authentication failed for user: admin",
      "log_timestamp": "Dec 21 10:31:22"
    }
  ]
}
```

### Markdown Report
Human-readable report with severity grouping and enhanced forensic details:

```markdown
# macOS Log Analysis Report

**Total Findings:** 23

## Severity Summary
- **HIGH:** 5
- **MEDIUM:** 12
- **LOW:** 6

## Findings
### HIGH Severity
#### Line 1234

- **Date/Time Logged:** 2025-12-22T10:30:00.123456
- **Log File Name:** system.log
- **Log Date/Time:** Dec 21 10:31:22
- **Pattern:** `authentication fail`
- **Match Type:** partial
- **Log Type:** application
- **Category:** Security
- **Full Log Line:**
  ```
  Dec 21 10:31:22 MacBook kernel[0]: Authentication failed for user: admin
  ```
- **Context:** `Dec 21 10:31:22 MacBook kernel[0]: Authentication failed for user: admin`
```

## Forensic Workflows

### 1. Initial Triage

```bash
# Quick scan for high-severity indicators
./log_directory_analyzer.py \
  -p critical_iocs.txt \
  -o triage/

# Review high-severity findings
grep "HIGH" triage/*.csv
```

### 2. Comprehensive Analysis

```bash
# Scan all standard log locations
./log_directory_analyzer.py \
  -d ~/Library/Logs /Library/Logs \
  -p exploits.txt malware.txt network.txt \
  -o analysis/ \
  -v
```

### 3. Incident Investigation

```bash
# Create case directory
mkdir -p /cases/2025-001/logs/

# Analyze with incident-specific patterns
./log_directory_analyzer.py \
  -d ~/Library/Logs \
  -p incident_iocs.txt known_apt_patterns.txt \
  -o /cases/2025-001/analysis/
```

### 4. Timeline Correlation

```bash
# Generate JSON for timeline tools
./log_directory_analyzer.py \
  -p patterns.txt \
  -f json \
  -o timeline/

# Correlate with other evidence
# (timestamps are ISO format for easy parsing)
```

## Pattern Development Workflow

### Step 1: Identify Indicators

```bash
# Find interesting patterns in logs
grep -r "error" ~/Library/Logs/*.log | head -20
grep -r "fail" ~/Library/Logs/*.log | head -20
```

### Step 2: Create Pattern File

```bash
cat > custom_patterns.txt << 'EOF'
# Custom IOCs for Case XYZ
PARTIAL:suspicious_binary|CATEGORY:Malware|SEVERITY:HIGH
REGEX:192\.168\.1\.50|CATEGORY:Network|SEVERITY:HIGH
PARTIAL:unauthorized access|CATEGORY:Security|SEVERITY:HIGH
EOF
```

### Step 3: Test Patterns

```bash
# Test on known-good logs (should have minimal findings)
./log_directory_analyzer.py \
  -d ~/Library/Logs \
  -p custom_patterns.txt \
  --list-only

# Test on suspected malicious logs
./log_directory_analyzer.py \
  -d /evidence/suspicious_logs \
  -p custom_patterns.txt
```

### Step 4: Refine

```bash
# Review findings, adjust patterns
# Add false positives to whitelist
# Increase specificity of patterns
```

## Integration with Other Tools

### With Spindump Analyzer

```bash
# Analyze both logs and spindumps
./log_directory_analyzer.py \
  -d ~/Library/Logs \
  -p signatures_enhanced.txt

./dump_analyzer.py \
  -d ~/Library/Logs/spindump.txt \
  -r signatures_enhanced.txt

# Correlate findings
```

### With Timeline Tools

```bash
# Export to JSON for plaso/log2timeline
./log_directory_analyzer.py \
  -p patterns.txt \
  -f json

# Import findings into timeline
```

### With SIEM

```bash
# Generate CSV for Splunk/ELK ingestion
./log_directory_analyzer.py \
  -p patterns.txt \
  -f csv

# Send to SIEM
curl -X POST http://siem:8088/services/collector \
  -H "Authorization: Splunk TOKEN" \
  -d @log_analysis_*.json
```

## Performance Considerations

### Large Log Directories

```bash
# Use --list-only first to see scope
./log_directory_analyzer.py --list-only

# If too many files, scan subdirectories separately
./log_directory_analyzer.py -d ~/Library/Logs/App1 -p patterns.txt
./log_directory_analyzer.py -d ~/Library/Logs/App2 -p patterns.txt
```

### Pattern Optimization

- **Exact matches** are fastest (string comparison)
- **Partial matches** are fast (case-insensitive substring)
- **Regex patterns** are slower (pattern compilation and matching)

**Tip**: Use exact/partial when possible, reserve regex for complex patterns

### Memory Usage

The analyzer reads logs line-by-line, so memory usage is minimal even with large log files.

## Common Use Cases

### 1. Malware Detection

```bash
# Pattern file: malware_iocs.txt
PARTIAL:malware|CATEGORY:Malware|SEVERITY:HIGH
PARTIAL:trojan|CATEGORY:Malware|SEVERITY:HIGH
PARTIAL:backdoor|CATEGORY:Malware|SEVERITY:HIGH
REGEX:suspicious.*binary|CATEGORY:Malware|SEVERITY:MEDIUM

# Run analysis
./log_directory_analyzer.py -p malware_iocs.txt
```

### 2. Authentication Failures

```bash
# Pattern file: auth_failures.txt
PARTIAL:authentication fail|CATEGORY:Security|SEVERITY:HIGH
PARTIAL:login failed|CATEGORY:Security|SEVERITY:HIGH
PARTIAL:access denied|CATEGORY:Security|SEVERITY:MEDIUM
PARTIAL:permission denied|CATEGORY:Security|SEVERITY:MEDIUM

# Run analysis
./log_directory_analyzer.py -p auth_failures.txt
```

### 3. Crash Analysis

```bash
# Scan crash reports specifically
./log_directory_analyzer.py \
  -d ~/Library/Logs/DiagnosticReports \
  -p crash_patterns.txt

# Pattern file focuses on crash indicators
EXACT:Exception Type:
PARTIAL:segmentation fault
REGEX:crashed.*thread
```

### 4. Network Activity

```bash
# Pattern file: network_iocs.txt
REGEX:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|CATEGORY:Network
PARTIAL:connection refused|CATEGORY:Network
PARTIAL:timeout|CATEGORY:Network
EXACT:DNS lookup|CATEGORY:Network

# Scan for network activity
./log_directory_analyzer.py -p network_iocs.txt
```

## Troubleshooting

### No Log Files Found

**Problem**: "No log files found"

**Solutions**:
- Check directory path is correct
- Ensure directory exists: `ls -la ~/Library/Logs`
- Try with verbose mode: `-v`
- Check permissions: `ls -la ~/Library/`

### Permission Denied

**Problem**: "Warning: Permission denied"

**Solutions**:
- Some logs require elevated privileges
- Use `sudo` for system logs: `sudo ./log_directory_analyzer.py -d /var/log`
- Copy logs to accessible location first

### No Patterns Loaded

**Problem**: "No patterns loaded. Cannot analyze."

**Solutions**:
- Verify pattern file exists: `ls -la patterns.txt`
- Check pattern file format (not empty, valid patterns)
- Use `--create-example` to generate valid pattern file

### Too Many Results

**Problem**: Thousands of findings, hard to review

**Solutions**:
- Focus on HIGH severity: `grep "HIGH" analysis/*.csv`
- Use more specific patterns (EXACT instead of PARTIAL)
- Create whitelist for false positives
- Narrow search to specific log types

## Best Practices

### Pattern Management

1. **Version Control**: Keep patterns in Git
2. **Document Sources**: Comment where patterns came from
3. **Test Regularly**: Validate against known-good and known-bad samples
4. **Peer Review**: Have another analyst review patterns

### Evidence Handling

1. **Read-Only**: Analyzer never modifies log files
2. **Hash Logs**: `shasum -a 256 *.log > evidence.sha256`
3. **Preserve Originals**: Work on copies
4. **Document Analysis**: Save all reports for chain of custody

### Workflow Integration

1. **Automated Triage**: Run on all new systems
2. **Baseline Creation**: Scan clean systems to build whitelists
3. **Continuous Monitoring**: Schedule periodic scans
4. **Incident Response**: Prepare pattern sets in advance

## Command Reference

```bash
# Full command syntax
./log_directory_analyzer.py [OPTIONS]

Options:
  -d, --directories DIR [DIR ...]
      Directories to scan (default: ~/Library/Logs)
  
  -p, --patterns FILE [FILE ...]
      Pattern files for searching
  
  -o, --output-dir DIR
      Output directory for reports (default: current)
  
  -f, --format {csv,json,md,markdown,all}
      Report format (default: all)
  
  --no-recursive
      Disable recursive scanning
  
  --create-example FILE
      Create example pattern file
  
  --list-only
      List log files without analyzing
  
  -v, --verbose
      Verbose output
  
  -h, --help
      Show help message
```

## Example Pattern Files

See the included example pattern files:
- `example_log_patterns.txt` - General purpose patterns
- `macos_security_patterns.txt` - macOS security indicators
- `crash_patterns.txt` - Crash and error detection
- `network_patterns.txt` - Network activity patterns

## Support

For issues, questions, or contributions:
- Review the documentation
- Check troubleshooting section
- Test with `--verbose` mode
- Use `--create-example` for valid pattern format

## Version History

- **v1.0** (2025-12-21): Initial release
  - Intelligent log discovery
  - Multiple pattern types
  - Multi-format reporting
  - Automatic log type detection
