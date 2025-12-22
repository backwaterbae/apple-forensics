# macOS Log Directory Analyzer

**Intelligent log file discovery and analysis for macOS forensic investigations**

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Forensic%20Use-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-production-brightgreen.svg)]()

## Overview

The macOS Log Directory Analyzer is a production-ready forensic tool that automatically discovers, classifies, and analyzes log files across macOS systems. Designed for digital forensics investigators, incident responders, and security analysts.

### Key Features

- ✅ **Automatic Log Discovery** - Recursively scans directories for log files
- ✅ **Intelligent Classification** - Auto-detects 7+ log types (crash, diagnostic, system, etc.)
- ✅ **Three Pattern Types** - Exact, Partial (case-insensitive), and Regex matching
- ✅ **Enhanced Forensic Output** - Includes timestamps, full log lines, and metadata
- ✅ **Multi-Format Reports** - CSV, JSON, and Markdown outputs
- ✅ **Severity Classification** - Automatic risk assessment (HIGH/MEDIUM/LOW)
- ✅ **Zero Dependencies** - Pure Python 3 standard library

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/macos-forensics-toolkit.git
cd macos-forensics-toolkit

# No dependencies required - uses Python 3 standard library
python3 --version  # Requires Python 3.7+
```

### Basic Usage

```bash
# Scan your user logs with security patterns
python3 log_directory_analyzer.py -p macos_security_patterns.txt

# Comprehensive scan with all pattern sets
python3 log_directory_analyzer.py \
  -p macos_security_patterns.txt crash_patterns.txt malware_patterns.txt \
  -v

# Scan specific directory
python3 log_directory_analyzer.py \
  -d ~/Library/Logs \
  -p macos_security_patterns.txt
```

### Output

Three report formats are generated:

1. **CSV** - Machine-readable for spreadsheets/SIEM
2. **JSON** - Structured data for programmatic analysis  
3. **Markdown** - Human-readable with enhanced forensic details

**Start with the Markdown report** - organized by severity with complete context.

## Enhanced Output Format

Each finding includes comprehensive forensic information:

```markdown
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
  Dec 21 10:31:22 MacBook kernel[0]: Authentication failed for user: testuser
  ```
- **Context:** `Dec 21 10:31:22 MacBook kernel[0]: Authentication failed...`
```

## Pattern Files Included

### Pre-Built Pattern Libraries

- **`macos_security_patterns.txt`** (60+ patterns)
  - Authentication failures, authorization issues
  - Privilege escalation, firewall events
  - Gatekeeper, XProtect, SIP violations
  - Keychain access, SSH/remote access

- **`crash_patterns.txt`** (50+ patterns)
  - Exception types, segmentation faults
  - Memory issues, kernel panics
  - Fatal errors, thread issues
  - Application hangs, dylib problems

- **`malware_patterns.txt`** (100+ patterns)
  - Known macOS malware families
  - Exploit indicators, CVE references
  - Adware/PUP, persistence mechanisms
  - Code injection, C2 communication

**Total: 210+ professional-grade detection patterns**

## Pattern File Format

### Basic Patterns

```
# Exact match (case-sensitive)
EXACT:kernel panic

# Partial match (case-insensitive)
PARTIAL:authentication fail

# Regex pattern
REGEX:CVE-\d{4}-\d+
```

### With Metadata

```
PARTIAL:malware|CATEGORY:Security|SEVERITY:HIGH|DESC:Malware detected
REGEX:error.*code\s+\d+|CATEGORY:Error|SEVERITY:MEDIUM
```

## Command-Line Options

```bash
usage: log_directory_analyzer.py [-h] [-d DIRECTORIES [DIRECTORIES ...]]
                                 [-p PATTERNS [PATTERNS ...]] [-o OUTPUT_DIR]
                                 [-f {csv,json,md,markdown,all}]
                                 [--no-recursive] [--create-example FILE]
                                 [--list-only] [-v]

Options:
  -d, --directories     Directories to scan (default: ~/Library/Logs)
  -p, --patterns        Pattern file(s) for searching
  -o, --output-dir      Output directory for reports
  -f, --format          Report format: csv, json, md, all (default: all)
  --no-recursive        Disable recursive directory scanning
  --create-example      Create example pattern file
  --list-only           List log files without analyzing
  -v, --verbose         Verbose output
```

## Forensic Workflows

### Quick Security Scan

```bash
# Scan for high-priority security indicators
python3 log_directory_analyzer.py \
  -p macos_security_patterns.txt \
  -o security_scan/

# Review high-severity findings
grep "HIGH" security_scan/*.csv
```

### Comprehensive Analysis

```bash
# Full scan with all patterns
python3 log_directory_analyzer.py \
  -d ~/Library/Logs /Library/Logs \
  -p macos_security_patterns.txt crash_patterns.txt malware_patterns.txt \
  -o full_analysis/ \
  -v
```

### Incident Response

```bash
# Quick triage
python3 log_directory_analyzer.py \
  -p macos_security_patterns.txt malware_patterns.txt \
  -o incident_triage/

# Deep dive if threats found
python3 log_directory_analyzer.py \
  -d ~/Library/Logs /Library/Logs /var/log \
  -p macos_security_patterns.txt crash_patterns.txt malware_patterns.txt \
  -o incident_deep_dive/ \
  -v
```

### System Logs (requires sudo)

```bash
sudo python3 log_directory_analyzer.py \
  -d /var/log \
  -p macos_security_patterns.txt
```

## Log Types Detected

The analyzer automatically classifies these log types:

- **Crash Reports** (`.crash`, `.ips`) - Application crashes
- **Diagnostic Reports** (`.diag`) - System diagnostics
- **Spindump Reports** (`.spin`) - Process sampling
- **Panic Reports** (`.panic`) - Kernel panics
- **Application Logs** (`.log`) - Standard application logs
- **System Logs** - System-level events
- **Text Logs** (`.txt`) - General text-based logs

## Common Log Locations

### User Logs
```bash
~/Library/Logs                      # User application logs
~/Library/Logs/CrashReporter        # User crash reports
~/Library/Logs/DiagnosticReports    # User diagnostics
```

### System Logs
```bash
/Library/Logs                       # System-wide application logs
/var/log                            # System logs (requires sudo)
```

## Integration

### With Spindump Analyzer

```bash
# Analyze logs
python3 log_directory_analyzer.py -p signatures_enhanced.txt

# Analyze spindumps
python3 dump_analyzer.py -d *.spindump -r signatures_enhanced.txt
```

### Export to SIEM

```bash
# Generate JSON for Splunk/ELK
python3 log_directory_analyzer.py -p patterns.txt -f json

# Send to SIEM
curl -X POST http://siem:8088/services/collector \
  -H "Authorization: Splunk TOKEN" \
  -d @log_analysis_*.json
```

### Timeline Analysis

```bash
# All findings include ISO timestamps
cat log_analysis_*.json | jq '.findings[] | .timestamp'
```

## Performance

Based on testing:

- **Small directories** (10-50 logs): < 2 seconds
- **Medium directories** (100-500 logs): 5-10 seconds  
- **Large directories** (1000+ logs): 20-30 seconds

**Memory usage:** Minimal (line-by-line processing)

## Troubleshooting

### No log files found
```bash
# Check directory exists
ls -la ~/Library/Logs

# Try absolute path
python3 log_directory_analyzer.py -d /Users/yourname/Library/Logs -p patterns.txt
```

### Permission denied
```bash
# System logs require sudo
sudo python3 log_directory_analyzer.py -d /var/log -p patterns.txt
```

### No patterns loaded
```bash
# Create example pattern file
python3 log_directory_analyzer.py --create-example patterns.txt
```

## Documentation

- **`LOG_ANALYZER_GUIDE.md`** - Comprehensive user guide
- **`LOG_ANALYZER_QUICKREF.md`** - Quick reference card
- **`HOW_TO_RUN_LOG_ANALYZER.md`** - Step-by-step instructions
- **`FINAL_FORMAT.md`** - Enhanced output format details

## Project Structure

```
macos-forensics-toolkit/
├── log_directory_analyzer.py       # Main analyzer
├── macos_security_patterns.txt     # 60+ security patterns
├── crash_patterns.txt              # 50+ crash patterns
├── malware_patterns.txt            # 100+ malware patterns
├── LOG_ANALYZER_GUIDE.md           # Complete documentation
├── LOG_ANALYZER_QUICKREF.md        # Quick reference
└── HOW_TO_RUN_LOG_ANALYZER.md      # Usage instructions
```

## Version History

- **v1.1** (2025-12-22): Enhanced markdown output with timestamps and full log lines
- **v1.0** (2025-12-21): Initial release with intelligent log discovery and analysis

## Related Tools

This tool is part of the **macOS Forensics Toolkit** which includes:

- **Spindump & Memory Dump Analyzer** - Process and memory analysis
- **Log Directory Analyzer** - Intelligent log analysis (this tool)
- **System Artifacts Analyzers** (Planned) - Safari, Keychain, Time Machine, Unified Logs

See `MACOS_FORENSICS_PROJECT_TRACKER.md` for the complete roadmap.

## License

This tool is provided for legitimate forensic analysis and security research purposes only. Always ensure proper legal authorization before analyzing systems.

## Contributing

Contributions welcome! Please:

1. Follow existing code style
2. Add tests for new features
3. Update documentation
4. Submit pull requests

## Support

For issues or questions:
- Review documentation in the `docs/` folder
- Check troubleshooting section above
- Open an issue on GitHub

## Credits

Created for digital forensics and incident response workflows. Built with feedback from professional forensic investigators.

---

**⚠️ Legal Notice:** This tool is designed for legitimate forensic analysis, incident response, and security research. Always operate under proper legal authority and follow organizational policies.

**🔍 Ready to analyze your Mac!**
