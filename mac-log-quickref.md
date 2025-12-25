# Log Directory Analyzer - Quick Reference

## Installation
```bash
chmod +x log_directory_analyzer.py
```

## Quick Start
```bash
# Create example patterns
./log_directory_analyzer.py --create-example patterns.txt

# Scan default location (~/Library/Logs)
./log_directory_analyzer.py -p patterns.txt

# Scan specific directory
./log_directory_analyzer.py -d /var/log -p patterns.txt
```

## Common Commands

### Basic Scanning
```bash
# Scan with security patterns
./log_directory_analyzer.py -p macos_security_patterns.txt

# Scan with multiple pattern sets
./log_directory_analyzer.py -p macos_security_patterns.txt crash_patterns.txt malware_patterns.txt

# List log files without analyzing
./log_directory_analyzer.py --list-only
```

### Multiple Directories
```bash
# Scan user and system logs
./log_directory_analyzer.py -d ~/Library/Logs /Library/Logs -p patterns.txt

# Scan all standard locations
./log_directory_analyzer.py \
  -d ~/Library/Logs /Library/Logs /var/log \
  -p patterns.txt
```

### Output Control
```bash
# Save to specific directory
./log_directory_analyzer.py -p patterns.txt -o /cases/analysis/

# CSV only
./log_directory_analyzer.py -p patterns.txt -f csv

# JSON only
./log_directory_analyzer.py -p patterns.txt -f json

# Markdown only
./log_directory_analyzer.py -p patterns.txt -f md
```

### Advanced Options
```bash
# Non-recursive (single directory level)
./log_directory_analyzer.py -d ~/Library/Logs --no-recursive -p patterns.txt

# Verbose output
./log_directory_analyzer.py -p patterns.txt -v
```

## Pattern File Syntax

### Basic Patterns
```
# Exact match (case-sensitive)
EXACT:kernel panic

# Partial match (case-insensitive)
PARTIAL:authentication fail

# Regex pattern
REGEX:error.*code\s+\d+
```

### With Metadata
```
PARTIAL:malware|CATEGORY:Security|SEVERITY:HIGH|DESC:Malware detected
REGEX:CVE-\d{4}-\d+|CATEGORY:Vulnerability|SEVERITY:HIGH
```

## Output Files

- `log_analysis_TIMESTAMP.csv` - Machine-readable findings
- `log_analysis_TIMESTAMP.json` - Structured data with metadata
- `log_analysis_TIMESTAMP.md` - Human-readable report

**Start with the Markdown (.md) file** - organized by severity with:
- Date/Time Logged (when analysis ran)
- Log File Name (which specific file)
- Log Date/Time (when event occurred)
- Pattern matched
- Full log line
- All forensic metadata

## Severity Levels

- **HIGH**: Critical threats, exploits, malware
- **MEDIUM**: Suspicious activity, warnings, potential threats
- **LOW**: Informational, minor issues

## Forensic Workflows

### Quick Triage
```bash
# High-priority indicators only
./log_directory_analyzer.py -p critical_iocs.txt

# Review high-severity findings
grep "HIGH" log_analysis_*.csv
```

### Comprehensive Analysis
```bash
# Full scan with all pattern sets
./log_directory_analyzer.py \
  -d ~/Library/Logs /Library/Logs \
  -p macos_security_patterns.txt crash_patterns.txt malware_patterns.txt \
  -o analysis/ \
  -v
```

### Incident Response
```bash
# Case-specific analysis
mkdir -p /cases/2025-001/analysis
./log_directory_analyzer.py \
  -p incident_iocs.txt \
  -o /cases/2025-001/analysis/
```

## Integration Examples

### With Spindump Analyzer
```bash
# Analyze logs
./log_directory_analyzer.py -p signatures_enhanced.txt

# Analyze spindumps
./dump_analyzer.py -d *.spindump -r signatures_enhanced.txt
```

### SIEM Export
```bash
# Generate JSON for ingestion
./log_directory_analyzer.py -p patterns.txt -f json

# Send to SIEM
curl -X POST http://siem:8088/collector \
  -H "Authorization: Splunk TOKEN" \
  -d @log_analysis_*.json
```

## Included Pattern Files

- `macos_security_patterns.txt` - Authentication, authorization, security events
- `crash_patterns.txt` - Crashes, errors, panics, diagnostics
- `malware_patterns.txt` - Malware, exploits, suspicious activity

## Command-Line Options

```
-d, --directories DIR [DIR ...]     Directories to scan
-p, --patterns FILE [FILE ...]      Pattern files
-o, --output-dir DIR                Output directory
-f, --format {csv,json,md,all}      Report format
--no-recursive                      Single directory level
--create-example FILE               Create example patterns
--list-only                         List files without analyzing
-v, --verbose                       Verbose output
-h, --help                          Show help
```

## Output Files

- `log_analysis_TIMESTAMP.csv` - Machine-readable findings
- `log_analysis_TIMESTAMP.json` - Structured data with metadata
- `log_analysis_TIMESTAMP.md` - Human-readable report

## Severity Levels

- **HIGH**: Critical threats, exploits, malware
- **MEDIUM**: Suspicious activity, warnings, potential threats
- **LOW**: Informational, minor issues

## Tips

1. **Start Small**: Use `--list-only` to see scope first
2. **Be Specific**: Use EXACT patterns when possible for speed
3. **Layer Patterns**: Combine multiple pattern files for comprehensive coverage
4. **Review Context**: Always check the context field in reports
5. **Build Baselines**: Scan clean systems to identify false positives

## Troubleshooting

**No logs found**: Check directory path with `ls -la ~/Library/Logs`

**Permission denied**: Use `sudo` for system logs or copy to accessible location

**Too many results**: Focus on HIGH severity or use more specific patterns

**Pattern not working**: Test pattern syntax with `--create-example`
