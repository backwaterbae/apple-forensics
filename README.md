# macOS Forensics Toolkit

**Professional-grade forensic analysis tools for macOS systems**

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Forensic%20Use-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active%20development-brightgreen.svg)]()

## Overview

A comprehensive suite of forensic analysis tools for macOS systems, designed for digital forensics investigators, incident responders, and security analysts. Built with forensic soundness and real-world workflows in mind.

## Current Tools (Phase 1 & 2 Complete ✅)

### 1. Spindump & Memory Dump Analyzer
**Status:** Production Ready  
**File:** `dump_analyzer.py`

Advanced forensic analysis tool for Mac spindump files and memory dumps.

**Features:**
- Multi-format support (spindump, memory dumps)
- Exploit signature detection (180+ signatures)
- Batch processing capabilities
- Context preservation (processes, PIDs, line numbers)
- Chunked memory dump processing

**Quick Start:**
```bash
python3 dump_analyzer.py -d spindump.txt -r signatures_enhanced.txt
```

[Full Documentation](README.md)

---

### 2. Log Directory Analyzer ⭐ NEW
**Status:** Production Ready (v1.1)  
**File:** `log_directory_analyzer.py`

Intelligent log file discovery and analysis for macOS forensic investigations.

**Features:**
- Automatic recursive directory scanning
- Intelligent log type detection (7+ types)
- Three pattern types (exact, partial, regex)
- Enhanced forensic output with timestamps
- Multi-format reports (CSV, JSON, Markdown)
- 210+ pre-built detection patterns

**Quick Start:**
```bash
python3 log_directory_analyzer.py -p macos_security_patterns.txt
```

**Enhanced Output (v1.1):**
- Analysis date/time (chain of custody)
- Log file name (explicit identification)
- Log event timestamp (when it occurred)
- Full untruncated log lines
- Complete forensic metadata

[Full Documentation](README_LOG_ANALYZER.md)

---

## Detection Pattern Libraries

### Included Pattern Sets

**`macos_security_patterns.txt`** (60+ patterns)
- Authentication failures and authorization issues
- Privilege escalation attempts
- Firewall events and network security
- Gatekeeper, XProtect, SIP violations
- SSH/remote access, keychain operations

**`crash_patterns.txt`** (50+ patterns)
- Exception types and segmentation faults
- Memory allocation failures
- Kernel panics and fatal errors
- Application crashes and hangs
- Thread and dylib issues

**`malware_patterns.txt`** (100+ patterns)
- Known macOS malware families (Shlayer, Dacls, WindTail, EvilQuest, Adload, etc.)
- Exploit indicators and CVE references
- Persistence mechanisms and code injection
- C2 communication and data exfiltration
- APT indicators and reverse shells

**`signatures_enhanced.txt`** (180+ patterns)
- Process and memory exploit signatures
- Shellcode patterns and ROP gadgets
- Malicious function calls
- Suspicious string patterns

**Total: 400+ professional-grade detection patterns**

---

## Quick Start Guide

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/macos-forensics-toolkit.git
cd macos-forensics-toolkit

# No dependencies required - uses Python 3 standard library
python3 --version  # Requires Python 3.7+
```

### Basic Forensic Workflow

```bash
# 1. Analyze system logs
python3 log_directory_analyzer.py \
  -p macos_security_patterns.txt crash_patterns.txt malware_patterns.txt \
  -v

# 2. Analyze spindump files
python3 dump_analyzer.py \
  -d ~/Library/Logs/*.spindump \
  -r signatures_enhanced.txt \
  -w macos_whitelist.txt

# 3. Review findings
# Start with markdown reports (organized by severity)
open log_analysis_*.md
open dump_analysis_*.md
```

### Incident Response Triage

```bash
# Quick security scan
python3 log_directory_analyzer.py \
  -p macos_security_patterns.txt malware_patterns.txt \
  -o incident_triage/

# Check for HIGH severity findings
grep "HIGH" incident_triage/*.csv
```

---

## Planned Tools (Phase 3 & Beyond 📋)

### Phase 3: System Artifacts Analysis

Based on the [7 Essential macOS Forensic Artifacts](https://www.magnetforensics.com/blog/essential-artifacts-for-macos-forensics/):

1. **User Home Directory Analyzer** - Shell history, documents, downloads
2. **System Logs Parser (Enhanced)** - system.log, install.log, appfirewall.log
3. **Safari Browser Forensics** - History.db, bookmarks, downloads
4. **Keychain Analyzer** - Passwords, credentials (with legal authorization)
5. **Time Machine Backup Analyzer** - Historical file recovery
6. **Spotlight Database Analyzer** - File metadata and search index
7. **Apple Unified Log Parser** - Comprehensive modern logging

Plus complementary tools:
- **Process Tree Visualizer** - Visual process hierarchy
- **Launch Agents Parser** - Persistence detection
- **Image Transcription** - Bulk OCR on image directories
- **Image Forensics** - EXIF, metadata, steganography

See [Project Tracker](MACOS_FORENSICS_PROJECT_TRACKER.md) for complete roadmap.

---

## Project Structure

```
macos-forensics-toolkit/
├── dump_analyzer.py                    # Spindump/memory analyzer
├── log_directory_analyzer.py           # Log analyzer (v1.1)
│
├── Pattern Files/
│   ├── macos_security_patterns.txt     # 60+ security patterns
│   ├── crash_patterns.txt              # 50+ crash patterns
│   ├── malware_patterns.txt            # 100+ malware patterns
│   ├── signatures_enhanced.txt         # 180+ exploit signatures
│   └── macos_whitelist.txt             # 83 legitimate Apple services
│
├── Documentation/
│   ├── README.md                       # Spindump analyzer docs
│   ├── README_LOG_ANALYZER.md          # Log analyzer docs
│   ├── LOG_ANALYZER_GUIDE.md           # Complete user guide
│   ├── LOG_ANALYZER_QUICKREF.md        # Quick reference
│   ├── HOW_TO_RUN_LOG_ANALYZER.md      # Step-by-step instructions
│   ├── DELIVERY_SUMMARY.md             # Project overview
│   └── MACOS_FORENSICS_PROJECT_TRACKER.md  # Roadmap
│
└── Project Management/
    ├── macos_forensics_project_tracker.csv  # Spreadsheet tracker
    └── project_dashboard.html               # Visual dashboard
```

---

## Features & Benefits

### Forensic Soundness
✅ Read-only operations (no modifications to evidence)  
✅ Chain of custody timestamps  
✅ Hash verification support  
✅ Complete context preservation  

### Professional Output
✅ Three report formats (CSV, JSON, Markdown)  
✅ Severity classification (HIGH/MEDIUM/LOW)  
✅ Category grouping (Security, Crash, Malware)  
✅ Full log lines with timestamps  

### Enterprise Ready
✅ Batch processing for scale  
✅ SIEM integration (JSON export)  
✅ Timeline analysis support  
✅ Zero external dependencies  

### Investigator Friendly
✅ Intelligent auto-detection  
✅ Human-readable reports  
✅ Comprehensive documentation  
✅ Real-world workflows  

---

## Common Use Cases

### Incident Response
```bash
# Quick triage
python3 log_directory_analyzer.py -p macos_security_patterns.txt malware_patterns.txt -o triage/

# Deep dive if threats found
python3 log_directory_analyzer.py \
  -d ~/Library/Logs /Library/Logs \
  -p macos_security_patterns.txt crash_patterns.txt malware_patterns.txt \
  -o deep_dive/ -v
```

### Malware Analysis
```bash
# Analyze suspicious system
python3 log_directory_analyzer.py -p malware_patterns.txt -o malware_scan/
python3 dump_analyzer.py -d suspicious.spindump -r signatures_enhanced.txt
```

### Crash Investigation
```bash
# Focus on crash reports
python3 log_directory_analyzer.py \
  -d ~/Library/Logs/DiagnosticReports \
  -p crash_patterns.txt -o crash_investigation/
```

### System Audit
```bash
# Comprehensive system analysis
python3 log_directory_analyzer.py \
  -d ~/Library/Logs /Library/Logs \
  -p macos_security_patterns.txt crash_patterns.txt \
  -o system_audit/ -v
```

---

## Integration

### With SIEM Tools
```bash
# Export to Splunk/ELK
python3 log_directory_analyzer.py -p patterns.txt -f json
curl -X POST http://siem:8088/services/collector -d @log_analysis_*.json
```

### Timeline Analysis
```bash
# Findings include ISO timestamps for correlation
cat log_analysis_*.json | jq '.findings[] | .timestamp'
```

### Cross-Tool Correlation
```bash
# Analyze both logs and dumps
python3 log_directory_analyzer.py -p signatures_enhanced.txt
python3 dump_analyzer.py -d *.spindump -r signatures_enhanced.txt

# Compare findings across tools
```

---

## Documentation

### Tool-Specific Guides
- [Spindump Analyzer Documentation](README.md)
- [Log Analyzer Documentation](README_LOG_ANALYZER.md)
- [Log Analyzer Complete Guide](LOG_ANALYZER_GUIDE.md)
- [Log Analyzer Quick Reference](LOG_ANALYZER_QUICKREF.md)

### Project Documentation
- [Project Tracker & Roadmap](MACOS_FORENSICS_PROJECT_TRACKER.md)
- [Delivery Summary](DELIVERY_SUMMARY.md)
- [Project Dashboard](project_dashboard.html) - Interactive visual tracker

### How-To Guides
- [How to Run Log Analyzer](HOW_TO_RUN_LOG_ANALYZER.md)
- [Enhanced Output Format](FINAL_FORMAT.md)

---

## Version History

### Phase 2 Complete (2025-12-22)
- ✅ Log Directory Analyzer v1.1 with enhanced output
- ✅ 210+ detection patterns across 3 libraries
- ✅ Project tracking system (CSV + HTML dashboard)
- ✅ 7 Essential macOS Artifacts added to roadmap

### Phase 1 Complete (2025-12-21)
- ✅ Spindump & Memory Dump Analyzer
- ✅ 180+ exploit signatures
- ✅ macOS whitelist (83 legitimate services)

### Coming Next (Phase 3)
- 📋 User Home Directory Analyzer
- 📋 Apple Unified Log Parser
- 📋 System Logs Parser (Enhanced)
- 📋 7 Essential Artifacts + Complementary Tools

---

## Requirements

- **Python:** 3.7 or higher
- **OS:** macOS (tools designed for macOS forensics)
- **Dependencies:** None (pure Python standard library)
- **Privileges:** Some system logs require sudo

---

## Legal & Ethical Use

⚠️ **This toolkit is designed for legitimate purposes only:**

✅ **Authorized Uses:**
- Digital forensic investigations with proper authorization
- Incident response on systems you own or are authorized to investigate
- Security research and vulnerability assessment
- Educational purposes in controlled environments

❌ **Prohibited:**
- Unauthorized access to systems
- Privacy violations
- Any illegal activities

**Always ensure:**
- Proper legal authorization before analysis
- Compliance with organizational policies
- Adherence to chain of custody procedures
- Respect for privacy and data protection laws

---

## Contributing

Contributions welcome! Please:

1. Follow existing code style and structure
2. Add tests for new features
3. Update documentation
4. Use descriptive commit messages
5. Submit pull requests

**Priority Areas:**
- Additional detection patterns
- New forensic artifacts (Phase 3 tools)
- Performance optimizations
- Bug fixes

---

## Support & Community

### Getting Help
- Review comprehensive documentation
- Check troubleshooting sections in guides
- Open GitHub issues for bugs

### Feedback
- Report false positives/negatives
- Suggest new detection patterns
- Request new features
- Share forensic workflows

---

## Acknowledgments

Built with feedback from digital forensics professionals and incident responders. Pattern libraries incorporate industry best practices and real-world threat intelligence.

**Special thanks to:**
- Magnet Forensics for documenting essential macOS artifacts
- macOS security research community
- Professional forensic investigators providing feedback

---

## License

This toolkit is provided for legitimate forensic analysis, incident response, and security research purposes. See LICENSE file for full terms.

---

## Project Status

**Active Development** - Phase 3 planning in progress

- ✅ Phase 1: Foundation (Complete)
- ✅ Phase 2: Log Analysis (Complete)  
- 📋 Phase 3: System Artifacts (Planned - 14 capabilities)
- 📋 Phase 4: Malware Intelligence (Planned)
- 🔮 Phase 5: Integration & Automation (Future)

See [Interactive Dashboard](project_dashboard.html) for visual progress tracking.

---

**🔍 Professional macOS Forensic Analysis Made Accessible**

Ready to analyze? Start with the [Quick Start Guide](#quick-start-guide) above!
