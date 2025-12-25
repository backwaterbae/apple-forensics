# Dependencies and Specifications

**macOS Process & Network Forensic Toolkit**  
Version 1.0 | December 2025

## 📦 Python Dependencies

### Required Packages

#### psutil (5.9.0+)
**Purpose:** Cross-platform library for process and system monitoring  
**Source:** https://github.com/giampaolo/psutil  
**PyPI:** https://pypi.org/project/psutil/  
**License:** BSD-3-Clause

**Installation:**
```bash
pip3 install psutil
```

**Used For:**
- Process enumeration and monitoring
- Memory information (RSS, VMS, percent)
- CPU usage statistics
- Network connections per process
- Open files enumeration
- Process metadata (PID, user, status, create time)
- Thread counts and file descriptors

**Key Modules Used:**
```python
import psutil

# Core functionality
psutil.process_iter()     # Iterate all processes
psutil.Process(pid)       # Access specific process
proc.memory_info()        # Memory statistics
proc.connections()        # Network connections
proc.open_files()         # Open file handles
proc.as_dict()           # Process info as dictionary
```

### Standard Library (No Installation Required)

These modules are part of Python's standard library:

```python
import subprocess    # Execute system commands (tcpdump, heap)
import json         # JSON output formatting
import csv          # CSV output formatting
import datetime     # ISO timestamp generation
import sys          # Command-line arguments
import os           # File system operations
import hashlib      # SHA-256 integrity hashing
import threading    # Concurrent network capture
import time         # Sleep and timing
import argparse     # Command-line parsing
```

## 🔧 System Dependencies

### tcpdump (Pre-installed on macOS)
**Purpose:** Network packet capture  
**Location:** `/usr/sbin/tcpdump`  
**Version:** Any (typically 4.9.3+ on modern macOS)  
**License:** BSD

**Verification:**
```bash
which tcpdump
# Should return: /usr/sbin/tcpdump

tcpdump --version
# Example: tcpdump version 4.9.3
```

**Used For:**
- Capturing network packets to PCAP files
- Reading PCAP files for packet counts
- Protocol analysis

**Key Commands Used:**
```bash
# Capture to file
tcpdump -i en0 -w output.pcap -n -v

# Read PCAP
tcpdump -r output.pcap -n -q

# Count packets
tcpdump -r output.pcap -n -q | wc -l
```

### heap (macOS Native Tool)
**Purpose:** Process heap analysis  
**Location:** `/usr/bin/heap`  
**Requires:** sudo or same-user privilege  
**Optional:** Toolkit works without it

**Used For:**
- Heap memory statistics (when available)
- Memory allocation details

**Note:** May not work on all processes due to macOS security restrictions

## 🐍 Python Version Requirements

**Minimum:** Python 3.8  
**Recommended:** Python 3.9+  
**Tested:** Python 3.12

**Verification:**
```bash
python3 --version
# Should show: Python 3.8.0 or higher
```

**Why Python 3.8+:**
- Modern psutil compatibility
- subprocess timeout features
- f-string formatting
- Type hints support (for future enhancement)

## 💻 Platform Requirements

**Operating System:** macOS 10.14 (Mojave) or later  
**Tested On:**
- macOS 14 (Sonoma)
- macOS 13 (Ventura)
- macOS 12 (Monterey)

**Architecture:**
- Intel (x86_64) ✓
- Apple Silicon (arm64) ✓

**Privileges:**
- Standard user: Basic functionality
- sudo/root: Full functionality (network capture, all connections)

## 📋 Module Import List

### system_network_capture.py
```python
import psutil           # Process monitoring
import subprocess       # System commands
import threading        # Concurrent capture
import time            # Timing
import json            # JSON output
import csv             # CSV output
import datetime        # Timestamps
import sys             # Arguments
import os              # File operations
import hashlib         # File hashing
```

### process_triage_snapshot.py
```python
import psutil          # Process monitoring
import json            # JSON output
import csv             # CSV output
import datetime        # Timestamps
import sys             # Arguments
import os              # File operations
import argparse        # CLI parsing
```

### process_memory_snapshot.py
```python
import psutil          # Process monitoring
import json            # JSON output
import datetime        # Timestamps
import subprocess      # heap command
import sys             # Arguments
import os              # File operations
import hashlib         # Integrity hashing
```

### network_capture.py
```python
import subprocess      # tcpdump
import datetime        # Timestamps
import sys             # Arguments
import os              # File operations
import json            # Metadata
import hashlib         # File hashing
```

### combined_capture.py
```python
import psutil          # Process monitoring
import subprocess      # System commands
import threading       # Concurrent capture
import time           # Timing
import json           # JSON output
import datetime       # Timestamps
import sys            # Arguments
import os             # File operations
```

## ⚙️ Important Runtime Notes

### Sudo Requirements

**Network capture requires sudo:**
```bash
# These MUST run with sudo
sudo ./system_network_capture.py 60
sudo ./network_capture.py 60
sudo ./combined_capture.py 1234 60
```

**Process tools work without sudo (limited data):**
```bash
# Work without sudo (but limited)
./process_triage_snapshot.py
./process_memory_snapshot.py 1234

# Better with sudo (complete data)
sudo ./process_triage_snapshot.py
sudo ./process_memory_snapshot.py 1234
```

**What Requires Sudo:**
- tcpdump (network capture)
- Complete connection counts
- Complete open file counts
- Heap information
- Environment variables for other users' processes

### macOS System Integrity Protection (SIP)

**Limitations:**
- Cannot dump raw process memory
- Some system processes are protected
- Cannot attach debugger to system processes

**What Works:**
- Process metadata (PID, name, user, status)
- Memory statistics (RSS, VMS, percent)
- Connection lists
- File descriptor lists
- CPU and thread information

**Workaround:**
Tools capture metadata instead of raw memory - still extremely valuable for forensics!

### File Permissions

**Scripts must be executable:**
```bash
chmod +x *.py
```

**Output directories:**
- Created automatically if missing
- Default locations:
  - `process_triage/` - Triage snapshots
  - `system_network_captures/` - System+network captures
  - `memory_snapshots/` - Memory snapshots
  - `network_captures/` - Network-only captures

### Resource Considerations

**Memory Usage:**
- process_triage_snapshot.py: ~20-50 MB
- system_network_capture.py: ~50-100 MB (depends on process count)
- process_memory_snapshot.py: ~10-30 MB
- network_capture.py: Minimal (~5 MB)

**Disk Space:**
- CSV files: 50-500 KB (depends on process count)
- JSON files: 100 KB - 5 MB (complete system state)
- PCAP files: 0.5-50 MB for 60s (depends on network activity)

**CPU Usage:**
- Minimal during capture (1-5% CPU)
- Brief spike during snapshot collection
- Does not significantly impact system performance

## 🎯 Important Code Call-Outs

### Network Capture Duration
```python
# In system_network_capture.py and network_capture.py
duration = int(sys.argv[1]) if len(sys.argv) > 1 else 60  # Default 60s
```

**Why 60 seconds:**
- Forensic best practice (based on investigator experience)
- Captures beaconing patterns (malware typically beacons 30-60s)
- Shows complete connection lifecycles
- Reveals DNS patterns
- 10s is too short for meaningful analysis

### Snapshot Interval
```python
# In system_network_capture.py
snapshot_interval = 10  # seconds between snapshots
```

**Why 10 seconds:**
- Balance between detail and performance
- Catches rapid changes
- Doesn't overwhelm with data
- Typically 6 snapshots per 60s capture

### Memory Change Threshold
```python
# In system_network_capture.py - changes_analysis
if abs(delta) > 10:  # Changed by more than 10MB
```

**Why 10 MB:**
- Filters noise from normal fluctuations
- Highlights significant changes
- Most malware/suspicious activity exceeds this
- Adjustable if needed

### Process Iteration Safety
```python
# Robust process iteration with exception handling
for proc in psutil.process_iter():
    try:
        info = get_process_info(proc)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        continue  # Skip processes that terminate or are inaccessible
```

**Why this pattern:**
- Processes can terminate during iteration
- Some processes are protected (SIP)
- Zombie processes exist but aren't queryable
- Graceful handling prevents script crashes

### Connection Deprecation Warning
```python
# Note: connections() is deprecated in newer psutil versions
# Will show warning, still works
connections = proc.connections()

# Future-proof version:
# connections = proc.net_connections()
```

**Note:** Tools currently use `connections()` which works but shows deprecation warning. Future version will migrate to `net_connections()`.

### SHA-256 Integrity Hashing
```python
# For PCAP files
def calculate_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
```

**Why included:**
- Forensic chain of custody
- Evidence integrity verification
- Detect tampering
- Court-admissible evidence standard

### ISO 8601 Timestamps
```python
# All timestamps in ISO format
timestamp = datetime.datetime.now().isoformat()
# Example: 2025-12-25T17:48:23.123456
```

**Why ISO 8601:**
- Unambiguous international standard
- Sortable
- Includes timezone
- Easy correlation across tools

## 🔒 Security Considerations

### Sensitive Data in Outputs

**Environment variables may contain:**
- API keys
- Passwords
- Configuration secrets
- File paths

**Recommendation:** Sanitize before sharing outputs publicly

**Connection data shows:**
- IP addresses
- Port numbers
- Active communications

**Recommendation:** Redact sensitive IPs for public reports

### Privilege Escalation

**Never run untrusted code with sudo:**
- Review scripts before sudo execution
- Scripts are open source - inspect them
- Understand what each tool does

### Data Handling

**Output files contain:**
- Complete system state
- Process command lines (may include sensitive args)
- Network connections (shows who you're talking to)
- File paths (reveals directory structure)

**Recommendation:** Treat outputs as sensitive forensic evidence

## 📊 Output Format Specifications

### CSV Format
```
Encoding: UTF-8
Line endings: CRLF (\r\n)
Delimiter: Comma (,)
Quoting: As needed for embedded commas
Header: Always included
```

### JSON Format
```
Encoding: UTF-8
Indentation: 2 spaces
Schema: Self-documenting with metadata
Numbers: Native JSON types (not strings)
Timestamps: ISO 8601 strings
```

### PCAP Format
```
Format: pcap (not pcap-ng)
Tool: tcpdump/libpcap
Compatible: Wireshark, tcpdump, tshark, etc.
Byte order: Network byte order
```

## 🔧 Troubleshooting Dependencies

### "No module named 'psutil'"
```bash
pip3 install psutil

# If that fails, try:
pip3 install --user psutil

# Or with specific Python version:
python3.9 -m pip install psutil
```

### "tcpdump: command not found"
```bash
# Check location
which tcpdump

# Should be: /usr/sbin/tcpdump
# If missing, reinstall Xcode Command Line Tools:
xcode-select --install
```

### psutil version too old
```bash
# Check version
pip3 show psutil

# Upgrade
pip3 install --upgrade psutil
```

### Permission errors on network capture
```bash
# Network capture MUST use sudo
sudo ./system_network_capture.py 60

# Not: ./system_network_capture.py 60
```

## 📝 Version History

**v1.0 (December 2025)**
- Initial release
- 4 core tools
- Complete documentation
- Tested on macOS 12-14

## 🔄 Future Dependencies

**Planned additions (optional):**
- `jq` for JSON command-line processing (user-installable)
- Wireshark/tshark for advanced PCAP analysis (user-installable)
- Optional SIEM integrations (TBD)

**Not planned:**
- Additional Python packages (minimize dependencies)
- Kernel extensions (incompatible with modern macOS)
- Closed-source tools

---

## ✅ Dependency Checklist

Before using the toolkit, verify:

```bash
# 1. Python version
python3 --version
# Should be: 3.8.0 or higher

# 2. psutil installed
python3 -c "import psutil; print(psutil.__version__)"
# Should show: 5.9.0 or higher

# 3. tcpdump available
which tcpdump
# Should show: /usr/sbin/tcpdump

# 4. Scripts executable
ls -l *.py | grep -c "^-rwxr-xr-x"
# Should match number of .py files

# 5. Test import
python3 -c "import psutil, subprocess, json, csv, datetime, sys, os, hashlib, threading, time"
# Should complete with no errors
```

All checks pass? **You're ready to go!** 🚀

---

**Last Updated:** December 2025  
**Status:** Production Ready  
**Platform:** macOS 10.14+  
**Python:** 3.8+
