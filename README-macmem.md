# macOS Process & Network Forensic Toolkit

![Platform](https://img.shields.io/badge/platform-macOS-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![Status](https://img.shields.io/badge/status-production-brightgreen)

**Professional-grade forensic tools for macOS process and network investigation**

[Quick Start](#-quick-start) •
[Documentation](#-documentation) •
[Tools](#-the-4-core-tools) •
[Examples](#-examples) •
[License](#-license)

---

## 🎯 Overview

A comprehensive toolkit for macOS forensic investigators, incident responders, and security professionals. Captures complete system state (all running processes), network activity, and detailed process information for forensic analysis.

**Built by a digital forensics investigator for real-world investigations.**

### ✨ Key Features

- ✅ **System-wide triage** - Capture all processes at once
- ✅ **Network traffic capture** - 30-60 second PCAP files  
- ✅ **Changes detection** - See what started/stopped during capture
- ✅ **Memory analysis** - Track memory usage across all processes
- ✅ **Deep process inspection** - Detailed memory maps, heap, environment
- ✅ **Multiple output formats** - CSV, JSON, PCAP
- ✅ **Forensic metadata** - ISO timestamps, integrity hashes, chain of custody
- ✅ **Court-admissible outputs** - Industry-standard formats

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/macos-forensics-toolkit.git
cd macos-forensics-toolkit

# Install dependency
pip3 install psutil

# Make executable
chmod +x *.py

# Test
./process_triage_snapshot.py --help
```

### Your First Capture

```bash
# System-wide triage + network (recommended)
sudo ./system_network_capture.py 60

# Review output
cat system_analysis_*.json | jq '.changes_analysis'
```

## 🛠️ The 4 Core Tools

### 1. System-Wide Triage + Network Capture ⭐

**`system_network_capture.py`** - The ultimate forensic triage tool

```bash
sudo ./system_network_capture.py 60
```

**Captures:**
- Complete system state (all processes) at start and end
- Network traffic (PCAP format)
- Periodic snapshots every 10 seconds
- Changes analysis (new/stopped processes, memory deltas)

**Outputs:** `network_*.pcap`, `system_analysis_*.json`, `system_analysis_*.csv`

**Use for:** Incident response, malware investigation, pre-crash triage

---

### 2. Process Triage Snapshot

**`process_triage_snapshot.py`** - Instant all-process snapshot

```bash
./process_triage_snapshot.py --top 20
```

**Captures:** All running processes in one moment

**Outputs:** `process_triage_*.csv`, `process_triage_*.json`

**Use for:** Quick "what's running" check, memory analysis, baselines

---

### 3. Deep Process Memory Analysis

**`process_memory_snapshot.py`** - Detailed single-process inspection

```bash
sudo ./process_memory_snapshot.py 1234
```

**Captures:** Complete forensic data for one PID

**Outputs:** `process_*_memory_*.json` with memory maps, heap, environment

**Use for:** Investigating suspicious processes, malware analysis

---

### 4. Network Traffic Capture

**`network_capture.py`** - Network-only capture

```bash
sudo ./network_capture.py 60
```

**Captures:** Network traffic without process monitoring

**Outputs:** `network_capture_*.pcap`, `network_capture_*_metadata.json`

**Use for:** Network health monitoring, traffic analysis

## 📊 Examples

### Incident Response Workflow

```bash
# 1. System triage - What happened?
sudo ./system_network_capture.py 60

# 2. Review changes
cat system_analysis_*.json | jq '.changes_analysis'

# Output shows:
# {
#   "new_processes": [
#     {"pid": 7777, "name": "cryptominer", "user": "nobody"}
#   ]
# }

# 3. Deep dive on suspicious PID
sudo ./process_memory_snapshot.py 7777

# 4. Analyze network
open -a Wireshark network_*.pcap
```

### Finding Memory Hogs

```bash
# Quick triage
./process_triage_snapshot.py --top 10

# Output:
# PID    MEMORY    CPU%   NAME
# 1234   1234.5M   45.2%  Google Chrome Helper
# 5678   892.3M    12.1%  Safari
```

### System Baseline

```bash
# Capture clean system
./process_triage_snapshot.py
mv process_triage/ baseline_clean/

# Later, compare
diff baseline_clean/*.csv process_triage/*.csv
```

## 📁 Sample Outputs

See [`samples/`](samples/) directory for example outputs:
- `sample_process_triage.csv` - Process list in CSV format
- `sample_system_analysis.json` - Complete system analysis with changes
- `sample_network_metadata.json` - Network capture metadata

## 📚 Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Get running in 5 minutes
- **[README.md](README.md)** - Complete toolkit overview (this file)
- **[TOOLKIT_SUMMARY.md](TOOLKIT_SUMMARY.md)** - All tools explained
- **[DEPENDENCIES.md](DEPENDENCIES.md)** - Technical specifications
- **[SYSTEM_NETWORK_CAPTURE_GUIDE.md](SYSTEM_NETWORK_CAPTURE_GUIDE.md)** - System-wide tool guide
- **[PROCESS_TRIAGE_GUIDE.md](PROCESS_TRIAGE_GUIDE.md)** - Triage tool guide

## 🔧 Requirements

- **OS:** macOS 10.14 (Mojave) or later
- **Python:** 3.8 or higher
- **Dependencies:** `psutil` (install via pip)
- **System:** `tcpdump` (pre-installed on macOS)
- **Privileges:** sudo for network capture and complete data

## 🎯 Use Cases

| Scenario | Tool | Output |
|----------|------|--------|
| **Incident Response** | system_network_capture | Complete system state + network |
| **Malware Investigation** | system_network_capture → process_memory_snapshot | Full analysis |
| **Memory Analysis** | process_triage_snapshot | All processes, sorted by memory |
| **Pre-Crash Triage** | system_network_capture | State before hang |
| **System Baseline** | process_triage_snapshot | Clean system snapshot |
| **Network Health** | network_capture | Traffic only |

## ⚠️ Important Notes

### Network Capture Duration
**30-60 seconds recommended** (based on forensic best practices)
- Captures beaconing patterns (malware typically beacons every 30-60s)
- Shows complete connection lifecycles
- 10 seconds is too short for meaningful analysis

### Sudo Requirements
- Network capture requires `sudo` (tcpdump needs root)
- Process tools work without sudo but show limited data
- With sudo: complete connections, files, heap, environment

### macOS Limitations (SIP)
- Cannot dump raw process memory (System Integrity Protection)
- Tools capture metadata instead (still extremely valuable)
- Designed to work within macOS security constraints

## 🤝 Contributing

Contributions welcome! Areas for contribution:
- Additional analysis modules
- Output format converters
- Integration with other forensic tools
- Documentation improvements
- Sample use cases

Please open an issue or pull request on GitHub.

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details.

**Forensic Notice:** This toolkit is designed for legitimate forensic investigation, incident response, and security research. Users are responsible for obtaining proper authorization and complying with all applicable laws.

## 🎓 Background

Developed by a digital forensics investigator (MS in Digital Forensics) as part of a comprehensive macOS forensics toolkit. Part of the "victim investigator" project - forensic tools designed to help victims and investigators, not exploit them.

**Philosophy:** Victim-focused forensics - Tools designed to investigate and protect, not to harm.

## 🏆 Acknowledgments

Built with insights from:
- Magnet Forensics - Essential macOS artifacts research
- SANS Digital Forensics community
- Real-world incident response experience

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/yourusername/macos-forensics-toolkit/issues)
- **Documentation:** See included MD files
- **Community:** Share findings and use cases

---

**Ready to start?**

```bash
sudo ./system_network_capture.py 60
```

**Welcome to professional macOS forensics!** 🔬

---

![Version](https://img.shields.io/badge/version-1.0-blue)
![Last Updated](https://img.shields.io/badge/updated-December%202025-green)
![Status](https://img.shields.io/badge/status-production%20ready-brightgreen)
