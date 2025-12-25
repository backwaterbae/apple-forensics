# macOS Process & Network Forensic Toolkit - Quick Start Guide

## ⚡ Get Running in 5 Minutes

### Prerequisites
- macOS 10.14 or later
- Python 3.8+
- sudo/root access (for network capture)

### Installation

```bash
# 1. Install Python dependency
pip3 install psutil

# 2. Make scripts executable
chmod +x *.py

# 3. Test installation
./process_triage_snapshot.py --help
```

### Your First Capture

```bash
# System-wide triage + network (recommended starting point)
sudo ./system_network_capture.py 60

# Output shows:
# - All running processes (initial and final)
# - New processes that started
# - Processes that stopped
# - Memory changes
# - Network traffic (PCAP)
```

## 🎯 The 4 Core Tools

### 1. System-Wide Triage + Network ⭐ RECOMMENDED
```bash
sudo ./system_network_capture.py 60
```
**Captures:** All processes + network traffic + changes over time  
**Output:** PCAP, CSV, JSON with complete analysis  
**Use For:** Incident response, malware investigation, complete triage

### 2. Process Triage Snapshot
```bash
./process_triage_snapshot.py --top 20
```
**Captures:** All processes at one moment  
**Output:** CSV, JSON  
**Use For:** Quick "what's running", memory analysis

### 3. Deep Process Analysis
```bash
sudo ./process_memory_snapshot.py 1234
```
**Captures:** Detailed info for one PID  
**Output:** JSON with memory maps, heap, environment  
**Use For:** Investigating specific suspicious process

### 4. Network Capture Only
```bash
sudo ./network_capture.py 60
```
**Captures:** Network traffic only  
**Output:** PCAP  
**Use For:** Network-focused investigation

## 📊 Typical Workflow

```bash
# 1. TRIAGE - What happened?
sudo ./system_network_capture.py 60

# 2. REVIEW - Check the output
cat system_analysis_*.json | jq '.changes_analysis'

# 3. If you find suspicious PID 7777:
sudo ./process_memory_snapshot.py 7777

# 4. ANALYZE - View network
open -a Wireshark network_*.pcap
```

## 📁 Output Files

| Tool | Output Files | Purpose |
|------|--------------|---------|
| **system_network_capture** | network_*.pcap<br>system_analysis_*.json<br>system_analysis_*.csv | Network traffic<br>Complete analysis<br>Process list |
| **process_triage_snapshot** | process_triage_*.csv<br>process_triage_*.json | Process list<br>Full data |
| **process_memory_snapshot** | process_*_memory_*.json | Detailed process info |
| **network_capture** | network_capture_*.pcap<br>network_capture_*_metadata.json | Network traffic<br>Capture metadata |

## 🔍 Common Use Cases

### "What's eating my memory?"
```bash
./process_triage_snapshot.py --top 10
```

### "Is my system compromised?"
```bash
sudo ./system_network_capture.py 90
# Check changes_analysis for new processes
```

### "What's this app doing?"
```bash
# Find PID: pgrep Safari
sudo ./system_network_capture.py 60
# Then search for that PID in output
```

### "System about to hang!"
```bash
sudo ./system_network_capture.py 30
# Quick capture before crash
```

## ⚠️ Important Notes

### Network Duration: 30-60 Seconds Recommended
- 30-60s captures beaconing patterns, connection cycles
- 10s is too short for meaningful patterns
- 90-120s for comprehensive analysis

### Sudo Requirements
- **Network capture requires sudo** (tcpdump needs root)
- **Process tools work without sudo** but show limited data:
  - Connection counts show N/A
  - File counts show N/A
  
### macOS Limitations
- Can't dump raw process memory (SIP protection)
- Tools capture metadata instead (still very valuable!)
- Some system processes are protected

## 🚩 Red Flags to Look For

### In System Capture Output
```
New Processes Started During Capture
  PID 7777   cryptominer    234 MB  (nobody)    <-- SUSPICIOUS!
  
Significant Memory Changes
  PID 1234   Safari    456 MB → 789 MB (+333 MB)  <-- Check this
```

**Investigate further:**
- Processes running as "nobody" or wrong user
- Processes with suspicious names
- Unexpected memory growth
- High connection counts

## 📚 Full Documentation

- **TOOLKIT_SUMMARY.md** - Complete overview of all tools
- **SYSTEM_NETWORK_CAPTURE_GUIDE.md** - Detailed guide for system-wide tool
- **PROCESS_TRIAGE_GUIDE.md** - Detailed guide for triage tool
- **DEPENDENCIES.md** - Complete dependency information

## 🆘 Troubleshooting

### "Permission denied" on network capture
```bash
# Network tools need sudo
sudo ./system_network_capture.py 60
```

### "tcpdump: command not found"
```bash
# tcpdump is pre-installed on macOS
# Check path: which tcpdump
# Should show: /usr/sbin/tcpdump
```

### "No module named 'psutil'"
```bash
pip3 install psutil
```

### Connection counts show "N/A"
```bash
# Run with sudo for complete data
sudo ./process_triage_snapshot.py
```

## 🎓 Learning Path

**Day 1: Basic Triage**
1. Run `process_triage_snapshot.py`
2. Review CSV output
3. Identify top memory users

**Day 2: System Capture**
1. Run `system_network_capture.py`
2. Review changes_analysis
3. Open PCAP in Wireshark

**Day 3: Deep Dive**
1. Find suspicious PID
2. Run `process_memory_snapshot.py`
3. Correlate with logs

**Day 4: Integration**
1. Combine all tools
2. Build investigation timeline
3. Document findings

## 🚀 Next Steps

1. **Test on your Mac** - Run system_network_capture.py
2. **Review outputs** - Familiarize with formats
3. **Create baseline** - Capture clean system state
4. **Read full docs** - Explore advanced features

## 📞 Support & Resources

- **GitHub Repository:** [Link to repo]
- **Documentation:** See included MD files
- **Issues:** Report on GitHub
- **License:** MIT License

---

**You're ready to start forensic investigations on macOS!** 🔬

**Recommended First Command:**
```bash
sudo ./system_network_capture.py 60
```

This gives you the complete picture - all processes, network activity, and what changed during the capture window.
