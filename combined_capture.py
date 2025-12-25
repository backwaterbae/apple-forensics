#!/usr/bin/env python3
"""
Combined Process Memory + Network Capture Tool
Captures both process memory snapshots and network activity simultaneously

This is ideal for:
- Pre-spindump triage (capture before process hangs)
- Malware analysis (behavior + network communication)
- Performance investigation (process state + network health)

Default: 60 seconds of monitoring with snapshots every 5 seconds

Usage:
    sudo ./combined_capture.py <PID> [duration] [interface]

Examples:
    sudo ./combined_capture.py 1234                 # 60s capture of PID 1234
    sudo ./combined_capture.py 1234 30              # 30s capture
    sudo ./combined_capture.py 1234 60 en0          # Specify interface
"""

import psutil
import subprocess
import threading
import time
import json
import datetime
import sys
import os
import hashlib

def network_capture_thread(duration, interface, output_file, status_dict):
    """Run network capture in background thread"""
    try:
        # Run tcpdump
        process = subprocess.Popen(
            ['tcpdump', '-i', interface, '-w', output_file, '-n', '-v'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Wait for duration
        time.sleep(duration)

        # Terminate gracefully
        process.terminate()
        try:
            process.wait(timeout=5)
            status_dict['network_status'] = 'completed'
        except subprocess.TimeoutExpired:
            process.kill()
            status_dict['network_status'] = 'killed'

    except Exception as e:
        status_dict['network_status'] = f'error: {str(e)}'

def capture_process_snapshot(pid):
    """Quick process snapshot for monitoring"""
    try:
        proc = psutil.Process(pid)

        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "status": proc.status(),
            "cpu_percent": proc.cpu_percent(interval=0.1),
            "memory_rss_mb": round(proc.memory_info().rss / 1024 / 1024, 2),
            "memory_vms_mb": round(proc.memory_info().vms / 1024 / 1024, 2),
            "num_threads": proc.num_threads(),
            "num_fds": proc.num_fds(),
            "connections": len(proc.connections()),
            "open_files": len(proc.open_files())
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "error": str(e)
        }

def capture_detailed_snapshot(pid):
    """Detailed process snapshot at start/end"""
    try:
        proc = psutil.Process(pid)

        snapshot = {
            "timestamp": datetime.datetime.now().isoformat(),
            "pid": pid,
            "name": proc.name(),
            "exe": proc.exe(),
            "cmdline": " ".join(proc.cmdline()),
            "status": proc.status(),
            "create_time": datetime.datetime.fromtimestamp(proc.create_time()).isoformat(),
            "username": proc.username(),
            "ppid": proc.ppid(),

            "cpu": {
                "percent": proc.cpu_percent(interval=0.1),
                "times_user": proc.cpu_times().user,
                "times_system": proc.cpu_times().system
            },

            "memory": {
                "rss": proc.memory_info().rss,
                "vms": proc.memory_info().vms,
                "rss_mb": round(proc.memory_info().rss / 1024 / 1024, 2),
                "vms_mb": round(proc.memory_info().vms / 1024 / 1024, 2),
                "percent": round(proc.memory_percent(), 2)
            },

            "threads": proc.num_threads(),
            "fds": proc.num_fds(),

            "connections": [
                {
                    "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    "status": c.status
                }
                for c in proc.connections()
            ],

            "open_files": [
                {"path": f.path, "fd": f.fd}
                for f in proc.open_files()
            ]
        }

        return snapshot

    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {"timestamp": datetime.datetime.now().isoformat(), "error": str(e)}

def combined_capture(pid, duration=60, interface="en0", output_dir="combined_captures"):
    """Capture process memory + network activity simultaneously"""

    os.makedirs(output_dir, exist_ok=True)

    # Generate filenames
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = f"{output_dir}/network_{pid}_{timestamp}.pcap"
    report_file = f"{output_dir}/combined_{pid}_{timestamp}.json"

    # Capture metadata
    capture_metadata = {
        "capture_start": datetime.datetime.now().isoformat(),
        "pid": pid,
        "duration_seconds": duration,
        "interface": interface,
        "snapshot_interval": 5,  # seconds between snapshots
        "pcap_file": pcap_file,
        "tool": "combined_capture.py v1.0",
        "user": os.getenv('USER', 'unknown'),
        "host": os.uname().nodename
    }

    print(f"\n{'='*70}")
    print(f"COMBINED PROCESS + NETWORK CAPTURE")
    print(f"{'='*70}")
    print(f"PID:        {pid}")
    print(f"Duration:   {duration} seconds")
    print(f"Interface:  {interface}")
    print(f"Snapshots:  Every 5 seconds")
    print(f"Started:    {capture_metadata['capture_start']}")
    print(f"{'='*70}\n")

    # Verify process exists
    try:
        proc_name = psutil.Process(pid).name()
        print(f"Target process: {proc_name} (PID {pid})")
    except psutil.NoSuchProcess:
        print(f"❌ Error: Process {pid} not found")
        return
    except psutil.AccessDenied:
        print(f"⚠️  Warning: Limited access to process {pid}")
        print("   Some data may be incomplete")

    # Capture initial detailed snapshot
    print("\n[1/4] Capturing initial process state...")
    initial_snapshot = capture_detailed_snapshot(pid)

    # Start network capture in background
    print("[2/4] Starting network capture...")
    status_dict = {'network_status': 'running'}
    network_thread = threading.Thread(
        target=network_capture_thread,
        args=(duration, interface, pcap_file, status_dict)
    )
    network_thread.start()

    # Monitor process over time
    print(f"[3/4] Monitoring process for {duration} seconds...")
    print(f"      Progress: [", end='', flush=True)

    snapshots = []
    snapshot_count = duration // 5  # Every 5 seconds

    for i in range(snapshot_count):
        time.sleep(5)
        snapshot = capture_process_snapshot(pid)
        snapshots.append(snapshot)
        print('█', end='', flush=True)

    # Sleep remaining time
    remaining = duration % 5
    if remaining > 0:
        time.sleep(remaining)

    print('] Done!\n')

    # Wait for network capture to complete
    print("[4/4] Finalizing network capture...")
    network_thread.join(timeout=10)

    # Capture final detailed snapshot
    final_snapshot = capture_detailed_snapshot(pid)

    # Calculate network file info
    network_info = {}
    if os.path.exists(pcap_file):
        file_size = os.path.getsize(pcap_file)
        network_info = {
            "file_size_bytes": file_size,
            "file_size_mb": round(file_size / 1024 / 1024, 2),
            "status": status_dict['network_status']
        }

        # Get packet count
        try:
            result = subprocess.run(
                ['tcpdump', '-r', pcap_file, '-n', '-q'],
                capture_output=True,
                text=True,
                timeout=10
            )
            network_info["packet_count"] = len(result.stdout.strip().split('\n'))
        except:
            network_info["packet_count"] = "unknown"

    # Build complete report
    report = {
        "metadata": capture_metadata,
        "capture_end": datetime.datetime.now().isoformat(),
        "network_capture": network_info,
        "initial_state": initial_snapshot,
        "monitoring_snapshots": snapshots,
        "final_state": final_snapshot,
        "summary": {
            "duration_seconds": duration,
            "snapshots_captured": len(snapshots),
            "process_survived": "error" not in final_snapshot
        }
    }

    # Calculate changes
    if "error" not in initial_snapshot and "error" not in final_snapshot:
        report["changes"] = {
            "memory_rss_delta_mb": round(
                final_snapshot["memory"]["rss_mb"] - initial_snapshot["memory"]["rss_mb"], 2
            ),
            "connections_delta": len(final_snapshot["connections"]) - len(initial_snapshot["connections"]),
            "files_delta": len(final_snapshot["open_files"]) - len(initial_snapshot["open_files"]),
            "threads_delta": final_snapshot["threads"] - initial_snapshot["threads"]
        }

    # Save report
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    capture_metadata["capture_end"] = datetime.datetime.now().isoformat()

    # Print summary
    print(f"\n{'='*70}")
    print(f"CAPTURE COMPLETE")
    print(f"{'='*70}")
    print(f"✓ Network capture: {pcap_file}")
    print(f"✓ Analysis report: {report_file}")

    if network_info:
        print(f"\n{'Network Activity':-^70}")
        print(f"  Captured:  {network_info.get('file_size_mb', 0):.2f} MB")
        print(f"  Packets:   {network_info.get('packet_count', 'unknown')}")
        print(f"  Status:    {network_info.get('status', 'unknown')}")

    print(f"\n{'Process Monitoring':-^70}")
    print(f"  Snapshots: {len(snapshots)}")
    print(f"  Interval:  5 seconds")
    print(f"  Duration:  {duration} seconds")

    if "changes" in report:
        print(f"\n{'Process Changes (Start → End)':-^70}")
        print(f"  Memory RSS:    {report['changes']['memory_rss_delta_mb']:+.2f} MB")
        print(f"  Connections:   {report['changes']['connections_delta']:+d}")
        print(f"  Open Files:    {report['changes']['files_delta']:+d}")
        print(f"  Threads:       {report['changes']['threads_delta']:+d}")

    print(f"\n{'Forensic Notes':-^70}")
    print(f"  - All timestamps in ISO format for correlation")
    print(f"  - Network capture: {pcap_file}")
    print(f"  - Can correlate with spindump if process hangs")
    print(f"  - Use Wireshark to analyze: open -a Wireshark {pcap_file}")
    print(f"{'='*70}\n")

    return report_file, pcap_file

def main():
    if os.geteuid() != 0:
        print("⚠️  Warning: Not running as root")
        print("   Network capture requires sudo privileges")
        print("   Usage: sudo ./combined_capture.py <PID> [duration] [interface]\n")

    if len(sys.argv) < 2:
        print("Combined Process Memory + Network Capture Tool")
        print("\nUsage:")
        print("  sudo ./combined_capture.py <PID> [duration] [interface]")
        print("\nExamples:")
        print("  sudo ./combined_capture.py 1234              # 60s capture")
        print("  sudo ./combined_capture.py 1234 30           # 30s capture")
        print("  sudo ./combined_capture.py 1234 60 en0       # Specify interface")
        print("\nForensic Applications:")
        print("  - Pre-spindump triage (capture before hang)")
        print("  - Malware behavior analysis")
        print("  - Network health investigation")
        print("  - Process performance profiling")
        sys.exit(1)

    pid = int(sys.argv[1])
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    interface = sys.argv[3] if len(sys.argv) > 3 else "en0"

    combined_capture(pid, duration, interface)

if __name__ == "__main__":
    main()
