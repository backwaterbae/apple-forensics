#!/usr/bin/env python3
"""
Process Memory Snapshot Tool
Captures process memory statistics and metadata for forensic analysis

Usage:
    ./process_memory_snapshot.py <PID>
    sudo ./process_memory_snapshot.py <PID>  # For heap info
"""

import psutil
import json
import datetime
import subprocess
import sys
import os
import hashlib

def calculate_hash(data_string):
    """Calculate SHA-256 hash of data for integrity verification"""
    return hashlib.sha256(data_string.encode()).hexdigest()

def capture_process_memory(pid, output_dir="memory_snapshots"):
    """Capture detailed process memory information"""
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        proc = psutil.Process(pid)
        
        snapshot = {
            # Forensic metadata
            "capture_timestamp": datetime.datetime.now().isoformat(),
            "capture_tool": "process_memory_snapshot.py v1.0",
            "capture_user": os.getenv('USER', 'unknown'),
            "capture_host": os.uname().nodename,
            
            # Process identification
            "pid": pid,
            "name": proc.name(),
            "exe": proc.exe(),
            "cmdline": " ".join(proc.cmdline()),
            "cwd": proc.cwd(),
            "create_time": datetime.datetime.fromtimestamp(proc.create_time()).isoformat(),
            "status": proc.status(),
            "username": proc.username(),
            
            # Process details
            "ppid": proc.ppid(),
            "num_threads": proc.num_threads(),
            "num_fds": proc.num_fds(),
            
            # CPU information
            "cpu_percent": proc.cpu_percent(interval=0.1),
            "cpu_times": {
                "user": proc.cpu_times().user,
                "system": proc.cpu_times().system
            },
            
            # Memory statistics
            "memory_info": {
                "rss": proc.memory_info().rss,  # Resident Set Size (bytes)
                "vms": proc.memory_info().vms,  # Virtual Memory Size (bytes)
            },
            
            # Add macOS-specific fields if available
            "memory_info_extended": {},
            
            # Human-readable memory
            "memory_mb": {
                "rss_mb": round(proc.memory_info().rss / 1024 / 1024, 2),
                "vms_mb": round(proc.memory_info().vms / 1024 / 1024, 2)
            },
            
            "memory_percent": 0.0,  # Will be set below
            
            # Memory maps (regions) - critical for forensics
            "memory_maps": [],
            
            # Open files - what is the process accessing?
            "open_files": [],
            
            # Network connections - active at capture time
            "connections": [],
            
            # Environment variables (can contain sensitive data)
            "environ": {}
        }
        
        # Try to add macOS-specific memory fields
        try:
            mem_info = proc.memory_info()
            if hasattr(mem_info, 'pfaults'):
                snapshot["memory_info_extended"]["pfaults"] = mem_info.pfaults
            if hasattr(mem_info, 'pageins'):
                snapshot["memory_info_extended"]["pageins"] = mem_info.pageins
        except:
            pass
        
        # Set memory percent
        snapshot["memory_percent"] = round(proc.memory_percent(), 2)
        
        # Capture memory maps
        try:
            for m in proc.memory_maps():
                map_data = {"path": m.path}
                if hasattr(m, 'rss'):
                    map_data["rss"] = m.rss
                    map_data["rss_mb"] = round(m.rss / 1024 / 1024, 2) if m.rss else 0
                if hasattr(m, 'size'):
                    map_data["size"] = m.size
                if hasattr(m, 'perms'):
                    map_data["perms"] = m.perms
                snapshot["memory_maps"].append(map_data)
        except psutil.AccessDenied:
            snapshot["memory_maps"] = ["ACCESS_DENIED - Run with sudo for full memory maps"]
        except Exception as e:
            snapshot["memory_maps"] = [f"ERROR: {str(e)}"]
        
        # Capture open files
        try:
            for f in proc.open_files():
                snapshot["open_files"].append({
                    "path": f.path,
                    "fd": f.fd,
                    "position": f.position,
                    "mode": f.mode
                })
        except psutil.AccessDenied:
            snapshot["open_files"] = ["ACCESS_DENIED"]
        
        # Capture network connections
        try:
            for c in proc.connections():
                conn_data = {
                    "fd": c.fd,
                    "family": str(c.family),
                    "type": str(c.type),
                    "status": c.status
                }
                if c.laddr:
                    conn_data["local"] = f"{c.laddr.ip}:{c.laddr.port}"
                if c.raddr:
                    conn_data["remote"] = f"{c.raddr.ip}:{c.raddr.port}"
                snapshot["connections"].append(conn_data)
        except psutil.AccessDenied:
            snapshot["connections"] = ["ACCESS_DENIED"]
        
        # Capture environment (may need sudo)
        try:
            snapshot["environ"] = proc.environ()
        except psutil.AccessDenied:
            snapshot["environ"] = {"error": "ACCESS_DENIED - Run with sudo"}
        
        # Try to get heap info (macOS specific, requires sudo)
        snapshot["heap_info"] = {}
        try:
            heap_output = subprocess.check_output(
                ['heap', str(pid)], 
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode()
            
            # Parse key heap statistics
            for line in heap_output.split('\n')[:20]:  # First 20 lines
                if 'TOTAL' in line or 'Heap' in line:
                    snapshot["heap_info"]["summary"] = line.strip()
            
            snapshot["heap_info"]["full_output"] = heap_output[:2000]  # First 2KB
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            snapshot["heap_info"]["error"] = "Unable to capture (requires root or same user)"
        
        # Calculate integrity hash
        json_str = json.dumps(snapshot, sort_keys=True)
        snapshot["integrity_hash"] = calculate_hash(json_str)
        
        return snapshot
        
    except psutil.NoSuchProcess:
        return {"error": f"Process {pid} not found", "timestamp": datetime.datetime.now().isoformat()}
    except psutil.AccessDenied:
        return {"error": f"Access denied to process {pid} (try sudo)", "timestamp": datetime.datetime.now().isoformat()}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "timestamp": datetime.datetime.now().isoformat()}

def print_summary(snapshot):
    """Print human-readable summary"""
    if "error" in snapshot:
        print(f"\n❌ Error: {snapshot['error']}")
        return
    
    print(f"\n{'='*70}")
    print(f"PROCESS MEMORY SNAPSHOT")
    print(f"{'='*70}")
    print(f"Captured: {snapshot['capture_timestamp']}")
    print(f"Process:  {snapshot['name']} (PID {snapshot['pid']})")
    print(f"User:     {snapshot['username']}")
    print(f"Status:   {snapshot['status']}")
    print(f"\n{'Memory Information':-^70}")
    print(f"  RSS:     {snapshot['memory_mb']['rss_mb']:.2f} MB")
    print(f"  VMS:     {snapshot['memory_mb']['vms_mb']:.2f} MB")
    print(f"  Percent: {snapshot['memory_percent']:.2f}%")
    print(f"  Regions: {len(snapshot['memory_maps'])} memory maps")
    print(f"\n{'Process Activity':-^70}")
    print(f"  CPU:     {snapshot['cpu_percent']:.1f}%")
    print(f"  Threads: {snapshot['num_threads']}")
    print(f"  FDs:     {snapshot['num_fds']}")
    print(f"\n{'Network & Files':-^70}")
    print(f"  Connections: {len(snapshot['connections']) if isinstance(snapshot['connections'], list) else 'N/A'}")
    print(f"  Open Files:  {len(snapshot['open_files']) if isinstance(snapshot['open_files'], list) else 'N/A'}")
    
    if isinstance(snapshot['connections'], list) and len(snapshot['connections']) > 0:
        print(f"\n{'Active Connections':-^70}")
        for conn in snapshot['connections'][:5]:  # Show first 5
            local = conn.get('local', 'N/A')
            remote = conn.get('remote', 'N/A')
            status = conn.get('status', 'N/A')
            print(f"  {local} → {remote} [{status}]")
        if len(snapshot['connections']) > 5:
            print(f"  ... and {len(snapshot['connections']) - 5} more")
    
    print(f"\n{'='*70}")

def main():
    if len(sys.argv) < 2:
        print("Process Memory Snapshot Tool")
        print("\nUsage:")
        print("  ./process_memory_snapshot.py <PID>")
        print("  sudo ./process_memory_snapshot.py <PID>  # For complete data")
        print("\nExample:")
        print("  ./process_memory_snapshot.py 1234")
        sys.exit(1)
    
    pid = int(sys.argv[1])
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "memory_snapshots"
    
    print(f"Capturing memory snapshot for PID {pid}...")
    snapshot = capture_process_memory(pid, output_dir)
    
    # Generate filename
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/process_{pid}_memory_{timestamp}.json"
    
    # Save to file
    with open(filename, 'w') as f:
        json.dump(snapshot, f, indent=2)
    
    # Print summary
    print_summary(snapshot)
    
    if "error" not in snapshot:
        print(f"\n✓ Full snapshot saved to: {filename}")
        print(f"  Integrity hash: {snapshot['integrity_hash'][:16]}...")
        print(f"\nForensic Notes:")
        print(f"  - Timestamp in ISO format for correlation")
        print(f"  - Hash provided for integrity verification")
        print(f"  - Run with sudo for complete memory maps and heap info")

if __name__ == "__main__":
    main()
