#!/usr/bin/env python3
"""
Network Activity Capture Tool
Captures network traffic for forensic analysis

Default: 60 seconds (minimum recommended for forensics)
Range: 30-120 seconds for comprehensive network behavior analysis

Usage:
    sudo ./network_capture.py [duration] [interface] [output_dir]

Examples:
    sudo ./network_capture.py                    # 60s on en0
    sudo ./network_capture.py 30                 # 30s on en0
    sudo ./network_capture.py 90 en0             # 90s on en0
    sudo ./network_capture.py 60 en0 evidence/   # Custom output dir
"""

import subprocess
import datetime
import sys
import os
import json
import hashlib

def get_available_interfaces():
    """List available network interfaces"""
    try:
        result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True)
        return result.stdout.strip().split()
    except:
        return ['en0', 'en1', 'lo0']  # Defaults

def calculate_file_hash(filepath):
    """Calculate SHA-256 hash of file for integrity"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def capture_network_activity(duration=60, interface="en0", output_dir="network_captures"):
    """Capture network traffic using tcpdump"""

    # Validate duration
    if duration < 10:
        print("⚠️  Warning: Duration < 10s may miss network patterns")
        print("   Recommended: 30-60s for forensic analysis")

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Generate filenames
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = f"{output_dir}/network_capture_{timestamp}.pcap"
    metadata_file = f"{output_dir}/network_capture_{timestamp}_metadata.json"

    # Create metadata structure
    metadata = {
        "capture_start": datetime.datetime.now().isoformat(),
        "capture_tool": "network_capture.py v1.0",
        "capture_user": os.getenv('USER', 'unknown'),
        "capture_host": os.uname().nodename,
        "duration_seconds": duration,
        "interface": interface,
        "pcap_file": pcap_file,
        "status": "in_progress"
    }

    print(f"\n{'='*70}")
    print(f"NETWORK ACTIVITY CAPTURE")
    print(f"{'='*70}")
    print(f"Interface:  {interface}")
    print(f"Duration:   {duration} seconds")
    print(f"Output:     {pcap_file}")
    print(f"Started:    {metadata['capture_start']}")
    print(f"\nNote: This requires sudo/root privileges")
    print(f"{'='*70}\n")

    try:
        # Build tcpdump command
        cmd = [
            'tcpdump',
            '-i', interface,      # Interface
            '-w', pcap_file,      # Write to file
            '-v',                 # Verbose
            '-n',                 # Don't resolve names (faster, better for forensics)
        ]

        # Start capture
        print(f"Capturing network traffic...")
        print(f"Progress: [", end='', flush=True)

        # Run tcpdump with timeout
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Show progress
        import time
        for i in range(duration):
            time.sleep(1)
            if (i + 1) % 5 == 0:
                print('█', end='', flush=True)
            else:
                print('▪', end='', flush=True)

        print('] Done!\n')

        # Terminate tcpdump gracefully
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

        # Update metadata
        metadata["capture_end"] = datetime.datetime.now().isoformat()
        metadata["status"] = "completed"

        # Get file info
        if os.path.exists(pcap_file):
            file_size = os.path.getsize(pcap_file)
            metadata["file_size_bytes"] = file_size
            metadata["file_size_mb"] = round(file_size / 1024 / 1024, 2)

            # Calculate hash for integrity
            print("Calculating file hash for integrity verification...")
            metadata["file_hash_sha256"] = calculate_file_hash(pcap_file)

            # Get packet count using tcpdump
            try:
                count_result = subprocess.run(
                    ['tcpdump', '-r', pcap_file, '-n', '-q'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                packet_count = len(count_result.stdout.strip().split('\n'))
                metadata["packet_count"] = packet_count
            except:
                metadata["packet_count"] = "unknown"

            # Quick protocol analysis
            try:
                print("\nAnalyzing captured traffic...")
                proto_result = subprocess.run(
                    ['tcpdump', '-r', pcap_file, '-n', '-q'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                # Count protocol types
                protocols = {}
                for line in proto_result.stdout.split('\n'):
                    if 'IP' in line:
                        protocols['IP'] = protocols.get('IP', 0) + 1
                    if 'TCP' in line:
                        protocols['TCP'] = protocols.get('TCP', 0) + 1
                    if 'UDP' in line:
                        protocols['UDP'] = protocols.get('UDP', 0) + 1
                    if 'DNS' in line or 'domain' in line:
                        protocols['DNS'] = protocols.get('DNS', 0) + 1
                    if 'HTTPS' in line or '.443' in line:
                        protocols['HTTPS'] = protocols.get('HTTPS', 0) + 1
                    if 'HTTP' in line or '.80' in line:
                        protocols['HTTP'] = protocols.get('HTTP', 0) + 1

                metadata["protocol_summary"] = protocols

            except:
                metadata["protocol_summary"] = {}

            # Save metadata
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

            # Print summary
            print(f"\n{'='*70}")
            print(f"CAPTURE COMPLETE")
            print(f"{'='*70}")
            print(f"✓ PCAP File:     {pcap_file}")
            print(f"✓ Metadata:      {metadata_file}")
            print(f"\n{'File Information':-^70}")
            print(f"  Size:          {metadata['file_size_mb']:.2f} MB ({file_size:,} bytes)")
            print(f"  Packets:       {metadata.get('packet_count', 'unknown')}")
            print(f"  Duration:      {duration} seconds")
            print(f"  Hash (SHA256): {metadata['file_hash_sha256'][:32]}...")

            if metadata.get('protocol_summary'):
                print(f"\n{'Protocol Summary':-^70}")
                for proto, count in sorted(metadata['protocol_summary'].items(), key=lambda x: x[1], reverse=True):
                    print(f"  {proto:.<15} {count:>6} packets")

            print(f"\n{'Quick Analysis Commands':-^70}")
            print(f"  View in Wireshark:")
            print(f"    open -a Wireshark {pcap_file}")
            print(f"\n  Top talkers:")
            print(f"    tcpdump -r {pcap_file} -n | awk '{{print $3}}' | sort | uniq -c | sort -rn | head -20")
            print(f"\n  DNS queries:")
            print(f"    tcpdump -r {pcap_file} -n port 53")
            print(f"\n  HTTPS connections:")
            print(f"    tcpdump -r {pcap_file} -n port 443")
            print(f"\n{'='*70}")

            return pcap_file, metadata_file
        else:
            print("❌ Error: Capture file not created")
            metadata["status"] = "failed"
            metadata["error"] = "PCAP file not created"
            return None, None

    except PermissionError:
        print("\n❌ Permission denied!")
        print("   Network capture requires root privileges")
        print("   Run with sudo: sudo ./network_capture.py")
        metadata["status"] = "failed"
        metadata["error"] = "Permission denied - needs sudo"
        return None, None

    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error running tcpdump: {e}")
        print("   Make sure tcpdump is installed")
        metadata["status"] = "failed"
        metadata["error"] = str(e)
        return None, None

    except KeyboardInterrupt:
        print("\n\n⚠️  Capture interrupted by user")
        metadata["status"] = "interrupted"
        metadata["capture_end"] = datetime.datetime.now().isoformat()
        return None, None

    finally:
        # Always save metadata
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠️  Warning: Not running as root")
        print("   Network capture requires sudo privileges")
        print("   Usage: sudo ./network_capture.py [duration] [interface]\n")

    # Parse arguments
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    interface = sys.argv[2] if len(sys.argv) > 2 else "en0"
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "network_captures"

    # Validate duration
    if duration > 300:
        print(f"⚠️  Warning: {duration}s is quite long")
        response = input("Continue? (y/n): ")
        if response.lower() != 'y':
            print("Cancelled")
            return

    # Show available interfaces
    available = get_available_interfaces()
    if interface not in available:
        print(f"⚠️  Warning: Interface '{interface}' may not exist")
        print(f"   Available interfaces: {', '.join(available)}")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            print("Cancelled")
            return

    # Run capture
    capture_network_activity(duration, interface, output_dir)

if __name__ == "__main__":
    main()
