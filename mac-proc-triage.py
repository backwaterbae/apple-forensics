    #!/usr/bin/env python3
    """
    Process Triage Collector Tool
    Captures ALL running processes with top-level details for forensic triage

    Shows: PID, name, user, memory (RSS/VMS), CPU%, connections, open files
    Outputs: CSV and JSON sorted by memory usage

    Perfect for:
    - Initial triage - what's running?
    - Memory hogs - which processes using most memory?
    - Suspicious processes - what doesn't belong?
    - System baseline - complete snapshot at a moment in time

    Usage:
        ./process_triage_snapshot.py
        sudo ./process_triage_snapshot.py  # For complete connection counts
        ./process_triage_snapshot.py --top 20  # Show only top 20 by memory
        ./process_triage_snapshot.py --sort cpu  # Sort by CPU instead
    """

    import psutil
    import json
    import csv
    import datetime
    import sys
    import os
    import argparse

    def get_process_info(proc):
        """Get top-level process information for triage"""
        try:
            # Get basic info
            info = proc.as_dict(attrs=[
                'pid', 'name', 'username', 'status',
                'create_time', 'exe', 'cmdline'
            ])
            
            # Memory info
            mem_info = proc.memory_info()
            info['memory_rss_mb'] = round(mem_info.rss / 1024 / 1024, 2)
            info['memory_vms_mb'] = round(mem_info.vms / 1024 / 1024, 2)
            info['memory_percent'] = round(proc.memory_percent(), 2)
            
            # CPU info
            info['cpu_percent'] = proc.cpu_percent(interval=0)
            
            # Process details
            info['num_threads'] = proc.num_threads()
            
            # Count connections (may need sudo for some processes)
            try:
                info['num_connections'] = len(proc.connections())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info['num_connections'] = -1  # -1 = access denied
            
            # Count open files (may need sudo)
            try:
                info['num_files'] = len(proc.open_files())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info['num_files'] = -1
            
            # Parent PID
            try:
                info['ppid'] = proc.ppid()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info['ppid'] = 0
            
            # Command line (first 100 chars)
            if info['cmdline']:
                info['cmdline_short'] = ' '.join(info['cmdline'])[:100]
            else:
                info['cmdline_short'] = ''
            
            # Create time
            if info['create_time']:
                info['create_time_iso'] = datetime.datetime.fromtimestamp(
                    info['create_time']
                ).isoformat()
            else:
                info['create_time_iso'] = ''
            
            return info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def capture_all_processes(sort_by='memory'):
        """Capture all running processes"""
        print("Scanning all processes...", flush=True)
        
        processes = []
        for proc in psutil.process_iter():
            info = get_process_info(proc)
            if info:
                processes.append(info)
        
        # Sort processes
        if sort_by == 'memory':
            processes.sort(key=lambda x: x['memory_rss_mb'], reverse=True)
        elif sort_by == 'cpu':
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        elif sort_by == 'pid':
            processes.sort(key=lambda x: x['pid'])
        
        return processes

    def save_csv(processes, filename):
        """Save processes to CSV"""
        if not processes:
            return
        
        # Define columns for CSV
        columns = [
            'pid', 'name', 'username', 'status',
            'memory_rss_mb', 'memory_vms_mb', 'memory_percent',
            'cpu_percent', 'num_threads', 'num_connections', 'num_files',
            'ppid', 'cmdline_short', 'create_time_iso'
        ]
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(processes)

    def save_json(processes, filename, metadata):
        """Save processes to JSON with metadata"""
        output = {
            "metadata": metadata,
            "summary": {
                "total_processes": len(processes),
                "total_memory_mb": round(sum(p['memory_rss_mb'] for p in processes), 2),
                "total_threads": sum(p['num_threads'] for p in processes),
            },
            "processes": processes
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)

    def print_summary(processes, top_n=None):
        """Print summary to console"""
        
        if top_n:
            display_procs = processes[:top_n]
            title = f"TOP {top_n} PROCESSES BY MEMORY"
        else:
            display_procs = processes
            title = "ALL PROCESSES"
        
        print(f"\n{'='*100}")
        print(f"{title}")
        print(f"{'='*100}")
        print(f"Total Processes: {len(processes)}")
        print(f"Total Memory:    {sum(p['memory_rss_mb'] for p in processes):.2f} MB")
        print(f"Total Threads:   {sum(p['num_threads'] for p in processes)}")
        print(f"{'='*100}")
        
        # Header
        print(f"\n{'PID':<7} {'MEMORY':<10} {'CPU%':<6} {'CONN':<5} {'FILES':<6} {'THREADS':<8} {'USER':<15} {'NAME':<30}")
        print(f"{'-'*100}")
        
        # Rows
        for p in display_procs:
            pid = str(p['pid'])
            mem = f"{p['memory_rss_mb']:.1f}M"
            cpu = f"{p['cpu_percent']:.1f}%"
            conn = str(p['num_connections']) if p['num_connections'] >= 0 else 'N/A'
            files = str(p['num_files']) if p['num_files'] >= 0 else 'N/A'
            threads = str(p['num_threads'])
            user = p['username'][:14] if p['username'] else 'N/A'
            name = p['name'][:29] if p['name'] else 'N/A'
            
            print(f"{pid:<7} {mem:<10} {cpu:<6} {conn:<5} {files:<6} {threads:<8} {user:<15} {name:<30}")
        
        if top_n and len(processes) > top_n:
            print(f"\n... and {len(processes) - top_n} more processes")
        
        print(f"\n{'='*100}")

    def print_statistics(processes):
        """Print useful statistics"""
        if not processes:
            return
        
        print(f"\n{'MEMORY STATISTICS':-^100}")
        
        # Top 5 memory users
        print("\nTop 5 Memory Users:")
        for i, p in enumerate(processes[:5], 1):
            print(f"  {i}. {p['name']:<30} {p['memory_rss_mb']:>8.1f} MB  (PID {p['pid']})")
        
        # Memory distribution
        total_mem = sum(p['memory_rss_mb'] for p in processes)
        top_10_mem = sum(p['memory_rss_mb'] for p in processes[:10])
        print(f"\nMemory Distribution:")
        print(f"  Total System Memory (RSS):     {total_mem:.2f} MB")
        print(f"  Top 10 processes:              {top_10_mem:.2f} MB ({100*top_10_mem/total_mem:.1f}%)")
        print(f"  All other processes:           {total_mem - top_10_mem:.2f} MB ({100*(total_mem-top_10_mem)/total_mem:.1f}%)")
        
        # Process by user
        by_user = {}
        for p in processes:
            user = p['username'] or 'unknown'
            if user not in by_user:
                by_user[user] = {'count': 0, 'memory': 0}
            by_user[user]['count'] += 1
            by_user[user]['memory'] += p['memory_rss_mb']
        
        print(f"\nProcesses by User:")
        for user, stats in sorted(by_user.items(), key=lambda x: x[1]['memory'], reverse=True)[:5]:
            print(f"  {user:<20} {stats['count']:>4} processes  {stats['memory']:>10.1f} MB")
        
        # Connection counts
        conn_procs = [p for p in processes if p['num_connections'] > 0]
        if conn_procs:
            print(f"\nNetwork Activity:")
            print(f"  Processes with connections:    {len(conn_procs)}")
            print(f"  Total connections:             {sum(p['num_connections'] for p in conn_procs if p['num_connections'] > 0)}")
            print(f"\n  Top 5 by connections:")
            for i, p in enumerate(sorted(conn_procs, key=lambda x: x['num_connections'], reverse=True)[:5], 1):
                print(f"    {i}. {p['name']:<30} {p['num_connections']:>4} connections  (PID {p['pid']})")

    def main():
        parser = argparse.ArgumentParser(
            description='Process Triage Snapshot - Capture all running processes'
        )
        parser.add_argument(
            '--top', '-t',
            type=int,
            metavar='N',
            help='Show only top N processes (default: show all)'
        )
        parser.add_argument(
            '--sort', '-s',
            choices=['memory', 'cpu', 'pid'],
            default='memory',
            help='Sort by: memory (default), cpu, or pid'
        )
        parser.add_argument(
            '--output', '-o',
            default='process_triage',
            help='Output directory (default: process_triage)'
        )
        parser.add_argument(
            '--no-stats',
            action='store_true',
            help='Skip statistics output'
        )
        
        args = parser.parse_args()
        
        # Create output directory
        os.makedirs(args.output, exist_ok=True)
        
        # Capture all processes
        timestamp = datetime.datetime.now()
        processes = capture_all_processes(sort_by=args.sort)
        
        print(f"✓ Captured {len(processes)} processes")
        
        # Create metadata
        metadata = {
            "capture_timestamp": timestamp.isoformat(),
            "capture_tool": "process_triage_snapshot.py v1.0",
            "capture_user": os.getenv('USER', 'unknown'),
            "capture_host": os.uname().nodename,
            "sort_order": args.sort,
            "total_processes": len(processes)
        }
        
        # Generate filenames
        timestamp_str = timestamp.strftime("%Y%m%d_%H%M%S")
        csv_file = f"{args.output}/process_triage_{timestamp_str}.csv"
        json_file = f"{args.output}/process_triage_{timestamp_str}.json"
        
        # Save files
        print(f"Saving outputs...", flush=True)
        save_csv(processes, csv_file)
        save_json(processes, json_file, metadata)
        
        # Print summary
        print_summary(processes, top_n=args.top)
        
        # Print statistics
        if not args.no_stats:
            print_statistics(processes)
        
        # Print file info
        print(f"\n{'FILES SAVED':-^100}")
        print(f"  CSV:  {csv_file}")
        print(f"  JSON: {json_file}")
        
        print(f"\n{'FORENSIC NOTES':-^100}")
        print(f"  - All timestamps in ISO format")
        print(f"  - Sorted by: {args.sort}")
        print(f"  - Connection counts may show N/A without sudo")
        print(f"  - Use CSV for sorting/filtering in spreadsheets")
        print(f"  - Use JSON for programmatic analysis")
        
        print(f"\n{'QUICK ANALYSIS':-^100}")
        print(f"  # View CSV in terminal")
        print(f"  column -t -s, {csv_file} | less -S")
        print(f"\n  # Top 10 memory users")
        print(f"  head -11 {csv_file} | column -t -s,")
        print(f"\n  # Search for specific process")
        print(f"  grep -i 'safari' {csv_file}")
        print(f"\n  # Processes with connections (requires sudo)")
        print(f"  sudo ./process_triage_snapshot.py --top 20")
        print(f"\n{'='*100}\n")

    if __name__ == "__main__":
        main()
