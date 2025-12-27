#!/usr/bin/env python3
"""
Mac Spindump & Memory Dump Forensic Analyzer
Searches for exploit signatures and suspicious patterns in system dumps
"""

import os
import sys
import re
import json
import csv
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import argparse


@dataclass
class Finding:
    """Represents a single finding from dump analysis"""
    timestamp: str
    dump_file: str
    dump_type: str  # 'spindump' or 'memdump'
    match_type: str  # 'exact', 'regex', 'partial'
    signature: str
    context: str
    line_number: int
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    severity: str = 'MEDIUM'
    category: Optional[str] = None  # Malware/Exploit/Network/etc
    description: Optional[str] = None  # What this signature indicates
    reference: Optional[str] = None  # CVE/URL/etc
    
    def to_dict(self):
        return asdict(self)


class SignatureLoader:
    """Loads and manages exploit signatures from reference files"""
    
    def __init__(self):
        self.exact_strings: Set[str] = set()
        self.regex_patterns: List[Tuple[str, re.Pattern]] = []
        self.partial_strings: Set[str] = set()
        # Metadata mapping: signature -> {category, description, reference, severity}
        self.metadata: Dict[str, Dict[str, str]] = {}
        
        # Whitelist signatures
        self.whitelist_exact: Set[str] = set()
        self.whitelist_partial: Set[str] = set()
        self.whitelist_regex: List[Tuple[str, re.Pattern]] = []
        self.whitelist_metadata: Dict[str, Dict[str, str]] = {}
        
    def _parse_metadata(self, line: str) -> Tuple[str, Dict[str, str]]:
        """Parse signature line with optional metadata"""
        # Format: PATTERN|CATEGORY:cat|DESC:desc|REF:ref|SEVERITY:sev|REASON:reason|PROCESS:proc|PATH:path
        parts = line.split('|')
        pattern = parts[0].strip()
        
        metadata = {}
        for part in parts[1:]:
            part = part.strip()
            if ':' in part:
                key, value = part.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key in ['category', 'cat']:
                    metadata['category'] = value
                elif key in ['description', 'desc']:
                    metadata['description'] = value
                elif key in ['reference', 'ref']:
                    metadata['reference'] = value
                elif key in ['severity', 'sev']:
                    metadata['severity'] = value.upper()
                elif key == 'reason':
                    metadata['reason'] = value
                elif key == 'process':
                    metadata['process'] = value
                elif key == 'path':
                    metadata['path'] = value
        
        return pattern, metadata
        
    def load_reference_file(self, filepath: Path) -> int:
        """Load signatures from a reference file"""
        loaded = 0
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse metadata if present
                    pattern_line, metadata = self._parse_metadata(line)
                    
                    # Detect signature type by prefix or pattern
                    if pattern_line.startswith('REGEX:'):
                        pattern = pattern_line[6:].strip()
                        try:
                            compiled = re.compile(pattern, re.IGNORECASE)
                            self.regex_patterns.append((pattern, compiled))
                            if metadata:
                                self.metadata[pattern] = metadata
                            loaded += 1
                        except re.error as e:
                            print(f"[!] Invalid regex '{pattern}': {e}", file=sys.stderr)
                    
                    elif pattern_line.startswith('PARTIAL:'):
                        sig = pattern_line[8:].strip()
                        self.partial_strings.add(sig.lower())
                        if metadata:
                            self.metadata[sig.lower()] = metadata
                        loaded += 1
                    
                    elif pattern_line.startswith('EXACT:'):
                        sig = pattern_line[6:].strip()
                        self.exact_strings.add(sig)
                        if metadata:
                            self.metadata[sig] = metadata
                        loaded += 1
                    
                    else:
                        # Default to exact match
                        self.exact_strings.add(pattern_line)
                        if metadata:
                            self.metadata[pattern_line] = metadata
                        loaded += 1
                        
        except Exception as e:
            print(f"[!] Error loading {filepath}: {e}", file=sys.stderr)
            return 0
            
        return loaded
    
    def load_directory(self, dirpath: Path) -> int:
        """Load all signature files from a directory"""
        total = 0
        for filepath in dirpath.rglob('*.txt'):
            count = self.load_reference_file(filepath)
            if count > 0:
                print(f"[+] Loaded {count} signatures from {filepath.name}")
                total += count
        return total
    
    def load_whitelist_file(self, filepath: Path) -> int:
        """Load whitelist/false alarm signatures"""
        loaded = 0
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse metadata if present
                    pattern_line, metadata = self._parse_metadata(line)
                    
                    # Detect signature type
                    if pattern_line.startswith('REGEX:'):
                        pattern = pattern_line[6:].strip()
                        try:
                            compiled = re.compile(pattern, re.IGNORECASE)
                            self.whitelist_regex.append((pattern, compiled))
                            if metadata:
                                self.whitelist_metadata[pattern] = metadata
                            loaded += 1
                        except re.error as e:
                            print(f"[!] Invalid whitelist regex '{pattern}': {e}", file=sys.stderr)
                    
                    elif pattern_line.startswith('PARTIAL:'):
                        sig = pattern_line[8:].strip()
                        self.whitelist_partial.add(sig.lower())
                        if metadata:
                            self.whitelist_metadata[sig.lower()] = metadata
                        loaded += 1
                    
                    elif pattern_line.startswith('EXACT:'):
                        sig = pattern_line[6:].strip()
                        self.whitelist_exact.add(sig)
                        if metadata:
                            self.whitelist_metadata[sig] = metadata
                        loaded += 1
                    
                    else:
                        # Default to exact match
                        self.whitelist_exact.add(pattern_line)
                        if metadata:
                            self.whitelist_metadata[pattern_line] = metadata
                        loaded += 1
                        
        except Exception as e:
            print(f"[!] Error loading whitelist {filepath}: {e}", file=sys.stderr)
            return 0
            
        return loaded
    
    def is_whitelisted(self, text: str, signature: str) -> Tuple[bool, Optional[str]]:
        """Check if text/signature is whitelisted. Returns (is_whitelisted, reason)"""
        # Check exact matches
        if signature in self.whitelist_exact or text in self.whitelist_exact:
            sig_key = signature if signature in self.whitelist_exact else text
            reason = self.whitelist_metadata.get(sig_key, {}).get('reason', 'Whitelisted')
            return True, reason
        
        # Check partial matches
        text_lower = text.lower()
        for wl_sig in self.whitelist_partial:
            if wl_sig in text_lower or wl_sig in signature.lower():
                reason = self.whitelist_metadata.get(wl_sig, {}).get('reason', 'Whitelisted')
                return True, reason
        
        # Check regex patterns
        for pattern_str, pattern in self.whitelist_regex:
            if pattern.search(text) or pattern.search(signature):
                reason = self.whitelist_metadata.get(pattern_str, {}).get('reason', 'Whitelisted')
                return True, reason
        
        return False, None
    
    def search_line(self, line: str, line_num: int) -> List[Tuple[str, str, str, Dict[str, str]]]:
        """Search a line for signatures. Returns [(match_type, signature, context, metadata)]"""
        matches = []
        
        # Exact string matching
        for sig in self.exact_strings:
            if sig in line:
                metadata = self.metadata.get(sig, {})
                matches.append(('exact', sig, line.strip(), metadata))
        
        # Partial string matching
        line_lower = line.lower()
        for sig in self.partial_strings:
            if sig in line_lower:
                metadata = self.metadata.get(sig, {})
                matches.append(('partial', sig, line.strip(), metadata))
        
        # Regex matching
        for pattern_str, pattern in self.regex_patterns:
            if pattern.search(line):
                metadata = self.metadata.get(pattern_str, {})
                matches.append(('regex', pattern_str, line.strip(), metadata))
        
        return matches


class SpindumpParser:
    """Parses Mac spindump files and extracts metadata"""
    
    def __init__(self):
        self.current_process = None
        self.current_pid = None
        
    def parse_header(self, lines: List[str]) -> Dict[str, str]:
        """Extract metadata from spindump header"""
        metadata = {}
        
        for line in lines[:100]:  # Header is typically in first 100 lines
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key in ['Date/Time', 'End time', 'OS Version', 'Architecture', 
                          'Hardware model', 'Memory size', 'Duration']:
                    metadata[key] = value
        
        return metadata
    
    def extract_process_info(self, line: str) -> Optional[Tuple[str, Optional[int]]]:
        """Extract process name and PID from process header line"""
        # Format: Process: name [PID]
        match = re.match(r'^Process:\s+(.+?)\s+\[(\d+)\]', line)
        if match:
            return (match.group(1), int(match.group(2)))
        return None


class MemdumpParser:
    """Handles raw memory dump analysis"""
    
    @staticmethod
    def get_strings(data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data"""
        ascii_strings = []
        current = []
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    ascii_strings.append(''.join(current))
                current = []
        
        if len(current) >= min_length:
            ascii_strings.append(''.join(current))
            
        return ascii_strings


class DumpAnalyzer:
    """Main analyzer for dump files"""
    
    def __init__(self, signatures: SignatureLoader, output_dir: Path, show_whitelisted: bool = False):
        self.signatures = signatures
        self.output_dir = output_dir
        self.show_whitelisted = show_whitelisted
        self.findings: List[Finding] = []
        self.whitelisted_findings: List[Tuple[Finding, str]] = []  # (finding, reason)
        self.spindump_parser = SpindumpParser()
        self.memdump_parser = MemdumpParser()
        
    def analyze_spindump(self, filepath: Path) -> int:
        """Analyze a Mac spindump file"""
        print(f"\n[*] Analyzing spindump: {filepath.name}")
        findings_count = 0
        whitelisted_count = 0
        current_process = None
        current_pid = None
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            # Parse header for metadata
            metadata = self.spindump_parser.parse_header(lines)
            print(f"    OS: {metadata.get('OS Version', 'Unknown')}")
            print(f"    Date: {metadata.get('Date/Time', 'Unknown')}")
            
            # Scan each line
            for line_num, line in enumerate(lines, 1):
                # Track current process context
                process_info = self.spindump_parser.extract_process_info(line)
                if process_info:
                    current_process, current_pid = process_info
                
                # Search for signatures
                matches = self.signatures.search_line(line, line_num)
                
                for match_type, signature, context, sig_metadata in matches:
                    # Get severity from metadata or assess automatically
                    severity = sig_metadata.get('severity') or self._assess_severity(signature, match_type)
                    
                    finding = Finding(
                        timestamp=datetime.now().isoformat(),
                        dump_file=filepath.name,
                        dump_type='spindump',
                        match_type=match_type,
                        signature=signature,
                        context=context[:200],  # Limit context length
                        line_number=line_num,
                        process_name=current_process,
                        process_pid=current_pid,
                        severity=severity,
                        category=sig_metadata.get('category'),
                        description=sig_metadata.get('description'),
                        reference=sig_metadata.get('reference')
                    )
                    
                    # Check whitelist
                    is_whitelisted, wl_reason = self.signatures.is_whitelisted(context, signature)
                    
                    if is_whitelisted:
                        self.whitelisted_findings.append((finding, wl_reason))
                        whitelisted_count += 1
                        if self.show_whitelisted:
                            self.findings.append(finding)
                    else:
                        self.findings.append(finding)
                        findings_count += 1
                    
        except Exception as e:
            print(f"[!] Error analyzing {filepath}: {e}", file=sys.stderr)
            return 0
        
        print(f"    Found {findings_count} signature matches")
        if whitelisted_count > 0:
            print(f"    Filtered {whitelisted_count} whitelisted (false alarm) matches")
        return findings_count
    
    def analyze_memdump(self, filepath: Path, chunk_size: int = 10*1024*1024) -> int:
        """Analyze a memory dump file in chunks"""
        print(f"\n[*] Analyzing memory dump: {filepath.name}")
        findings_count = 0
        whitelisted_count = 0
        chunk_num = 0
        
        try:
            file_size = filepath.stat().st_size
            print(f"    Size: {file_size / (1024*1024):.2f} MB")
            
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    chunk_num += 1
                    
                    # Extract strings from binary data
                    strings = self.memdump_parser.get_strings(chunk)
                    
                    # Search each string
                    for string_num, string in enumerate(strings):
                        matches = self.signatures.search_line(string, chunk_num * 1000000 + string_num)
                        
                        for match_type, signature, context, sig_metadata in matches:
                            # Get severity from metadata or assess automatically
                            severity = sig_metadata.get('severity') or self._assess_severity(signature, match_type)
                            
                            finding = Finding(
                                timestamp=datetime.now().isoformat(),
                                dump_file=filepath.name,
                                dump_type='memdump',
                                match_type=match_type,
                                signature=signature,
                                context=context[:200],
                                line_number=chunk_num,
                                severity=severity,
                                category=sig_metadata.get('category'),
                                description=sig_metadata.get('description'),
                                reference=sig_metadata.get('reference')
                            )
                            
                            # Check whitelist
                            is_whitelisted, wl_reason = self.signatures.is_whitelisted(context, signature)
                            
                            if is_whitelisted:
                                self.whitelisted_findings.append((finding, wl_reason))
                                whitelisted_count += 1
                                if self.show_whitelisted:
                                    self.findings.append(finding)
                            else:
                                self.findings.append(finding)
                                findings_count += 1
                    
                    if chunk_num % 10 == 0:
                        print(f"    Processed {chunk_num * chunk_size / (1024*1024):.1f} MB...")
                        
        except Exception as e:
            print(f"[!] Error analyzing {filepath}: {e}", file=sys.stderr)
            return 0
        
        print(f"    Found {findings_count} signature matches")
        if whitelisted_count > 0:
            print(f"    Filtered {whitelisted_count} whitelisted (false alarm) matches")
        return findings_count
    
    def analyze_file(self, filepath: Path) -> int:
        """Automatically detect and analyze dump file"""
        suffix = filepath.suffix.lower()
        
        if suffix == '.mem':
            return self.analyze_memdump(filepath)
        elif suffix == '.txt' or 'spindump' in filepath.name.lower():
            return self.analyze_spindump(filepath)
        else:
            # Try to detect by content
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    first_lines = [f.readline() for _ in range(10)]
                    if any('spindump' in line.lower() or 'Date/Time:' in line for line in first_lines):
                        return self.analyze_spindump(filepath)
            except:
                pass
            
            # Default to memory dump
            print(f"[*] Treating {filepath.name} as memory dump")
            return self.analyze_memdump(filepath)
    
    def batch_analyze(self, paths: List[Path]) -> int:
        """Analyze multiple dump files"""
        total_findings = 0
        
        for path in paths:
            if path.is_file():
                total_findings += self.analyze_file(path)
            elif path.is_dir():
                for dumpfile in path.rglob('*'):
                    if dumpfile.is_file() and not dumpfile.name.startswith('.'):
                        total_findings += self.analyze_file(dumpfile)
        
        return total_findings
    
    def _assess_severity(self, signature: str, match_type: str) -> str:
        """Assess finding severity based on signature characteristics"""
        sig_lower = signature.lower()
        
        # High severity indicators
        high_keywords = ['exploit', 'shellcode', 'payload', 'backdoor', 'rootkit', 
                        'malware', 'ransomware', 'inject', 'overflow']
        if any(kw in sig_lower for kw in high_keywords):
            return 'HIGH'
        
        # Medium severity for regex patterns
        if match_type == 'regex':
            return 'MEDIUM'
        
        # Low severity for partial matches
        if match_type == 'partial':
            return 'LOW'
        
        return 'MEDIUM'
    
    def generate_report(self, format_type: str = 'all') -> None:
        """Generate analysis reports"""
        if not self.findings:
            print("\n[*] No findings to report")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # CSV Report
        if format_type in ['csv', 'all']:
            csv_path = self.output_dir / f'dump_analysis_{timestamp}.csv'
            self._generate_csv_report(csv_path)
            print(f"\n[+] CSV report: {csv_path}")
        
        # JSON Report
        if format_type in ['json', 'all']:
            json_path = self.output_dir / f'dump_analysis_{timestamp}.json'
            self._generate_json_report(json_path)
            print(f"[+] JSON report: {json_path}")
        
        # Markdown Report
        if format_type in ['md', 'markdown', 'all']:
            md_path = self.output_dir / f'dump_analysis_{timestamp}.md'
            self._generate_markdown_report(md_path)
            print(f"[+] Markdown report: {md_path}")
    
    def _generate_csv_report(self, filepath: Path) -> None:
        """Generate CSV format report"""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            if self.findings:
                fieldnames = list(self.findings[0].to_dict().keys())
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for finding in self.findings:
                    writer.writerow(finding.to_dict())
    
    def _generate_json_report(self, filepath: Path) -> None:
        """Generate JSON format report"""
        data = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'findings': [f.to_dict() for f in self.findings]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    def _generate_markdown_report(self, filepath: Path) -> None:
        """Generate Markdown format report"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("# Mac Dump Analysis Report\n\n")
            f.write(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Total Findings:** {len(self.findings)}\n")
            if self.whitelisted_findings:
                f.write(f"**Whitelisted (False Alarms):** {len(self.whitelisted_findings)}\n")
            f.write("\n")
            
            # Summary by severity
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            for finding in self.findings:
                severity_counts[finding.severity] += 1
                if finding.category:
                    category_counts[finding.category] += 1
            
            f.write("## Severity Summary\n\n")
            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                count = severity_counts.get(severity, 0)
                f.write(f"- **{severity}:** {count}\n")
            f.write("\n")
            
            # Summary by category
            if category_counts:
                f.write("## Category Summary\n\n")
                for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"- **{category}:** {count}\n")
                f.write("\n")
            
            # Group by dump file
            findings_by_file = defaultdict(list)
            for finding in self.findings:
                findings_by_file[finding.dump_file].append(finding)
            
            f.write("## Findings by Dump File\n\n")
            for dump_file, findings in sorted(findings_by_file.items()):
                f.write(f"### {dump_file}\n\n")
                f.write(f"**Findings:** {len(findings)}\n\n")
                
                # Sort by severity
                for finding in sorted(findings, key=lambda x: ('HIGH', 'MEDIUM', 'LOW').index(x.severity)):
                    f.write(f"#### {finding.severity} - Line {finding.line_number}")
                    if finding.category:
                        f.write(f" - [{finding.category}]")
                    f.write("\n\n")
                    
                    f.write(f"- **Signature:** `{finding.signature}`\n")
                    f.write(f"- **Match Type:** {finding.match_type}\n")
                    
                    if finding.description:
                        f.write(f"- **Description:** {finding.description}\n")
                    
                    if finding.reference:
                        f.write(f"- **Reference:** {finding.reference}\n")
                    
                    if finding.process_name:
                        f.write(f"- **Process:** {finding.process_name} [{finding.process_pid}]\n")
                    
                    f.write(f"- **Context:** `{finding.context[:100]}...`\n\n")
            
            # Whitelisted findings section
            if self.whitelisted_findings:
                f.write("\n---\n\n")
                f.write("## Whitelisted Findings (False Alarms)\n\n")
                f.write(f"**Total Whitelisted:** {len(self.whitelisted_findings)}\n\n")
                f.write("These findings matched signatures but were filtered as known false alarms:\n\n")
                
                # Group whitelisted by dump file
                whitelisted_by_file = defaultdict(list)
                for finding, reason in self.whitelisted_findings:
                    whitelisted_by_file[finding.dump_file].append((finding, reason))
                
                for dump_file, items in sorted(whitelisted_by_file.items()):
                    f.write(f"### {dump_file}\n\n")
                    
                    for finding, reason in items[:10]:  # Limit to first 10 per file
                        f.write(f"#### Line {finding.line_number} - {finding.signature}\n\n")
                        f.write(f"- **Reason:** {reason}\n")
                        if finding.process_name:
                            f.write(f"- **Process:** {finding.process_name} [{finding.process_pid}]\n")
                        f.write(f"- **Context:** `{finding.context[:80]}...`\n\n")
                    
                    if len(items) > 10:
                        f.write(f"*... and {len(items) - 10} more whitelisted findings*\n\n")


def create_example_signatures(output_path: Path) -> None:
    """Create example signature reference file"""
    examples = r"""# Mac Exploit Signature Reference File
# Lines starting with # are comments
# Prefix signatures with EXACT:, PARTIAL:, or REGEX: for specific matching
# Default (no prefix) = exact match

# Common exploit patterns
REGEX:shellcode|shell\s*code
REGEX:ROP\s*chain|return.*oriented
REGEX:buffer\s*overflow|heap\s*overflow
PARTIAL:exploit
PARTIAL:payload
PARTIAL:metasploit

# Suspicious function calls
strcpy_unsafe
gets(
system(
exec(

# Known malware strings
PARTIAL:backdoor
PARTIAL:rootkit
PARTIAL:ransomware

# Suspicious network activity
REGEX:connect.*1\.1\.1\.1
REGEX:nc.*-e.*sh
REGEX:bash.*-i

# Memory manipulation
mmap_rwx
mprotect_rwx
REGEX:VirtualAlloc.*PAGE_EXECUTE

# Process injection
PARTIAL:inject
ptrace_attach
PARTIAL:dyld_insert

# XNU kernel exploits
PARTIAL:kernel_exploit
PARTIAL:kext_inject
PARTIAL:IOKit_exploit

# Common CVE strings (examples)
CVE-2024-
CVE-2023-
"""
    
    with open(output_path, 'w') as f:
        f.write(examples)
    
    print(f"[+] Created example signature file: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Mac Spindump & Memory Dump Forensic Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze single spindump with signatures
  %(prog)s -d spindump.txt -r signatures.txt
  
  # Analyze with whitelist to filter false alarms
  %(prog)s -d spindump.txt -r signatures.txt -w macos_whitelist.txt
  
  # Batch analyze directory of dumps
  %(prog)s -d /path/to/dumps/ -r /path/to/signatures/
  
  # Analyze memory dump
  %(prog)s -d memdump.mem -r exploits.txt
  
  # Show whitelisted findings in reports
  %(prog)s -d dump.txt -r sigs.txt -w whitelist.txt --show-whitelisted
  
  # Create example signature file
  %(prog)s --create-example-sigs example_signatures.txt
        """
    )
    
    parser.add_argument('-d', '--dumps', nargs='+', type=Path,
                       help='Dump file(s) or directory to analyze')
    parser.add_argument('-r', '--references', nargs='+', type=Path,
                       help='Signature reference file(s) or directory')
    parser.add_argument('-w', '--whitelist', nargs='+', type=Path,
                       help='Whitelist/false alarm signature file(s)')
    parser.add_argument('-o', '--output-dir', type=Path, default=Path('.'),
                       help='Output directory for reports (default: current directory)')
    parser.add_argument('-f', '--format', choices=['csv', 'json', 'md', 'markdown', 'all'],
                       default='all', help='Report format (default: all)')
    parser.add_argument('--show-whitelisted', action='store_true',
                       help='Include whitelisted findings in main reports')
    parser.add_argument('--create-example-sigs', type=Path, metavar='FILE',
                       help='Create example signature reference file and exit')
    parser.add_argument('--chunk-size', type=int, default=10,
                       help='Chunk size for memory dumps in MB (default: 10)')
    
    args = parser.parse_args()
    
    # Create example signatures
    if args.create_example_sigs:
        create_example_signatures(args.create_example_sigs)
        return 0
    
    # Validate required arguments
    if not args.dumps or not args.references:
        parser.error('--dumps and --references are required (or use --create-example-sigs)')
    
    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load signatures
    print("[*] Loading exploit signatures...")
    signatures = SignatureLoader()
    total_sigs = 0
    
    for ref_path in args.references:
        if ref_path.is_file():
            count = signatures.load_reference_file(ref_path)
            if count > 0:
                print(f"[+] Loaded {count} signatures from {ref_path.name}")
                total_sigs += count
        elif ref_path.is_dir():
            total_sigs += signatures.load_directory(ref_path)
    
    if total_sigs == 0:
        print("[!] No signatures loaded. Use --create-example-sigs to generate example file.")
        return 1
    
    print(f"\n[+] Total signatures loaded: {total_sigs}")
    print(f"    - Exact strings: {len(signatures.exact_strings)}")
    print(f"    - Partial strings: {len(signatures.partial_strings)}")
    print(f"    - Regex patterns: {len(signatures.regex_patterns)}")
    
    # Load whitelist if provided
    total_whitelist = 0
    if args.whitelist:
        print("\n[*] Loading whitelist/false alarm signatures...")
        for wl_path in args.whitelist:
            if wl_path.is_file():
                count = signatures.load_whitelist_file(wl_path)
                if count > 0:
                    print(f"[+] Loaded {count} whitelist entries from {wl_path.name}")
                    total_whitelist += count
        
        if total_whitelist > 0:
            print(f"\n[+] Total whitelist entries: {total_whitelist}")
            print(f"    - Exact: {len(signatures.whitelist_exact)}")
            print(f"    - Partial: {len(signatures.whitelist_partial)}")
            print(f"    - Regex: {len(signatures.whitelist_regex)}")
    
    # Initialize analyzer
    analyzer = DumpAnalyzer(signatures, args.output_dir, args.show_whitelisted)
    
    # Convert chunk size to bytes
    chunk_size_bytes = args.chunk_size * 1024 * 1024
    analyzer.memdump_parser.chunk_size = chunk_size_bytes
    
    # Analyze dumps
    print("\n" + "="*60)
    print("Starting Analysis")
    print("="*60)
    
    total_findings = analyzer.batch_analyze(args.dumps)
    
    print("\n" + "="*60)
    print(f"Analysis Complete - {total_findings} findings")
    print("="*60)
    
    # Generate reports
    if total_findings > 0:
        analyzer.generate_report(args.format)
        print(f"\n[+] Analysis complete. Reports saved to {args.output_dir}")
    else:
        print("\n[*] No exploit signatures found in dumps")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
