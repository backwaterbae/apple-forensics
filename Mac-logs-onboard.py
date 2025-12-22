#!/usr/bin/env python3
"""
macOS Log Directory Analyzer
Intelligent log file discovery and analysis for ~/Library/Logs
"""

import os
import sys
import re
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import argparse


@dataclass
class LogFile:
    """Represents a discovered log file"""
    path: str
    filename: str
    size: int
    modified: str
    log_type: str  # 'crash', 'diagnostic', 'application', 'system', 'unknown'
    encoding: str = 'utf-8'
    
    def to_dict(self):
        return asdict(self)


@dataclass
class LogFinding:
    """Represents a finding in a log file"""
    timestamp: str
    log_file: str
    log_type: str
    line_number: int
    match_type: str  # 'exact', 'regex', 'partial'
    pattern: str
    context: str
    severity: str = 'MEDIUM'
    category: Optional[str] = None
    full_line: Optional[str] = None  # Complete log line
    log_timestamp: Optional[str] = None  # Timestamp extracted from log line
    
    def to_dict(self):
        return asdict(self)


class LogTypeDetector:
    """Detects log file types based on extension and content"""
    
    EXTENSION_MAP = {
        '.crash': 'crash',
        '.ips': 'crash',  # iOS/macOS crash format
        '.panic': 'panic',
        '.spin': 'spindump',
        '.diag': 'diagnostic',
        '.log': 'application',
        '.txt': 'text',
    }
    
    CONTENT_PATTERNS = {
        'crash': [
            re.compile(r'Incident Identifier:', re.I),
            re.compile(r'CrashReporter Key:', re.I),
            re.compile(r'Exception Type:', re.I),
        ],
        'diagnostic': [
            re.compile(r'Diagnostic Report', re.I),
            re.compile(r'sysdiagnose', re.I),
        ],
        'spindump': [
            re.compile(r'spindump.*report', re.I),
            re.compile(r'Heavy format:', re.I),
        ],
        'system': [
            re.compile(r'kernel\[\d+\]:', re.I),
            re.compile(r'com\.apple\.', re.I),
        ],
    }
    
    @classmethod
    def detect_type(cls, filepath: Path) -> str:
        """Detect log file type from extension and content"""
        # First try extension
        extension = filepath.suffix.lower()
        if extension in cls.EXTENSION_MAP:
            log_type = cls.EXTENSION_MAP[extension]
            if log_type != 'text':  # If not generic, use it
                return log_type
        
        # Check content for more specific type
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                # Read first 2KB for type detection
                sample = f.read(2048)
                
                for log_type, patterns in cls.CONTENT_PATTERNS.items():
                    for pattern in patterns:
                        if pattern.search(sample):
                            return log_type
        except Exception:
            pass
        
        # Default based on extension or unknown
        return cls.EXTENSION_MAP.get(extension, 'application')


class SignatureManager:
    """Manages search patterns for log analysis"""
    
    def __init__(self):
        self.exact_patterns: Set[str] = set()
        self.regex_patterns: List[Tuple[str, re.Pattern]] = []
        self.partial_patterns: Set[str] = set()
        self.pattern_metadata: Dict[str, Dict] = {}
    
    def load_from_file(self, filepath: Path) -> int:
        """Load patterns from signature file"""
        loaded = 0
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse metadata if present
                    pattern, metadata = self._parse_metadata(line)
                    
                    # Determine pattern type
                    if pattern.startswith('REGEX:'):
                        pattern_str = pattern[6:].strip()
                        try:
                            compiled = re.compile(pattern_str, re.IGNORECASE)
                            self.regex_patterns.append((pattern_str, compiled))
                            if metadata:
                                self.pattern_metadata[pattern_str] = metadata
                            loaded += 1
                        except re.error:
                            print(f"Warning: Invalid regex pattern: {pattern_str}", file=sys.stderr)
                    
                    elif pattern.startswith('PARTIAL:'):
                        pattern_str = pattern[8:].strip().lower()
                        self.partial_patterns.add(pattern_str)
                        if metadata:
                            self.pattern_metadata[pattern_str] = metadata
                        loaded += 1
                    
                    elif pattern.startswith('EXACT:'):
                        pattern_str = pattern[6:].strip()
                        self.exact_patterns.add(pattern_str)
                        if metadata:
                            self.pattern_metadata[pattern_str] = metadata
                        loaded += 1
                    
                    else:
                        # Default to exact match
                        self.exact_patterns.add(pattern)
                        if metadata:
                            self.pattern_metadata[pattern] = metadata
                        loaded += 1
        
        except Exception as e:
            print(f"Error loading signatures from {filepath}: {e}", file=sys.stderr)
        
        return loaded
    
    def _parse_metadata(self, line: str) -> Tuple[str, Dict[str, str]]:
        """Parse pattern with optional metadata"""
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
                elif key in ['severity', 'sev']:
                    metadata['severity'] = value.upper()
                elif key in ['description', 'desc']:
                    metadata['description'] = value
        
        return pattern, metadata
    
    def search_line(self, line: str, line_lower: str) -> List[Tuple[str, str, Dict]]:
        """Search a line for all patterns. Returns [(pattern, match_type, metadata)]"""
        matches = []
        
        # Exact matches
        for pattern in self.exact_patterns:
            if pattern in line:
                metadata = self.pattern_metadata.get(pattern, {})
                matches.append((pattern, 'exact', metadata))
        
        # Partial matches (case-insensitive)
        for pattern in self.partial_patterns:
            if pattern in line_lower:
                metadata = self.pattern_metadata.get(pattern, {})
                matches.append((pattern, 'partial', metadata))
        
        # Regex matches
        for pattern_str, compiled_pattern in self.regex_patterns:
            if compiled_pattern.search(line):
                metadata = self.pattern_metadata.get(pattern_str, {})
                matches.append((pattern_str, 'regex', metadata))
        
        return matches


class LogDirectoryScanner:
    """Scans directories for log files"""
    
    # Common log directories in macOS
    LOG_DIRECTORIES = [
        '~/Library/Logs',
        '/var/log',
        '/Library/Logs',
    ]
    
    # File extensions to scan
    LOG_EXTENSIONS = {
        '.log', '.txt', '.crash', '.ips', '.panic', '.spin', 
        '.diag', '.diagnostic', '.out', '.err'
    }
    
    def __init__(self, follow_symlinks: bool = False):
        self.follow_symlinks = follow_symlinks
    
    def scan_directory(self, base_path: str, recursive: bool = True) -> List[LogFile]:
        """Scan directory for log files"""
        base_path = Path(base_path).expanduser()
        
        if not base_path.exists():
            print(f"Warning: Directory does not exist: {base_path}", file=sys.stderr)
            return []
        
        if not base_path.is_dir():
            print(f"Warning: Not a directory: {base_path}", file=sys.stderr)
            return []
        
        log_files = []
        
        try:
            if recursive:
                for root, dirs, files in os.walk(base_path, followlinks=self.follow_symlinks):
                    # Skip hidden directories
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    
                    for filename in files:
                        filepath = Path(root) / filename
                        if self._is_log_file(filepath):
                            log_file = self._create_log_file(filepath)
                            if log_file:
                                log_files.append(log_file)
            else:
                for item in base_path.iterdir():
                    if item.is_file() and self._is_log_file(item):
                        log_file = self._create_log_file(item)
                        if log_file:
                            log_files.append(log_file)
        
        except PermissionError as e:
            print(f"Warning: Permission denied: {base_path}", file=sys.stderr)
        except Exception as e:
            print(f"Error scanning directory {base_path}: {e}", file=sys.stderr)
        
        return log_files
    
    def _is_log_file(self, filepath: Path) -> bool:
        """Check if file is a log file based on extension"""
        if not filepath.is_file():
            return False
        
        # Skip hidden files
        if filepath.name.startswith('.'):
            return False
        
        # Check extension
        extension = filepath.suffix.lower()
        if extension in self.LOG_EXTENSIONS:
            return True
        
        # Files without extension might still be logs
        if not extension and filepath.stat().st_size > 0:
            # Check if it's a text file
            try:
                with open(filepath, 'rb') as f:
                    chunk = f.read(512)
                    # Simple text file heuristic
                    if b'\x00' not in chunk:  # Not binary
                        return True
            except Exception:
                pass
        
        return False
    
    def _create_log_file(self, filepath: Path) -> Optional[LogFile]:
        """Create LogFile object from path"""
        try:
            stat = filepath.stat()
            log_type = LogTypeDetector.detect_type(filepath)
            
            return LogFile(
                path=str(filepath),
                filename=filepath.name,
                size=stat.st_size,
                modified=datetime.fromtimestamp(stat.st_mtime).isoformat(),
                log_type=log_type
            )
        except Exception as e:
            print(f"Warning: Error processing {filepath}: {e}", file=sys.stderr)
            return None


class LogAnalyzer:
    """Analyzes log files for patterns"""
    
    def __init__(self, signatures: SignatureManager, max_context_chars: int = 200):
        self.signatures = signatures
        self.max_context_chars = max_context_chars
        self.findings: List[LogFinding] = []
    
    def _extract_log_timestamp(self, line: str) -> Optional[str]:
        """Try to extract timestamp from common macOS log formats"""
        # Common patterns:
        # Dec 21 10:30:15
        # 2025-12-21 10:30:15
        # Dec 21 2025 10:30:15
        # [2025-12-21 10:30:15]
        
        import re
        
        patterns = [
            # Dec 21 10:30:15
            r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            # 2025-12-21 10:30:15
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            # Dec 21 2025 10:30:15
            r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        
        return None
    
    def analyze_log_file(self, log_file: LogFile, progress: bool = True) -> List[LogFinding]:
        """Analyze a single log file"""
        findings = []
        
        try:
            with open(log_file.path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.rstrip('\n\r')
                    line_lower = line.lower()
                    
                    # Search for patterns
                    matches = self.signatures.search_line(line, line_lower)
                    
                    for pattern, match_type, metadata in matches:
                        # Create context (truncated)
                        context = line[:self.max_context_chars]
                        if len(line) > self.max_context_chars:
                            context += '...'
                        
                        # Extract timestamp from log line
                        log_timestamp = self._extract_log_timestamp(line)
                        
                        # Determine severity
                        severity = metadata.get('severity', self._auto_severity(pattern))
                        category = metadata.get('category', None)
                        
                        finding = LogFinding(
                            timestamp=datetime.now().isoformat(),
                            log_file=log_file.filename,
                            log_type=log_file.log_type,
                            line_number=line_num,
                            match_type=match_type,
                            pattern=pattern,
                            context=context,
                            severity=severity,
                            category=category,
                            full_line=line,  # Store complete log line
                            log_timestamp=log_timestamp  # Store extracted timestamp
                        )
                        findings.append(finding)
            
            if progress and findings:
                print(f"  Found {len(findings)} matches in {log_file.filename}")
        
        except Exception as e:
            print(f"Error analyzing {log_file.path}: {e}", file=sys.stderr)
        
        return findings
    
    def _auto_severity(self, pattern: str) -> str:
        """Automatically determine severity based on pattern keywords"""
        pattern_lower = pattern.lower()
        
        high_keywords = {
            'exploit', 'shellcode', 'payload', 'backdoor', 'rootkit',
            'malware', 'ransomware', 'trojan', 'keylog', 'password',
            'credential', 'inject', 'overflow', 'vulnerability'
        }
        
        medium_keywords = {
            'suspicious', 'anomaly', 'warning', 'error', 'fail',
            'unauthorized', 'denied', 'violation', 'breach'
        }
        
        if any(keyword in pattern_lower for keyword in high_keywords):
            return 'HIGH'
        elif any(keyword in pattern_lower for keyword in medium_keywords):
            return 'MEDIUM'
        else:
            return 'LOW'


class ReportGenerator:
    """Generates analysis reports in multiple formats"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_reports(self, log_files: List[LogFile], findings: List[LogFinding], 
                        format: str = 'all') -> List[Path]:
        """Generate analysis reports"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        generated = []
        
        if format in ['csv', 'all']:
            csv_path = self.output_dir / f'log_analysis_{timestamp}.csv'
            self._generate_csv(findings, csv_path)
            generated.append(csv_path)
        
        if format in ['json', 'all']:
            json_path = self.output_dir / f'log_analysis_{timestamp}.json'
            self._generate_json(log_files, findings, json_path)
            generated.append(json_path)
        
        if format in ['md', 'markdown', 'all']:
            md_path = self.output_dir / f'log_analysis_{timestamp}.md'
            self._generate_markdown(log_files, findings, md_path)
            generated.append(md_path)
        
        return generated
    
    def _generate_csv(self, findings: List[LogFinding], filepath: Path):
        """Generate CSV report"""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            if findings:
                writer = csv.DictWriter(f, fieldnames=findings[0].to_dict().keys())
                writer.writeheader()
                for finding in findings:
                    writer.writerow(finding.to_dict())
        
        print(f"CSV report: {filepath}")
    
    def _generate_json(self, log_files: List[LogFile], findings: List[LogFinding], 
                      filepath: Path):
        """Generate JSON report"""
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_log_files': len(log_files),
            'total_findings': len(findings),
            'severity_summary': self._get_severity_summary(findings),
            'log_files': [lf.to_dict() for lf in log_files],
            'findings': [f.to_dict() for f in findings]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"JSON report: {filepath}")
    
    def _generate_markdown(self, log_files: List[LogFile], findings: List[LogFinding], 
                          filepath: Path):
        """Generate Markdown report"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("# macOS Log Analysis Report\n\n")
            f.write(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Total Log Files Scanned:** {len(log_files)}\n\n")
            f.write(f"**Total Findings:** {len(findings)}\n\n")
            
            # Severity summary
            severity_summary = self._get_severity_summary(findings)
            f.write("## Severity Summary\n\n")
            for severity, count in sorted(severity_summary.items(), reverse=True):
                f.write(f"- **{severity}:** {count}\n")
            f.write("\n")
            
            # Category summary
            category_summary = self._get_category_summary(findings)
            if category_summary:
                f.write("## Category Summary\n\n")
                for category, count in sorted(category_summary.items(), 
                                            key=lambda x: x[1], reverse=True):
                    f.write(f"- **{category}:** {count}\n")
                f.write("\n")
            
            # Log file summary
            f.write("## Log Files Analyzed\n\n")
            log_type_groups = defaultdict(list)
            for log_file in log_files:
                log_type_groups[log_file.log_type].append(log_file)
            
            for log_type, files in sorted(log_type_groups.items()):
                f.write(f"### {log_type.title()} Logs ({len(files)})\n\n")
                for log_file in sorted(files, key=lambda x: x.filename)[:10]:
                    size_mb = log_file.size / (1024 * 1024)
                    f.write(f"- `{log_file.filename}` ({size_mb:.2f} MB)\n")
                if len(files) > 10:
                    f.write(f"- ... and {len(files) - 10} more\n")
                f.write("\n")
            
            # Findings by severity
            f.write("## Findings\n\n")
            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                severity_findings = [f for f in findings if f.severity == severity]
                if severity_findings:
                    f.write(f"### {severity} Severity ({len(severity_findings)})\n\n")
                    
                    for finding in severity_findings[:20]:  # Limit to first 20
                        f.write(f"#### Line {finding.line_number}\n\n")
                        
                        # Add analysis timestamp
                        f.write(f"- **Date/Time Logged:** {finding.timestamp}\n")
                        
                        # Add log file name prominently
                        f.write(f"- **Log File Name:** {finding.log_file}\n")
                        
                        # Add log timestamp if available
                        if finding.log_timestamp:
                            f.write(f"- **Log Date/Time:** {finding.log_timestamp}\n")
                        
                        f.write(f"- **Pattern:** `{finding.pattern}`\n")
                        f.write(f"- **Match Type:** {finding.match_type}\n")
                        f.write(f"- **Log Type:** {finding.log_type}\n")
                        if finding.category:
                            f.write(f"- **Category:** {finding.category}\n")
                        
                        # Add full log line
                        if finding.full_line:
                            f.write(f"- **Full Log Line:**\n")
                            f.write(f"  ```\n")
                            f.write(f"  {finding.full_line}\n")
                            f.write(f"  ```\n")
                        
                        f.write(f"- **Context:** `{finding.context}`\n\n")
                    
                    if len(severity_findings) > 20:
                        f.write(f"*... and {len(severity_findings) - 20} more {severity} findings*\n\n")
        
        print(f"Markdown report: {filepath}")
    
    def _get_severity_summary(self, findings: List[LogFinding]) -> Dict[str, int]:
        """Get count of findings by severity"""
        summary = defaultdict(int)
        for finding in findings:
            summary[finding.severity] += 1
        return dict(summary)
    
    def _get_category_summary(self, findings: List[LogFinding]) -> Dict[str, int]:
        """Get count of findings by category"""
        summary = defaultdict(int)
        for finding in findings:
            if finding.category:
                summary[finding.category] += 1
        return dict(summary)


def create_example_patterns(filepath: Path):
    """Create example pattern file"""
    examples = """# macOS Log Analysis Patterns
# Format: PATTERN|CATEGORY:cat|SEVERITY:sev|DESC:description

# Crashes and Errors
EXACT:Exception Type:|CATEGORY:Crash|SEVERITY:HIGH|DESC:Application crash detected
PARTIAL:segmentation fault|CATEGORY:Crash|SEVERITY:HIGH
REGEX:fatal error.*|CATEGORY:Error|SEVERITY:MEDIUM

# Security Events
PARTIAL:authentication fail|CATEGORY:Security|SEVERITY:HIGH
PARTIAL:unauthorized|CATEGORY:Security|SEVERITY:HIGH
REGEX:permission denied|CATEGORY:Security|SEVERITY:MEDIUM
PARTIAL:sudo|CATEGORY:Security|SEVERITY:LOW

# Malware Indicators
PARTIAL:malware|CATEGORY:Malware|SEVERITY:HIGH
PARTIAL:virus|CATEGORY:Malware|SEVERITY:HIGH
PARTIAL:trojan|CATEGORY:Malware|SEVERITY:HIGH
REGEX:suspicious.*process|CATEGORY:Malware|SEVERITY:MEDIUM

# Network Activity
PARTIAL:connection refused|CATEGORY:Network|SEVERITY:LOW
PARTIAL:timeout|CATEGORY:Network|SEVERITY:LOW
REGEX:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|CATEGORY:Network|SEVERITY:LOW

# System Events
PARTIAL:kernel panic|CATEGORY:System|SEVERITY:HIGH
PARTIAL:system shutdown|CATEGORY:System|SEVERITY:MEDIUM
PARTIAL:out of memory|CATEGORY:System|SEVERITY:MEDIUM

# User-Defined Patterns
# Add your custom patterns below:
"""
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(examples)
    
    print(f"Created example pattern file: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description='macOS Log Directory Analyzer - Intelligent log discovery and analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan ~/Library/Logs with example patterns
  %(prog)s
  
  # Scan specific directory
  %(prog)s -d /var/log -p patterns.txt
  
  # Scan multiple directories
  %(prog)s -d ~/Library/Logs /Library/Logs -p patterns.txt
  
  # Non-recursive scan
  %(prog)s -d ~/Library/Logs --no-recursive
  
  # Create example pattern file
  %(prog)s --create-example patterns.txt
        """
    )
    
    parser.add_argument('-d', '--directories', nargs='+', 
                       default=['~/Library/Logs'],
                       help='Directory/directories to scan (default: ~/Library/Logs)')
    
    parser.add_argument('-p', '--patterns', nargs='+',
                       help='Pattern file(s) for searching')
    
    parser.add_argument('-o', '--output-dir', default='.',
                       help='Output directory for reports (default: current directory)')
    
    parser.add_argument('-f', '--format', 
                       choices=['csv', 'json', 'md', 'markdown', 'all'],
                       default='all',
                       help='Report format (default: all)')
    
    parser.add_argument('--no-recursive', action='store_true',
                       help='Disable recursive directory scanning')
    
    parser.add_argument('--create-example', metavar='FILE',
                       help='Create example pattern file and exit')
    
    parser.add_argument('--list-only', action='store_true',
                       help='List log files without analyzing')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Create example patterns if requested
    if args.create_example:
        create_example_patterns(Path(args.create_example))
        return 0
    
    # Initialize components
    print("macOS Log Directory Analyzer")
    print("=" * 60)
    
    # Scan directories
    scanner = LogDirectoryScanner()
    all_log_files = []
    
    for directory in args.directories:
        print(f"\nScanning: {directory}")
        log_files = scanner.scan_directory(directory, recursive=not args.no_recursive)
        all_log_files.extend(log_files)
        print(f"  Found {len(log_files)} log files")
    
    if not all_log_files:
        print("\nNo log files found.")
        return 1
    
    # Group by type
    log_type_summary = defaultdict(int)
    for log_file in all_log_files:
        log_type_summary[log_file.log_type] += 1
    
    print(f"\nTotal log files discovered: {len(all_log_files)}")
    print("\nLog types:")
    for log_type, count in sorted(log_type_summary.items(), key=lambda x: x[1], reverse=True):
        print(f"  {log_type}: {count}")
    
    # If list-only, stop here
    if args.list_only:
        return 0
    
    # Load patterns
    if not args.patterns:
        print("\nNo pattern files specified. Use -p to specify patterns.")
        print("Use --create-example to generate example pattern file.")
        return 1
    
    signatures = SignatureManager()
    total_patterns = 0
    
    for pattern_file in args.patterns:
        pattern_path = Path(pattern_file).expanduser()
        if not pattern_path.exists():
            print(f"Warning: Pattern file not found: {pattern_file}", file=sys.stderr)
            continue
        
        loaded = signatures.load_from_file(pattern_path)
        total_patterns += loaded
        print(f"\nLoaded {loaded} patterns from {pattern_file}")
    
    if total_patterns == 0:
        print("\nNo patterns loaded. Cannot analyze.")
        return 1
    
    print(f"\nTotal patterns loaded: {total_patterns}")
    print(f"  Exact: {len(signatures.exact_patterns)}")
    print(f"  Partial: {len(signatures.partial_patterns)}")
    print(f"  Regex: {len(signatures.regex_patterns)}")
    
    # Analyze logs
    print("\nAnalyzing log files...")
    analyzer = LogAnalyzer(signatures)
    all_findings = []
    
    for i, log_file in enumerate(all_log_files, 1):
        if args.verbose:
            print(f"  [{i}/{len(all_log_files)}] {log_file.filename}")
        
        findings = analyzer.analyze_log_file(log_file, progress=args.verbose)
        all_findings.extend(findings)
    
    print(f"\nAnalysis complete: {len(all_findings)} findings")
    
    # Generate reports
    output_dir = Path(args.output_dir)
    reporter = ReportGenerator(output_dir)
    
    print("\nGenerating reports...")
    generated_files = reporter.generate_reports(all_log_files, all_findings, args.format)
    
    print(f"\nReports generated: {len(generated_files)}")
    for report_file in generated_files:
        print(f"  {report_file}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
