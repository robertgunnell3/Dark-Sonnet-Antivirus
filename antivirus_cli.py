#!/usr/bin/env python3
"""
Antivirus CLI - Command Line Interface
User-friendly interface for the antivirus system
"""

import sys
import os
import argparse
import json
from pathlib import Path
from datetime import datetime
from antivirus_engine import AntivirusEngine, ScanResult
from behavioral_analysis import BehavioralAnalyzer
import time

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_banner():
    """Print application banner"""
    banner = f"""
{Colors.CYAN}{'=' * 70}
    █████╗ ███╗   ██╗████████╗██╗██╗   ██╗██╗██████╗ ██╗   ██╗███████╗
   ██╔══██╗████╗  ██║╚══██╔══╝██║██║   ██║██║██╔══██╗██║   ██║██╔════╝
   ███████║██╔██╗ ██║   ██║   ██║██║   ██║██║██████╔╝██║   ██║███████╗
   ██╔══██║██║╚██╗██║   ██║   ██║╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║
   ██║  ██║██║ ╚████║   ██║   ██║ ╚████╔╝ ██║██║  ██║╚██████╔╝███████║
   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
                    Advanced Protection System v1.0
{'=' * 70}{Colors.ENDC}
    """
    print(banner)


def print_status(message: str, status: str = 'info'):
    """Print formatted status message"""
    if status == 'success':
        print(f"{Colors.GREEN}[✓]{Colors.ENDC} {message}")
    elif status == 'error':
        print(f"{Colors.RED}[✗]{Colors.ENDC} {message}")
    elif status == 'warning':
        print(f"{Colors.YELLOW}[!]{Colors.ENDC} {message}")
    elif status == 'info':
        print(f"{Colors.BLUE}[i]{Colors.ENDC} {message}")
    else:
        print(f"[ ] {message}")


def print_scan_result(result: ScanResult):
    """Print formatted scan result"""
    status_color = Colors.RED if result.is_infected else Colors.GREEN
    status_text = "INFECTED" if result.is_infected else "CLEAN"
    
    print(f"\n{Colors.BOLD}File:{Colors.ENDC} {result.filepath}")
    print(f"{Colors.BOLD}Status:{Colors.ENDC} {status_color}{status_text}{Colors.ENDC}")
    print(f"{Colors.BOLD}Hash:{Colors.ENDC} {result.file_hash}")
    print(f"{Colors.BOLD}Heuristic Score:{Colors.ENDC} {result.heuristic_score}")
    
    if result.is_infected:
        print(f"\n{Colors.RED}{Colors.BOLD}Threats Detected:{Colors.ENDC}")
        for threat in result.threats_found:
            print(f"  • {threat['name']}")
            print(f"    Method: {threat['method']} | Severity: {threat['severity']}")
    
    if result.details.get('heuristic_findings'):
        print(f"\n{Colors.YELLOW}Heuristic Findings:{Colors.ENDC}")
        for finding in result.details['heuristic_findings'][:5]:  # Show top 5
            print(f"  • {finding}")


def scan_command(args):
    """Handle scan command"""
    print_status(f"Initializing antivirus engine...", 'info')
    av = AntivirusEngine()
    
    target = args.target
    use_heuristics = not args.no_heuristics
    
    if not os.path.exists(target):
        print_status(f"Target not found: {target}", 'error')
        return
    
    # Determine if target is file or directory
    if os.path.isfile(target):
        print_status(f"Scanning file: {target}", 'info')
        result = av.scan_file(target, use_heuristics)
        print_scan_result(result)
        
        if result.is_infected and args.quarantine:
            print_status("Moving file to quarantine...", 'warning')
            if av.quarantine_file(target):
                print_status("File quarantined successfully", 'success')
            else:
                print_status("Failed to quarantine file", 'error')
    
    elif os.path.isdir(target):
        print_status(f"Scanning directory: {target}", 'info')
        print_status("This may take a while...", 'info')
        
        results = av.scan_directory(target, recursive=args.recursive, use_heuristics=use_heuristics)
        
        # Generate report
        report = av.generate_report(results)
        
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.ENDC}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.ENDC}")
        print(f"{Colors.BOLD}{'=' * 70}{Colors.ENDC}")
        print(f"Total Files Scanned: {report['scan_summary']['total_files_scanned']}")
        print(f"{Colors.RED}Infected Files: {report['scan_summary']['infected_files']}{Colors.ENDC}")
        print(f"{Colors.GREEN}Clean Files: {report['scan_summary']['clean_files']}{Colors.ENDC}")
        
        if report['scan_summary']['infected_files'] > 0:
            print(f"\n{Colors.RED}{Colors.BOLD}INFECTED FILES:{Colors.ENDC}")
            for infected in report['infected_files']:
                print(f"  • {infected['filepath']}")
                for threat in infected['threats']:
                    print(f"    - {threat['name']} ({threat['method']})")
            
            if args.quarantine:
                print(f"\n{Colors.YELLOW}Quarantining infected files...{Colors.ENDC}")
                for result in results:
                    if result.is_infected:
                        if av.quarantine_file(result.filepath):
                            print_status(f"Quarantined: {result.filepath}", 'success')
        
        # Save report to file
        if args.report:
            report_path = args.report
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            print_status(f"Report saved to: {report_path}", 'success')


def update_command(args):
    """Handle signature update command"""
    print_status("Checking for signature updates...", 'info')
    
    av = AntivirusEngine()
    
    # In a real implementation, this would download from a server
    # For now, we'll show how to add custom signatures
    if args.signature_file:
        print_status(f"Loading signatures from: {args.signature_file}", 'info')
        try:
            with open(args.signature_file, 'r') as f:
                signatures = json.load(f)
            
            av.update_signatures(signatures)
            print_status(f"Added {len(signatures)} signatures", 'success')
        except Exception as e:
            print_status(f"Error loading signatures: {e}", 'error')
    else:
        print_status("No signature file provided", 'warning')
        print_status("Use --signature-file to specify a JSON file with signatures", 'info')


def monitor_command(args):
    """Handle real-time monitoring command"""
    print_status("Starting behavioral monitoring...", 'info')
    
    analyzer = BehavioralAnalyzer()
    analyzer.start_monitoring()
    
    print_status("Monitoring active. Press Ctrl+C to stop.", 'success')
    print_status("Watching for suspicious behavior...", 'info')
    
    try:
        while True:
            time.sleep(5)
            
            # Check for alerts
            if analyzer.alerts:
                recent_alerts = [a for a in analyzer.alerts 
                               if (datetime.now() - datetime.fromisoformat(a['timestamp'])).seconds < 10]
                
                for alert in recent_alerts:
                    severity_color = Colors.RED if alert['severity'] == 'critical' else Colors.YELLOW
                    print(f"\n{severity_color}[ALERT]{Colors.ENDC} {alert.get('description', 'Unknown')}")
                    if 'pid' in alert:
                        print(f"  Process: {alert.get('process_name')} (PID: {alert['pid']})")
                    if 'filepath' in alert:
                        print(f"  File: {alert['filepath']}")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Stopping monitoring...{Colors.ENDC}")
        analyzer.stop_monitoring()
        
        # Print summary
        report = analyzer.get_report()
        print(f"\n{Colors.BOLD}MONITORING SUMMARY{Colors.ENDC}")
        print(f"Total Alerts: {report['total_alerts']}")
        print(f"Suspicious Processes: {len(report['suspicious_processes'])}")
        
        if report['suspicious_processes']:
            print(f"\n{Colors.YELLOW}Suspicious Processes Detected:{Colors.ENDC}")
            for proc in report['suspicious_processes']:
                print(f"  • {proc['name']} (PID: {proc['pid']}) - Score: {proc['score']}")


def quarantine_command(args):
    """Handle quarantine management"""
    av = AntivirusEngine()
    quarantine_dir = av.quarantine_dir
    
    if args.list:
        print_status(f"Quarantine directory: {quarantine_dir}", 'info')
        
        if not quarantine_dir.exists():
            print_status("Quarantine is empty", 'info')
            return
        
        files = list(quarantine_dir.iterdir())
        if not files:
            print_status("Quarantine is empty", 'info')
        else:
            print(f"\n{Colors.BOLD}Quarantined Files ({len(files)}):{Colors.ENDC}")
            for f in files:
                size = f.stat().st_size
                mtime = datetime.fromtimestamp(f.stat().st_mtime)
                print(f"  • {f.name}")
                print(f"    Size: {size} bytes | Quarantined: {mtime}")
    
    elif args.restore:
        file_to_restore = quarantine_dir / args.restore
        if file_to_restore.exists():
            restore_path = input(f"Restore to (path): ")
            try:
                os.rename(file_to_restore, restore_path)
                print_status(f"Restored: {restore_path}", 'success')
            except Exception as e:
                print_status(f"Error restoring file: {e}", 'error')
        else:
            print_status(f"File not found in quarantine: {args.restore}", 'error')
    
    elif args.delete:
        file_to_delete = quarantine_dir / args.delete
        if file_to_delete.exists():
            confirm = input(f"Delete {args.delete} permanently? (yes/no): ")
            if confirm.lower() == 'yes':
                file_to_delete.unlink()
                print_status(f"Deleted: {args.delete}", 'success')
        else:
            print_status(f"File not found in quarantine: {args.delete}", 'error')
    
    elif args.clear:
        confirm = input("Delete ALL quarantined files? (yes/no): ")
        if confirm.lower() == 'yes':
            for f in quarantine_dir.iterdir():
                f.unlink()
            print_status("Quarantine cleared", 'success')


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced Antivirus Protection System',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan files or directories')
    scan_parser.add_argument('target', help='File or directory to scan')
    scan_parser.add_argument('-r', '--recursive', action='store_true', 
                           help='Recursively scan directories')
    scan_parser.add_argument('-q', '--quarantine', action='store_true',
                           help='Quarantine infected files')
    scan_parser.add_argument('--no-heuristics', action='store_true',
                           help='Disable heuristic analysis')
    scan_parser.add_argument('--report', help='Save report to file')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update signature database')
    update_parser.add_argument('--signature-file', help='JSON file with signatures')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Real-time behavioral monitoring')
    
    # Quarantine command
    quarantine_parser = subparsers.add_parser('quarantine', help='Manage quarantine')
    quarantine_parser.add_argument('-l', '--list', action='store_true',
                                  help='List quarantined files')
    quarantine_parser.add_argument('--restore', help='Restore file from quarantine')
    quarantine_parser.add_argument('--delete', help='Delete file from quarantine')
    quarantine_parser.add_argument('--clear', action='store_true',
                                  help='Clear all quarantined files')
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.command == 'scan':
        scan_command(args)
    elif args.command == 'update':
        update_command(args)
    elif args.command == 'monitor':
        monitor_command(args)
    elif args.command == 'quarantine':
        quarantine_command(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
