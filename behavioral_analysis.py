"""
Behavioral Analysis Module
Monitors process behavior for suspicious activity
"""

import os
import time
import psutil
import threading
from datetime import datetime
from typing import Dict, List, Callable
import logging

logger = logging.getLogger(__name__)


class BehaviorPattern:
    """Represents a suspicious behavior pattern"""
    def __init__(self, name: str, description: str, severity: str, threshold: int):
        self.name = name
        self.description = description
        self.severity = severity
        self.threshold = threshold
        self.occurrences = 0


class ProcessMonitor:
    """Monitors running processes for suspicious behavior"""
    
    def __init__(self):
        self.monitored_processes: Dict[int, dict] = {}
        self.suspicious_behaviors: List[dict] = []
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Define suspicious behavior patterns
        self.behavior_patterns = {
            'rapid_file_creation': BehaviorPattern(
                'Rapid File Creation',
                'Process creating many files quickly (possible ransomware)',
                'high',
                threshold=50
            ),
            'mass_file_modification': BehaviorPattern(
                'Mass File Modification',
                'Process modifying many files (possible ransomware)',
                'high',
                threshold=30
            ),
            'network_scanning': BehaviorPattern(
                'Network Scanning',
                'Process opening many network connections',
                'medium',
                threshold=20
            ),
            'privilege_escalation': BehaviorPattern(
                'Privilege Escalation Attempt',
                'Process attempting to gain elevated privileges',
                'critical',
                threshold=1
            ),
            'registry_modification': BehaviorPattern(
                'Registry Modification',
                'Suspicious registry changes',
                'medium',
                threshold=10
            ),
            'data_exfiltration': BehaviorPattern(
                'Data Exfiltration',
                'Large amounts of data being sent over network',
                'high',
                threshold=5
            )
        }
        
        # Callbacks for when suspicious behavior is detected
        self.alert_callbacks: List[Callable] = []
    
    def register_alert_callback(self, callback: Callable):
        """Register a callback to be called when suspicious behavior is detected"""
        self.alert_callbacks.append(callback)
    
    def start_monitoring(self):
        """Start monitoring processes"""
        if self.is_monitoring:
            logger.warning("Monitoring already started")
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Process monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring processes"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Process monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                self._check_processes()
                time.sleep(2)  # Check every 2 seconds
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
    
    def _check_processes(self):
        """Check all running processes"""
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
            try:
                pid = proc.info['pid']
                
                # Initialize process tracking if new
                if pid not in self.monitored_processes:
                    self.monitored_processes[pid] = {
                        'name': proc.info['name'],
                        'exe': proc.info['exe'],
                        'start_time': proc.info['create_time'],
                        'file_operations': 0,
                        'network_connections': 0,
                        'suspicious_score': 0,
                        'alerts': []
                    }
                
                # Analyze process behavior
                self._analyze_process_behavior(proc, pid)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    
    def _analyze_process_behavior(self, proc, pid: int):
        """Analyze a specific process for suspicious behavior"""
        try:
            process_data = self.monitored_processes[pid]
            
            # Check file operations
            try:
                open_files = proc.open_files()
                current_file_count = len(open_files)
                
                # Detect rapid file creation
                if current_file_count > process_data['file_operations'] + 10:
                    self._flag_behavior(pid, 'rapid_file_creation', 
                                      f"Opened {current_file_count - process_data['file_operations']} files")
                
                process_data['file_operations'] = current_file_count
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Check network connections
            try:
                connections = proc.connections()
                current_conn_count = len(connections)
                
                # Detect network scanning
                if current_conn_count > 15:
                    self._flag_behavior(pid, 'network_scanning', 
                                      f"{current_conn_count} active connections")
                
                # Check for connections to suspicious ports
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        # Check for common malware C2 ports
                        suspicious_ports = [4444, 5555, 6666, 7777, 8080, 8888, 9999]
                        if conn.raddr and conn.raddr.port in suspicious_ports:
                            self._flag_behavior(pid, 'data_exfiltration',
                                              f"Connection to suspicious port {conn.raddr.port}")
                
                process_data['network_connections'] = current_conn_count
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Check process privileges
            try:
                if proc.username() == 'SYSTEM' or proc.username() == 'root':
                    # Check if this process spawned recently with high privileges
                    if time.time() - process_data['start_time'] < 300:  # 5 minutes
                        self._flag_behavior(pid, 'privilege_escalation',
                                          f"Recently started with elevated privileges")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Check CPU usage (cryptocurrency mining detection)
            try:
                cpu_percent = proc.cpu_percent(interval=0.1)
                if cpu_percent > 80:
                    process_data['suspicious_score'] += 5
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
                
        except Exception as e:
            logger.debug(f"Error analyzing process {pid}: {e}")
    
    def _flag_behavior(self, pid: int, behavior_type: str, details: str):
        """Flag suspicious behavior"""
        if behavior_type not in self.behavior_patterns:
            return
        
        pattern = self.behavior_patterns[behavior_type]
        pattern.occurrences += 1
        
        process_data = self.monitored_processes[pid]
        process_data['suspicious_score'] += 10
        
        alert = {
            'timestamp': datetime.now().isoformat(),
            'pid': pid,
            'process_name': process_data['name'],
            'process_exe': process_data['exe'],
            'behavior': pattern.name,
            'description': pattern.description,
            'details': details,
            'severity': pattern.severity,
            'suspicious_score': process_data['suspicious_score']
        }
        
        process_data['alerts'].append(alert)
        self.suspicious_behaviors.append(alert)
        
        logger.warning(f"Suspicious behavior detected: {pattern.name} - PID {pid} - {details}")
        
        # Call alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def get_suspicious_processes(self, min_score: int = 20) -> List[dict]:
        """Get list of suspicious processes"""
        suspicious = []
        for pid, data in self.monitored_processes.items():
            if data['suspicious_score'] >= min_score:
                suspicious.append({
                    'pid': pid,
                    'name': data['name'],
                    'exe': data['exe'],
                    'score': data['suspicious_score'],
                    'alerts': data['alerts']
                })
        return suspicious
    
    def kill_process(self, pid: int) -> bool:
        """Terminate a suspicious process"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=5)
            logger.info(f"Terminated process: PID {pid}")
            return True
        except Exception as e:
            logger.error(f"Error terminating process {pid}: {e}")
            return False


class FileSystemWatcher:
    """Watches file system for suspicious activity"""
    
    def __init__(self, watch_paths: List[str] = None):
        self.watch_paths = watch_paths or [os.path.expanduser('~')]
        self.is_watching = False
        self.watch_thread = None
        self.suspicious_activities = []
        
        # Track file operations
        self.file_snapshots: Dict[str, dict] = {}
        self.alert_callbacks: List[Callable] = []
    
    def register_alert_callback(self, callback: Callable):
        """Register callback for file system alerts"""
        self.alert_callbacks.append(callback)
    
    def start_watching(self):
        """Start watching file system"""
        if self.is_watching:
            return
        
        self.is_watching = True
        self.watch_thread = threading.Thread(target=self._watch_loop, daemon=True)
        self.watch_thread.start()
        logger.info(f"File system watching started for: {self.watch_paths}")
    
    def stop_watching(self):
        """Stop watching file system"""
        self.is_watching = False
        if self.watch_thread:
            self.watch_thread.join(timeout=5)
        logger.info("File system watching stopped")
    
    def _watch_loop(self):
        """Main watching loop"""
        while self.is_watching:
            try:
                for watch_path in self.watch_paths:
                    if os.path.exists(watch_path):
                        self._scan_directory(watch_path)
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Error in watch loop: {e}")
    
    def _scan_directory(self, directory: str):
        """Scan directory for changes"""
        try:
            for root, dirs, files in os.walk(directory):
                # Limit depth to avoid performance issues
                if root.count(os.sep) - directory.count(os.sep) > 3:
                    continue
                
                for filename in files:
                    filepath = os.path.join(root, filename)
                    self._check_file(filepath)
        except Exception as e:
            logger.debug(f"Error scanning directory {directory}: {e}")
    
    def _check_file(self, filepath: str):
        """Check individual file for suspicious changes"""
        try:
            # Get file stats
            stats = os.stat(filepath)
            current_snapshot = {
                'size': stats.st_size,
                'mtime': stats.st_mtime,
                'extension': os.path.splitext(filepath)[1].lower()
            }
            
            # Check if file was tracked before
            if filepath in self.file_snapshots:
                old_snapshot = self.file_snapshots[filepath]
                
                # Detect extension change (possible ransomware)
                if old_snapshot['extension'] != current_snapshot['extension']:
                    suspicious_extensions = ['.encrypted', '.locked', '.crypto', '.crypt']
                    if current_snapshot['extension'] in suspicious_extensions:
                        self._alert_file_activity(
                            filepath,
                            'File extension changed to encrypted format',
                            'critical'
                        )
            
            # Update snapshot
            self.file_snapshots[filepath] = current_snapshot
            
        except Exception as e:
            logger.debug(f"Error checking file {filepath}: {e}")
    
    def _alert_file_activity(self, filepath: str, description: str, severity: str):
        """Alert on suspicious file activity"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'filepath': filepath,
            'description': description,
            'severity': severity,
            'type': 'file_system'
        }
        
        self.suspicious_activities.append(alert)
        logger.warning(f"File system alert: {description} - {filepath}")
        
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")


class BehavioralAnalyzer:
    """Main behavioral analysis coordinator"""
    
    def __init__(self):
        self.process_monitor = ProcessMonitor()
        self.fs_watcher = FileSystemWatcher()
        self.alerts = []
        
        # Register callbacks
        self.process_monitor.register_alert_callback(self._handle_alert)
        self.fs_watcher.register_alert_callback(self._handle_alert)
    
    def _handle_alert(self, alert: dict):
        """Handle alerts from monitors"""
        self.alerts.append(alert)
        
        # Auto-response logic (can be customized)
        if alert.get('severity') == 'critical':
            logger.critical(f"CRITICAL ALERT: {alert}")
            # Could trigger automatic quarantine here
    
    def start_monitoring(self):
        """Start all monitoring"""
        self.process_monitor.start_monitoring()
        self.fs_watcher.start_watching()
        logger.info("Behavioral analysis started")
    
    def stop_monitoring(self):
        """Stop all monitoring"""
        self.process_monitor.stop_monitoring()
        self.fs_watcher.stop_watching()
        logger.info("Behavioral analysis stopped")
    
    def get_report(self) -> dict:
        """Generate behavioral analysis report"""
        return {
            'timestamp': datetime.now().isoformat(),
            'total_alerts': len(self.alerts),
            'suspicious_processes': self.process_monitor.get_suspicious_processes(),
            'recent_alerts': self.alerts[-50:],  # Last 50 alerts
            'monitored_processes': len(self.process_monitor.monitored_processes),
            'file_system_activities': len(self.fs_watcher.suspicious_activities)
        }


if __name__ == "__main__":
    print("Behavioral Analysis Module")
    print("=" * 50)
    
    # Example usage
    analyzer = BehavioralAnalyzer()
    
    print("\n[+] Starting behavioral monitoring...")
    analyzer.start_monitoring()
    
    print("[+] Monitoring active. Press Ctrl+C to stop.")
    print("[+] Watching for suspicious process and file system activity...")
    
    try:
        # Monitor for a period
        time.sleep(30)
        
        # Get report
        report = analyzer.get_report()
        print(f"\n[+] Report: {report}")
        
    except KeyboardInterrupt:
        print("\n[+] Stopping monitoring...")
    finally:
        analyzer.stop_monitoring()
