#!/usr/bin/env python3
"""
Universal Email & File Protocol Scanner v3.0
Professional scanner for Email (SMTP/POP3/IMAP) and File (FTP/SMB) services
High-performance multi-threaded scanner with real-time results
"""

import socket
import threading
import argparse
import time
import re
import sqlite3
import yaml
import json
import base64
import ssl
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from ipaddress import IPv4Network
import xml.etree.ElementTree as ET
from threading import Lock, RLock
import warnings

# Suppress SSL warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*unclosed.*", category=ResourceWarning)

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @staticmethod
    def colorize(text, color):
        return f"{color}{text}{Colors.RESET}"

class ProgressTracker:
    """Thread-safe progress tracking"""
    def __init__(self, total_tasks):
        self.total_tasks = total_tasks
        self.completed = 0
        self.vulnerable_found = 0
        self.services_found = 0
        self.start_time = time.time()
        self.lock = Lock()
        
    def update(self, vulnerable=False, service_found=False):
        with self.lock:
            self.completed += 1
            if vulnerable:
                self.vulnerable_found += 1
            if service_found:
                self.services_found += 1
                
    def get_status(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            rate = self.completed / elapsed if elapsed > 0 else 0
            eta = (self.total_tasks - self.completed) / rate if rate > 0 else 0
            
            return {
                'completed': self.completed,
                'total': self.total_tasks,
                'percentage': (self.completed / self.total_tasks * 100) if self.total_tasks > 0 else 0,
                'vulnerable': self.vulnerable_found,
                'services': self.services_found,
                'rate': rate,
                'eta': eta,
                'elapsed': elapsed
            }

class DatabaseManager:
    """Thread-safe database operations"""
    def __init__(self, db_path, scan_id):
        self.db_path = db_path
        self.scan_id = scan_id
        self.lock = RLock()
        self.init_database()
        
    def get_connection(self):
        """Get thread-safe database connection"""
        return sqlite3.connect(self.db_path, 
                              check_same_thread=False,
                              timeout=30.0,
                              isolation_level='IMMEDIATE')
    
    def init_database(self):
        """Initialize database with enhanced schema"""
        with self.lock:
            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        port INTEGER NOT NULL,
                        protocol_type TEXT,
                        service TEXT,
                        version TEXT,
                        banner TEXT,
                        ssl_enabled INTEGER DEFAULT 0,
                        anonymous_access INTEGER DEFAULT 0,
                        weak_credentials TEXT,
                        vulnerabilities TEXT,
                        file_access TEXT,
                        shares_found TEXT,
                        data_volume_level TEXT,
                        email_count INTEGER DEFAULT 0,
                        response_time INTEGER,
                        server_info TEXT,
                        capabilities TEXT,
                        risk_score INTEGER DEFAULT 0,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(scan_id, ip, port) ON CONFLICT REPLACE
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_metadata (
                        scan_id TEXT PRIMARY KEY,
                        start_time DATETIME,
                        end_time DATETIME,
                        total_hosts INTEGER,
                        total_ports INTEGER,
                        vulnerable_services INTEGER,
                        scan_args TEXT
                    )
                ''')
                
                # Insert scan metadata
                cursor.execute('''
                    INSERT OR REPLACE INTO scan_metadata 
                    (scan_id, start_time, scan_args) 
                    VALUES (?, ?, ?)
                ''', (self.scan_id, datetime.now().isoformat(), str(sys.argv)))
                
                conn.commit()
            finally:
                conn.close()
    
    def save_result(self, result):
        """Save scan result to database"""
        with self.lock:
            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO scan_results (
                        scan_id, ip, port, protocol_type, service, version, banner, ssl_enabled,
                        anonymous_access, weak_credentials, vulnerabilities, file_access,
                        shares_found, data_volume_level, email_count, response_time,
                        server_info, capabilities, risk_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    self.scan_id, result['ip'], result['port'], result.get('protocol_type'),
                    result['service'], result['version'], result['banner'], 
                    result.get('ssl_enabled', 0),
                    1 if result.get('vulnerabilities') else 0,
                    json.dumps(result.get('weak_credentials', [])),
                    json.dumps(result.get('vulnerabilities', [])),
                    json.dumps(result.get('file_access', [])),
                    json.dumps(result.get('shares_found', [])),
                    result.get('data_volume', {}).get('level', 'unknown'),
                    result.get('data_volume', {}).get('email_count', 0),
                    result.get('response_time', 0),
                    json.dumps(result.get('server_info', {})),
                    json.dumps(result.get('capabilities', [])),
                    result.get('risk_score', 0)
                ))
                conn.commit()
            finally:
                conn.close()

class UniversalProtocolScanner:
    def __init__(self, config_file="config.yaml", verbose=False):
        self.config = self.load_config(config_file)
        self.verbose = verbose
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.db_manager = None
        self.progress_tracker = None
        self.results = []
        self.lock = Lock()
        
        # SSL context cache
        self.ssl_context = self.create_ssl_context()
        
        # Enhanced service port mapping
        self.port_service_map = {
            # Email protocols
            25: 'smtp', 465: 'smtps', 587: 'submission', 2525: 'smtp-alt',
            110: 'pop3', 995: 'pop3s',
            143: 'imap', 993: 'imaps',
            # File protocols
            21: 'ftp', 989: 'ftps', 990: 'ftps',
            445: 'smb', 139: 'netbios-ssn', 135: 'rpc',
            # Web protocols (for webmail)
            80: 'http', 443: 'https', 8080: 'http-alt', 8443: 'https-alt'
        }
        
        # Protocol type mapping
        self.protocol_types = {
            'smtp': 'email', 'smtps': 'email', 'submission': 'email', 'smtp-alt': 'email',
            'pop3': 'email', 'pop3s': 'email',
            'imap': 'email', 'imaps': 'email',
            'ftp': 'file', 'ftps': 'file',
            'smb': 'file', 'netbios-ssn': 'file', 'rpc': 'file',
            'http': 'web', 'https': 'web', 'http-alt': 'web', 'https-alt': 'web'
        }
        
        # Known SSL ports
        self.ssl_ports = {465, 995, 993, 443, 8443, 989, 990}
        
    def create_ssl_context(self):
        """Create optimized SSL context"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.SSLv3
        context.set_ciphers('ALL:@SECLEVEL=0')
        return context
        
    def load_config(self, config_file):
        """Load configuration with better error handling"""
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    if self.verbose:
                        print(f"[+] Loaded config from {config_file}")
                    return config
            else:
                if self.verbose:
                    print(f"[!] Config file {config_file} not found, using defaults")
                return self.get_default_config()
        except Exception as e:
            print(f"[!] Error loading config: {e}")
            return self.get_default_config()
    
    def get_default_config(self):
        """Enhanced default configuration for email + file protocols"""
        return {
            'ports': {
                'smtp': [25, 465, 587, 2525],
                'pop3': [110, 995],
                'imap': [143, 993],
                'ftp': [21, 989, 990],
                'smb': [445, 139, 135],
                'web': [80, 443, 8080, 8443],
                'custom': [10025, 10110, 10143, 8025, 8110, 8143]
            },
            'services': {
                'smtp': {
                    'banners': ["220", "ESMTP", "Postfix", "Exchange", "Sendmail", "qmail", "Exim"],
                    'commands': ["EHLO scanner.local", "HELP", "NOOP"],
                    'auth_commands': ["AUTH LOGIN", "AUTH PLAIN"]
                },
                'pop3': {
                    'banners': ["+OK", "POP3", "ready", "Dovecot", "Exchange"],
                    'commands': ["CAPA", "STAT", "LIST"]
                },
                'imap': {
                    'banners': ["* OK", "IMAP4", "ready", "Dovecot", "Exchange"],
                    'commands': ["A001 CAPABILITY", "A002 ID NIL"]
                },
                'ftp': {
                    'banners': ["220", "FTP", "FileZilla", "vsftpd", "ProFTPD", "Pure-FTPd"],
                    'commands': ["USER anonymous", "SYST", "FEAT", "HELP"]
                },
                'smb': {
                    'banners': ["SMB", "CIFS", "Samba", "Windows"],
                    'commands': []  # SMB has binary protocol
                }
            },
            'version_patterns': {
                # Email servers
                'postfix': r"220.*?Postfix\s+(\d+\.\d+\.\d+)",
                'exchange': r"220.*?Microsoft.*?Version[:\s]*(\d+\.\d+)",
                'dovecot': r"\*\s+OK.*?Dovecot\s+(?:ready\s+)?v?(\d+\.\d+\.\d+)",
                'sendmail': r"220.*?Sendmail\s+(\d+\.\d+)",
                'qmail': r"220.*?qmail\s+(\d+\.\d+)",
                'exim': r"220.*?Exim\s+(\d+\.\d+)",
                # FTP servers
                'vsftpd': r"220.*?vsftpd\s+(\d+\.\d+\.\d+)",
                'filezilla': r"220.*?FileZilla\s+Server\s+(\d+\.\d+\.\d+)",
                'proftpd': r"220.*?ProFTPD\s+(\d+\.\d+\.\d+)",
                'pureftpd': r"220.*?Pure-FTPd\s+(\d+\.\d+\.\d+)",
                'iis': r"220.*?Microsoft\s+FTP\s+Service.*?Version\s+(\d+\.\d+)",
                # SMB/Windows
                'samba': r"Samba\s+(\d+\.\d+\.\d+)",
                'windows': r"Windows\s+(\d+\.\d+)"
            },
            'authentication': {
                'test_anonymous': True,
                'test_weak_creds': True,
                'max_attempts_per_service': 20,
                'delay_between_attempts': 0.1,
                'stop_on_first_success': True,
                'common_users': ["admin", "test", "guest", "postmaster", "mail", "ftp", "anonymous"],
                'common_passwords': ["", "password", "123456", "admin", "test", "ftp", "anonymous"]
            },
            'timeouts': {
                'connect': 5,
                'read': 8,
                'ssl_handshake': 10
            },
            'data_volume': {
                'high_indicators': {
                    'banner_size': 1024,
                    'response_time': 5000,
                    'email_count': 10000
                }
            }
        }
    
    def print_banner(self):
        """Print enhanced scanner banner"""
        banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║           Universal Email & File Protocol Scanner v3.0        ║
║              Email (SMTP/POP3/IMAP) + File (FTP/SMB)         ║
╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.YELLOW}[+] Scan ID: {self.scan_id}
[+] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
[+] Protocols: Email, File Transfer, Network Shares{Colors.RESET}
"""
        print(banner)
    
    def create_socket(self, timeout=5):
        """Create socket with proper settings"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock
    
    def create_ssl_socket(self, sock, hostname=''):
        """Create SSL socket with enhanced compatibility"""
        try:
            return self.ssl_context.wrap_socket(sock, server_hostname=hostname)
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] SSL wrap failed: {e}")
            return ssl.wrap_socket(sock)
    
    def scan_port(self, ip, port, timeout=None):
        """Enhanced port scanning"""
        if timeout is None:
            timeout = self.config.get('timeouts', {}).get('connect', 5)
            
        try:
            sock = self.create_socket(timeout)
            start_time = time.time()
            result = sock.connect_ex((ip, port))
            response_time = int((time.time() - start_time) * 1000)
            sock.close()
            
            return result == 0, response_time
            
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Port scan error {ip}:{port} - {e}")
            return False, timeout * 1000
    
    def grab_banner_and_info(self, ip, port, service_type):
        """Enhanced banner grabbing for multiple protocols"""
        timeout = self.config.get('timeouts', {}).get('read', 8)
        ssl_enabled = port in self.ssl_ports
        
        try:
            sock = self.create_socket(timeout)
            
            # Handle SSL ports
            if ssl_enabled:
                try:
                    sock.connect((ip, port))
                    sock = self.create_ssl_socket(sock, ip)
                except Exception as e:
                    if self.verbose:
                        print(f"[DEBUG] SSL handshake failed {ip}:{port} - {e}")
                    sock.close()
                    return None
            else:
                sock.connect((ip, port))
            
            # Get initial banner
            try:
                banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            except:
                banner = ""
            
            banner_size = len(banner)
            
            # Protocol-specific information gathering
            if service_type.startswith('smtp'):
                info = self.gather_smtp_info(sock, banner)
            elif service_type.startswith('pop3'):
                info = self.gather_pop3_info(sock, banner)
            elif service_type.startswith('imap'):
                info = self.gather_imap_info(sock, banner)
            elif service_type.startswith('ftp'):
                info = self.gather_ftp_info(sock, banner)
            elif service_type in ['smb', 'netbios-ssn']:
                info = self.gather_smb_info(sock, banner)
            elif service_type.startswith('http'):
                info = self.gather_http_info(sock, banner, ssl_enabled)
            else:
                info = {'additional_data': ''}
            
            sock.close()
            
            return {
                'banner': banner,
                'banner_size': banner_size,
                'ssl_enabled': ssl_enabled,
                'server_info': info.get('server_info', {}),
                'capabilities': info.get('capabilities', []),
                'security_features': info.get('security_features', []),
                'additional_data': info.get('additional_data', ''),
                'file_access': info.get('file_access', []),
                'shares_found': info.get('shares_found', [])
            }
            
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Banner grab error {ip}:{port} - {e}")
            return None
    
    def gather_smtp_info(self, sock, banner):
        """Gather SMTP-specific information"""
        server_info = {}
        capabilities = []
        security_features = []
        additional_data = banner
        
        try:
            # EHLO command for extended features
            sock.send(b"EHLO scanner.local\r\n")
            time.sleep(0.5)
            ehlo_response = sock.recv(2048).decode('utf-8', errors='ignore')
            additional_data += "\n" + ehlo_response
            
            # Parse EHLO response
            for line in ehlo_response.split('\n'):
                line = line.strip()
                if line.startswith('250-') or line.startswith('250 '):
                    capability = line[4:].strip()
                    if capability and capability != 'scanner.local':
                        capabilities.append(capability)
                        
                        if 'STARTTLS' in capability:
                            security_features.append('STARTTLS')
                        elif 'AUTH' in capability:
                            security_features.append(f"AUTH: {capability}")
                        elif 'SIZE' in capability:
                            server_info['max_message_size'] = capability
                            
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] SMTP info gathering error: {e}")
        
        return {
            'server_info': server_info,
            'capabilities': capabilities,
            'security_features': security_features,
            'additional_data': additional_data
        }
    
    def gather_pop3_info(self, sock, banner):
        """Gather POP3-specific information"""
        server_info = {}
        capabilities = []
        security_features = []
        additional_data = banner
        
        try:
            # CAPA command
            sock.send(b"CAPA\r\n")
            time.sleep(0.5)
            capa_response = sock.recv(2048).decode('utf-8', errors='ignore')
            additional_data += "\n" + capa_response
            
            # Parse capabilities
            for line in capa_response.split('\n'):
                line = line.strip()
                if line and not line.startswith('+OK') and not line.startswith('.'):
                    capabilities.append(line)
                    
                    if 'STLS' in line:
                        security_features.append('STLS')
                    elif 'SASL' in line:
                        security_features.append(f"SASL: {line}")
            
            # STAT command for mailbox info
            try:
                sock.send(b"STAT\r\n")
                time.sleep(0.3)
                stat_response = sock.recv(1024).decode('utf-8', errors='ignore')
                additional_data += "\n" + stat_response
                
                if '+OK' in stat_response:
                    parts = stat_response.split()
                    if len(parts) >= 3:
                        try:
                            server_info['message_count'] = int(parts[1])
                            server_info['mailbox_size'] = int(parts[2])
                        except:
                            pass
            except:
                pass
                
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] POP3 info gathering error: {e}")
        
        return {
            'server_info': server_info,
            'capabilities': capabilities,
            'security_features': security_features,
            'additional_data': additional_data
        }
    
    def gather_imap_info(self, sock, banner):
        """Gather IMAP-specific information"""
        server_info = {}
        capabilities = []
        security_features = []
        additional_data = banner
        
        try:
            # CAPABILITY command
            sock.send(b"A001 CAPABILITY\r\n")
            time.sleep(0.5)
            cap_response = sock.recv(2048).decode('utf-8', errors='ignore')
            additional_data += "\n" + cap_response
            
            # Parse capabilities
            for line in cap_response.split('\n'):
                if '* CAPABILITY' in line:
                    caps = line.replace('* CAPABILITY', '').strip().split()
                    capabilities.extend(caps)
                    
                    for cap in caps:
                        if 'STARTTLS' in cap:
                            security_features.append('STARTTLS')
                        elif cap.startswith('AUTH='):
                            security_features.append(f"AUTH: {cap[5:]}")
            
            # ID command for server identification
            try:
                sock.send(b'A002 ID ("name" "scanner" "version" "1.0")\r\n')
                time.sleep(0.5)
                id_response = sock.recv(1024).decode('utf-8', errors='ignore')
                additional_data += "\n" + id_response
                
                if '* ID' in id_response:
                    server_info['server_id'] = id_response
            except:
                pass
                
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] IMAP info gathering error: {e}")
        
        return {
            'server_info': server_info,
            'capabilities': capabilities,
            'security_features': security_features,
            'additional_data': additional_data
        }
    
    def gather_ftp_info(self, sock, banner):
        """Gather FTP-specific information"""
        server_info = {}
        capabilities = []
        security_features = []
        additional_data = banner
        file_access = []
        
        try:
            # SYST command for system info
            sock.send(b"SYST\r\n")
            time.sleep(0.5)
            syst_response = sock.recv(1024).decode('utf-8', errors='ignore')
            additional_data += "\n" + syst_response
            
            if '215 ' in syst_response:
                server_info['system_type'] = syst_response.strip()
            
            # FEAT command for features
            sock.send(b"FEAT\r\n")
            time.sleep(0.5)
            feat_response = sock.recv(2048).decode('utf-8', errors='ignore')
            additional_data += "\n" + feat_response
            
            # Parse features
            for line in feat_response.split('\n'):
                line = line.strip()
                if line and not line.startswith('211-') and not line.startswith('211 '):
                    if line.startswith(' '):
                        feature = line.strip()
                        capabilities.append(feature)
                        
                        if 'TLS' in feature or 'SSL' in feature:
                            security_features.append(feature)
                        elif 'AUTH' in feature:
                            security_features.append(feature)
            
            # Test anonymous access
            try:
                sock.send(b"USER anonymous\r\n")
                time.sleep(0.3)
                user_response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '331' in user_response:  # Username OK, need password
                    sock.send(b"PASS anonymous@test.com\r\n")
                    time.sleep(0.3)
                    pass_response = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if '230' in pass_response:  # Login successful
                        file_access.append("Anonymous FTP access enabled")
                        
                        # Try to list directory
                        sock.send(b"PWD\r\n")
                        time.sleep(0.3)
                        pwd_response = sock.recv(1024).decode('utf-8', errors='ignore')
                        
                        if '257' in pwd_response:
                            server_info['current_directory'] = pwd_response.strip()
                            
                        # Try passive mode listing
                        sock.send(b"PASV\r\n")
                        time.sleep(0.3)
                        pasv_response = sock.recv(1024).decode('utf-8', errors='ignore')
                        
                        if '227' in pasv_response:
                            file_access.append("Directory listing available")
            except:
                pass
                
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] FTP info gathering error: {e}")
        
        return {
            'server_info': server_info,
            'capabilities': capabilities,
            'security_features': security_features,
            'additional_data': additional_data,
            'file_access': file_access
        }
    
    def gather_smb_info(self, sock, banner):
        """Gather SMB/NetBIOS information"""
        server_info = {}
        capabilities = []
        security_features = []
        additional_data = banner
        file_access = []
        shares_found = []
        
        try:
            # SMB has binary protocol, basic detection only
            if banner:
                additional_data = banner
            else:
                # Try simple NetBIOS name query for port 139
                if sock.getsockname()[1] == 139:
                    # This is very basic, real SMB enumeration needs proper SMB packets
                    additional_data = "NetBIOS session service detected"
                    server_info['service_type'] = 'NetBIOS'
                else:
                    additional_data = "SMB service detected"
                    server_info['service_type'] = 'SMB'
            
            # Note: Full SMB enumeration would require implementing SMB protocol
            # For now, just detect the service is running
            
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] SMB info gathering error: {e}")
        
        return {
            'server_info': server_info,
            'capabilities': capabilities,
            'security_features': security_features,
            'additional_data': additional_data,
            'file_access': file_access,
            'shares_found': shares_found
        }
    
    def gather_http_info(self, sock, banner, ssl_enabled):
        """Gather HTTP information for webmail detection"""
        server_info = {}
        capabilities = []
        security_features = []
        additional_data = banner
        
        try:
            # Send HTTP request
            request = b"GET / HTTP/1.1\r\nHost: scanner\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            sock.send(request)
            time.sleep(1)
            
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            additional_data += "\n" + response
            
            # Parse HTTP headers
            if 'Server:' in response:
                server_line = [line for line in response.split('\n') if line.startswith('Server:')]
                if server_line:
                    server_info['web_server'] = server_line[0].replace('Server:', '').strip()
            
            # Look for webmail interfaces
            webmail_indicators = [
                'roundcube', 'squirrelmail', 'horde', 'zimbra', 'outlook', 'owa',
                'webmail', 'mail', 'email', 'afterlogic', 'rainloop'
            ]
            
            for indicator in webmail_indicators:
                if indicator.lower() in response.lower():
                    capabilities.append(f"Webmail: {indicator}")
                    break
            
            if ssl_enabled:
                security_features.append('HTTPS')
            
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] HTTP info gathering error: {e}")
        
        return {
            'server_info': server_info,
            'capabilities': capabilities,
            'security_features': security_features,
            'additional_data': additional_data
        }
    
    def detect_service_and_version(self, banner, additional_data, port):
        """Enhanced service and version detection for multiple protocols"""
        full_text = f"{banner} {additional_data}"
        
        # Get base service type from port
        service = self.port_service_map.get(port, 'unknown')
        
        # Refine service detection based on banner content
        if any(keyword in full_text.upper() for keyword in ["SMTP", "ESMTP", "MAIL"]):
            if port == 465:
                service = "smtps"
            elif port == 587:
                service = "submission"
            else:
                service = "smtp"
        elif any(keyword in full_text.upper() for keyword in ["POP3", "+OK"]):
            service = "pop3s" if port == 995 else "pop3"
        elif any(keyword in full_text.upper() for keyword in ["IMAP", "* OK"]):
            service = "imaps" if port == 993 else "imap"
        elif any(keyword in full_text.upper() for keyword in ["FTP", "FILE TRANSFER"]):
            if port in [989, 990]:
                service = "ftps"
            else:
                service = "ftp"
        elif any(keyword in full_text.upper() for keyword in ["SMB", "CIFS", "NETBIOS"]):
            if port == 139:
                service = "netbios-ssn"
            else:
                service = "smb"
        elif any(keyword in full_text.upper() for keyword in ["HTTP", "HTML", "WEB"]):
            service = "https" if port in [443, 8443] else "http"
        
        # Version detection
        version = "Unknown"
        detected_software = "Unknown"
        
        for software, pattern in self.config['version_patterns'].items():
            try:
                match = re.search(pattern, full_text, re.IGNORECASE | re.MULTILINE)
                if match:
                    version = match.group(1)
                    detected_software = software.capitalize()
                    break
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] Version pattern error: {e}")
        
        return service, f"{detected_software} {version}" if version != "Unknown" else detected_software
    
    def check_vulnerabilities(self, ip, port, service_type, banner_info):
        """Enhanced vulnerability checking for multiple protocols"""
        vulnerabilities = []
        
        protocol_type = self.protocol_types.get(service_type, 'unknown')
        
        if protocol_type == 'email':
            vulns = self.check_email_vulnerabilities(ip, port, service_type, banner_info)
            vulnerabilities.extend(vulns)
        elif protocol_type == 'file':
            vulns = self.check_file_vulnerabilities(ip, port, service_type, banner_info)
            vulnerabilities.extend(vulns)
        elif protocol_type == 'web':
            vulns = self.check_web_vulnerabilities(ip, port, service_type, banner_info)
            vulnerabilities.extend(vulns)
        
        # Check for information disclosure (common to all protocols)
        info_vulns = self.check_information_disclosure(banner_info)
        vulnerabilities.extend(info_vulns)
        
        return vulnerabilities
    
    def check_email_vulnerabilities(self, ip, port, service_type, banner_info):
        """Check email-specific vulnerabilities"""
        vulnerabilities = []
        
        try:
            sock = self.create_socket(5)
            
            if port in self.ssl_ports:
                sock.connect((ip, port))
                sock = self.create_ssl_socket(sock, ip)
            else:
                sock.connect((ip, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if service_type.lower().startswith('smtp'):
                # Test VRFY command
                sock.send(b"VRFY root\r\n")
                time.sleep(0.3)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if any(code in response for code in ["250", "251", "252"]):
                    vulnerabilities.append("VRFY command enabled - User enumeration possible")
                
                # Test EXPN command
                sock.send(b"EXPN root\r\n")
                time.sleep(0.3)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if "250" in response:
                    vulnerabilities.append("EXPN command enabled - Mailing list enumeration possible")
                
                # Test for open relay
                try:
                    sock.send(b"HELO test.com\r\n")
                    time.sleep(0.3)
                    sock.recv(1024)
                    
                    sock.send(b"MAIL FROM:<test@external.com>\r\n")
                    time.sleep(0.3)
                    response1 = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if "250" in response1:
                        sock.send(b"RCPT TO:<victim@external-domain.com>\r\n")
                        time.sleep(0.3)
                        response2 = sock.recv(1024).decode('utf-8', errors='ignore')
                        
                        if "250" in response2:
                            vulnerabilities.append("CRITICAL: Open mail relay detected")
                except:
                    pass
            
            elif service_type.lower().startswith('pop3'):
                # Test anonymous login
                sock.send(b"USER anonymous\r\n")
                time.sleep(0.3)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if "+OK" in response:
                    sock.send(b"PASS \r\n")
                    time.sleep(0.3)
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    if "+OK" in response:
                        vulnerabilities.append("Anonymous POP3 access enabled")
            
            elif service_type.lower().startswith('imap'):
                # Test anonymous login
                sock.send(b"A001 LOGIN anonymous \r\n")
                time.sleep(0.3)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if "A001 OK" in response:
                    vulnerabilities.append("Anonymous IMAP access enabled")
            
            sock.close()
            
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Email vulnerability check error {ip}:{port} - {e}")
        
        return vulnerabilities
    
    def check_file_vulnerabilities(self, ip, port, service_type, banner_info):
        """Check file protocol vulnerabilities"""
        vulnerabilities = []
        
        try:
            sock = self.create_socket(5)
            
            if port in self.ssl_ports:
                sock.connect((ip, port))
                sock = self.create_ssl_socket(sock, ip)
            else:
                sock.connect((ip, port))
            
            if service_type.lower().startswith('ftp'):
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Test anonymous FTP access
                sock.send(b"USER anonymous\r\n")
                time.sleep(0.5)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if "331" in response:  # Username OK, need password
                    sock.send(b"PASS anonymous@test.com\r\n")
                    time.sleep(0.5)
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if "230" in response:  # Login successful
                        vulnerabilities.append("Anonymous FTP access enabled")
                        
                        # Test directory listing
                        try:
                            sock.send(b"PASV\r\n")
                            time.sleep(0.3)
                            pasv_response = sock.recv(1024).decode('utf-8', errors='ignore')
                            
                            if "227" in pasv_response:
                                vulnerabilities.append("Anonymous FTP directory listing enabled")
                                
                            # Test if we can upload
                            sock.send(b"STOR test.txt\r\n")
                            time.sleep(0.3)
                            stor_response = sock.recv(1024).decode('utf-8', errors='ignore')
                            
                            if "150" in stor_response or "125" in stor_response:
                                vulnerabilities.append("CRITICAL: Anonymous FTP upload enabled")
                        except:
                            pass
            
            elif service_type in ['smb', 'netbios-ssn']:
                # SMB vulnerability checks would require implementing SMB protocol
                # For now, just note that SMB is running
                vulnerabilities.append("SMB service detected - Manual enumeration recommended")
            
            sock.close()
            
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] File vulnerability check error {ip}:{port} - {e}")
        
        return vulnerabilities
    
    def check_web_vulnerabilities(self, ip, port, service_type, banner_info):
        """Check web vulnerabilities (basic webmail detection)"""
        vulnerabilities = []
        
        try:
            sock = self.create_socket(5)
            
            if port in self.ssl_ports:
                sock.connect((ip, port))
                sock = self.create_ssl_socket(sock, ip)
            else:
                sock.connect((ip, port))
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            time.sleep(1)
            
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            # Check for common webmail interfaces
            webmail_patterns = {
                'roundcube': 'RoundCube Webmail',
                'squirrelmail': 'SquirrelMail',
                'horde': 'Horde Groupware',
                'zimbra': 'Zimbra Web Client',
                'owa': 'Outlook Web',
                'afterlogic': 'AfterLogic WebMail'
            }
            
            for webmail, description in webmail_patterns.items():
                if webmail.lower() in response.lower():
                    vulnerabilities.append(f"Webmail interface detected: {description}")
            
            # Check for default credentials pages
            if any(keyword in response.lower() for keyword in ['login', 'password', 'username']):
                if any(keyword in response.lower() for keyword in ['admin', 'administrator', 'default']):
                    vulnerabilities.append("Default login page detected")
            
            sock.close()
            
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Web vulnerability check error {ip}:{port} - {e}")
        
        return vulnerabilities
    
    def check_information_disclosure(self, banner_info):
        """Check for information disclosure in banners"""
        vulnerabilities = []
        
        if not banner_info:
            return vulnerabilities
        
        banner = banner_info.get('banner', '')
        additional_data = banner_info.get('additional_data', '')
        full_text = f"{banner} {additional_data}"
        
        # Check for version disclosure
        if re.search(r'\d+\.\d+\.\d+', full_text):
            vulnerabilities.append("Detailed version information disclosed")
        
        # Check for hostname disclosure
        hostname_patterns = [
            r'[a-zA-Z0-9.-]+\.(?:com|org|net|edu|gov|mil|local)',
            r'[a-zA-Z0-9.-]+\.internal',
            r'[a-zA-Z0-9.-]+\.domain'
        ]
        
        for pattern in hostname_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                vulnerabilities.append("Internal hostname disclosed in banner")
                break
        
        # Check for software paths
        if re.search(r'[A-Z]:\\|/usr/|/var/|/etc/', full_text):
            vulnerabilities.append("System paths disclosed in banner")
        
        return vulnerabilities
    
    def test_weak_credentials(self, ip, port, service_type):
        """Test for weak credentials across protocols"""
        weak_creds = []
        
        if not self.config.get('authentication', {}).get('test_weak_creds', True):
            return weak_creds
        
        users = self.config.get('authentication', {}).get('common_users', ['admin'])
        passwords = self.config.get('authentication', {}).get('common_passwords', [''])
        
        # Protocol-specific user lists
        if service_type.lower().startswith(('smtp', 'pop3', 'imap')):
            users.extend(['postmaster', 'mail', 'mailman', 'webmail'])
        elif service_type.lower().startswith('ftp'):
            users.extend(['ftp', 'ftpuser', 'upload'])
        elif service_type in ['smb', 'netbios-ssn']:
            users.extend(['guest', 'share', 'public'])
        
        max_attempts = self.config.get('authentication', {}).get('max_attempts_per_service', 20)
        attempt_count = 0
        
        for user in users[:5]:  # Limit users
            if attempt_count >= max_attempts:
                break
                
            for password in passwords[:4]:  # Limit passwords per user
                if attempt_count >= max_attempts:
                    break
                
                try:
                    if self.test_single_credential(ip, port, service_type, user, password):
                        weak_creds.append(f"{user}:{password}" if password else f"{user}:<empty>")
                        if self.verbose:
                            print(f"[!] Weak credential found: {user}:{password if password else '<empty>'}")
                        break  # Stop on first success for this user
                    
                    attempt_count += 1
                    time.sleep(self.config.get('authentication', {}).get('delay_between_attempts', 0.1))
                    
                except Exception as e:
                    if self.verbose:
                        print(f"[DEBUG] Credential test error: {e}")
                    attempt_count += 1
        
        return weak_creds
    
    def test_single_credential(self, ip, port, service_type, username, password):
        """Test a single credential combination for various protocols"""
        try:
            sock = self.create_socket(3)
            
            if port in self.ssl_ports:
                sock.connect((ip, port))
                sock = self.create_ssl_socket(sock, ip)
            else:
                sock.connect((ip, port))
            
            banner = sock.recv(1024)
            success = False
            
            if service_type.lower().startswith('smtp'):
                # Try AUTH PLAIN
                auth_string = base64.b64encode(f"\0{username}\0{password}".encode()).decode()
                sock.send(f"AUTH PLAIN {auth_string}\r\n".encode())
                time.sleep(0.5)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                success = "235" in response
                
            elif service_type.lower().startswith('pop3'):
                sock.send(f"USER {username}\r\n".encode())
                time.sleep(0.3)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if "+OK" in response:
                    sock.send(f"PASS {password}\r\n".encode())
                    time.sleep(0.3)
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    success = "+OK" in response and "mailbox" in response.lower()
                    
            elif service_type.lower().startswith('imap'):
                sock.send(f"A001 LOGIN {username} {password}\r\n".encode())
                time.sleep(0.5)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                success = "A001 OK" in response
                
            elif service_type.lower().startswith('ftp'):
                sock.send(f"USER {username}\r\n".encode())
                time.sleep(0.3)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if "331" in response:
                    sock.send(f"PASS {password}\r\n".encode())
                    time.sleep(0.5)
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    success = "230" in response
            
            sock.close()
            return success
            
        except Exception:
            return False
    
    def calculate_risk_score(self, result):
        """Calculate risk score based on findings"""
        score = 0
        
        # Base score for open service
        score += 10
        
        # Protocol type scoring
        protocol_type = self.protocol_types.get(result.get('service', ''), 'unknown')
        if protocol_type == 'file':
            score += 20  # File services are higher risk
        elif protocol_type == 'email':
            score += 15
        elif protocol_type == 'web':
            score += 10
        
        # SSL/TLS scoring
        if result.get('ssl_enabled'):
            score += 5
        else:
            score += 20  # Higher risk for unencrypted
        
        # Vulnerability scoring
        vulnerabilities = result.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if 'CRITICAL' in vuln.upper():
                score += 50
            elif any(keyword in vuln.lower() for keyword in ['open relay', 'upload', 'anonymous']):
                score += 40
            elif 'enumeration' in vuln.lower():
                score += 20
            else:
                score += 10
        
        # Weak credentials
        weak_creds = result.get('weak_credentials', [])
        score += len(weak_creds) * 25
        
        # File access bonus scoring
        file_access = result.get('file_access', [])
        score += len(file_access) * 15
        
        return min(score, 100)  # Cap at 100
    
    def print_real_time_result(self, result):
        """Enhanced real-time result display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Determine risk level and color
        risk_score = result.get('risk_score', 0)
        if risk_score >= 70:
            risk_color = Colors.RED
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_color = Colors.YELLOW
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_color = Colors.BLUE
            risk_level = "MEDIUM"
        else:
            risk_color = Colors.GREEN
            risk_level = "LOW"
        
        # Protocol type indicator
        protocol_type = self.protocol_types.get(result.get('service', ''), 'unknown')
        if protocol_type == 'email':
            protocol_icon = "📧"
        elif protocol_type == 'file':
            protocol_icon = "📁"
        elif protocol_type == 'web':
            protocol_icon = "🌐"
        else:
            protocol_icon = "❓"
        
        # SSL indicator
        ssl_indicator = "🔒" if result.get('ssl_enabled') else "🔓"
        
        # Format basic info
        service_info = f"{result['service']:<12}"
        version_info = f"{result['version']:<25}"
        
        # Main result line
        print(f"{Colors.CYAN}[{timestamp}]{Colors.RESET} "
              f"{Colors.WHITE}{result['ip']}:{result['port']:<5}{Colors.RESET} │ "
              f"{protocol_icon} {ssl_indicator} {service_info} │ "
              f"{version_info} │ "
              f"{risk_color}RISK:{risk_level}({risk_score}){Colors.RESET}")
        
        # Vulnerabilities
        vulnerabilities = result.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"    {Colors.RED}⚠ VULNERABILITIES:{Colors.RESET}")
            for vuln in vulnerabilities[:3]:  # Show max 3
                print(f"      • {vuln}")
            if len(vulnerabilities) > 3:
                print(f"      • ... and {len(vulnerabilities) - 3} more")
        
        # Weak credentials
        weak_creds = result.get('weak_credentials', [])
        if weak_creds:
            print(f"    {Colors.YELLOW}🔑 WEAK CREDENTIALS:{Colors.RESET}")
            for cred in weak_creds[:2]:  # Show max 2
                print(f"      • {cred}")
        
        # File access info
        file_access = result.get('file_access', [])
        if file_access:
            print(f"    {Colors.MAGENTA}📁 FILE ACCESS:{Colors.RESET}")
            for access in file_access[:2]:
                print(f"      • {access}")
        
        # Email data info
        if protocol_type == 'email':
            data_volume = result.get('data_volume', {})
            if data_volume.get('level') != 'low':
                email_count = data_volume.get('email_count', 0)
                if email_count > 0:
                    print(f"    {Colors.MAGENTA}📧 DATA: {email_count:,} emails, "
                          f"Level: {data_volume['level'].upper()}{Colors.RESET}")
        
        # Capabilities (interesting ones)
        capabilities = result.get('capabilities', [])
        interesting_caps = [cap for cap in capabilities if any(keyword in cap.upper() 
                           for keyword in ['AUTH', 'STARTTLS', 'TLS', 'SSL', 'WEBMAIL'])]
        if interesting_caps:
            print(f"    {Colors.CYAN}⚙ FEATURES: {', '.join(interesting_caps[:3])}{Colors.RESET}")
        
        print()  # Empty line for readability
    
    def scan_single_target(self, ip, port):
        """Enhanced single target scanning for multiple protocols"""
        try:
            # Port scan
            is_open, response_time = self.scan_port(ip, port)
            
            if not is_open:
                return None
            
            # Determine service type
            service_type = self.port_service_map.get(port, 'unknown')
            
            # Banner grabbing and service detection
            banner_info = self.grab_banner_and_info(ip, port, service_type)
            
            if not banner_info:
                # Create minimal result for open port with no banner
                result = {
                    'ip': ip,
                    'port': port,
                    'service': service_type,
                    'version': 'Unknown',
                    'banner': '',
                    'ssl_enabled': port in self.ssl_ports,
                    'response_time': response_time,
                    'protocol_type': self.protocol_types.get(service_type, 'unknown'),
                    'vulnerabilities': [],
                    'weak_credentials': [],
                    'file_access': [],
                    'shares_found': [],
                    'data_volume': {'level': 'unknown'},
                    'server_info': {},
                    'capabilities': [],
                    'security_features': [],
                    'timestamp': datetime.now().isoformat()
                }
                result['risk_score'] = self.calculate_risk_score(result)
                return result
            
            # Service and version detection
            service, version = self.detect_service_and_version(
                banner_info['banner'], 
                banner_info.get('additional_data', ''), 
                port
            )
            
            # Security analysis
            vulnerabilities = self.check_vulnerabilities(ip, port, service, banner_info)
            weak_creds = self.test_weak_credentials(ip, port, service)
            
            # Data volume analysis (for email services)
            data_volume = {'level': 'unknown'}
            if self.protocol_types.get(service, '') == 'email':
                data_volume = self.analyze_email_data_volume(ip, port, service, banner_info)
            
            # Build result
            result = {
                'ip': ip,
                'port': port,
                'service': service,
                'version': version,
                'banner': banner_info['banner'][:500],  # Limit banner length
                'ssl_enabled': banner_info.get('ssl_enabled', False),
                'response_time': response_time,
                'protocol_type': self.protocol_types.get(service, 'unknown'),
                'vulnerabilities': vulnerabilities,
                'weak_credentials': weak_creds,
                'file_access': banner_info.get('file_access', []),
                'shares_found': banner_info.get('shares_found', []),
                'data_volume': data_volume,
                'server_info': banner_info.get('server_info', {}),
                'capabilities': banner_info.get('capabilities', []),
                'security_features': banner_info.get('security_features', []),
                'timestamp': datetime.now().isoformat()
            }
            
            # Calculate risk score
            result['risk_score'] = self.calculate_risk_score(result)
            
            # Real-time display
            self.print_real_time_result(result)
            
            # Save to database
            if self.db_manager:
                self.db_manager.save_result(result)
            
            # Update progress
            is_vulnerable = bool(vulnerabilities or weak_creds or result['file_access'])
            if self.progress_tracker:
                self.progress_tracker.update(vulnerable=is_vulnerable, service_found=True)
            
            return result
            
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] Scan error {ip}:{port} - {e}")
            return None
    
    def analyze_email_data_volume(self, ip, port, service_type, banner_info):
        """Analyze email data volume"""
        data_analysis = {
            'level': 'low',
            'email_count': 0,
            'folder_count': 0,
            'traffic_volume': 'Unknown'
        }
        
        try:
            sock = self.create_socket(5)
            
            if port in self.ssl_ports:
                sock.connect((ip, port))
                sock = self.create_ssl_socket(sock, ip)
            else:
                sock.connect((ip, port))
            
            banner = sock.recv(1024)
            
            if service_type.lower().startswith('pop3'):
                # Get POP3 statistics
                sock.send(b"STAT\r\n")
                time.sleep(0.5)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if "+OK" in response:
                    parts = response.split()
                    if len(parts) >= 3:
                        try:
                            data_analysis['email_count'] = int(parts[1])
                            mailbox_size = int(parts[2])
                            data_analysis['traffic_volume'] = f"{mailbox_size / 1024 / 1024:.1f}MB"
                        except ValueError:
                            pass
            
            elif service_type.lower().startswith('imap'):
                # Get IMAP statistics
                sock.send(b"A001 STATUS INBOX (MESSAGES)\r\n")
                time.sleep(0.5)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Parse MESSAGES count
                match = re.search(r'MESSAGES (\d+)', response)
                if match:
                    data_analysis['email_count'] = int(match.group(1))
                
                # Get folder count
                sock.send(b"A002 LIST \"\" \"*\"\r\n")
                time.sleep(1)
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                data_analysis['folder_count'] = response.count('* LIST')
            
            sock.close()
            
            # Determine data level
            email_count = data_analysis['email_count']
            high_threshold = self.config.get('data_volume', {}).get('high_indicators', {}).get('email_count', 10000)
            
            if email_count > high_threshold:
                data_analysis['level'] = 'critical'
            elif email_count > high_threshold // 2:
                data_analysis['level'] = 'high'
            elif email_count > 1000:
                data_analysis['level'] = 'medium'
            
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Email data analysis error {ip}:{port} - {e}")
        
        return data_analysis
    
    def print_progress(self):
        """Print progress information periodically"""
        while True:
            if self.progress_tracker:
                status = self.progress_tracker.get_status()
                
                progress_bar = "█" * int(status['percentage'] / 5) + "░" * (20 - int(status['percentage'] / 5))
                
                print(f"\r{Colors.YELLOW}[PROGRESS]{Colors.RESET} "
                      f"{progress_bar} {status['percentage']:.1f}% "
                      f"({status['completed']}/{status['total']}) │ "
                      f"Vulnerable: {Colors.RED}{status['vulnerable']}{Colors.RESET} │ "
                      f"Rate: {status['rate']:.1f}/s │ "
                      f"ETA: {status['eta']:.0f}s", end='', flush=True)
                
                if status['completed'] >= status['total']:
                    print()  # New line when complete
                    break
            
            time.sleep(2)
    
    def get_default_ports(self):
        """Get default ports from config"""
        ports = []
        for port_list in self.config.get('ports', {}).values():
            if isinstance(port_list, list):
                ports.extend(port_list)
        return sorted(list(set(ports)))  # Remove duplicates and sort
    
    def parse_targets(self, target_inputs, target_file=None):
        """Parse targets from command line and/or file"""
        all_targets = []
        
        # Load from file if specified
        if target_file:
            file_targets = self.load_targets_from_file(target_file)
            all_targets.extend(file_targets)
        
        # Add command line targets
        if target_inputs:
            for target in target_inputs:
                parsed = self.parse_single_target(target)
                if parsed:
                    all_targets.extend(parsed)
        
        return all_targets
    
    def parse_single_target(self, target):
        """Parse a single target string"""
        targets = []
        
        try:
            if ':' in target:
                # Format: IP:PORT or IP:PORT1,PORT2,PORT3
                ip_part, port_part = target.split(':', 1)
                ip_part = ip_part.strip()
                
                if ',' in port_part:
                    # Multiple ports
                    ports = []
                    for p in port_part.split(','):
                        p = p.strip()
                        if p.isdigit() and 1 <= int(p) <= 65535:
                            ports.append(int(p))
                    if ports:
                        targets.append({'target': ip_part, 'ports': ports})
                else:
                    # Single port
                    if port_part.strip().isdigit():
                        port = int(port_part.strip())
                        if 1 <= port <= 65535:
                            targets.append({'target': ip_part, 'ports': [port]})
            else:
                # Just IP/domain without port specification
                targets.append({'target': target, 'ports': None})
                
        except Exception as e:
            print(f"[!] Invalid target format: {target} - {e}")
        
        return targets
    
    def load_targets_from_file(self, filename):
        """Load targets from file with enhanced parsing"""
        targets = []
        
        try:
            if not os.path.exists(filename):
                print(f"[!] Target file not found: {filename}")
                return []
            
            with open(filename, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#') or line.startswith('//'):
                        continue
                    
                    parsed = self.parse_single_target(line)
                    if parsed:
                        targets.extend(parsed)
                    else:
                        if self.verbose:
                            print(f"[!] Invalid target on line {line_num}: {line}")
            
            print(f"{Colors.GREEN}[+] Loaded {len(targets)} targets from {filename}{Colors.RESET}")
            
        except Exception as e:
            print(f"[!] Error reading target file {filename}: {e}")
        
        return targets
    
    def expand_targets(self, target_list):
        """Expand CIDR ranges and resolve domains"""
        expanded = []
        
        for target_info in target_list:
            target = target_info['target']
            custom_ports = target_info['ports']
            
            # Expand IP ranges
            ip_list = []
            try:
                if '/' in target:  # CIDR notation
                    try:
                        network = IPv4Network(target, strict=False)
                        ip_list.extend([str(ip) for ip in network])
                        if self.verbose:
                            print(f"[+] Expanded {target} to {len(ip_list)} IPs")
                    except Exception as e:
                        print(f"[!] Invalid CIDR range: {target} - {e}")
                        continue
                else:  # Single IP or domain
                    # Try to resolve domain to IP
                    try:
                        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
                            # It's a domain, resolve it
                            import socket as sock
                            resolved_ip = sock.gethostbyname(target)
                            ip_list.append(resolved_ip)
                            if self.verbose:
                                print(f"[+] Resolved {target} to {resolved_ip}")
                        else:
                            ip_list.append(target)
                    except Exception as e:
                        print(f"[!] Could not resolve {target}: {e}")
                        continue
            except Exception as e:
                print(f"[!] Target parsing error for {target}: {e}")
                continue
            
            # Create final target list with ports
            for ip in ip_list:
                expanded.append({
                    'ip': ip,
                    'ports': custom_ports  # None means use default ports
                })
        
        return expanded
    
    def scan_targets(self, targets=None, ports=None, threads=100, target_file=None):
        """Main scanning function with enhanced features"""
        self.print_banner()
        
        # Parse and expand targets
        target_list = self.parse_targets(targets, target_file)
        
        if not target_list:
            print(f"{Colors.RED}[!] No valid targets specified!{Colors.RESET}")
            return
        
        expanded_targets = self.expand_targets(target_list)
        
        if not expanded_targets:
            print(f"{Colors.RED}[!] No valid targets after expansion!{Colors.RESET}")
            return
        
        # Determine ports to scan
        if ports is None:
            ports = self.get_default_ports()
        
        # Create scan tasks
        tasks = []
        unique_ips = set()
        
        for target_info in expanded_targets:
            ip = target_info['ip']
            target_ports = target_info['ports'] if target_info['ports'] else ports
            unique_ips.add(ip)
            
            for port in target_ports:
                tasks.append((ip, port))
        
        # Initialize components
        self.db_manager = DatabaseManager(
            self.config.get('output', {}).get('db_file', 'scanner.db'), 
            self.scan_id
        )
        self.progress_tracker = ProgressTracker(len(tasks))
        
        # Print scan information
        print(f"{Colors.GREEN}[+] Scan Configuration:{Colors.RESET}")
        print(f"    • Protocol Support: Email (SMTP/POP3/IMAP), File (FTP/SMB), Web")
        print(f"    • Targets: {len(unique_ips)} hosts")
        print(f"    • Ports per host: {len(set(port for _, port in tasks))} unique ports")
        print(f"    • Total tasks: {len(tasks)}")
        print(f"    • Threads: {threads}")
        print(f"    • Scan ID: {self.scan_id}")
        print(f"    • Database: {self.db_manager.db_path}")
        print()
        
        # Start progress tracking thread
        progress_thread = threading.Thread(target=self.print_progress, daemon=True)
        progress_thread.start()
        
        print(f"{Colors.BOLD}Starting universal protocol scan...{Colors.RESET}\n")
        
        # Execute scanning
        start_time = time.time()
        successful_scans = 0
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit all tasks
            future_to_task = {
                executor.submit(self.scan_single_target, ip, port): (ip, port) 
                for ip, port in tasks
            }
            
            # Process results as they complete
            for future in as_completed(future_to_task):
                ip, port = future_to_task[future]
                try:
                    result = future.result()
                    if result:
                        successful_scans += 1
                        with self.lock:
                            self.results.append(result)
                except Exception as e:
                    if self.verbose:
                        print(f"[ERROR] Task failed {ip}:{port} - {e}")
        
        # Calculate final statistics
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Print final summary
        self.print_final_summary(scan_duration, successful_scans, len(tasks))
        
        # Generate reports
        self.generate_reports()
    
    def print_final_summary(self, duration, successful_scans, total_tasks):
        """Print comprehensive scan summary"""
        if not self.progress_tracker:
            return
        
        status = self.progress_tracker.get_status()
        
        print(f"\n{Colors.BOLD}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}UNIVERSAL PROTOCOL SCAN COMPLETED{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*80}{Colors.RESET}")
        
        print(f"{Colors.CYAN}Timing Information:{Colors.RESET}")
        print(f"  • Duration: {duration:.1f} seconds ({duration/60:.1f} minutes)")
        print(f"  • Average rate: {total_tasks/duration:.1f} scans/second")
        print(f"  • Successful scans: {successful_scans}/{total_tasks}")
        
        print(f"\n{Colors.CYAN}Results Summary:{Colors.RESET}")
        print(f"  • Open services found: {status['services']}")
        print(f"  • Vulnerable services: {status['vulnerable']}")
        
        # Analyze results by protocol type
        if self.results:
            protocol_analysis = self.analyze_protocol_distribution()
            print(f"\n{Colors.CYAN}Protocol Distribution:{Colors.RESET}")
            for protocol, count in protocol_analysis.items():
                if count > 0:
                    print(f"  • {protocol.capitalize()}: {count}")
            
            # Risk analysis
            risk_analysis = self.analyze_risk_distribution()
            print(f"\n{Colors.CYAN}Risk Distribution:{Colors.RESET}")
            print(f"  • {Colors.RED}Critical (70-100): {risk_analysis['critical']}{Colors.RESET}")
            print(f"  • {Colors.YELLOW}High (50-69): {risk_analysis['high']}{Colors.RESET}")
            print(f"  • {Colors.BLUE}Medium (30-49): {risk_analysis['medium']}{Colors.RESET}")
            print(f"  • {Colors.GREEN}Low (0-29): {risk_analysis['low']}{Colors.RESET}")
            
            # Top vulnerabilities
            top_vulns = self.get_top_vulnerabilities()
            if top_vulns:
                print(f"\n{Colors.CYAN}Top Vulnerabilities:{Colors.RESET}")
                for vuln, count in top_vulns[:5]:
                    print(f"  • {vuln}: {count} instances")
            
            # File access findings
            file_access_count = len([r for r in self.results if r.get('file_access')])
            if file_access_count > 0:
                print(f"\n{Colors.CYAN}File Access Findings:{Colors.RESET}")
                print(f"  • Services with file access: {file_access_count}")
        
        print(f"\n{Colors.CYAN}Output Files:{Colors.RESET}")
        print(f"  • Database: scanner.db")
        print(f"  • XML Report: scan_{self.scan_id}.xml")
        print(f"  • JSON Report: scan_{self.scan_id}.json")
        
        print(f"\n{Colors.BOLD}Scan ID: {self.scan_id}{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*80}{Colors.RESET}")
    
    def analyze_protocol_distribution(self):
        """Analyze protocol type distribution"""
        distribution = {}
        
        for result in self.results:
            protocol = result.get('protocol_type', 'unknown')
            distribution[protocol] = distribution.get(protocol, 0) + 1
        
        return distribution
    
    def analyze_risk_distribution(self):
        """Analyze risk score distribution"""
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for result in self.results:
            risk_score = result.get('risk_score', 0)
            if risk_score >= 70:
                distribution['critical'] += 1
            elif risk_score >= 50:
                distribution['high'] += 1
            elif risk_score >= 30:
                distribution['medium'] += 1
            else:
                distribution['low'] += 1
        
        return distribution
    
    def get_top_vulnerabilities(self):
        """Get most common vulnerabilities"""
        vuln_count = {}
        
        for result in self.results:
            for vuln in result.get('vulnerabilities', []):
                vuln_count[vuln] = vuln_count.get(vuln, 0) + 1
        
        return sorted(vuln_count.items(), key=lambda x: x[1], reverse=True)
    
    def generate_reports(self):
        """Generate comprehensive reports"""
        try:
            # XML Report
            xml_filename = f"scan_{self.scan_id}.xml"
            self.generate_xml_report(xml_filename)
            
            # JSON Report
            json_filename = f"scan_{self.scan_id}.json"
            self.generate_json_report(json_filename)
            
            print(f"\n{Colors.GREEN}[+] Reports generated:{Colors.RESET}")
            print(f"    • XML: {xml_filename}")
            print(f"    • JSON: {json_filename}")
            
        except Exception as e:
            print(f"{Colors.RED}[!] Report generation error: {e}{Colors.RESET}")
    
    def generate_xml_report(self, filename):
        """Generate detailed XML report"""
        root = ET.Element("universal_scan_results")
        root.set("scan_id", self.scan_id)
        root.set("generated", datetime.now().isoformat())
        
        # Scan summary
        summary = ET.SubElement(root, "summary")
        ET.SubElement(summary, "total_services").text = str(len(self.results))
        ET.SubElement(summary, "vulnerable_services").text = str(len([r for r in self.results if r.get('vulnerabilities')]))
        
        # Protocol distribution
        protocol_dist = self.analyze_protocol_distribution()
        protocols_elem = ET.SubElement(summary, "protocols")
        for protocol, count in protocol_dist.items():
            proto_elem = ET.SubElement(protocols_elem, "protocol")
            proto_elem.set("type", protocol)
            proto_elem.text = str(count)
        
        # Individual results
        for result in self.results:
            host_elem = ET.SubElement(root, "host")
            host_elem.set("ip", result['ip'])
            
            port_elem = ET.SubElement(host_elem, "port")
            port_elem.set("number", str(result['port']))
            port_elem.set("service", result['service'])
            port_elem.set("protocol_type", result.get('protocol_type', 'unknown'))
            port_elem.set("risk_score", str(result.get('risk_score', 0)))
            
            # Basic information
            ET.SubElement(port_elem, "version").text = result['version']
            ET.SubElement(port_elem, "ssl_enabled").text = str(result.get('ssl_enabled', False))
            ET.SubElement(port_elem, "response_time").text = str(result.get('response_time', 0))
            
            # Vulnerabilities
            if result.get('vulnerabilities'):
                vulns_elem = ET.SubElement(port_elem, "vulnerabilities")
                for vuln in result['vulnerabilities']:
                    ET.SubElement(vulns_elem, "vulnerability").text = vuln
            
            # Weak credentials
            if result.get('weak_credentials'):
                creds_elem = ET.SubElement(port_elem, "weak_credentials")
                for cred in result['weak_credentials']:
                    ET.SubElement(creds_elem, "credential").text = cred
            
            # File access
            if result.get('file_access'):
                file_elem = ET.SubElement(port_elem, "file_access")
                for access in result['file_access']:
                    ET.SubElement(file_elem, "access").text = access
        
        # Write XML file
        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)
    
    def generate_json_report(self, filename):
        """Generate JSON report"""
        report_data = {
            'scan_info': {
                'scan_id': self.scan_id,
                'timestamp': datetime.now().isoformat(),
                'scanner_version': '3.0',
                'protocols_supported': ['email', 'file', 'web'],
                'total_services': len(self.results),
                'vulnerable_services': len([r for r in self.results if r.get('vulnerabilities')]),
                'protocol_distribution': self.analyze_protocol_distribution(),
                'risk_distribution': self.analyze_risk_distribution()
            },
            'results': self.results
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

def main():
    parser = argparse.ArgumentParser(
        description="Universal Email & File Protocol Scanner v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported Protocols:
  • Email: SMTP, POP3, IMAP (including SSL/TLS variants)
  • File Transfer: FTP, FTPS
  • Network Shares: SMB, NetBIOS
  • Web: HTTP, HTTPS (webmail detection)

Examples:
  %(prog)s -t 192.168.1.1                    # Scan single IP (all protocols)
  %(prog)s -t 192.168.1.0/24                 # Scan CIDR range  
  %(prog)s -t mail.company.com:25,587,993    # Scan specific ports
  %(prog)s -f targets.txt --threads 500      # Mass scan from file
  %(prog)s -t 10.0.0.1 -p 21 25 445 --verbose # Specific protocols only
  %(prog)s -f huge_list.txt --threads 1000 --quick # Fast scan, no vulns
        """)
    
    parser.add_argument('-t', '--targets', nargs='+',
                       help='Target IPs, domains, or CIDR ranges')
    parser.add_argument('-f', '--file', 
                       help='File containing targets (one per line)')
    parser.add_argument('-p', '--ports', nargs='+', type=int,
                       help='Specific ports to scan (default: all supported protocols)')
    parser.add_argument('--threads', type=int, default=100,
                       help='Number of concurrent threads (default: 100, max: 1000)')
    parser.add_argument('--config', default='config.yaml',
                       help='Configuration file (default: config.yaml)')
    parser.add_argument('--timeout', type=int, default=5,
                       help='Connection timeout in seconds (default: 5)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--quick', action='store_true',
                       help='Quick scan (skip vulnerability and credential checks)')
    parser.add_argument('--no-ssl', action='store_true',
                       help='Skip SSL/TLS ports')
    parser.add_argument('--email-only', action='store_true',
                       help='Scan only email protocols (SMTP/POP3/IMAP)')
    parser.add_argument('--file-only', action='store_true',
                       help='Scan only file protocols (FTP/SMB)')
    parser.add_argument('--output-dir', default='.',
                       help='Output directory for reports (default: current)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.targets and not args.file:
        print(f"{Colors.RED}[!] Error: Must specify targets with -t or target file with -f{Colors.RESET}")
        parser.print_help()
        return 1
    
    if args.threads < 1 or args.threads > 1000:
        print(f"{Colors.RED}[!] Error: Thread count must be between 1 and 1000{Colors.RESET}")
        return 1
    
    # Validate ports
    if args.ports:
        for port in args.ports:
            if port < 1 or port > 65535:
                print(f"{Colors.RED}[!] Error: Invalid port {port} (must be 1-65535){Colors.RESET}")
                return 1
    
    # Create output directory
    if args.output_dir != '.' and not os.path.exists(args.output_dir):
        try:
            os.makedirs(args.output_dir)
            print(f"{Colors.GREEN}[+] Created output directory: {args.output_dir}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Could not create output directory: {e}{Colors.RESET}")
            return 1
    
    # Change to output directory
    if args.output_dir != '.':
        os.chdir(args.output_dir)
    
    try:
        # Create scanner instance
        scanner = UniversalProtocolScanner(args.config, args.verbose)
        
        # Update timeouts if specified
        if args.timeout != 5:
            scanner.config.setdefault('timeouts', {})['connect'] = args.timeout
            scanner.config['timeouts']['read'] = args.timeout + 3
        
        # Handle protocol-specific scanning
        if args.email_only:
            if args.ports is None:
                args.ports = [25, 587, 465, 110, 995, 143, 993, 2525]
                print(f"{Colors.YELLOW}[!] Email-only mode: Scanning ports {args.ports}{Colors.RESET}")
        
        elif args.file_only:
            if args.ports is None:
                args.ports = [21, 989, 990, 445, 139, 135]
                print(f"{Colors.YELLOW}[!] File-only mode: Scanning ports {args.ports}{Colors.RESET}")
        
        # Filter SSL ports if requested
        if args.no_ssl:
            if args.ports:
                args.ports = [p for p in args.ports if p not in scanner.ssl_ports]
            else:
                # Remove SSL ports from default config
                for service_ports in scanner.config.get('ports', {}).values():
                    if isinstance(service_ports, list):
                        for ssl_port in scanner.ssl_ports:
                            if ssl_port in service_ports:
                                service_ports.remove(ssl_port)
            print(f"{Colors.YELLOW}[!] SSL ports excluded from scan{Colors.RESET}")
        
        # Quick scan mode
        if args.quick:
            scanner.config['authentication']['test_weak_creds'] = False
            scanner.config['authentication']['test_anonymous'] = False
            print(f"{Colors.YELLOW}[!] Quick scan mode: Vulnerability checks disabled{Colors.RESET}")
        
        # Start scanning
        scanner.scan_targets(
            targets=args.targets,
            ports=args.ports,
            threads=args.threads,
            target_file=args.file
        )
        
        return 0
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        return 130
    except Exception as e:
        print(f"{Colors.RED}[!] Unexpected error: {e}{Colors.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
