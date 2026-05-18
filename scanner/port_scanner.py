"""
Port Scanner Module
Detects open ports using socket-based TCP/UDP scanning (no external tools required)
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional


class PortScanner:
    """
    Lightweight port scanner using native Python sockets.
    Supports both TCP and UDP scanning with configurable timeouts.
    """
    
    def __init__(self, timeout: float = 2.0, max_workers: int = 50):
        """
        Args:
            timeout: Connection timeout in seconds
            max_workers: Max concurrent threads for scanning
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.open_ports = []
        self.lock = threading.Lock()
    
    def scan_tcp(self, host: str, ports: List[int], progress_callback=None) -> Dict[int, str]:
        """
        TCP port scan using socket connection.
        
        Args:
            host: Target hostname or IP
            ports: List of port numbers to scan
            progress_callback: Optional callback(current, total) for progress reporting
            
        Returns:
            Dict mapping open port -> state ("open" or "closed")
        """
        results = {}
        total = len(ports)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._check_tcp_port, host, port): port 
                for port in ports
            }
            
            completed = 0
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                    results[port] = "open" if is_open else "closed"
                except Exception as e:
                    results[port] = f"error: {str(e)[:50]}"
                
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
        
        return results
    
    def scan_udp(self, host: str, ports: List[int], progress_callback=None) -> Dict[int, str]:
        """
        UDP port scan (ICMP-based timeout detection).
        Note: UDP scanning is less reliable without raw sockets (requires admin).
        
        Args:
            host: Target hostname or IP
            ports: List of port numbers to scan
            progress_callback: Optional callback for progress reporting
            
        Returns:
            Dict mapping port -> state
        """
        results = {}
        total = len(ports)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._check_udp_port, host, port): port 
                for port in ports
            }
            
            completed = 0
            for future in as_completed(futures):
                port = futures[future]
                try:
                    state = future.result()
                    results[port] = state
                except Exception as e:
                    results[port] = f"error: {str(e)[:50]}"
                
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
        
        return results
    
    def _check_tcp_port(self, host: str, port: int) -> bool:
        """
        Check if a single TCP port is open.
        
        Returns: True if port is open, False otherwise
        """
        try:
            # Try to resolve hostname first
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                return False
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            return result == 0
        except Exception:
            return False
    
    def _check_udp_port(self, host: str, port: int) -> str:
        """
        Check UDP port state (less reliable).
        
        Returns: "open|filtered", "closed", or "error"
        """
        try:
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                return "error"
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b"", (ip, port))
            try:
                sock.recvfrom(1024)
                sock.close()
                return "open"
            except socket.timeout:
                sock.close()
                return "open|filtered"
            
        except Exception:
            return "error"
    
    def get_common_ports(self, priority: str = "web") -> List[int]:
        """
        Get list of common ports based on scanning priority.
        
        Args:
            priority: "web" (HTTP/HTTPS), "full" (top 1000), or "default" (top 100)
            
        Returns:
            List of port numbers
        """
        web_ports = [80, 8080, 8000, 8888, 3000, 5000, 5500, 9000, 443, 8443]
        
        default_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            8080,  # HTTP Alt
            8443,  # HTTPS Alt
            27017, # MongoDB
            6379,  # Redis
        ]
        
        if priority == "web":
            return web_ports
        elif priority == "full":
            return list(range(1, 1001))
        else:
            return default_ports


def scan_target_ports(host: str, ports: Optional[List[int]] = None, 
                      port_type: str = "tcp", progress_callback=None) -> Dict:
    """
    Convenience function to scan a target.
    
    Args:
        host: Target hostname/IP
        ports: Specific ports to scan (default: common ports)
        port_type: "tcp", "udp", or "both"
        progress_callback: Progress reporting callback
        
    Returns:
        Normalized results dict
    """
    scanner = PortScanner(timeout=3.0, max_workers=50)
    
    if ports is None:
        ports = scanner.get_common_ports("default")
    
    results = {
        "host": host,
        "ports_scanned": len(ports),
        "open_ports": [],
        "closed_ports": [],
        "filtered_ports": [],
        "errors": []
    }
    
    try:
        if port_type in ["tcp", "both"]:
            tcp_results = scanner.scan_tcp(host, ports, progress_callback)
            for port, state in tcp_results.items():
                if state == "open":
                    results["open_ports"].append(port)
                elif state == "closed":
                    results["closed_ports"].append(port)
                elif "error" in state:
                    results["errors"].append(f"Port {port}: {state}")
        
        if port_type in ["udp", "both"]:
            udp_results = scanner.scan_udp(host, ports, progress_callback)
            for port, state in udp_results.items():
                if state == "open":
                    results["open_ports"].append(port)
                elif "filtered" in state:
                    results["filtered_ports"].append(port)
    
    except Exception as e:
        results["errors"].append(f"Scan failed: {str(e)}")
    
    return results
