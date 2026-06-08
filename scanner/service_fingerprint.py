# Modulo de escaneo y analisis para service fingerprint.

"""
Service Fingerprinting Module
Detects running services and their versions via banner grabbing and protocol analysis
"""

import socket
import ssl
import re
from typing import Dict, List, Optional, Tuple


class ServiceFingerprinter:
    """
    Identifies services running on open ports through banner grabbing
    and protocol-specific queries.
    """


    PORT_HINTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        8080: "HTTP", 8443: "HTTPS", 27017: "MongoDB", 6379: "Redis",
        9200: "Elasticsearch", 9300: "Elasticsearch", 5601: "Kibana",
        3000: "Node.js/Rails", 5000: "Python/Flask", 8000: "Django",
    }


    SERVICE_PROBES = {
        "SSH": (b"", b"SSH-"),
        "FTP": (b"\r\n", b"220"),
        "SMTP": (b"\r\n", b"220"),
        "IMAP": (b"\r\n", b"* OK"),
        "POP3": (b"\r\n", b"+OK"),
        "HTTP": (b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n", b"HTTP/"),
        "HTTPS": (None, None),
        "TELNET": (b"\r\n", b"login:|telnet|Username|Password"),
        "MYSQL": (b"", b"MySQL"),
        "PostgreSQL": (b"", b"PostgreSQL"),
        "MongoDB": (b"", None),
        "Redis": (b"COMMAND\r\n", b"redis"),
    }

    def __init__(self, timeout: float = 3.0):
        """Initialize fingerprinter with connection timeout."""
        self.timeout = timeout

    def fingerprint_port(self, host: str, port: int) -> Dict:
        """
        Attempt to identify the service running on a port.

        Args:
            host: Target hostname/IP
            port: Port number

        Returns:
            Dict with service info: name, version, banner, certainty
        """
        result = {
            "port": port,
            "service": None,
            "version": None,
            "banner": None,
            "method": None,
            "certainty": "low",
            "protocol": "tcp"
        }


        if port in self.PORT_HINTS:
            result["service"] = self.PORT_HINTS[port]
            result["certainty"] = "low"
            result["method"] = "port_mapping"


        banner_result = self._grab_banner(host, port)
        if banner_result:
            result.update(banner_result)
            return result


        probe_result = self._probe_service(host, port)
        if probe_result:
            result.update(probe_result)
            return result


        if port in [443, 8443, 9443, 465, 989, 992, 995]:
            ssl_result = self._detect_ssl_service(host, port)
            if ssl_result:
                result.update(ssl_result)
                return result

        return result

    def _grab_banner(self, host: str, port: int) -> Optional[Dict]:
        """
        Grab service banner by connecting and reading response.

        Returns: Dict with service/version/banner info, or None
        """
        try:
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                return None

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))


            banner = sock.recv(1024).decode(errors='ignore')

            if banner:
                sock.close()
                service_info = self._parse_banner(banner, port)
                if service_info:
                    service_info["banner"] = banner[:200]
                    service_info["method"] = "banner_grabbing"
                    return service_info

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            try:
                sock.close()
            except:
                pass

        return None

    def _probe_service(self, host: str, port: int) -> Optional[Dict]:
        """
        Send protocol-specific probes to detect service.

        Returns: Service info dict or None
        """
        for service_name, (probe, response_marker) in self.SERVICE_PROBES.items():
            if probe is None or response_marker is None:
                continue

            try:
                try:
                    ip = socket.gethostbyname(host)
                except socket.gaierror:
                    continue

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, port))

                if probe:
                    sock.sendall(probe)

                response = sock.recv(1024).decode(errors='ignore')
                sock.close()

                if isinstance(response_marker, str):
                    if re.search(response_marker, response, re.IGNORECASE):
                        service_info = self._parse_banner(response, port)
                        service_info["service"] = service_name
                        service_info["certainty"] = "high"
                        service_info["method"] = "protocol_probe"
                        return service_info
                else:
                    if response_marker in response.encode():
                        return {
                            "service": service_name,
                            "version": None,
                            "certainty": "high",
                            "method": "protocol_probe"
                        }

            except (socket.timeout, ConnectionRefusedError, OSError):
                continue

        return None

    def _detect_ssl_service(self, host: str, port: int) -> Optional[Dict]:
        """
        Detect SSL/TLS-wrapped services.

        Returns: SSL service info
        """
        try:
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                return None

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:

                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    result = {
                        "service": "HTTPS",
                        "version": ssock.version(),
                        "cipher": cipher[0] if cipher else None,
                        "certainty": "high",
                        "method": "ssl_detection",
                        "ssl_version": ssock.version()
                    }


                    try:
                        ssock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                        banner = ssock.recv(1024).decode(errors='ignore')
                        result["banner"] = banner[:200]
                    except:
                        pass

                    return result

        except (socket.timeout, ssl.SSLError, ConnectionRefusedError, OSError):
            return None

    def _parse_banner(self, banner: str, port: int) -> Dict:
        """
        Extract service and version from banner text.

        Returns: Dict with service/version/certainty
        """
        banner_lower = banner.lower()


        if banner_lower.startswith("ssh-"):
            match = re.search(r"SSH-2\.0-([^\r\n]+)", banner)
            version = match.group(1) if match else None
            return {
                "service": "SSH",
                "version": version,
                "certainty": "high"
            }


        if "http/" in banner_lower:
            match = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
            server = match.group(1).strip() if match else None
            return {
                "service": "HTTP",
                "version": server,
                "certainty": "high"
            }


        if banner_lower.startswith("220"):
            match = re.search(r"220[^(]*\(?(.*?)\)?", banner, re.IGNORECASE)
            version = match.group(1) if match else None
            return {
                "service": "FTP",
                "version": version,
                "certainty": "high"
            }


        if "mysql" in banner_lower:
            match = re.search(r"5\.\d+\.\d+", banner)
            version = match.group(0) if match else None
            return {
                "service": "MySQL",
                "version": version,
                "certainty": "high"
            }


        if "postgresql" in banner_lower:
            match = re.search(r"(\d+\.\d+)", banner)
            version = match.group(1) if match else None
            return {
                "service": "PostgreSQL",
                "version": version,
                "certainty": "high"
            }


        if port in self.PORT_HINTS:
            return {
                "service": self.PORT_HINTS[port],
                "version": None,
                "certainty": "medium"
            }

        return {
            "service": None,
            "version": None,
            "certainty": "low"
        }


def fingerprint_services(host: str, ports: List[int], progress_callback=None) -> Dict:
    """
    Fingerprint multiple services on open ports.

    Args:
        host: Target hostname/IP
        ports: List of open ports
        progress_callback: Progress reporting callback

    Returns:
        Dict mapping port -> service info
    """
    fingerprinter = ServiceFingerprinter(timeout=3.0)
    results = {
        "host": host,
        "services": {}
    }

    total = len(ports)
    for idx, port in enumerate(ports):
        service_info = fingerprinter.fingerprint_port(host, port)
        results["services"][port] = service_info

        if progress_callback:
            progress_callback(idx + 1, total)

    return results
