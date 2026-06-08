# Modulo de escaneo y analisis para ssl analyzer.

"""
SSL/TLS Analysis Module
Analyzes SSL/TLS certificates, cipher strength, and protocol versions
"""

import ssl
import socket
from typing import Dict, Optional, List
from datetime import datetime
import re


class SSLAnalyzer:
    """
    Analyzes SSL/TLS configurations for security issues:
    - Weak ciphers
    - Old protocol versions
    - Certificate validity
    - Self-signed certificates
    """


    WEAK_CIPHERS = {
        "DES": "critical",
        "MD5": "critical",
        "NULL": "critical",
        "EXPORT": "high",
        "RC4": "high",
        "anon": "high",
        "eNULL": "high",
        "aNULL": "high"
    }


    WEAK_PROTOCOLS = {
        "SSLv2": "critical",
        "SSLv3": "critical",
        "TLSv1.0": "high",
        "TLSv1.1": "high"
    }

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def analyze_certificate(self, host: str, port: int = 443) -> Dict:
        """
        Analyze SSL/TLS certificate and configuration.

        Args:
            host: Hostname or IP
            port: HTTPS port (default 443)

        Returns:
            Dict with certificate info and security findings
        """
        result = {
            "host": host,
            "port": port,
            "ssl_enabled": False,
            "certificate": None,
            "protocols": [],
            "ciphers": [],
            "vulnerabilities": [],
            "warnings": [],
            "score": 0
        }

        try:
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                result["vulnerabilities"].append("Cannot resolve hostname")
                return result


            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    result["ssl_enabled"] = True


                    protocol = ssock.version()
                    result["protocols"].append(protocol)


                    for weak_proto, severity in self.WEAK_PROTOCOLS.items():
                        if weak_proto in protocol:
                            result["vulnerabilities"].append({
                                "type": "weak_protocol",
                                "value": protocol,
                                "severity": severity,
                                "description": f"Weak SSL/TLS version in use: {protocol}"
                            })
                            result["score"] = max(result["score"], 7 if severity == "high" else 9)


                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        cipher_protocol = cipher[1]
                        cipher_bits = cipher[2]
                        result["ciphers"].append({
                            "name": cipher_name,
                            "protocol": cipher_protocol,
                            "bits": cipher_bits
                        })


                        for weak_pattern, severity in self.WEAK_CIPHERS.items():
                            if weak_pattern in cipher_name.upper():
                                result["vulnerabilities"].append({
                                    "type": "weak_cipher",
                                    "value": cipher_name,
                                    "severity": severity,
                                    "description": f"Weak cipher in use: {cipher_name} ({cipher_bits} bits)"
                                })
                                result["score"] = max(result["score"], 7 if severity == "high" else 9)


                        if cipher_bits < 128:
                            result["vulnerabilities"].append({
                                "type": "weak_cipher_strength",
                                "value": f"{cipher_bits} bits",
                                "severity": "high",
                                "description": f"Cipher too weak: only {cipher_bits} bits"
                            })
                            result["score"] = max(result["score"], 7)


                    try:
                        cert_der = ssock.getpeercert_chain()[0]
                        cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                        cert_dict = ssock.getpeercert()

                        result["certificate"] = self._parse_certificate(cert_dict)
                    except Exception as e:
                        result["warnings"].append(f"Could not parse certificate: {str(e)}")

        except ssl.SSLError as e:
            result["ssl_enabled"] = False
            if "CERTIFICATE_VERIFY_FAILED" in str(e):
                result["warnings"].append("Self-signed or untrusted certificate")
            else:
                result["vulnerabilities"].append(str(e))

        except socket.timeout:
            result["vulnerabilities"].append("Connection timeout")

        except (ConnectionRefusedError, OSError) as e:
            result["vulnerabilities"].append(f"Connection error: {str(e)}")

        return result

    def _parse_certificate(self, cert_dict: Dict) -> Dict:
        """
        Parse certificate information from getpeercert() output.

        Returns: Certificate info dict
        """
        cert_info = {
            "subject": None,
            "issuer": None,
            "version": None,
            "valid_from": None,
            "valid_until": None,
            "is_self_signed": False,
            "san": [],
            "issues": []
        }


        subject = dict(x[0] for x in cert_dict.get("subject", []))
        if "commonName" in subject:
            cert_info["subject"] = subject["commonName"]


        issuer = dict(x[0] for x in cert_dict.get("issuer", []))
        if "commonName" in issuer:
            cert_info["issuer"] = issuer["commonName"]


            if cert_info["subject"] == cert_info["issuer"]:
                cert_info["is_self_signed"] = True
                cert_info["issues"].append("Self-signed certificate")


        cert_info["valid_from"] = cert_dict.get("notBefore")
        cert_info["valid_until"] = cert_dict.get("notAfter")


        try:
            from email.utils import parsedate_to_datetime
            expiry = parsedate_to_datetime(cert_dict.get("notAfter", ""))
            if expiry < datetime.utcnow():
                cert_info["issues"].append("Certificate expired")
            elif (expiry - datetime.utcnow()).days < 30:
                cert_info["issues"].append(f"Certificate expires soon: {(expiry - datetime.utcnow()).days} days")
        except:
            pass


        for san_type, san_value in cert_dict.get("subjectAltName", []):
            if san_type == "DNS":
                cert_info["san"].append(san_value)

        return cert_info

    def check_tls_version_support(self, host: str, port: int = 443) -> Dict:
        """
        Check which TLS versions are supported.

        Returns: Dict mapping TLS version -> supported (bool)
        """
        results = {
            "host": host,
            "port": port,
            "supported_versions": [],
            "unsupported_versions": []
        }


        tls_versions = [
            (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
            (ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
        ]

        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return results

        for tls_version, version_name in tls_versions:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = tls_version
                context.maximum_version = tls_version
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host):
                        results["supported_versions"].append(version_name)
            except (ssl.SSLError, socket.timeout, OSError):
                results["unsupported_versions"].append(version_name)

        return results


def analyze_ssl_security(host: str, port: int = 443) -> Dict:
    """
    Convenience function to perform complete SSL/TLS security analysis.

    Args:
        host: Target hostname
        port: HTTPS port

    Returns:
        Comprehensive SSL analysis
    """
    analyzer = SSLAnalyzer(timeout=5.0)

    analysis = analyzer.analyze_certificate(host, port)
    tls_support = analyzer.check_tls_version_support(host, port)

    analysis["tls_versions"] = tls_support


    if analysis["ssl_enabled"]:
        if analysis["score"] >= 8:
            analysis["risk_level"] = "critical"
        elif analysis["score"] >= 6:
            analysis["risk_level"] = "high"
        elif analysis["score"] >= 4:
            analysis["risk_level"] = "medium"
        else:
            analysis["risk_level"] = "low"
    else:
        analysis["risk_level"] = "critical"

    return analysis
