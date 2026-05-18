"""
DNS/Subdomain Enumeration Module
Discovers subdomains and DNS records for targets
"""

import dns.resolver
import dns.rdatatype
import dns.zone
import socket
import re
from typing import Dict, List, Optional, Set
import requests


class DNSScanner:
    """
    Enumerates DNS records and discovers subdomains for targets.
    """
    
    # Common subdomain patterns to try
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns",
        "admin", "test", "portal", "dev", "development", "staging", "prod",
        "api", "backend", "app", "mobile", "static", "cdn", "images",
        "assets", "blog", "news", "support", "help", "forums", "shop",
        "store", "sales", "marketing", "jobs", "careers", "hr",
        "accounting", "finance", "legal", "health", "medical",
        "secure", "login", "auth", "vpn", "remote", "access",
        "server", "mail2", "mx", "dns", "ns1", "ns2",
        "dashboard", "analytics", "monitoring", "status", "health",
        "prometheus", "grafana", "elastic", "kibana", "splunk",
        "jenkins", "gitlab", "github", "bitbucket", "docker",
        "kubernetes", "k8s", "aws", "azure", "gcp",
        "old", "backup", "bak", "temp", "tmp", "test2"
    ]
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
    
    def resolve_host(self, host: str) -> Optional[str]:
        """
        Resolve hostname to IP address.
        
        Args:
            host: Hostname or domain
            
        Returns:
            IP address or None
        """
        try:
            ip = socket.gethostbyname(host)
            return ip
        except socket.gaierror:
            return None
    
    def get_dns_records(self, domain: str, record_types: List[str] = None) -> Dict:
        """
        Query DNS records for a domain.
        
        Args:
            domain: Target domain
            record_types: Types to query (A, AAAA, MX, TXT, NS, etc.)
            
        Returns:
            Dict mapping record type -> list of records
        """
        if record_types is None:
            record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]
        
        results = {
            "domain": domain,
            "records": {}
        }
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records = []
                
                for rdata in answers:
                    if record_type == "MX":
                        records.append({
                            "type": "MX",
                            "priority": rdata.preference,
                            "value": str(rdata.exchange).rstrip(".")
                        })
                    elif record_type == "NS":
                        records.append({
                            "type": "NS",
                            "value": str(rdata).rstrip(".")
                        })
                    elif record_type == "TXT":
                        records.append({
                            "type": "TXT",
                            "value": str(rdata)
                        })
                    elif record_type == "SOA":
                        records.append({
                            "type": "SOA",
                            "mname": str(rdata.mname).rstrip("."),
                            "rname": str(rdata.rname).rstrip(".")
                        })
                    else:
                        records.append({
                            "type": record_type,
                            "value": str(rdata)
                        })
                
                if records:
                    results["records"][record_type] = records
            
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                pass
        
        return results
    
    def enumerate_subdomains(self, domain: str, wordlist: Optional[List[str]] = None,
                           progress_callback=None) -> Dict:
        """
        Attempt to discover subdomains via DNS enumeration.
        
        Args:
            domain: Target domain
            wordlist: Custom subdomain list (uses common list if None)
            progress_callback: Progress reporting callback
            
        Returns:
            Dict with discovered subdomains
        """
        if wordlist is None:
            wordlist = self.COMMON_SUBDOMAINS
        
        results = {
            "domain": domain,
            "subdomains": [],
            "total_tried": 0
        }
        
        total = len(wordlist)
        
        for idx, subdomain in enumerate(wordlist):
            full_domain = f"{subdomain}.{domain}"
            results["total_tried"] += 1
            
            try:
                ip = socket.gethostbyname(full_domain)
                results["subdomains"].append({
                    "subdomain": subdomain,
                    "fqdn": full_domain,
                    "ip": ip
                })
            except socket.gaierror:
                pass
            
            if progress_callback and (idx + 1) % 5 == 0:
                progress_callback(idx + 1, total)
        
        return results
    
    def reverse_dns_lookup(self, ip_address: str) -> Optional[str]:
        """
        Perform reverse DNS lookup (IP -> hostname).
        
        Args:
            ip_address: IP address
            
        Returns:
            Hostname or None
        """
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror):
            return None
    
    def get_dns_security_info(self, domain: str) -> Dict:
        """
        Check DNS security configurations (DNSSEC, SPF, DKIM, DMARC).
        
        Args:
            domain: Target domain
            
        Returns:
            Security info dict
        """
        security_info = {
            "domain": domain,
            "dnssec": False,
            "spf": None,
            "dkim": None,
            "dmarc": None,
            "issues": []
        }
        
        try:
            # Check DNSSEC
            try:
                dns.resolver.resolve(domain, "DNSKEY")
                security_info["dnssec"] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                security_info["issues"].append("DNSSEC not enabled")
            
            # Check SPF
            try:
                spf_records = dns.resolver.resolve(domain, "TXT")
                for rdata in spf_records:
                    spf_txt = str(rdata)
                    if spf_txt.startswith('"v=spf1'):
                        security_info["spf"] = spf_txt
                        break
                
                if not security_info["spf"]:
                    security_info["issues"].append("SPF record not found")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                security_info["issues"].append("SPF record not found")
            
            # Check DMARC
            try:
                dmarc_domain = f"_dmarc.{domain}"
                dmarc_records = dns.resolver.resolve(dmarc_domain, "TXT")
                for rdata in dmarc_records:
                    dmarc_txt = str(rdata)
                    if "v=DMARC1" in dmarc_txt:
                        security_info["dmarc"] = dmarc_txt
                        break
                
                if not security_info["dmarc"]:
                    security_info["issues"].append("DMARC record not found")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                security_info["issues"].append("DMARC record not found")
        
        except Exception as e:
            security_info["issues"].append(f"Error: {str(e)}")
        
        return security_info


def scan_dns_target(domain: str, include_subdomains: bool = True,
                   include_security: bool = True) -> Dict:
    """
    Convenience function for complete DNS scanning of a domain.
    
    Args:
        domain: Target domain
        include_subdomains: Whether to enumerate subdomains
        include_security: Whether to check DNS security configs
        
    Returns:
        Comprehensive DNS scan results
    """
    scanner = DNSScanner(timeout=5.0)
    
    results = {
        "domain": domain,
        "primary_ip": scanner.resolve_host(domain),
        "dns_records": scanner.get_dns_records(domain),
        "subdomains": [],
        "security": None
    }
    
    if include_subdomains:
        sub_enum = scanner.enumerate_subdomains(domain)
        results["subdomains"] = sub_enum["subdomains"]
        results["subdomains_tried"] = sub_enum["total_tried"]
    
    if include_security:
        results["security"] = scanner.get_dns_security_info(domain)
    
    return results
