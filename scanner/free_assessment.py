"""
Free Assessment Module
Complete vulnerability assessment without paid tools (Nessus, Nmap).
Combines port scanning, service fingerprinting, CVE lookup, and SSL analysis.
"""

from scanner.port_scanner import PortScanner, scan_target_ports
from scanner.service_fingerprint import ServiceFingerprinter, fingerprint_services
from scanner.cve_lookup import CVELookup, lookup_service_vulnerabilities
from scanner.ssl_analyzer import SSLAnalyzer, analyze_ssl_security
from scanner.dns_scanner import DNSScanner, scan_dns_target

from typing import Dict, List, Optional, Callable
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed


class FreeAssessment:
    """
    Complete vulnerability assessment combining:
    - Port scanning (TCP/UDP)
    - Service fingerprinting
    - CVE database lookups
    - SSL/TLS analysis
    - DNS enumeration
    
    Designed to replace expensive tools like Nessus/Nmap with open-source alternatives.
    """
    
    def __init__(self, timeout: float = 5.0, max_workers: int = 50):
        """
        Initialize assessment engine.
        
        Args:
            timeout: Connection timeout for probes
            max_workers: Max concurrent threads
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.logger = logging.getLogger(__name__)
    
    def run_full_assessment(self, target: str, include_dns: bool = True,
                           port_type: str = "tcp", progress_callback: Optional[Callable] = None) -> Dict:
        """
        Execute complete vulnerability assessment on target.
        
        Args:
            target: Hostname, domain, or IP address
            include_dns: Include DNS enumeration
            port_type: "tcp", "udp", or "both"
            progress_callback: Optional progress callback
            
        Returns:
            Comprehensive assessment results with normalized schema
        """
        assessment = {
            "target": target,
            "phases": {
                "port_scan": None,
                "service_fingerprint": None,
                "cve_lookup": None,
                "ssl_analysis": None,
                "dns_enumeration": None
            },
            "summary": {
                "total_findings": 0,
                "critical_findings": 0,
                "high_findings": 0,
                "medium_findings": 0,
                "open_ports": 0
            },
            "normalized_results": []
        }
        
        try:
            # Phase 1: Port Scanning
            if progress_callback:
                progress_callback("Port scanning...", 10)
            
            port_scan = scan_target_ports(target, port_type=port_type)
            assessment["phases"]["port_scan"] = port_scan
            assessment["summary"]["open_ports"] = len(port_scan.get("open_ports", []))
            
            if not port_scan.get("open_ports"):
                return assessment
            
            # Phase 2: Service Fingerprinting
            if progress_callback:
                progress_callback("Fingerprinting services...", 30)
            
            fingerprint = fingerprint_services(target, port_scan["open_ports"])
            assessment["phases"]["service_fingerprint"] = fingerprint
            
            # Phase 3: CVE Lookup
            if progress_callback:
                progress_callback("Searching for CVEs...", 50)
            
            cve_findings = []
            lookup = CVELookup(timeout=self.timeout)

            cve_jobs = []
            for port, service_info in fingerprint["services"].items():
                service_name = service_info.get("service")
                if not service_name:
                    continue
                service_str = service_name
                if service_info.get("version"):
                    service_str += f" {service_info['version']}"
                cve_jobs.append((port, service_info, service_str))

            if cve_jobs:
                max_cve_workers = min(max(2, self.max_workers // 2), 8)
                with ThreadPoolExecutor(max_workers=max_cve_workers) as executor:
                    future_map = {
                        executor.submit(
                            lookup_service_vulnerabilities,
                            service_str,
                            None,
                            80,
                            lookup,
                        ): (port, service_info)
                        for port, service_info, service_str in cve_jobs
                    }
                    for future in as_completed(future_map):
                        port, service_info = future_map[future]
                        try:
                            vuln_result = future.result()
                        except Exception as e:
                            self.logger.debug(f"CVE lookup failed for {service_info.get('service')}:{port}: {e}")
                            vuln_result = {
                                "service": service_info.get("service"),
                                "version": service_info.get("version"),
                                "total_vulnerabilities": 0,
                                "critical": [],
                                "high": [],
                                "medium": [],
                                "low": [],
                            }

                        cve_findings.append({
                            "port": port,
                            "service": service_info.get("service"),
                            "version": service_info.get("version"),
                            "vulnerabilities": vuln_result
                        })
            
            assessment["phases"]["cve_lookup"] = cve_findings
            
            # Phase 4: SSL/TLS Analysis (for HTTPS ports)
            if progress_callback:
                progress_callback("Analyzing SSL/TLS...", 70)
            
            ssl_findings = []
            https_ports = [443, 8443, 9443, 465, 989, 992, 995]
            
            for port in port_scan.get("open_ports", []):
                if port in https_ports:
                    try:
                        ssl_analysis = analyze_ssl_security(target, port)
                        ssl_findings.append({
                            "port": port,
                            "analysis": ssl_analysis
                        })
                    except Exception as e:
                        self.logger.debug(f"SSL analysis failed for port {port}: {e}")
            
            assessment["phases"]["ssl_analysis"] = ssl_findings
            
            # Phase 5: DNS Enumeration (optional)
            if include_dns and "." in target:
                if progress_callback:
                    progress_callback("Enumerating DNS...", 85)
                
                try:
                    dns_scan = scan_dns_target(target)
                    assessment["phases"]["dns_enumeration"] = dns_scan
                except Exception as e:
                    self.logger.debug(f"DNS enumeration failed: {e}")
            
            # Generate normalized results
            if progress_callback:
                progress_callback("Generating report...", 95)
            
            assessment["normalized_results"] = self._normalize_results(assessment)
            
            # Update summary
            for result in assessment["normalized_results"]:
                assessment["summary"]["total_findings"] += 1
                if result.get("severity") == "critical":
                    assessment["summary"]["critical_findings"] += 1
                elif result.get("severity") == "high":
                    assessment["summary"]["high_findings"] += 1
                elif result.get("severity") == "medium":
                    assessment["summary"]["medium_findings"] += 1
        
        except Exception as e:
            self.logger.error(f"Assessment failed: {str(e)}", exc_info=True)
            assessment["error"] = str(e)
        
        return assessment
    
    def _normalize_results(self, assessment: Dict) -> List[Dict]:
        """
        Convert assessment findings to normalized schema for reporting.
        
        Returns:
            List of normalized result dicts
        """
        results = []
        
        # Port scan findings
        port_scan = assessment["phases"]["port_scan"]
        if port_scan and port_scan.get("open_ports"):
            for port in sorted(port_scan["open_ports"]):
                service_info = assessment["phases"]["service_fingerprint"]["services"].get(port, {})
                service_name = service_info.get("service", f"Unknown/Port{port}")
                
                results.append({
                    "module": "Port Scanning",
                    "control": f"Open Port Detection",
                    "port": port,
                    "service": service_name,
                    "version": service_info.get("version"),
                    "status": "Open",
                    "severity": "info",
                    "description": f"Port {port} is open with service {service_name}",
                    "evidence": f"TCP connection successful to {assessment['target']}:{port}",
                    "recommendation": f"Review if port {port} should be exposed; restrict access if unnecessary",
                    "module_acronym": "PS"
                })
        
        # Service fingerprinting findings
        fingerprint = assessment["phases"]["service_fingerprint"]
        if fingerprint:
            for port, service_info in fingerprint["services"].items():
                service_info = service_info or {}
                service_name = str(service_info.get("service") or "").strip()
                if service_name:
                    banner = str(service_info.get("banner") or "N/A")
                    results.append({
                        "module": "Service Detection",
                        "control": f"Service Version Detection",
                        "port": port,
                        "service": service_name,
                        "version": service_info.get("version"),
                        "status": f"Detected: {service_name}",
                        "severity": "info",
                        "description": f"Identified {service_name} service",
                        "evidence": f"Banner: {banner[:100]}",
                        "recommendation": f"Verify {service_name} version is up to date; apply security patches",
                        "module_acronym": "SF"
                    })
        
        # CVE findings
        cve_findings = assessment["phases"]["cve_lookup"]
        if cve_findings:
            for finding in cve_findings:
                vuln_result = finding["vulnerabilities"]
                
                for severity_level in ["critical", "high", "medium"]:
                    for cve in vuln_result.get(severity_level, []):
                        results.append({
                            "module": "CVE Database",
                            "control": "Known Vulnerability Detection",
                            "port": finding["port"],
                            "service": finding["service"],
                            "version": finding["version"],
                            "status": cve["id"],
                            "severity": severity_level,
                            "description": cve.get("description", "")[:200],
                            "evidence": f"CVE {cve['id']} affects {finding['service']} {finding['version']} (CVSS: {cve.get('score', 'N/A')})",
                            "recommendation": f"Update {finding['service']} to patched version; review CVE {cve['id']} details",
                            "module_acronym": "CVE"
                        })
        
        # SSL/TLS findings
        ssl_findings = assessment["phases"]["ssl_analysis"]
        if ssl_findings:
            for finding in ssl_findings:
                analysis = finding["analysis"]
                
                if analysis.get("vulnerabilities"):
                    for vuln in analysis["vulnerabilities"]:
                        results.append({
                            "module": "SSL/TLS Analysis",
                            "control": "SSL/TLS Configuration",
                            "port": finding["port"],
                            "status": vuln["type"],
                            "severity": vuln.get("severity", "medium"),
                            "description": vuln.get("description", ""),
                            "evidence": f"Port {finding['port']}: {vuln.get('value', '')}",
                            "recommendation": "Update SSL/TLS configuration; use modern protocols (TLS 1.2+) and strong ciphers",
                            "module_acronym": "SSL"
                        })
        
        return results
    
    def quick_scan(self, target: str, progress_callback: Optional[Callable] = None) -> Dict:
        """
        Quick assessment focusing on critical findings.
        
        Args:
            target: Target hostname/IP
            progress_callback: Progress callback
            
        Returns:
            Assessment results
        """
        return self.run_full_assessment(target, include_dns=False, progress_callback=progress_callback)
    
    def deep_scan(self, target: str, progress_callback: Optional[Callable] = None) -> Dict:
        """
        Deep assessment including all modules.
        
        Args:
            target: Target hostname/IP
            progress_callback: Progress callback
            
        Returns:
            Complete assessment results
        """
        return self.run_full_assessment(target, include_dns=True, port_type="both", 
                                       progress_callback=progress_callback)


def run_free_assessment(target: str, assessment_type: str = "full") -> Dict:
    """
    Convenience function to run free vulnerability assessment.
    
    Args:
        target: Target hostname, domain, or IP
        assessment_type: "quick", "full", or "deep"
        
    Returns:
        Assessment results
    """
    assessment = FreeAssessment()
    
    if assessment_type == "quick":
        return assessment.quick_scan(target)
    elif assessment_type == "deep":
        return assessment.deep_scan(target)
    else:
        return assessment.run_full_assessment(target)
