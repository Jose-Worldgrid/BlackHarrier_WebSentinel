"""
CVE Lookup Module
Searches for known vulnerabilities using free public APIs (Vulners, NVD)
"""

import requests
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import json
import os


class CVELookup:
    """
    Query free CVE databases to find known vulnerabilities for detected services.
    Uses Vulners API (free tier) and NVD database.
    """
    
    # Service name variants for CVE searching
    SERVICE_ALIASES = {
        "SSH": ["openssh", "libssh"],
        "Apache": ["httpd", "apache"],
        "Nginx": ["nginx"],
        "MySQL": ["mysql"],
        "PostgreSQL": ["postgresql", "postgres"],
        "MongoDB": ["mongodb"],
        "Redis": ["redis"],
        "OpenSSL": ["openssl"],
        "FTP": ["vsftpd", "pure-ftpd", "proftpd"],
    }

    CACHE_TTL_SECONDS = 24 * 3600
    
    def __init__(self, timeout: float = 10.0, cache_path: str = "storage/cve_cache.json"):
        self.timeout = timeout
        self.cache = {}
        self.cache_path = cache_path
        self._load_cache()

    def _cache_key(self, service: str, version: Optional[str]) -> str:
        return f"{str(service or '').strip().lower()}::{str(version or '').strip().lower()}"

    def _load_cache(self) -> None:
        try:
            if not self.cache_path or not os.path.exists(self.cache_path):
                return
            with open(self.cache_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self.cache = data
        except Exception:
            self.cache = {}

    def _save_cache(self) -> None:
        try:
            if not self.cache_path:
                return
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as fh:
                json.dump(self.cache, fh, ensure_ascii=False)
        except Exception:
            pass
    
    def search_cves(self, service: str, version: Optional[str] = None) -> List[Dict]:
        """
        Search for CVEs affecting a specific service/version.
        
        Args:
            service: Service name (e.g., "SSH", "Apache")
            version: Version string (e.g., "7.4p1")
            
        Returns:
            List of CVE dicts: id, score, description, severity
        """
        if not service:
            return []

        normalized_service = str(service or "").strip()

        # Check cache first
        cache_key = self._cache_key(normalized_service, version)
        cached = self.cache.get(cache_key)
        if isinstance(cached, dict):
            fetched_at = float(cached.get("fetched_at", 0) or 0)
            if fetched_at > 0 and (datetime.now().timestamp() - fetched_at) <= self.CACHE_TTL_SECONDS:
                return list(cached.get("results") or [])

        # Build candidate search terms from service aliases
        service_terms = [normalized_service]
        service_key = normalized_service.split()[0]
        for alias in self.SERVICE_ALIASES.get(service_key, []):
            if alias not in service_terms:
                service_terms.append(alias)

        results = []

        for term in service_terms[:4]:
            # Try Vulners API (free, no auth required)
            results.extend(self._search_vulners(term, version))

            # Try NVD/CVE API
            results.extend(self._search_nvd(term, version))
        
        # Deduplicate by CVE ID
        seen = set()
        deduped = []
        for cve in results:
            cve_id = cve.get("id", "")
            if cve_id and cve_id not in seen:
                seen.add(cve_id)
                deduped.append(cve)
        
        self.cache[cache_key] = {
            "fetched_at": datetime.now().timestamp(),
            "results": deduped,
        }
        self._save_cache()
        return deduped
    
    def _search_vulners(self, service: str, version: Optional[str] = None) -> List[Dict]:
        """
        Search Vulners.com free API for CVEs.
        
        Returns: List of CVE objects
        """
        try:
            # Build search query
            query = service
            if version:
                query += f" {version}"
            
            # Vulners API endpoint (free tier, no API key required)
            url = "https://vulners.com/api/v3/search/lucene/"
            params = {
                "query": query,
                "limit": 10,
                "type": "cve",
                "apiKey": "public"  # Public free tier
            }
            
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            if data.get("data", {}).get("documents"):
                for cve_id, cve_data in data["data"]["documents"].items():
                    cves.append({
                        "id": cve_id,
                        "score": cve_data.get("cvssScore", [0])[0] if cve_data.get("cvssScore") else 0,
                        "description": cve_data.get("description", ""),
                        "severity": self._score_to_severity(cve_data.get("cvssScore", [0])[0] if cve_data.get("cvssScore") else 0),
                        "source": "vulners",
                        "affected_versions": cve_data.get("affectedVersions", [])
                    })
            
            return cves
        
        except requests.RequestException:
            return []
        except Exception as e:
            print(f"Vulners search error: {e}")
            return []
    
    def _search_nvd(self, service: str, version: Optional[str] = None) -> List[Dict]:
        """
        Search NVD (National Vulnerability Database) API for CVEs.
        
        Returns: List of CVE objects
        """
        try:
            # NVD API v2 (free, no key required for basic queries)
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            # Build keyword query
            keywords = [service]
            if version:
                keywords.append(version)
            
            params = {
                "keywordSearch": " ".join(keywords),
                "startIndex": 0,
                "resultsPerPage": 10
            }
            
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            if data.get("vulnerabilities"):
                for vuln in data["vulnerabilities"][:10]:
                    cve_data = vuln.get("cve", {})
                    metrics = cve_data.get("metrics", {})
                    
                    # Get CVSS score (try v3 first, then v2)
                    score = 0
                    if metrics.get("cvssMetricV31"):
                        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif metrics.get("cvssMetricV3"):
                        score = metrics["cvssMetricV3"][0]["cvssData"]["baseScore"]
                    elif metrics.get("cvssMetricV2"):
                        score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    
                    cves.append({
                        "id": cve_data.get("id", ""),
                        "score": score,
                        "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
                        "severity": self._score_to_severity(score),
                        "source": "nvd",
                        "published": cve_data.get("published", ""),
                        "updated": cve_data.get("lastModified", "")
                    })
            
            return cves
        
        except requests.RequestException:
            return []
        except Exception as e:
            print(f"NVD search error: {e}")
            return []
    
    def _score_to_severity(self, score: float) -> str:
        """
        Convert CVSS score to severity level.
        
        Args:
            score: CVSS score (0-10)
            
        Returns: Severity string (critical, high, medium, low, info)
        """
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0:
            return "low"
        else:
            return "info"
    
    def search_software_version(self, software: str, version: str) -> Dict:
        """
        Check if a specific software version has known vulnerabilities.
        
        Args:
            software: Software/product name
            version: Version string
            
        Returns:
            Dict with vulnerabilities found and severity summary
        """
        cves = self.search_cves(software, version)
        
        result = {
            "software": software,
            "version": version,
            "vulnerabilities_found": len(cves),
            "critical_count": sum(1 for c in cves if c["severity"] == "critical"),
            "high_count": sum(1 for c in cves if c["severity"] == "high"),
            "medium_count": sum(1 for c in cves if c["severity"] == "medium"),
            "cves": cves
        }
        
        return result


def lookup_service_vulnerabilities(service: str, version: Optional[str] = None,
                                   max_results: int = 20,
                                   lookup: Optional[CVELookup] = None) -> Dict:
    """
    Convenience function to lookup vulnerabilities for a detected service.
    
    Args:
        service: Service name (e.g., "SSH OpenSSH 7.4")
        version: Version if available
        max_results: Maximum CVEs to return
        
    Returns:
        Normalized vulnerability results
    """
    lookup = lookup or CVELookup(timeout=10.0)
    
    # Extract service name and version if not provided
    if not version and " " in service:
        parts = service.split()
        service_name = parts[0]
        version = parts[1] if len(parts) > 1 else None
    else:
        service_name = service
    
    cves = lookup.search_cves(service_name, version)
    
    result = {
        "service": service,
        "version": version,
        "total_vulnerabilities": len(cves),
        "critical": [],
        "high": [],
        "medium": [],
        "low": []
    }
    
    for cve in cves[:max_results]:
        severity = cve["severity"]
        if severity in result:
            result[severity].append({
                "id": cve["id"],
                "score": cve["score"],
                "description": cve["description"][:200]
            })
    
    return result
