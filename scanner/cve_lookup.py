# Modulo de escaneo y analisis para cve lookup.

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

    @staticmethod
    def _normalize_version_tokens(version: str) -> List[int]:
        parts = re.findall(r"\d+", str(version or ""))
        return [int(x) for x in parts[:6]] if parts else []

    @classmethod
    def _compare_versions(cls, left: str, right: str) -> int:
        """Return -1 if left<right, 0 if equal, 1 if left>right (numeric token comparison)."""
        ltok = cls._normalize_version_tokens(left)
        rtok = cls._normalize_version_tokens(right)
        if not ltok and not rtok:
            return 0
        max_len = max(len(ltok), len(rtok))
        ltok.extend([0] * (max_len - len(ltok)))
        rtok.extend([0] * (max_len - len(rtok)))
        for lv, rv in zip(ltok, rtok):
            if lv < rv:
                return -1
            if lv > rv:
                return 1
        return 0

    @classmethod
    def _version_within_bounds(cls, version: str, cpe_match: Dict) -> bool:
        if not version:
            return True

        v = str(version or "").strip()
        if not v:
            return True

        start_inc = str(cpe_match.get("versionStartIncluding") or "").strip()
        start_exc = str(cpe_match.get("versionStartExcluding") or "").strip()
        end_inc = str(cpe_match.get("versionEndIncluding") or "").strip()
        end_exc = str(cpe_match.get("versionEndExcluding") or "").strip()

        if start_inc and cls._compare_versions(v, start_inc) < 0:
            return False
        if start_exc and cls._compare_versions(v, start_exc) <= 0:
            return False
        if end_inc and cls._compare_versions(v, end_inc) > 0:
            return False
        if end_exc and cls._compare_versions(v, end_exc) >= 0:
            return False

        criteria = str(cpe_match.get("criteria") or "")
        if criteria and v and f":{v}:" in criteria:
            return True


        if not any([start_inc, start_exc, end_inc, end_exc]):
            return True

        return True

    @classmethod
    def _likely_affected_by_nvd_config(cls, cve_data: Dict, version: Optional[str]) -> bool:
        if not version:
            return True

        configurations = cve_data.get("configurations") or []
        if not isinstance(configurations, list):
            return True

        saw_match = False
        for cfg in configurations:
            nodes = cfg.get("nodes") or []
            for node in nodes:
                for cpe_match in (node.get("cpeMatch") or []):
                    if not isinstance(cpe_match, dict):
                        continue
                    if cpe_match.get("vulnerable") is False:
                        continue
                    saw_match = True
                    if cls._version_within_bounds(str(version or ""), cpe_match):
                        return True


        return not saw_match

    @staticmethod
    def _extract_reference_urls(cve_data: Dict) -> List[str]:
        urls = []
        for ref in cve_data.get("references") or []:
            if isinstance(ref, dict):
                url = str(ref.get("url") or "").strip()
            else:
                url = str(ref or "").strip()
            if url.startswith("http"):
                urls.append(url)
        return list(dict.fromkeys(urls))[:12]

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


        cache_key = self._cache_key(normalized_service, version)
        cached = self.cache.get(cache_key)
        if isinstance(cached, dict):
            fetched_at = float(cached.get("fetched_at", 0) or 0)
            if fetched_at > 0 and (datetime.now().timestamp() - fetched_at) <= self.CACHE_TTL_SECONDS:
                return list(cached.get("results") or [])


        service_terms = [normalized_service]
        service_key = normalized_service.split()[0]
        for alias in self.SERVICE_ALIASES.get(service_key, []):
            if alias not in service_terms:
                service_terms.append(alias)

        results = []

        for term in service_terms[:4]:

            results.extend(self._search_vulners(term, version))


            results.extend(self._search_nvd(term, version))


        best = {}
        for cve in results:
            cve_id = str(cve.get("id") or "").strip().upper()
            if not cve_id:
                continue
            current = best.get(cve_id)
            if not current:
                best[cve_id] = dict(cve)
                continue

            cand_score = float(cve.get("score", 0) or 0)
            cur_score = float(current.get("score", 0) or 0)
            cand_desc = str(cve.get("description") or "")
            cur_desc = str(current.get("description") or "")
            choose_candidate = cand_score > cur_score or (cand_score == cur_score and len(cand_desc) > len(cur_desc))

            if choose_candidate:
                base = dict(cve)
                base_refs = list(dict.fromkeys((current.get("references") or []) + (cve.get("references") or [])))[:20]
                base["references"] = base_refs
                base["likely_affected"] = bool(current.get("likely_affected", True) or cve.get("likely_affected", True))
                best[cve_id] = base
            else:
                current["references"] = list(dict.fromkeys((current.get("references") or []) + (cve.get("references") or [])))[:20]
                current["likely_affected"] = bool(current.get("likely_affected", True) or cve.get("likely_affected", True))

        deduped = list(best.values())

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

            query = service
            if version:
                query += f" {version}"


            url = "https://vulners.com/api/v3/search/lucene/"
            params = {
                "query": query,
                "limit": 10,
                "type": "cve",
                "apiKey": "public"
            }

            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            cves = []

            if data.get("data", {}).get("documents"):
                for cve_id, cve_data in data["data"]["documents"].items():
                    references = []
                    raw_refs = cve_data.get("references")
                    if isinstance(raw_refs, list):
                        for ref in raw_refs:
                            if isinstance(ref, dict):
                                url = str(ref.get("url") or ref.get("href") or "").strip()
                            else:
                                url = str(ref or "").strip()
                            if url.startswith("http"):
                                references.append(url)

                    cves.append({
                        "id": cve_id,
                        "score": cve_data.get("cvssScore", [0])[0] if cve_data.get("cvssScore") else 0,
                        "description": cve_data.get("description", ""),
                        "severity": self._score_to_severity(cve_data.get("cvssScore", [0])[0] if cve_data.get("cvssScore") else 0),
                        "source": "vulners",
                        "affected_versions": cve_data.get("affectedVersions", []),
                        "references": list(dict.fromkeys(references))[:12],
                        "likely_affected": True,
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

            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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


                    score = 0
                    if metrics.get("cvssMetricV31"):
                        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif metrics.get("cvssMetricV3"):
                        score = metrics["cvssMetricV3"][0]["cvssData"]["baseScore"]
                    elif metrics.get("cvssMetricV2"):
                        score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                    likely_affected = self._likely_affected_by_nvd_config(cve_data, version)
                    cves.append({
                        "id": cve_data.get("id", ""),
                        "score": score,
                        "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
                        "severity": self._score_to_severity(score),
                        "source": "nvd",
                        "published": cve_data.get("published", ""),
                        "updated": cve_data.get("lastModified", ""),
                        "references": self._extract_reference_urls(cve_data),
                        "likely_affected": bool(likely_affected),
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
                                   max_results: Optional[int] = 80,
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

    selected = cves if not max_results else cves[:int(max_results)]
    for cve in selected:
        severity = cve["severity"]
        if severity in result:
            result[severity].append({
                "id": cve["id"],
                "score": cve["score"],
                "description": cve["description"][:200]
            })

    return result
