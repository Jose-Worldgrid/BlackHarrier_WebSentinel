import requests


EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _chunks(items, size):
    chunk = []
    for item in items:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def _fetch_epss_scores(cve_ids, timeout=8.0):
    scores = {}
    ids = [str(cve or "").strip().upper() for cve in cve_ids if str(cve or "").strip().upper().startswith("CVE-")]
    if not ids:
        return scores

    session = requests.Session()
    # Keep batches small to avoid proxy/gateway URL limits.
    for batch in _chunks(ids, 40):
        try:
            response = session.get(
                EPSS_API_URL,
                params={"cve": ",".join(batch)},
                timeout=timeout,
            )
            response.raise_for_status()
            data = response.json() or {}
            for row in data.get("data") or []:
                cve_id = str(row.get("cve") or "").strip().upper()
                epss = float(row.get("epss") or 0)
                percentile = float(row.get("percentile") or 0)
                if cve_id:
                    scores[cve_id] = {
                        "epss": epss,
                        "epss_percentile": percentile,
                    }
        except Exception:
            continue

    return scores


def _fetch_kev_set(timeout=8.0):
    kev = set()
    try:
        response = requests.get(KEV_CATALOG_URL, timeout=timeout)
        response.raise_for_status()
        data = response.json() or {}
        for row in data.get("vulnerabilities") or []:
            cve_id = str(row.get("cveID") or "").strip().upper()
            if cve_id.startswith("CVE-"):
                kev.add(cve_id)
    except Exception:
        return set()
    return kev


def _priority_tier(score, epss, in_kev):
    score = float(score or 0)
    epss = float(epss or 0)
    if in_kev or score >= 9.0 or epss >= 0.70:
        return "Urgente"
    if score >= 7.0 or epss >= 0.30:
        return "Alta"
    if score >= 4.0 or epss >= 0.10:
        return "Media"
    return "Baja"


def enrich_cves_with_free_intel(cves, timeout=8.0):
    """Enrich CVEs with free EPSS + CISA KEV intelligence.

    Returns:
      (enriched_cves, summary)
    """
    cves = [dict(c or {}) for c in (cves or []) if isinstance(c, dict)]
    cve_ids = [str(c.get("id") or "").strip().upper() for c in cves]

    epss_map = _fetch_epss_scores(cve_ids, timeout=timeout)
    kev_set = _fetch_kev_set(timeout=timeout)

    enriched = []
    kev_hits = 0
    epss_hits = 0

    for cve in cves:
        cve_id = str(cve.get("id") or "").strip().upper()
        intel = epss_map.get(cve_id, {})
        epss = float(intel.get("epss", 0) or 0)
        percentile = float(intel.get("epss_percentile", 0) or 0)
        in_kev = cve_id in kev_set

        if in_kev:
            kev_hits += 1
        if epss > 0:
            epss_hits += 1

        cve["epss"] = epss
        cve["epss_percentile"] = percentile
        cve["kev"] = bool(in_kev)
        cve["priority_tier"] = _priority_tier(cve.get("score", 0), epss, in_kev)
        enriched.append(cve)

    summary = {
        "total": len(enriched),
        "epss_enriched": epss_hits,
        "kev_hits": kev_hits,
        "urgent": len([x for x in enriched if x.get("priority_tier") == "Urgente"]),
        "high": len([x for x in enriched if x.get("priority_tier") == "Alta"]),
        "medium": len([x for x in enriched if x.get("priority_tier") == "Media"]),
        "low": len([x for x in enriched if x.get("priority_tier") == "Baja"]),
    }

    return enriched, summary
