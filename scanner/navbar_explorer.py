# Modulo de exploracion dinamica de navegacion (navbar/enlaces/botones) con Playwright.

from __future__ import annotations

from typing import Dict, List, Any
from urllib.parse import urlparse


def _safe(value: Any) -> str:
    return str(value or "").strip()


def _same_origin(base_url: str, candidate_url: str) -> bool:
    a = urlparse(_safe(base_url))
    b = urlparse(_safe(candidate_url))
    if not a.scheme or not a.netloc or not b.scheme or not b.netloc:
        return False
    return (
        a.scheme == b.scheme
        and a.hostname == b.hostname
        and (a.port or (443 if a.scheme == "https" else 80)) == (b.port or (443 if b.scheme == "https" else 80))
    )


def _normalize_url(url: str) -> str:
    raw = _safe(url)
    if not raw:
        return ""
    return raw.split("#", 1)[0].rstrip("/")


def discover_navbar_routes(
    start_url: str,
    known_urls: List[str] | None = None,
    *,
    max_clicks: int = 24,
    timeout_ms: int = 8000,
    headless: bool = True,
) -> Dict[str, Any]:
    """
    Explore navbar/header links and clickable navigation controls in a rendered browser.

    Returns:
      {
        "available": bool,
        "executed": bool,
        "routes": [
            {
              "url": str,
              "from_url": str,
              "label": str,
              "selector": str,
              "known": bool,
              "is_new": bool,
            }
        ],
        "errors": [str],
      }
    """
    result: Dict[str, Any] = {
        "available": False,
        "executed": False,
        "routes": [],
        "errors": [],
    }

    base_url = _normalize_url(start_url)
    known = {_normalize_url(url) for url in (known_urls or []) if _normalize_url(url)}
    seen = set()

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    except Exception as exc:
        result["errors"].append(f"Playwright no disponible: {type(exc).__name__}: {exc}")
        return result

    result["available"] = True

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            try:
                page.goto(base_url, wait_until="networkidle", timeout=timeout_ms)
            except PlaywrightTimeoutError:
                page.goto(base_url, wait_until="domcontentloaded", timeout=timeout_ms)

            page.wait_for_timeout(400)

            # Tag candidates in the DOM so each one can be clicked deterministically.
            candidates = page.evaluate(
                """
                () => {
                  const deny = ['logout','sign out','cerrar sesión','cerrar sesion','delete','remove','eliminar'];
                  const selectors = [
                    'nav a[href]',
                    'header a[href]',
                    '[role="navigation"] a[href]',
                    'nav button',
                    'header button',
                    'a[href]'
                  ];

                  const all = [];
                  const seen = new Set();
                  let idx = 0;

                  for (const sel of selectors) {
                    for (const el of document.querySelectorAll(sel)) {
                      if (!(el instanceof HTMLElement)) continue;
                      const text = (el.innerText || el.textContent || '').trim();
                      const low = text.toLowerCase();
                      if (deny.some(x => low.includes(x))) continue;

                      const href = (el.getAttribute('href') || '').trim();
                      const dataHref = (el.getAttribute('data-href') || '').trim();
                      const dataUrl = (el.getAttribute('data-url') || '').trim();
                      const onclick = (el.getAttribute('onclick') || '').trim();
                      const typeAttr = (el.getAttribute('type') || '').trim().toLowerCase();

                      if (typeAttr === 'submit') continue;
                      if (href && (href.startsWith('javascript:') || href === '#')) continue;

                      const hasNavSignal = Boolean(href || dataHref || dataUrl || onclick || el.tagName.toLowerCase() === 'a');
                      if (!hasNavSignal) continue;

                      const key = [el.tagName, href, dataHref, dataUrl, text].join('|').toLowerCase();
                      if (seen.has(key)) continue;
                      seen.add(key);

                      const marker = `bh-nav-${idx++}`;
                      el.setAttribute('data-bh-nav-index', marker);

                      all.push({
                        marker,
                        text,
                        href,
                        dataHref,
                        dataUrl,
                        tag: el.tagName.toLowerCase(),
                      });
                    }
                  }

                  return all;
                }
                """
            ) or []

            for candidate in candidates[: max(0, int(max_clicks or 0))]:
                marker = _safe(candidate.get("marker"))
                if not marker:
                    continue

                selector = f"[data-bh-nav-index='{marker}']"
                from_url = _normalize_url(page.url)
                label = _safe(candidate.get("text") or candidate.get("href") or candidate.get("dataHref") or candidate.get("dataUrl"))

                try:
                    locator = page.locator(selector)
                    if locator.count() == 0:
                        continue

                    locator.first.click(timeout=2500)
                    try:
                        page.wait_for_load_state("networkidle", timeout=2500)
                    except Exception:
                        page.wait_for_timeout(350)

                    current_url = _normalize_url(page.url)
                    if current_url and _same_origin(base_url, current_url) and current_url != from_url:
                        if current_url not in seen:
                            seen.add(current_url)
                            result["routes"].append({
                                "url": current_url,
                                "from_url": from_url,
                                "label": label,
                                "selector": selector,
                                "known": current_url in known,
                                "is_new": current_url not in known,
                            })

                    # Try to return to previous location and continue exploration.
                    try:
                        page.go_back(timeout=2500)
                        page.wait_for_timeout(250)
                    except Exception:
                        try:
                            page.goto(from_url or base_url, wait_until="domcontentloaded", timeout=timeout_ms)
                            page.wait_for_timeout(250)
                        except Exception:
                            page.goto(base_url, wait_until="domcontentloaded", timeout=timeout_ms)
                            page.wait_for_timeout(250)

                except Exception:
                    continue

            browser.close()

    except Exception as exc:
        result["errors"].append(f"Error explorando navegación: {type(exc).__name__}: {exc}")

    result["executed"] = True
    return result
