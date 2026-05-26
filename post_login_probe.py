import argparse
import json
from urllib.parse import urlparse

from scanner.auth import authenticate
from scanner.crawler import crawl_site
from scanner.discovery import discover_surface


def normalize_url(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}".rstrip("/")


def dedupe_pages_by_url(pages):
    unique = []
    seen = set()
    for page in pages or []:
        key = str(page.get("final_url") or page.get("url") or "").strip().rstrip("/")
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(page)
    return unique


def run_post_login_probe(target_url, login_url, username, password, verify_ssl=True):
    out = {
        "target_url": target_url,
        "login_url": login_url,
        "auth_status": "",
        "auth_evidence": "",
        "auth_final_url": "",
        "pages_pre_auth": 0,
        "pages_post_auth": 0,
        "new_urls_after_login": [],
        "protected_urls_after_login": [],
        "api_candidates_after_login": [],
    }

    auth_client, auth_results = authenticate(login_url, username, password, verify_ssl=verify_ssl)
    first_auth = (auth_results or [{}])[0]
    out["auth_status"] = str(first_auth.get("status") or "")
    out["auth_evidence"] = str(first_auth.get("evidence") or "")
    out["auth_final_url"] = str(first_auth.get("final_url") or login_url)

    pre_pages, _ = crawl_site(target_url, max_pages=None, client=auth_client)
    out["pages_pre_auth"] = len(pre_pages or [])

    if out["auth_status"] not in ["Autenticado", "Indeterminado"]:
        return out

    for page in pre_pages or []:
        page["discovery_context"] = "pre_login"

    post_pages, _ = crawl_site(target_url, max_pages=None, client=auth_client)
    for page in post_pages or []:
        page["discovery_context"] = "post_login"

    merged_seed = dedupe_pages_by_url((pre_pages or []) + (post_pages or []))
    post_discovery = discover_surface(
        target_url,
        client=auth_client,
        seed_pages=merged_seed,
        max_active_checks=800,
    )
    discovered_pages = post_discovery.get("pages") or []
    for page in discovered_pages:
        page["discovery_context"] = "post_login"

    merged = dedupe_pages_by_url(merged_seed + discovered_pages)

    pre_urls = {
        str(page.get("final_url") or page.get("url") or "").strip().rstrip("/")
        for page in pre_pages or []
    }
    post_urls = {
        str(page.get("final_url") or page.get("url") or "").strip().rstrip("/")
        for page in merged
        if str(page.get("discovery_context") or "") == "post_login"
    }

    new_after_login = sorted([url for url in post_urls if url and url not in pre_urls])

    protected_cls = {"protected", "protected_redirect_to_auth", "admin_candidate", "sensitive_candidate", "api_candidate"}
    protected_urls = []
    api_urls = []
    for page in merged:
        if str(page.get("discovery_context") or "") != "post_login":
            continue
        url = str(page.get("final_url") or page.get("url") or "").strip()
        classification = str(page.get("classification") or "").lower()
        if not url:
            continue
        if classification in protected_cls:
            protected_urls.append(url)
        if classification == "api_candidate" or "/api" in url.lower() or "/graphql" in url.lower():
            api_urls.append(url)

    out["pages_post_auth"] = len(merged)
    out["new_urls_after_login"] = new_after_login[:200]
    out["protected_urls_after_login"] = sorted(set(protected_urls))[:200]
    out["api_candidates_after_login"] = sorted(set(api_urls))[:200]
    return out


def main():
    parser = argparse.ArgumentParser(description="Focused post-login discovery probe")
    parser.add_argument("--target", required=True, help="Target base URL")
    parser.add_argument("--login", required=True, help="Login URL")
    parser.add_argument("--username", required=True, help="Valid username")
    parser.add_argument("--password", required=True, help="Valid password")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    args = parser.parse_args()

    target = normalize_url(args.target)
    login = normalize_url(args.login)

    if not target or not login:
        raise SystemExit("Target/login URL inválida")

    result = run_post_login_probe(
        target_url=target,
        login_url=login,
        username=args.username,
        password=args.password,
        verify_ssl=bool(args.verify_ssl),
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()