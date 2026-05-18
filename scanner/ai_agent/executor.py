"""
Adaptive Offensive Execution Engine
Logs exhaustively every test execution for post-analysis and learning.
"""

import json
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional


class ExecutionLog:
    """Immutable record of a single attack execution."""

    def __init__(
        self,
        attack_name: str,
        target_url: str,
        payload: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        context: Optional[Dict] = None,
    ):
        self.attack_name = attack_name
        self.target_url = target_url
        self.payload = payload
        self.method = method
        self.headers = headers or {}
        self.context = context or {}
        self.timestamp = datetime.now().isoformat()
        self.payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]

    def capture_execution(
        self,
        status_code: int,
        response_body: str,
        response_headers: Dict,
        elapsed_ms: float,
        result: str,  # "success", "partial", "failure", "blocked"
        reason: str = "",
        detected_tech: Optional[List[str]] = None,
        waf_indicators: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Record complete execution outcome."""
        return {
            "execution_id": f"{self.payload_hash}_{int(time.time() * 1000) % 10000}",
            "attack_name": self.attack_name,
            "target_url": self.target_url,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "payload_hash": self.payload_hash,
            "method": self.method,
            "request_headers": self.headers,
            "request_context": self.context,
            "http_status": status_code,
            "response_headers": response_headers,
            "response_body_sample": response_body[:2000],  # First 2KB
            "response_length": len(response_body),
            "elapsed_ms": elapsed_ms,
            "result": result,
            "failure_reason": reason,
            "detected_technologies": detected_tech or [],
            "waf_indicators": waf_indicators or [],
        }


class PayloadVariant:
    """Template for dynamic payload generation."""

    def __init__(
        self,
        base_payload: str,
        encoding: str = "none",  # none, url, html, js, base64, hex, unicode
        obfuscation: str = "none",  # none, comment, split, nested, random_case
        context: str = "attribute",  # attribute, script, html_body, js_string, etc.
    ):
        self.base_payload = base_payload
        self.encoding = encoding
        self.obfuscation = obfuscation
        self.context = context

    def render(self) -> str:
        """Generate actual payload from template."""
        payload = self.base_payload

        # Apply obfuscation
        if self.obfuscation == "comment":
            # Insert comments to bypass simple filters
            payload = payload.replace(
                "alert", "al/**/ert"
            )  # XSS example
        elif self.obfuscation == "nested":
            # Nested encoding
            payload = f"eval(atob('{self._to_base64(payload)}'))"
        elif self.obfuscation == "split":
            # Split payload across multiple elements
            parts = [payload[i : i + 3] for i in range(0, len(payload), 3)]
            payload = '"+'.join([f"'{p}'" for p in parts]) + '+"'

        # Apply encoding
        if self.encoding == "url":
            payload = "".join([f"%{ord(c):02x}" for c in payload])
        elif self.encoding == "html":
            payload = "".join([f"&#x{ord(c):x};" for c in payload])
        elif self.encoding == "base64":
            import base64

            payload = base64.b64encode(payload.encode()).decode()
        elif self.encoding == "hex":
            payload = "".join([f"\\x{ord(c):02x}" for c in payload])
        elif self.encoding == "unicode":
            payload = "".join([f"\\u{ord(c):04x}" for c in payload])

        return payload

    @staticmethod
    def _to_base64(s: str) -> str:
        import base64

        return base64.b64encode(s.encode()).decode()


class AdaptiveExecutor:
    """Manages test execution with comprehensive logging."""

    def __init__(self, storage_path: str = "storage/execution_logs.jsonl"):
        self.storage_path = storage_path
        self.executions: List[Dict[str, Any]] = []

    def execute_attack(
        self,
        attack_name: str,
        target_url: str,
        payload: str,
        executor_fn,  # Callable that runs actual attack
        method: str = "GET",
        headers: Optional[Dict] = None,
        context: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Execute attack with comprehensive logging.
        executor_fn should return: (status_code, response_body, response_headers, elapsed_ms)
        """
        log = ExecutionLog(attack_name, target_url, payload, method, headers, context)

        try:
            start = time.time()
            status, body, resp_headers, elapsed_ms = executor_fn(
                target_url, payload, method, headers
            )
            elapsed_ms = elapsed_ms or (time.time() - start) * 1000

            # Heuristic analysis
            result, reason = self._analyze_result(
                status, body, resp_headers, payload
            )
            detected_tech = self._detect_technology(body, resp_headers)
            waf_indicators = self._detect_waf_signatures(body, resp_headers, status)

            execution_record = log.capture_execution(
                status,
                body,
                resp_headers,
                elapsed_ms,
                result,
                reason,
                detected_tech,
                waf_indicators,
            )

            self.executions.append(execution_record)
            self._persist_execution(execution_record)

            return execution_record

        except Exception as exc:
            execution_record = log.capture_execution(
                0,
                "",
                {},
                0,
                "failure",
                f"Exception: {type(exc).__name__}: {str(exc)}",
            )
            self.executions.append(execution_record)
            self._persist_execution(execution_record)
            return execution_record

    def _analyze_result(
        self, status: int, body: str, headers: Dict, payload: str
    ) -> tuple:
        """Heuristic analysis of why test succeeded/failed."""
        body_lower = body.lower()

        # Success indicators
        if "alert(" in payload and ("alert(" in body or "xss" in body_lower):
            return "success", "Payload reflection or XSS execution detected"

        if status == 200 and len(body) > 100:
            # Check for error patterns
            if any(
                x in body_lower
                for x in [
                    "sql syntax",
                    "database error",
                    "mysql",
                    "unclosed quote",
                ]
            ):
                return "success", "SQL Injection error-based response"

            if any(x in body_lower for x in ["template", "jinja", "expression"]):
                return "success", "Template Injection indicators"

        # Partial success
        if status == 429:
            return "partial", "Rate limiting detected during payload execution"

        # Blocked/Failed
        if status == 403:
            return "blocked", "Access denied - WAF/Authorization block"
        if status == 400:
            return "failure", "Bad request - Payload syntax error or sanitization"
        if status in [404, 500]:
            return "failure", f"HTTP {status} - Server/resource error"

        # Check for WAF strings
        if any(
            x in body_lower
            for x in ["blocked", "forbidden", "attack", "malicious", "detected"]
        ):
            return "blocked", "Explicit WAF/IDS blocking message"

        return "failure", "No exploitation indicators found"

    @staticmethod
    def _detect_technology(body: str, headers: Dict) -> List[str]:
        """Detect technology stack from response."""
        techs = []
        body_lower = body.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        signatures = {
            "nextjs": ["__next", "_next/static", "buildid"],
            "react": ["react-dom", "reactroot", "__react"],
            "angular": ["ng-version", "angular"],
            "vue": ["v-app", "vue"],
            "django": ["django", "csrftoken", "sessionid"],
            "flask": ["werkzeug", "flask"],
            "express": ["express"],
            "laravel": ["laravel", "artisan"],
            "wordpress": ["wp-content", "wp-admin"],
            "asp.net": ["asp.net", "webforms"],
            "java": ["jsessionid", "javaservletpath"],
        }

        for tech, markers in signatures.items():
            if any(marker in body_lower or marker in str(headers_lower) for marker in markers):
                techs.append(tech)

        return techs

    @staticmethod
    def _detect_waf_signatures(body: str, headers: Dict, status: int) -> List[str]:
        """Detect WAF/CDN/security mechanisms."""
        indicators = []
        body_lower = body.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        waf_sigs = {
            "cloudflare": ["cf-ray", "cloudflare"],
            "akamai": ["akamai", "edgescape"],
            "modsecurity": ["modsecurity", "core rule set"],
            "f5_asm": ["x-cnection", "x-forwarded"],
            "imperva": ["imperva", "x-iinfo"],
            "rate_limiting": ["x-ratelimit", "retry-after"],
            "csp": ["content-security-policy"],
            "xss_protection": ["x-xss-protection"],
        }

        for waf, sigs in waf_sigs.items():
            if any(sig in body_lower or sig in str(headers_lower) for sig in sigs):
                indicators.append(waf)

        if status == 429:
            indicators.append("rate_limiting_active")

        return indicators

    def _persist_execution(self, record: Dict[str, Any]):
        """Append execution record to persistent log."""
        try:
            with open(self.storage_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as exc:
            import logging

            logging.warning(f"Failed to persist execution log: {exc}")

    def load_execution_history(
        self, attack_name: str = None, limit: int = 100
    ) -> List[Dict]:
        """Load execution history for analysis."""
        history = []
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        record = json.loads(line)
                        if attack_name is None or record.get("attack_name") == attack_name:
                            history.append(record)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass

        return history[-limit:]
