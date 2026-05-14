"""
Failure Analysis and Heuristic Learning
Infers defensive mechanisms and generates mitigation strategies.
"""

from typing import Dict, List, Any, Tuple
from collections import defaultdict, Counter


class FailureAnalyzer:
    """Analyzes why attacks failed and infers defensive patterns."""

    FAILURE_PATTERNS = {
        "waf_signature_match": {
            "indicators": ["blocked", "attack detected", "malicious", "forbidden"],
            "mitigation": ["obfuscate", "encode", "split_payload", "timing_delay"],
        },
        "sanitization": {
            "indicators": ["stripped", "removed", "invalid", "escaped"],
            "mitigation": ["double_encode", "mixed_case", "bypass_filter", "context_switch"],
        },
        "validation_error": {
            "indicators": ["invalid", "bad request", "syntax error"],
            "mitigation": ["correct_syntax", "valid_format", "type_match"],
        },
        "csp_violation": {
            "indicators": ["csp", "content security policy", "refused"],
            "mitigation": ["dom_based", "event_handler", "data_uri", "nonce_bypass"],
        },
        "rate_limiting": {
            "indicators": ["429", "retry-after", "rate limit"],
            "mitigation": ["increase_delay", "reduce_concurrency", "vary_source"],
        },
        "authentication_required": {
            "indicators": ["401", "403", "unauthorized", "login"],
            "mitigation": ["use_credentials", "session_reuse", "auth_bypass"],
        },
        "input_length_limit": {
            "indicators": ["too long", "max length", "overflow"],
            "mitigation": ["shorten_payload", "multi_request", "chunk_payload"],
        },
        "encoding_mismatch": {
            "indicators": ["encoding", "charset", "codec"],
            "mitigation": ["match_encoding", "try_alternatives", "normalize"],
        },
    }

    def __init__(self):
        self.failure_cache = defaultdict(list)

    def analyze_failure(
        self, execution_record: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze why an attack failed and suggest remediation.
        Returns inference about defensive mechanisms and next-step strategies.
        """
        analysis = {
            "execution_id": execution_record.get("execution_id"),
            "attack_name": execution_record.get("attack_name"),
            "result": execution_record.get("result"),
            "inferred_defenses": [],
            "probable_bypass_strategies": [],
            "confidence": 0.0,
            "reasoning": "",
        }

        if execution_record.get("result") == "success":
            return {**analysis, "reasoning": "Attack succeeded - no remediation needed"}

        # Collect evidence
        response_body = execution_record.get("response_body_sample", "").lower()
        status = execution_record.get("http_status", 0)
        waf_indicators = execution_record.get("waf_indicators", [])
        response_headers = execution_record.get("response_headers", {})
        elapsed_ms = execution_record.get("elapsed_ms", 0)

        # Infer defensive patterns
        detected_defenses = self._infer_defenses(
            response_body, status, waf_indicators, response_headers, elapsed_ms
        )
        analysis["inferred_defenses"] = detected_defenses

        # Generate bypass strategies
        bypass_strategies = self._generate_bypass_strategies(detected_defenses)
        analysis["probable_bypass_strategies"] = bypass_strategies
        analysis["confidence"] = self._calculate_confidence(detected_defenses)
        analysis["reasoning"] = self._generate_reasoning(
            detected_defenses, bypass_strategies
        )

        self.failure_cache[execution_record.get("attack_name")].append(analysis)
        return analysis

    def _infer_defenses(
        self,
        response_body: str,
        status: int,
        waf_indicators: List[str],
        response_headers: Dict,
        elapsed_ms: float,
    ) -> List[Dict[str, Any]]:
        """Infer which defensive mechanisms are active."""
        defenses = []

        # WAF detection
        if waf_indicators:
            defenses.append(
                {
                    "type": "waf_present",
                    "indicators": waf_indicators,
                    "confidence": 0.9,
                }
            )

        # Rate limiting
        if status == 429 or "retry-after" in str(response_headers).lower():
            defenses.append(
                {
                    "type": "rate_limiting",
                    "indicators": ["429_status", "retry_after_header"],
                    "confidence": 0.95,
                }
            )

        # CSP detection
        if "content-security-policy" in str(response_headers).lower():
            defenses.append(
                {
                    "type": "csp_enforced",
                    "indicators": ["csp_header_present"],
                    "confidence": 0.95,
                }
            )

        # Input sanitization/validation
        if any(
            x in response_body
            for x in ["invalid", "syntax error", "escaped", "stripped"]
        ):
            defenses.append(
                {
                    "type": "input_validation",
                    "indicators": response_body[:200],
                    "confidence": 0.7,
                }
            )

        # Authentication/authorization
        if status in [401, 403]:
            defenses.append(
                {
                    "type": "authentication_required",
                    "indicators": [f"http_{status}"],
                    "confidence": 0.95,
                }
            )

        # Possible anti-automation
        if elapsed_ms > 2000:
            defenses.append(
                {
                    "type": "response_delay_detection",
                    "indicators": [f"elapsed_{int(elapsed_ms)}ms"],
                    "confidence": 0.6,
                }
            )

        return defenses

    def _generate_bypass_strategies(
        self, defenses: List[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Generate specific bypass techniques for detected defenses."""
        strategies = []
        defense_types = [d["type"] for d in defenses]

        if "waf_present" in defense_types:
            strategies.extend(
                [
                    {
                        "technique": "obfuscation",
                        "method": "Comment injection",
                        "example": "al/**/ert(1)",
                    },
                    {
                        "technique": "encoding",
                        "method": "HTML entity encoding",
                        "example": "&#x61;&#x6c;&#x65;&#x72;&#x74;",
                    },
                    {
                        "technique": "case_variation",
                        "method": "Mixed case bypass",
                        "example": "AlErT(1)",
                    },
                    {
                        "technique": "payload_split",
                        "method": "Split across DOM manipulation",
                        "example": "eval(atob('...'))",
                    },
                ]
            )

        if "rate_limiting" in defense_types:
            strategies.extend(
                [
                    {
                        "technique": "timing",
                        "method": "Increase delay between requests",
                        "example": "delay_between_requests: 5000ms",
                    },
                    {
                        "technique": "concurrency",
                        "method": "Reduce concurrent requests",
                        "example": "max_parallel: 1",
                    },
                    {
                        "technique": "source_variation",
                        "method": "Vary source IPs/headers",
                        "example": "rotate_proxies: true",
                    },
                ]
            )

        if "csp_enforced" in defense_types:
            strategies.extend(
                [
                    {
                        "technique": "dom_based",
                        "method": "Target DOM sinks instead of scripts",
                        "example": "element.innerHTML = userInput",
                    },
                    {
                        "technique": "event_handler",
                        "method": "Use event attributes",
                        "example": "<img src=x onerror=alert(1)>",
                    },
                    {
                        "technique": "nonce_bypass",
                        "method": "Extract nonce from page",
                        "example": "extract_nonce_from_script_tag()",
                    },
                ]
            )

        if "input_validation" in defense_types:
            strategies.extend(
                [
                    {
                        "technique": "double_encoding",
                        "method": "Double URL encode payload",
                        "example": "%252F%252Fetc%252Fpasswd",
                    },
                    {
                        "technique": "normalization_bypass",
                        "method": "Use unicode/utf8 variations",
                        "example": "\\u002e\\u002e/etc/passwd",
                    },
                    {
                        "technique": "null_byte",
                        "method": "Insert null bytes to bypass checks",
                        "example": "/etc/passwd%00.jpg",
                    },
                ]
            )

        if "authentication_required" in defense_types:
            strategies.append(
                {
                    "technique": "credential_reuse",
                    "method": "Use captured session tokens",
                    "example": "reuse_auth_token_from_memory",
                }
            )

        return strategies

    @staticmethod
    def _calculate_confidence(defenses: List[Dict[str, Any]]) -> float:
        """Calculate confidence score for inferred defenses."""
        if not defenses:
            return 0.0
        avg_confidence = sum(d.get("confidence", 0.5) for d in defenses) / len(
            defenses
        )
        return min(0.99, avg_confidence)

    @staticmethod
    def _generate_reasoning(
        defenses: List[Dict[str, Any]], strategies: List[Dict[str, str]]
    ) -> str:
        """Generate human-readable reasoning for failure."""
        if not defenses:
            return "Attack failed; no defensive mechanisms detected - payload syntax or context issue."

        defense_str = ", ".join([d["type"] for d in defenses])
        strategies_str = ", ".join([s["technique"] for s in strategies[:3]])

        return (
            f"Inferred defenses: {defense_str}. "
            f"Recommended bypass techniques: {strategies_str}."
        )

    def get_historical_patterns(
        self, attack_name: str, limit: int = 50
    ) -> Dict[str, Any]:
        """Analyze patterns from historical failures."""
        failures = self.failure_cache.get(attack_name, [])[-limit:]

        if not failures:
            return {"attack_name": attack_name, "patterns": [], "effectiveness": 0.0}

        defense_counter = Counter()
        for failure in failures:
            for defense in failure.get("inferred_defenses", []):
                defense_counter[defense.get("type")] += 1

        total_failures = len(failures)
        success_count = sum(
            1 for f in failures if f.get("result") == "success"
        )
        effectiveness = success_count / total_failures if total_failures > 0 else 0.0

        return {
            "attack_name": attack_name,
            "total_attempts": total_failures,
            "successful_attempts": success_count,
            "effectiveness": effectiveness,
            "most_common_defenses": defense_counter.most_common(5),
            "recommended_techniques": self._aggregate_strategies(failures),
        }

    @staticmethod
    def _aggregate_strategies(failures: List[Dict]) -> List[str]:
        """Aggregate most recommended strategies from failures."""
        all_strategies = []
        for failure in failures:
            all_strategies.extend(
                [s["technique"] for s in failure.get("probable_bypass_strategies", [])]
            )
        strategy_counter = Counter(all_strategies)
        return [tech for tech, _ in strategy_counter.most_common(5)]
