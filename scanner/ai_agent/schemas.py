from dataclasses import dataclass, field
from typing import Any


@dataclass
class AIDecision:
    page_type: str = "unknown"
    confidence: float = 0.0
    requires_browser_dom: bool = False
    requires_api_endpoint_discovery: bool = False
    should_test_auth_sqli: bool = False
    should_run_post_auth_discovery: bool = False
    reason: str = ""
    recommended_next_steps: list[str] = field(default_factory=list)
    selectors: dict[str, str] = field(default_factory=dict)
    candidate_endpoints: list[str] = field(default_factory=list)
    recommended_attacks: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "page_type": self.page_type,
            "confidence": self.confidence,
            "requires_browser_dom": self.requires_browser_dom,
            "requires_api_endpoint_discovery": self.requires_api_endpoint_discovery,
            "should_test_auth_sqli": self.should_test_auth_sqli,
            "should_run_post_auth_discovery": self.should_run_post_auth_discovery,
            "reason": self.reason,
            "recommended_next_steps": self.recommended_next_steps,
            "selectors": self.selectors,
            "candidate_endpoints": self.candidate_endpoints,
            "recommended_attacks": self.recommended_attacks,
            "metadata": self.metadata,
        }