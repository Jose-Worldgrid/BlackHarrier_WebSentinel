"""
Semantic Knowledge Base and Scoring System
Persistent memory of attack effectiveness by environment, framework, and technique.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Tuple
from collections import defaultdict


class KnowledgeBase:
    """Semantic knowledge base for attack patterns and effectiveness."""

    def __init__(self, storage_path: str = "storage/agent_knowledge.json"):
        self.storage_path = storage_path
        self.knowledge = self._load_knowledge()

    def _load_knowledge(self) -> Dict[str, Any]:
        """Load persisted knowledge or initialize."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass

        return {
            "frameworks": {},
            "attack_effectiveness": defaultdict(dict),
            "filter_patterns": {},
            "bypass_techniques": {},
            "environment_profiles": {},
            "technology_stack_vectors": {},
        }

    def _persist_knowledge(self):
        """Save knowledge base to disk."""
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            with open(self.storage_path, "w", encoding="utf-8") as f:
                # Convert defaultdict to regular dict for JSON serialization
                serializable = {}
                for key, value in self.knowledge.items():
                    if isinstance(value, defaultdict):
                        serializable[key] = dict(value)
                    else:
                        serializable[key] = value
                json.dump(serializable, f, ensure_ascii=False, indent=2)
        except Exception as e:
            import logging

            logging.warning(f"Failed to persist knowledge: {e}")

    def register_framework(
        self, framework: str, version: str, detected_from: str
    ):
        """Record detected framework and version."""
        if framework not in self.knowledge["frameworks"]:
            self.knowledge["frameworks"][framework] = {
                "versions": {},
                "first_seen": datetime.now().isoformat(),
                "occurrences": 0,
            }

        if version not in self.knowledge["frameworks"][framework]["versions"]:
            self.knowledge["frameworks"][framework]["versions"][version] = {
                "first_seen": datetime.now().isoformat(),
                "occurrences": 0,
                "sources": [],
            }

        self.knowledge["frameworks"][framework]["versions"][version]["occurrences"] += 1
        self.knowledge["frameworks"][framework]["versions"][version]["sources"].append(detected_from)
        self.knowledge["frameworks"][framework]["occurrences"] += 1

        self._persist_knowledge()

    def record_attack_effectiveness(
        self,
        attack_name: str,
        framework: str,
        payload: str,
        result: str,  # success, partial, failure, blocked
        time_ms: float,
        reason: str = "",
    ):
        """Record effectiveness of attack against specific framework."""
        if framework not in self.knowledge["attack_effectiveness"]:
            self.knowledge["attack_effectiveness"][framework] = {}

        if attack_name not in self.knowledge["attack_effectiveness"][framework]:
            self.knowledge["attack_effectiveness"][framework][attack_name] = {
                "attempts": 0,
                "successes": 0,
                "partials": 0,
                "failures": 0,
                "blocked": 0,
                "avg_time_ms": 0,
                "last_used": None,
                "payloads_used": [],
            }

        stats = self.knowledge["attack_effectiveness"][framework][attack_name]
        stats["attempts"] += 1
        stats["last_used"] = datetime.now().isoformat()

        if result == "success":
            stats["successes"] += 1
        elif result == "partial":
            stats["partials"] += 1
        elif result == "blocked":
            stats["blocked"] += 1
        else:
            stats["failures"] += 1

        # Update average time
        stats["avg_time_ms"] = (stats["avg_time_ms"] * (stats["attempts"] - 1) + time_ms) / stats["attempts"]

        # Record payload
        stats["payloads_used"].append(
            {
                "payload": payload[:100],  # First 100 chars
                "result": result,
                "reason": reason,
                "timestamp": datetime.now().isoformat(),
            }
        )

        self._persist_knowledge()

    def record_filter_pattern(
        self, framework: str, filter_type: str, detected_signature: str
    ):
        """Record detected filter/WAF patterns."""
        key = f"{framework}_{filter_type}"
        if key not in self.knowledge["filter_patterns"]:
            self.knowledge["filter_patterns"][key] = {
                "occurrences": 0,
                "signatures": [],
                "first_seen": datetime.now().isoformat(),
            }

        self.knowledge["filter_patterns"][key]["occurrences"] += 1
        if detected_signature not in self.knowledge["filter_patterns"][key]["signatures"]:
            self.knowledge["filter_patterns"][key]["signatures"].append(detected_signature)

        self._persist_knowledge()

    def record_bypass_success(
        self,
        attack_type: str,
        filter_bypassed: str,
        technique_used: str,
        payload_sample: str,
    ):
        """Record successful bypass technique."""
        key = f"{attack_type}_{filter_bypassed}"
        if key not in self.knowledge["bypass_techniques"]:
            self.knowledge["bypass_techniques"][key] = {
                "techniques": {},
                "success_count": 0,
                "last_used": None,
            }

        if technique_used not in self.knowledge["bypass_techniques"][key]["techniques"]:
            self.knowledge["bypass_techniques"][key]["techniques"][technique_used] = {
                "uses": 0,
                "successes": 0,
                "payloads": [],
            }

        tech_stats = self.knowledge["bypass_techniques"][key]["techniques"][technique_used]
        tech_stats["uses"] += 1
        tech_stats["successes"] += 1
        tech_stats["payloads"].append(payload_sample[:100])

        self.knowledge["bypass_techniques"][key]["success_count"] += 1
        self.knowledge["bypass_techniques"][key]["last_used"] = datetime.now().isoformat()

        self._persist_knowledge()

    def get_best_attacks_for_framework(
        self, framework: str, limit: int = 10
    ) -> List[Tuple[str, float]]:
        """Rank attacks by effectiveness for a framework."""
        if framework not in self.knowledge["attack_effectiveness"]:
            return []

        attacks = self.knowledge["attack_effectiveness"][framework]

        # Calculate effectiveness score
        scored_attacks = []
        for attack_name, stats in attacks.items():
            if stats["attempts"] > 0:
                success_rate = stats["successes"] / stats["attempts"]
                partial_weight = stats["partials"] * 0.3 / stats["attempts"]
                score = success_rate + partial_weight
                scored_attacks.append((attack_name, score))

        scored_attacks.sort(key=lambda x: x[1], reverse=True)
        return scored_attacks[:limit]

    def get_bypass_techniques_for_filter(
        self, filter_type: str, limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Get most effective bypass techniques for a filter type."""
        techniques = []

        for key, bypass_info in self.knowledge["bypass_techniques"].items():
            if filter_type.lower() in key.lower():
                for tech_name, tech_stats in bypass_info["techniques"].items():
                    techniques.append(
                        {
                            "technique": tech_name,
                            "success_rate": tech_stats["successes"] / max(tech_stats["uses"], 1),
                            "uses": tech_stats["uses"],
                            "payloads": tech_stats["payloads"][:3],
                        }
                    )

        techniques.sort(key=lambda x: x["success_rate"], reverse=True)
        return techniques[:limit]

    def get_environment_profile(self, target_url: str) -> Dict[str, Any]:
        """Build profile of target environment from historical data."""
        if target_url not in self.knowledge["environment_profiles"]:
            self.knowledge["environment_profiles"][target_url] = {
                "frameworks": {},
                "filters": [],
                "waf_types": [],
                "attack_results": {},
                "last_scanned": None,
            }

        return self.knowledge["environment_profiles"][target_url]

    def update_environment_profile(
        self, target_url: str, frameworks: List[str], waf_types: List[str]
    ):
        """Update environment profile with discovered information."""
        if target_url not in self.knowledge["environment_profiles"]:
            self.knowledge["environment_profiles"][target_url] = {
                "frameworks": {},
                "filters": [],
                "waf_types": [],
                "attack_results": {},
                "last_scanned": datetime.now().isoformat(),
            }

        profile = self.knowledge["environment_profiles"][target_url]

        for fw in frameworks:
            if fw not in profile["frameworks"]:
                profile["frameworks"][fw] = {"occurrences": 0}
            profile["frameworks"][fw]["occurrences"] += 1

        profile["waf_types"] = list(set(profile["waf_types"] + waf_types))
        profile["last_scanned"] = datetime.now().isoformat()

        self._persist_knowledge()


class ScoringEngine:
    """Scores payloads and techniques for prioritization."""

    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base

    def score_payload(
        self,
        attack_type: str,
        payload: str,
        framework: str,
        waf_types: List[str],
    ) -> float:
        """
        Score a payload's likelihood of success (0.0 - 1.0).
        Based on historical effectiveness and known defenses.
        """
        score = 0.5  # Base score

        # Bonus for framework-specific payloads
        best_attacks = self.kb.get_best_attacks_for_framework(framework, limit=20)
        for attack_name, effectiveness in best_attacks:
            if attack_name.lower() in attack_type.lower():
                score += effectiveness * 0.3

        # Penalty for known WAF types
        for waf in waf_types:
            bypass_techniques = self.kb.get_bypass_techniques_for_filter(waf, limit=10)
            if bypass_techniques:
                best_bypass_rate = max(t["success_rate"] for t in bypass_techniques)
                score = score * (1 - best_bypass_rate * 0.2)

        return min(1.0, max(0.0, score))

    def rank_attacks_for_target(
        self, target_url: str, attack_types: List[str]
    ) -> List[Tuple[str, float]]:
        """Rank attack types for a target based on environment profile."""
        profile = self.kb.get_environment_profile(target_url)
        primary_framework = max(
            profile["frameworks"].items(), key=lambda x: x[1]["occurrences"], default=(None, {})
        )[0]

        ranked = []
        for attack in attack_types:
            if primary_framework:
                best_attacks = self.kb.get_best_attacks_for_framework(
                    primary_framework, limit=50
                )
                for att_name, score in best_attacks:
                    if attack.lower() in att_name.lower():
                        ranked.append((attack, score))
                        break
                else:
                    ranked.append((attack, 0.5))
            else:
                ranked.append((attack, 0.5))

        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked
