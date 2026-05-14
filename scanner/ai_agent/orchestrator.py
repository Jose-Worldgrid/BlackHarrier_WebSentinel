"""
Adaptive Learning Orchestrator
Coordinates execution, analysis, learning, and payload generation into a cohesive learning loop.
"""

import os
import json
import logging
from typing import Dict, List, Any, Callable, Optional
from datetime import datetime

from scanner.ai_agent.executor import AdaptiveExecutor, ExecutionLog
from scanner.ai_agent.analyzer import FailureAnalyzer
from scanner.ai_agent.generator import DynamicPayloadGenerator
from scanner.ai_agent.scoring import KnowledgeBase, ScoringEngine

logger = logging.getLogger(__name__)


class AdaptiveOrchestrator:
    """
    Orchestrates the complete adaptive learning cycle:
    1. Execute attack with logging
    2. Analyze failure reasons
    3. Generate intelligent variants
    4. Score variants for next iteration
    5. Persist learnings to knowledge base
    """

    def __init__(
        self,
        storage_path: str = "storage",
        knowledge_path: str = "storage/agent_knowledge.json",
    ):
        self.storage_path = storage_path
        self.executor = AdaptiveExecutor(storage_path=storage_path)
        self.analyzer = FailureAnalyzer()
        self.generator = DynamicPayloadGenerator()
        self.knowledge_base = KnowledgeBase(storage_path=knowledge_path)
        self.scoring_engine = ScoringEngine(self.knowledge_base)
        self.learning_history = []

    def adaptive_attack_cycle(
        self,
        target_url: str,
        attack_type: str,  # xss, sqli, ssti, etc.
        base_payload: str,
        executor_fn: Callable,
        max_iterations: int = 3,
        framework: Optional[str] = None,
        waf_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute adaptive attack cycle: test → analyze → learn → generate → repeat.
        Returns comprehensive results including all attempts and learnings.
        """
        waf_types = waf_types or []
        results = {
            "target_url": target_url,
            "attack_type": attack_type,
            "iterations": [],
            "best_result": None,
            "learned_patterns": [],
            "total_time_ms": 0,
        }

        execution_records = []
        previous_failures = []

        for iteration in range(max_iterations):
            iteration_result = {
                "iteration": iteration + 1,
                "attempts": [],
                "analysis": None,
                "generated_variants": [],
                "best_variant": None,
            }

            # Step 1: Generate payload variants
            variants = self.generator.generate_variants(
                attack_type=attack_type,
                base_payload=base_payload,
                framework=framework,
                detected_filters=waf_types,
                previous_failures=previous_failures,
            )
            iteration_result["generated_variants"] = [
                {
                    "payload": v["payload"][:100],
                    "variant": v["variant"],
                    "reason": v["reason"],
                }
                for v in variants
            ]

            # Step 2: Execute each variant and score results
            best_variant_this_round = None
            best_score = 0

            for variant in variants[:5]:  # Limit to top 5 per iteration
                try:
                    execution_record = self.executor.execute_attack(
                        attack_name=f"{attack_type}_{variant['variant']}",
                        target_url=target_url,
                        payload=variant["payload"],
                        executor_fn=executor_fn,
                        metadata={
                            "iteration": iteration + 1,
                            "framework": framework,
                            "waf_types": waf_types,
                            "base_variant": variant["variant"],
                        },
                    )

                    execution_records.append(execution_record)

                    # Score the variant
                    variant_score = self.scoring_engine.score_payload(
                        attack_type=attack_type,
                        payload=variant["payload"],
                        framework=framework or "unknown",
                        waf_types=waf_types,
                    )

                    attempt_info = {
                        "variant": variant["variant"],
                        "payload_preview": variant["payload"][:80],
                        "status": execution_record.get("status"),
                        "score": variant_score,
                        "waf_detected": execution_record.get("waf_indicators", []),
                        "elapsed_ms": execution_record.get("elapsed_ms", 0),
                    }
                    iteration_result["attempts"].append(attempt_info)

                    # Track best variant
                    if variant_score > best_score:
                        best_score = variant_score
                        best_variant_this_round = attempt_info

                    # Record success for learning
                    if execution_record["status"] == "success":
                        self.knowledge_base.record_attack_effectiveness(
                            attack_name=attack_type,
                            framework=framework or "unknown",
                            payload=variant["payload"][:100],
                            result="success",
                            time_ms=execution_record.get("elapsed_ms", 0),
                            reason="Successful execution",
                        )

                        # Early exit on success
                        results["best_result"] = {
                            "iteration": iteration + 1,
                            "variant": variant["variant"],
                            "payload": variant["payload"],
                            "score": best_score,
                        }
                        results["iterations"].append(iteration_result)
                        self._learn_from_success(
                            attack_type, framework, variant, execution_record
                        )
                        return results

                except Exception as e:
                    logger.error(f"Error executing variant: {e}", exc_info=True)
                    previous_failures.append(
                        {
                            "variant": variant["variant"],
                            "error": str(e),
                            "iteration": iteration + 1,
                        }
                    )

            # Step 3: Analyze failure patterns
            if execution_records:
                failure_analysis = self.analyzer.analyze_failure(
                    execution_record=execution_records[-1],
                    previous_attempts=execution_records,
                )
                iteration_result["analysis"] = failure_analysis

                # Record in knowledge base
                if failure_analysis.get("inferred_defenses"):
                    for defense in failure_analysis["inferred_defenses"]:
                        self.knowledge_base.record_filter_pattern(
                            framework=framework or "unknown",
                            filter_type=defense,
                            detected_signature=execution_records[-1].get("response_headers", {}).get(
                                "server", "unknown"
                            ),
                        )

                # Track for next iteration
                previous_failures.extend(
                    [
                        {
                            "variant": v["variant"],
                            "result": "failure",
                            "iteration": iteration + 1,
                        }
                        for v in variants[:3]
                    ]
                )

            iteration_result["best_variant"] = best_variant_this_round
            results["iterations"].append(iteration_result)

        # Step 4: Final learning from all attempts
        if execution_records:
            self._consolidate_learnings(
                attack_type, framework, execution_records, results
            )

        return results

    def _learn_from_success(
        self,
        attack_type: str,
        framework: Optional[str],
        variant: Dict[str, str],
        execution_record: Dict[str, Any],
    ):
        """Record successful attack pattern to knowledge base."""
        self.knowledge_base.record_attack_effectiveness(
            attack_name=attack_type,
            framework=framework or "unknown",
            payload=variant["payload"][:100],
            result="success",
            time_ms=execution_record.get("elapsed_ms", 0),
            reason=f"Success with variant: {variant['variant']}",
        )

        # If this bypassed WAF, record the technique
        if execution_record.get("waf_indicators"):
            for waf in execution_record["waf_indicators"]:
                self.knowledge_base.record_bypass_success(
                    attack_type=attack_type,
                    filter_bypassed=waf,
                    technique_used=variant["variant"],
                    payload_sample=variant["payload"],
                )

    def _consolidate_learnings(
        self,
        attack_type: str,
        framework: Optional[str],
        execution_records: List[Dict[str, Any]],
        results: Dict[str, Any],
    ):
        """Extract and persist patterns learned from all execution attempts."""
        # Analyze which defenses were encountered most frequently
        defense_frequency = {}
        for record in execution_records:
            if record.get("detected_tech"):
                for tech in record["detected_tech"]:
                    defense_frequency[tech] = defense_frequency.get(tech, 0) + 1

        # Record top defenses
        for defense, count in sorted(
            defense_frequency.items(), key=lambda x: x[1], reverse=True
        )[:3]:
            self.knowledge_base.record_filter_pattern(
                framework=framework or "unknown",
                filter_type=attack_type,
                detected_signature=defense,
            )

        # Store learnings
        results["learned_patterns"] = [
            {"defense": d, "frequency": f} for d, f in list(defense_frequency.items())[:5]
        ]

    def continuous_learning_from_audit(
        self, audit_results: Dict[str, Any], target_url: str
    ):
        """
        Process full audit results to extract learnings for future attacks.
        Called after each complete security audit.
        """
        # Extract frameworks and technologies
        frameworks = audit_results.get("detected_frameworks", [])
        waf_types = audit_results.get("detected_waf", [])

        # Update environment profile
        self.knowledge_base.update_environment_profile(
            target_url=target_url, frameworks=frameworks, waf_types=waf_types
        )

        # Record all vulnerability findings with context
        findings = audit_results.get("findings", [])
        for finding in findings:
            self.knowledge_base.record_attack_effectiveness(
                attack_name=finding.get("attack_type", "unknown"),
                framework=frameworks[0] if frameworks else "unknown",
                payload=finding.get("payload", "unknown")[:100],
                result=finding.get("severity", "low"),
                time_ms=0,
                reason=finding.get("description", ""),
            )

        logger.info(
            f"Recorded learnings for {target_url}: "
            f"{len(frameworks)} frameworks, {len(waf_types)} WAF types"
        )

    def get_adaptation_summary(self) -> Dict[str, Any]:
        """Return summary of learned patterns and effectiveness."""
        return {
            "total_frameworks_seen": len(self.knowledge_base.knowledge["frameworks"]),
            "total_attacks_recorded": sum(
                len(v) for v in self.knowledge_base.knowledge["attack_effectiveness"].values()
            ),
            "bypass_techniques_learned": len(self.knowledge_base.knowledge["bypass_techniques"]),
            "target_environments_profiled": len(
                self.knowledge_base.knowledge["environment_profiles"]
            ),
            "last_updated": datetime.now().isoformat(),
        }
