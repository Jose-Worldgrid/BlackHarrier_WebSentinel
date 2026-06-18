# Modulo de escaneo y analisis para orchestrator.

"""
Adaptive Learning Orchestrator
Coordinates execution, analysis, learning, and payload generation into a cohesive learning loop.
"""

import os
import json
import logging
from typing import Dict, List, Any, Callable, Optional
from datetime import datetime
from urllib.parse import urlparse

from scanner.ai_agent.executor import AdaptiveExecutor, ExecutionLog
from scanner.ai_agent.analyzer import FailureAnalyzer
from scanner.ai_agent.generator import DynamicPayloadGenerator
from scanner.ai_agent.scoring import KnowledgeBase, ScoringEngine
from scanner.ai_agent.providers import call_llm_json

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
        attack_type: str,
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


            best_variant_this_round = None
            best_score = 0

            for variant in variants[:5]:
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


                    if variant_score > best_score:
                        best_score = variant_score
                        best_variant_this_round = attempt_info


                    if execution_record["status"] == "success":
                        self.knowledge_base.record_attack_effectiveness(
                            attack_name=attack_type,
                            framework=framework or "unknown",
                            payload=variant["payload"][:100],
                            result="success",
                            time_ms=execution_record.get("elapsed_ms", 0),
                            reason="Successful execution",
                        )


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


            if execution_records:
                failure_analysis = self.analyzer.analyze_failure(
                    execution_record=execution_records[-1],
                    previous_attempts=execution_records,
                )
                iteration_result["analysis"] = failure_analysis


                if failure_analysis.get("inferred_defenses"):
                    for defense in failure_analysis["inferred_defenses"]:
                        self.knowledge_base.record_filter_pattern(
                            framework=framework or "unknown",
                            filter_type=defense,
                            detected_signature=execution_records[-1].get("response_headers", {}).get(
                                "server", "unknown"
                            ),
                        )


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

        defense_frequency = {}
        for record in execution_records:
            if record.get("detected_tech"):
                for tech in record["detected_tech"]:
                    defense_frequency[tech] = defense_frequency.get(tech, 0) + 1


        for defense, count in sorted(
            defense_frequency.items(), key=lambda x: x[1], reverse=True
        )[:3]:
            self.knowledge_base.record_filter_pattern(
                framework=framework or "unknown",
                filter_type=attack_type,
                detected_signature=defense,
            )


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

        frameworks = audit_results.get("detected_frameworks", [])
        waf_types = audit_results.get("detected_waf", [])


        self.knowledge_base.update_environment_profile(
            target_url=target_url, frameworks=frameworks, waf_types=waf_types
        )


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

    @staticmethod
    def _safe_lower(value: Any) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _extract_host(url: str) -> str:
        try:
            return str(urlparse(str(url or "")).hostname or "").lower()
        except Exception:
            return ""

    def _extract_framework_and_waf_signals(
        self,
        pages: List[Dict[str, Any]],
        phase1_results: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:
        frameworks = set()
        waf_types = set()

        for page in pages or []:
            ai_context = page.get("ai_context") or {}
            framework = self._safe_lower(
                ai_context.get("framework")
                or ai_context.get("detected_framework")
                or page.get("framework")
            )
            if framework and framework not in {"unknown", "none"}:
                frameworks.add(framework)

        for row in phase1_results or []:
            blob = " ".join(
                [
                    str(row.get("Módulo") or row.get("module") or ""),
                    str(row.get("Descripción") or row.get("description") or ""),
                    str(row.get("Evidencia") or row.get("evidence") or ""),
                ]
            ).lower()
            for token in ["react", "next.js", "nextjs", "angular", "vue", "django", "flask", "laravel"]:
                if token in blob:
                    frameworks.add(token.replace("next.js", "nextjs"))
            for waf in ["cloudflare", "akamai", "modsecurity", "imperva", "f5", "aws waf"]:
                if waf in blob:
                    waf_types.add(waf)

        return {
            "frameworks": sorted(frameworks),
            "waf_types": sorted(waf_types),
        }

    def _collect_attack_surface(
        self,
        target_url: str,
        pages: List[Dict[str, Any]],
        discovery: Dict[str, Any],
        phase_state: Dict[str, Any],
    ) -> Dict[str, Any]:
        target_host = self._extract_host(target_url)
        candidate_endpoints = []
        seen = set()

        def _push(url_value: str, source: str):
            text = str(url_value or "").strip()
            if not text.startswith(("http://", "https://", "/")):
                return
            if text.startswith("/"):
                base = str(target_url or "").rstrip("/")
                text = f"{base}{text}"
            host = self._extract_host(text)
            if target_host and host and host != target_host:
                return
            key = text.rstrip("/").lower()
            if key in seen:
                return
            seen.add(key)
            candidate_endpoints.append({"url": text, "source": source})

        for page in pages or []:
            page_url = str(page.get("final_url") or page.get("url") or "")
            if page_url:
                _push(page_url, "page")

            ai_context = page.get("ai_context") or {}
            for endpoint in ai_context.get("candidate_endpoints") or []:
                _push(endpoint, "ai_context")

            runtime = page.get("browser_runtime") or {}
            for endpoint in runtime.get("candidate_endpoints") or []:
                _push(endpoint, "browser_runtime")

            for form in page.get("forms") or []:
                _push(form.get("action") or "", "form_action")

        for entry in (discovery or {}).get("discovered") or []:
            if isinstance(entry, dict):
                _push(
                    entry.get("final_url")
                    or entry.get("requested_url")
                    or entry.get("url")
                    or "",
                    "discovery",
                )
            else:
                _push(entry, "discovery")

        for event in phase_state.get("post_login_http_events") or []:
            _push(event.get("final_url") or event.get("url") or "", "auth_event")

        return {
            "target_host": target_host,
            "candidate_endpoints": candidate_endpoints[:250],
            "has_auth_session": bool(phase_state.get("auth_cookies") or {}),
            "auth_status": str(phase_state.get("auth_status") or "No configurado"),
            "database_assets": phase_state.get("database_assets") or [],
            "nmap_hosts": (phase_state.get("nmap_structured") or {}).get("hosts") or [],
            "nessus_vulns": (phase_state.get("nessus_structured") or {}).get("vulnerabilities") or [],
            "external_pipeline": phase_state.get("external_pipeline") or {},
            "all_cves_found": phase_state.get("all_cves_found") or [],
        }

    def _identify_false_positive_candidates(
        self,
        phase1_results: List[Dict[str, Any]],
        strict_fp_mode: bool,
    ) -> List[Dict[str, Any]]:
        markers_weak = [
            "no evidenciado",
            "sin evidencia",
            "placeholder",
            "unknown",
            "posible",
            "heur",
            "estimad",
        ]
        markers_strong = [
            "confirm",
            "comprobado",
            "request",
            "response",
            "status",
            "endpoint",
            "selector",
            "cookie",
            "payload",
        ]

        suspects = []
        for row in phase1_results or []:
            status = self._safe_lower(row.get("Resultado") or row.get("status"))
            if status not in {"posible hallazgo", "hallazgo", "comprobado"}:
                continue

            module_name = str(row.get("Módulo") or row.get("module") or "desconocido")
            desc = str(row.get("Descripción") or row.get("description") or "")
            ev = str(row.get("Evidencia") or row.get("evidence") or "")
            blob = f"{desc} {ev}".lower()

            weak_hits = sum(1 for marker in markers_weak if marker in blob)
            strong_hits = sum(1 for marker in markers_strong if marker in blob)
            confidence = max(0.0, min(0.99, 0.45 + (strong_hits * 0.1) - (weak_hits * 0.12)))

            if strict_fp_mode and status == "posible hallazgo" and confidence < 0.55:
                suspects.append(
                    {
                        "module": module_name,
                        "status": status,
                        "reason": "Posible hallazgo con baja evidencia técnica verificable.",
                        "confidence": round(confidence, 3),
                    }
                )

        return suspects[:40]

    def _base_payload_for_attack(self, attack_type: str) -> str:
        templates = {
            "xss": "<img src=x onerror=alert(1)>",
            "sqli": "' OR '1'='1'--",
            "auth_sqli": "' OR '1'='1'--",
            "ssti": "{{7*7}}",
            "ssrf": "http://127.0.0.1:80",
            "path_traversal": "../../../../etc/passwd",
            "open_redirect": "https://example.org",
            "idor": "id=1",
            "jwt": "alg=none",
        }
        return templates.get(attack_type, "test-payload")

    def _default_vector_catalog(self) -> List[Dict[str, str]]:
        return [
            {"attack_type": "xss", "module": "XSS reflejado"},
            {"attack_type": "sqli", "module": "SQL Injection"},
            {"attack_type": "auth_sqli", "module": "SQL Injection Auth (Browser)"},
            {"attack_type": "ssti", "module": "SSTI"},
            {"attack_type": "ssrf", "module": "SSRF"},
            {"attack_type": "path_traversal", "module": "Path Traversal"},
            {"attack_type": "open_redirect", "module": "Open Redirect"},
            {"attack_type": "idor", "module": "Control de acceso"},
            {"attack_type": "jwt", "module": "JWT"},
        ]

    def build_phase2_attack_strategy(
        self,
        target_url: str,
        pages: List[Dict[str, Any]],
        discovery: Dict[str, Any],
        phase1_results: List[Dict[str, Any]],
        phase_state: Optional[Dict[str, Any]] = None,
        strict_fp_mode: bool = True,
        max_vectors: int = 30,
        llm_provider: str = "azure_openai",
    ) -> Dict[str, Any]:
        """
        Build an evidence-based attack strategy from full phase-1 context.
        The plan keeps audit-local evidence as source of truth and uses historical
        knowledge only as a soft prioritization hint.
        """
        phase_state = phase_state or {}
        phase1_results = phase1_results or []
        pages = pages or []
        discovery = discovery or {}

        signals = self._extract_framework_and_waf_signals(pages, phase1_results)
        attack_surface = self._collect_attack_surface(target_url, pages, discovery, phase_state)
        fp_candidates = self._identify_false_positive_candidates(phase1_results, strict_fp_mode)

        audit_host = self._extract_host(target_url)
        environment_profile = self.knowledge_base.get_environment_profile(target_url)
        global_attack_stats = self.knowledge_base.knowledge.get("attack_effectiveness") or {}

        vectors = []
        module_scores = {}
        endpoints = attack_surface.get("candidate_endpoints") or []

        preferred_framework = (signals.get("frameworks") or ["unknown"])[0]
        waf_types = signals.get("waf_types") or []

        fp_modules = {
            str(item.get("module") or "").strip(): float(item.get("confidence", 0.0) or 0.0)
            for item in fp_candidates
        }

        for vector_spec in self._default_vector_catalog():
            attack_type = vector_spec["attack_type"]
            module_name = vector_spec["module"]
            base_payload = self._base_payload_for_attack(attack_type)
            payload_variants = self.generator.generate_variants(
                attack_type="sqli" if attack_type == "auth_sqli" else attack_type,
                base_payload=base_payload,
                framework=preferred_framework,
                detected_filters=waf_types,
                previous_failures=[],
            )[:6]

            base_score = self.scoring_engine.score_payload(
                attack_type=attack_type,
                payload=base_payload,
                framework=preferred_framework,
                waf_types=waf_types,
            )

            local_evidence_boost = 0.0
            if any(module_name.lower() in str(item.get("Módulo") or "").lower() for item in phase1_results):
                local_evidence_boost += 0.18
            if attack_surface.get("has_auth_session") and attack_type in {"auth_sqli", "idor", "jwt"}:
                local_evidence_boost += 0.25
            if attack_surface.get("database_assets") and attack_type in {"sqli", "auth_sqli"}:
                local_evidence_boost += 0.22
            if attack_type in {"ssrf", "path_traversal"} and attack_surface.get("nmap_hosts"):
                local_evidence_boost += 0.14

            fp_penalty = 0.0
            if module_name in fp_modules:
                fp_penalty = (1.0 - fp_modules[module_name]) * 0.35

            historical_hint = 0.0
            framework_stats = global_attack_stats.get(preferred_framework) or {}
            if attack_type in framework_stats:
                attempts = int((framework_stats.get(attack_type) or {}).get("attempts", 0) or 0)
                successes = int((framework_stats.get(attack_type) or {}).get("successes", 0) or 0)
                if attempts > 0:
                    historical_hint = min(0.18, (successes / attempts) * 0.2)

            final_score = max(0.0, min(0.99, base_score + local_evidence_boost + historical_hint - fp_penalty))
            module_scores[module_name] = round(final_score, 3)

            evidence_endpoints = [entry.get("url") for entry in endpoints[:8]]
            vectors.append(
                {
                    "attack_type": attack_type,
                    "module": module_name,
                    "target_host": audit_host,
                    "priority_score": round(final_score, 3),
                    "justification": (
                        "Priorizado por evidencia local de fase 1 (fuente principal), "
                        "señales de framework/WAF y control de falsos positivos."
                    ),
                    "evidence_endpoints": evidence_endpoints,
                    "candidate_payloads": [
                        {
                            "variant": variant.get("variant"),
                            "payload": str(variant.get("payload") or "")[:180],
                            "reason": variant.get("reason"),
                        }
                        for variant in payload_variants
                    ],
                }
            )

        vectors.sort(key=lambda item: item.get("priority_score", 0.0), reverse=True)
        vectors = vectors[: max(5, int(max_vectors or 30))]

        ranked_modules = [
            {"module": module, "score": score}
            for module, score in sorted(module_scores.items(), key=lambda item: item[1], reverse=True)
        ]

        strategy = {
            "target_url": target_url,
            "target_host": audit_host,
            "generated_at": datetime.now().isoformat(),
            "audit_scope_policy": {
                "local_audit_evidence_is_primary": True,
                "cross_audit_learning_used_as_hint_only": True,
                "cross_audit_warning": (
                    "Cada auditoría es independiente: una técnica efectiva en un objetivo "
                    "anterior no se asume efectiva en el objetivo actual sin evidencia local."
                ),
            },
            "signals": signals,
            "attack_surface_summary": {
                "candidate_endpoints": len(attack_surface.get("candidate_endpoints") or []),
                "has_auth_session": bool(attack_surface.get("has_auth_session")),
                "database_assets": len(attack_surface.get("database_assets") or []),
                "nmap_hosts": len(attack_surface.get("nmap_hosts") or []),
                "nessus_vulns": len(attack_surface.get("nessus_vulns") or []),
                "cves": len(attack_surface.get("all_cves_found") or []),
            },
            "ranked_modules": ranked_modules,
            "attack_vectors": vectors,
            "false_positive_candidates": fp_candidates,
            "reasoning": {
                "summary": (
                    "La estrategia de ataque se construye desde todo el escaneo inicial "
                    "(surface mapping, resultados técnicos, Nmap/Nessus/CVE y contexto de autenticación), "
                    "filtrando señales débiles para minimizar falsos positivos."
                ),
                "historical_profile_known": bool(environment_profile.get("frameworks") or {}),
            },
        }

        try:
            llm_prompt = {
                "task": "refine_attack_strategy",
                "target_url": target_url,
                "signals": strategy["signals"],
                "attack_surface_summary": strategy["attack_surface_summary"],
                "ranked_modules": strategy["ranked_modules"][:8],
                "attack_vectors_preview": strategy["attack_vectors"][:5],
                "constraints": {
                    "authorized_only": True,
                    "non_destructive_default": True,
                    "no_invented_findings": True,
                    "return_json_only": True,
                },
            }
            llm_data = call_llm_json(
                prompt=json.dumps(llm_prompt, ensure_ascii=False),
                provider=llm_provider,
            )
            if isinstance(llm_data, dict):
                strategy["llm_refinement"] = llm_data
        except Exception:
            strategy["llm_refinement"] = None

        return strategy

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
