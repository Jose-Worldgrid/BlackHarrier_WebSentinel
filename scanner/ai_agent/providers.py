# Modulo de escaneo y analisis para providers.

import json
import logging
import os


logger = logging.getLogger(__name__)


def _clean_json_block(text):
    raw = str(text or "").strip()
    if not raw:
        return ""

    if raw.startswith("```"):
        lines = raw.splitlines()
        if len(lines) >= 3:
            body = lines[1:]
            if body and body[-1].strip().startswith("```"):
                body = body[:-1]
            if body and body[0].strip().lower() == "json":
                body = body[1:]
            raw = "\n".join(body).strip()

    return raw


def parse_json_response(text):
    raw = _clean_json_block(text)
    if not raw:
        return None

    try:
        return json.loads(raw)
    except Exception:
        pass

    start = raw.find("{")
    end = raw.rfind("}")
    if start >= 0 and end > start:
        candidate = raw[start:end + 1]
        try:
            return json.loads(candidate)
        except Exception:
            return None
    return None


def has_openai_api_key():
    return bool(os.getenv("OPENAI_API_KEY"))


def has_anthropic_api_key():
    return bool(os.getenv("ANTHROPIC_API_KEY"))


def has_azure_openai_config():
    endpoint = str(os.getenv("AZURE_OPENAI_ENDPOINT", "") or "").strip()
    api_key = str(os.getenv("AZURE_OPENAI_API_KEY", "") or "").strip()
    deployment = str(os.getenv("AZURE_OPENAI_MINI_DEPLOYMENT", "gpt-4o-mini") or "").strip()
    return bool(endpoint and api_key and deployment)


def _call_azure_openai_json(prompt):
    try:
        from openai import AzureOpenAI
    except Exception as exc:
        logger.warning("AzureOpenAI SDK no disponible: %s", exc)
        return None

    endpoint = str(os.getenv("AZURE_OPENAI_ENDPOINT", "") or "").strip()
    api_key = str(os.getenv("AZURE_OPENAI_API_KEY", "") or "").strip()
    deployment = str(os.getenv("AZURE_OPENAI_MINI_DEPLOYMENT", "gpt-4o-mini") or "").strip()
    api_version = str(
        os.getenv("AZURE_OPENAI_MINI_API_VERSION", "")
        or os.getenv("AZURE_OPENAI_API_VERSION", "")
        or "2025-01-01-preview"
    ).strip()

    if not endpoint or not api_key or not deployment:
        return None

    try:
        client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=api_key,
            api_version=api_version,
        )

        response = client.chat.completions.create(
            model=deployment,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Eres un analista de seguridad ofensiva. "
                        "Debes responder solo JSON válido y sin texto adicional."
                    ),
                },
                {"role": "user", "content": str(prompt or "")},
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
        )

        content = ""
        if response and getattr(response, "choices", None):
            msg = response.choices[0].message
            content = str(getattr(msg, "content", "") or "").strip()
        return parse_json_response(content)
    except Exception as exc:
        logger.warning("Fallo llamada Azure OpenAI: %s", exc)
        return None


def call_llm_json(prompt, provider="azure_openai"):
    """Calls configured LLM provider and returns parsed JSON dict or None."""
    requested = str(provider or "azure_openai").strip().lower()

    if requested in {"azure", "azure_openai"}:
        return _call_azure_openai_json(prompt)

    if requested in {"auto", "none"}:
        if has_azure_openai_config():
            return _call_azure_openai_json(prompt)
        return None

    return None
