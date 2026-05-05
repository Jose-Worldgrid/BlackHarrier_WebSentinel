import json
import os


def call_llm_json(prompt, provider="none"):
    """
    Placeholder para OpenAI/Claude.
    De momento no llama a APIs externas.
    Más adelante aquí conectaremos OpenAI o Claude.
    """
    return None


def has_openai_api_key():
    return bool(os.getenv("OPENAI_API_KEY"))


def has_anthropic_api_key():
    return bool(os.getenv("ANTHROPIC_API_KEY"))


def parse_json_response(text):
    try:
        return json.loads(text)
    except Exception:
        return None