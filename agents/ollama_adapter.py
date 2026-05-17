"""
Ollama adapter — translates Anthropic-style (system, messages, tools)
into a POST to Ollama's /api/chat, and translates the response back.

Tool use: Ollama's tool support varies by model. We append a JSON-schema
constraint to the system prompt and parse a single ``{"tool_calls": [...]}``
block out of the response. One retry on parse failure.

URL configured via ``config["llm.ollama_url"]`` (default
``http://localhost:11434``). Timeouts default to 120s.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


_DEFAULT_URL = "http://localhost:11434"
_TIMEOUT = 120


def call(
    model_id: str,
    system: str,
    messages: List[Dict],
    tools: Optional[List[Dict]] = None,
    max_tokens: int = 4096,
) -> Dict[str, Any]:
    url = _resolve_url() + "/api/chat"
    ollama_messages = _to_ollama_messages(system, messages, tools)

    payload = {
        "model": model_id,
        "messages": ollama_messages,
        "stream": False,
        "options": {"num_predict": max_tokens},
    }

    # First attempt
    data = _post(url, payload)
    content = data.get("message", {}).get("content", "")
    tool_calls = _extract_tool_calls(content) if tools else []

    # Retry once if tools were requested but parse yielded nothing.
    if tools and not tool_calls and content:
        retry_msgs = list(ollama_messages) + [
            {"role": "assistant", "content": content},
            {"role": "user",
             "content": 'Your previous response did not include a parseable '
                        'tool call. Reply with ONLY one JSON object: '
                        '{"tool_calls": [{"name": "<tool>", "input": {...}}]}.'},
        ]
        payload["messages"] = retry_msgs
        data = _post(url, payload)
        content = data.get("message", {}).get("content", "")
        tool_calls = _extract_tool_calls(content)

    return {
        "content": content,
        "tool_calls": tool_calls,
        "prompt_tokens": int(data.get("prompt_eval_count", 0) or 0),
        "completion_tokens": int(data.get("eval_count", 0) or 0),
    }


# ── helpers ────────────────────────────────────────────────────────
def _resolve_url() -> str:
    try:
        import main as M
        return M.get_config("llm.ollama_url", _DEFAULT_URL).rstrip("/")
    except Exception:
        return _DEFAULT_URL


def _to_ollama_messages(
    system: str,
    messages: List[Dict],
    tools: Optional[List[Dict]],
) -> List[Dict]:
    out: List[Dict] = []
    sys_content = system or ""
    if tools:
        sys_content = (sys_content + "\n\n" + _tools_to_constraint_prompt(tools)).strip()
    if sys_content:
        out.append({"role": "system", "content": sys_content})
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if isinstance(content, list):
            # Anthropic block format → flatten text blocks; drop everything else
            content = "".join(
                b.get("text", "") for b in content
                if isinstance(b, dict) and b.get("type") == "text"
            )
        out.append({"role": role, "content": content})
    return out


def _tools_to_constraint_prompt(tools: List[Dict]) -> str:
    lines = [
        "Tool use protocol:",
        "When you need to invoke a tool, respond with ONLY one JSON object "
        'in this exact shape, and nothing else:',
        '  {"tool_calls": [{"name": "<tool_name>", "input": {...}}]}',
        "Available tools:",
    ]
    for t in tools:
        nm = t.get("name", "?")
        desc = t.get("description", "")
        lines.append(f"  - {nm}: {desc}")
    return "\n".join(lines)


def _extract_tool_calls(content: str) -> List[Dict]:
    if not content or "{" not in content:
        return []
    # Greedy outer-brace match
    start = content.find("{")
    end = content.rfind("}")
    if end <= start:
        return []
    try:
        obj = json.loads(content[start:end + 1])
    except (json.JSONDecodeError, ValueError):
        return []
    calls = obj.get("tool_calls") if isinstance(obj, dict) else None
    return calls if isinstance(calls, list) else []


def _post(url: str, payload: Dict) -> Dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        raise RuntimeError(f"Ollama HTTP error: {e}")
