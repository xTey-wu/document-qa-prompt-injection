import json
import os
import subprocess
import sys


KEY = os.environ["LLM_API_KEY"]
BASE = "https://faroapi.com/v1"


def request(path, payload=None, timeout=18):
    config = ['header = "Authorization: Bearer ' + KEY.replace("\\", "\\\\").replace('"', '\\"') + '"']
    if payload is not None:
        escaped = json.dumps(payload, ensure_ascii=False).replace("\\", "\\\\").replace('"', '\\"')
        config += ['header = "Content-Type: application/json"', f'data-binary = "{escaped}"']
    result = subprocess.run(
        ["curl", "--disable", "--silent", "--show-error", "--proto", "=https",
         "--connect-timeout", "6", "--max-time", str(timeout),
         "--config", "-", "--write-out", "\n%{http_code}", BASE + path],
        input="\n".join(config) + "\n", capture_output=True, text=True, check=False,
    )
    raw, _, status = result.stdout.rpartition("\n")
    if result.returncode:
        print("transport exit", result.returncode, "HTTP", status[-3:] or "000", flush=True)
        return None
    print("HTTP", status, flush=True)
    if status != "200":
        return None
    try:
        return json.loads(raw)
    except ValueError:
        print("non-JSON response", flush=True)
        return None


print("Checking scoped model availability", flush=True)
model_response = request("/models")
if not isinstance(model_response, dict):
    sys.exit(2)
model_ids = {item.get("id") for item in model_response.get("data", []) if isinstance(item, dict)}
choices = [x for x in ("gpt-6.1-sol", "gpt-6.1-terra", "gpt-6-sol", "gpt-5.6-sol",
                       "gpt-5.6-terra", "gpt-4.1-mini", "gpt-4o-mini") if x in model_ids]
print("Known text models available:", choices, flush=True)
if not choices:
    sys.exit(3)
data = request("/chat/completions", {
    "model": choices[0],
    "messages": [{"role": "user", "content": "只回答数字2"}],
    "temperature": 0, "max_tokens": 160,
}, timeout=50)
if not isinstance(data, dict):
    sys.exit(4)
text = ((data.get("choices") or [{}])[0].get("message") or {}).get("content")
print("Text response:", bool(text), "matches test:", isinstance(text, str) and text.strip() == "2",
      "token usage returned:", isinstance(data.get("usage"), dict), flush=True)
