# agent-sniffer

Inspect what an LLM agent client really sends to its backend. Built for Claude Code, extensible to any client speaking the Anthropic Messages API.

Captures traffic via mitmproxy, parses it into structured form, and streams it to a browser viewer in real time. No build step, no dependencies in the browser.

## What you see

- System prompt (full text, all blocks)
- Tool definitions with JSON schemas
- Message history, including `tool_use` and `tool_result` blocks
- Streaming SSE events as they arrive
- Status, latency, token counts

## Setup

Requires **Python 3.10+**. Check with `python3 --version`. If your system `python`/`pip` point to Python 2 (common on older macOS), always use `python3` and `pip3` explicitly.

```bash
git clone https://github.com/openbashok/agent-sniffer
cd agent-sniffer

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate     # macOS/Linux
# .venv\Scripts\activate      # Windows PowerShell

# Install dependencies inside the venv
pip install -r requirements.txt
```

From now on, run every command below with the venv activated (`source .venv/bin/activate`). To leave it later: `deactivate`.

First-time only — trust the mitmproxy CA:

```bash
mitmdump  # let it run for a moment, then Ctrl+C
# CA cert is now at ~/.mitmproxy/mitmproxy-ca-cert.pem
```

## Run

Three terminals, one browser tab. Activate the venv (`source .venv/bin/activate`) in each terminal that runs a Python command.

**Terminal 1 — proxy + sniffer:**

```bash
source .venv/bin/activate
mitmdump -s addon.py --listen-port 8080
```

**Terminal 2 — Claude Code through the proxy:**

```bash
export HTTPS_PROXY=http://localhost:8080
export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem
claude
```

**Browser — open the viewer:**

```bash
open index.html   # macOS
xdg-open index.html   # Linux
```

Type anything in Claude Code. Requests appear in the timeline in real time.

## Search

The viewer has a search box in the filter bar. It matches against category, URL, model, and (in `deep` mode, default on) the raw request/response bodies. Anything wrapped in `/…/flags` is treated as a JavaScript regex — handy for grep-style hunts:

```
test@example.com         # plain substring, case-insensitive
/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i   # email regex
/sk-ant-[A-Za-z0-9_-]+/  # Anthropic API key shape
```

The timeline shows only matching items, with a live hit count next to the input.

## Capture traffic to disk (for offline analysis)

Pass `--set sniffer_log_dir=PATH` to `mitmdump` and every captured flow is appended to a per-session JSONL file at `PATH/agent-sniffer-YYYYMMDD-HHMMSS.jsonl`. Each line is one self-contained flow — request headers, request body (the raw text that actually reached Anthropic, post-rules), original pre-rules body, response headers, response body, parsed SSE events, and timing.

```bash
mitmdump -s addon.py --listen-port 8080 \
  --set sniffer_log_dir=./captures \
  --set sniffer_log_all=false
```

- `sniffer_log_dir`: directory for the JSONL log. Empty (default) disables logging.
- `sniffer_log_all`: if `true`, also log every other flow that crosses the proxy (not just classified Anthropic/Datadog/npm traffic). Useful when you don't yet know what endpoints your client touches. Default `false`.

The log is meant to be consumed by a separate post-processing script (PII / email / secret classification, dataset extraction, etc.). One flow per line, UTF-8, no rotation — start a new session for a new file.

## Layout

```
agent-sniffer/
├── addon.py          mitmproxy addon (parser + WS broadcaster)
├── index.html        standalone viewer, connects to ws://127.0.0.1:8765
└── requirements.txt
```

## Notes

- Only traffic to `api.anthropic.com/v1/messages` is captured. Everything else passes through untouched (unless `sniffer_log_all=true`).
- The viewer is open-by-default on `127.0.0.1:8765`. Don't expose it on a public interface.
- Scrub API keys and any sensitive file content from screenshots before publishing captures.
- The JSONL log can contain `x-api-key` headers and user-typed prompts verbatim. Treat the directory as sensitive — don't commit it, and `.gitignore` already excludes a `captures/` folder if you use that name.

## License

MIT
