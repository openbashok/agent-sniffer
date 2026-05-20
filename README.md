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

```bash
git clone https://github.com/openbashok/agent-sniffer
cd agent-sniffer
pip install -r requirements.txt
```

First-time only — trust the mitmproxy CA:

```bash
mitmdump  # let it run for a moment, then Ctrl+C
# CA cert is now at ~/.mitmproxy/mitmproxy-ca-cert.pem
```

## Run

Three terminals, one browser tab.

**Terminal 1 — proxy + sniffer:**

```bash
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

## Layout

```
agent-sniffer/
├── addon.py          mitmproxy addon (parser + WS broadcaster)
├── index.html        standalone viewer, connects to ws://127.0.0.1:8765
└── requirements.txt
```

## Notes

- Only traffic to `api.anthropic.com/v1/messages` is captured. Everything else passes through untouched.
- The viewer is open-by-default on `127.0.0.1:8765`. Don't expose it on a public interface.
- Scrub API keys and any sensitive file content from screenshots before publishing captures.

## License

MIT
