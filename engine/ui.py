"""Local page for suggesting remediations from a prerequisite file path."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml
from pathlib import Path
from urllib.parse import urlparse

from engine.prerequisites import load_prerequisites
from engine.suggester import suggest

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Remediation plans</title>
<style>
  :root { color-scheme: light; }
  body { margin: 0; font: 16px/1.5 "Iowan Old Style", Palatino, Georgia, serif; color: #1c1915; background: #f6f3ee; }
  main { max-width: 44rem; margin: 0 auto; padding: 3rem 1.25rem 4rem; }
  h1 { font-size: 1.6rem; font-weight: 600; margin: 0 0 0.25rem; }
  p.lead { margin: 0 0 1.5rem; color: #5c564e; }
  form { display: flex; gap: 0.5rem; }
  input[type=text] { flex: 1; font: inherit; padding: 0.55rem 0.7rem; border: 1px solid #c9c2b6; border-radius: 6px; background: #fff; }
  button { font: 600 0.95rem/1 sans-serif; padding: 0.55rem 1rem; border: 0; border-radius: 6px; background: #1c1915; color: #fff; cursor: pointer; }
  button:disabled { opacity: 0.5; }
  .error { margin-top: 1rem; color: #8a2b1c; }
  article { margin-top: 2rem; }
  article h2 { font-size: 1.25rem; margin: 0; color: #1d4e89; }
  article .meta { color: #5c564e; margin: 0.15rem 0 1rem; }
  .intro { margin: 0 0 1rem; }
  .path { border-top: 1px solid #e2dcd2; padding: 0.9rem 0; }
  .path h3 { font-size: 1rem; margin: 0 0 0.4rem; }
  .layer-software h3 { color: #1d4e89; }
  .layer-configuration h3 { color: #8a4b12; }
  .layer-network h3 { color: #2f6b4f; }
  .badge { font: 600 0.7rem/1 sans-serif; letter-spacing: 0.03em; text-transform: uppercase; color: #2f6b4f; margin-left: 0.4rem; }
  .option { margin: 0.35rem 0 0.35rem 0.2rem; }
  .option strong { font-weight: 600; color: #6b3f86; }
  .option p { margin: 0.1rem 0 0 1rem; color: #3a342c; }
  code { background: #efe4cc; border-radius: 4px; padding: 0.05rem 0.35rem; font: 0.9em ui-monospace, Menlo, monospace; }
  .condition { font-weight: 400; color: #5c564e; }
  .notes { margin-top: 0.5rem; }
  .notes strong { color: #8a2b1c; }
  .notes li { margin: 0.2rem 0; }
  details { margin-top: 1.25rem; }
  summary { cursor: pointer; font: 600 0.9rem/1 sans-serif; color: #3a342c; }
  pre { overflow: auto; background: #1c1915; color: #f3efe8; border-radius: 6px; padding: 0.8rem; font: 0.8rem/1.45 ui-monospace, Menlo, monospace; }
  pre .key { color: #8ec5ff; }
  pre .str { color: #b6e3c0; }
  pre .num { color: #f0c674; }
  pre .bool { color: #f0a0c0; }
  pre .null { color: #c9c2b6; }
</style>
</head>
<body>
<main>
  <h1>Remediation plans</h1>
  <p class="lead">Enter the path to a prerequisite file. Any one of the plans closes the issue on its own.</p>
  <form id="form">
    <input id="path" type="text" name="path" placeholder="/path/to/cve.yaml" autocomplete="off" required>
    <button type="submit" id="go">Suggest</button>
  </form>
  <div id="error" class="error" hidden></div>
  <div id="out"></div>
</main>
<script>
const form = document.getElementById("form");
const out = document.getElementById("out");
const error = document.getElementById("error");
const button = document.getElementById("go");

function escape(value) {
  return String(value).replace(/[&<>]/g, (ch) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;"}[ch]));
}

function inline(value) {
  return escape(value).split("`").map((part, index) => (
    index % 2 ? `<code>${part}</code>` : part
  )).join("");
}

function highlight(json) {
  return escape(json).replace(
    /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\\s*:)?|\\b(true|false|null)\\b|-?\\d+(?:\\.\\d+)?(?:[eE][+\\-]?\\d+)?)/g,
    (match) => {
      let kind = "num";
      if (match.startsWith('"')) kind = match.endsWith(":") ? "key" : "str";
      else if (match === "true" || match === "false") kind = "bool";
      else if (match === "null") kind = "null";
      return `<span class="${kind}">${match}</span>`;
    }
  );
}

function render(plan) {
  const score = plan.cvss_score == null ? "" : `<p class="meta">CVSS ${plan.cvss_score}${plan.cvss_vector ? " · " + escape(plan.cvss_vector) : ""}</p>`;
  const paths = plan.paths.map((path, index) => {
    const options = path.options.map((option) => `
      <div class="option">
        <strong>${escape(option.title)}</strong>${option.condition ? ` <span class="condition">(${escape(option.condition)})</span>` : ""}
        <p>${inline(option.detail)}</p>
      </div>`).join("");
    return `<section class="path layer-${escape(path.layer)}">
      <h3>${index + 1}. ${escape(path.layer)} — ${escape(path.target_label)}${path.recommended ? '<span class="badge">recommended</span>' : ""}</h3>
      ${options}
    </section>`;
  }).join("");
  const notes = plan.notes.length
    ? `<div class="notes"><strong>Notes</strong><ul>${plan.notes.map((note) => `<li>${inline(note)}</li>`).join("")}</ul></div>`
    : "";
  return `<article>
    <h2>${escape(plan.cve_id)}</h2>
    ${score}
    ${plan.paths.length ? '<p class="intro">Any one of these remediations closes this issue on its own.</p>' : ""}
    ${paths}
    ${notes}
    <details>
      <summary>Show JSON</summary>
      <pre>${highlight(JSON.stringify(plan, (key, value) => typeof value === "string" ? value.replaceAll("`", "") : value, 2))}</pre>
    </details>
  </article>`;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  error.hidden = true;
  button.disabled = true;
  try {
    const response = await fetch("/suggest", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({path: document.getElementById("path").value}),
    });
    const body = await response.json();
    if (!response.ok) {
      out.innerHTML = "";
      error.textContent = body.error;
      error.hidden = false;
      return;
    }
    out.innerHTML = body.plans.map(render).join("");
  } catch (problem) {
    error.textContent = "Could not reach the local server.";
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
});
</script>
</body>
</html>
"""


def suggest_file(path: str) -> list[dict]:
    """Plans for one prerequisite file, as dictionaries."""
    from engine.__main__ import plan_to_dict

    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise FileNotFoundError(f"No file at {file_path}")
    return [plan_to_dict(suggest(load_prerequisites(file_path)))]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if urlparse(self.path).path != "/":
            self.send_error(404)
            return
        body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/suggest":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            path = str(payload.get("path") or "").strip()
            if not path:
                raise ValueError("Enter a path to a prerequisite file.")
            plans = suggest_file(path)
            status, body = 200, {"plans": plans}
        except (OSError, ValueError, KeyError, yaml.YAMLError) as problem:
            status, body = 400, {"error": str(problem)}
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Serve the page until interrupted."""
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Remediation plans: http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()
