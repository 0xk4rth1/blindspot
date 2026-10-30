# Blindspot

Blindspot is a cross-platform black-box reconnaissance case file for bug bounty work you are authorized to do. It runs on Windows, macOS, and Linux with Python 3.11 or newer. Collectors are separate from the intelligence layer. Every stored fact keeps its source, and historical events are inserted rather than overwritten.

The case file is the thing you reuse. Query it, export lane files, or open the local viewer when you come back to a specific test idea.

## What it records

- Passive names from Subfinder, passive Amass, and certificate transparency, filtered through scope
- DNS relationships: addresses, CNAME, MX, NS, CAA, SPF include graph, and SaaS verification service names
- HTTP responses from httpx or the built-in client: status, selected headers, technology marks, cookie flags, form field names
- Historical URLs from Wayback, Common Crawl, URLScan, and gau
- A bounded same-origin crawl from Katana or the built-in crawler
- JavaScript endpoints, parameter names, feature-flag names, and source-map paths
- OpenAPI and Swagger operations from a fixed set of spec documents and from links the crawl already found
- Review prompts that name the hypothesis, the assets and endpoints involved, the original observations, why the lead was kept, its confidence and limitations, and a high-level manual check

## What it does not do

Blindspot does not ship exploit payloads, brute-force wordlists, or vulnerability checks. Amass is passive only, and brute-force tool flags are stripped. Cloud metadata addresses are refused. Cookie values, query values, hidden field values, raw secrets, and source-map file contents are not stored. Out-of-scope names returned by a tool are dropped. External names found in SPF or script tags are recorded as relationships and are not scanned.

Review prompts are leads. They are not confirmed findings. You decide what to test by hand. The intelligence layer is meant to make those leads fewer and more specific: related routes stay together, a script's endpoints stay together, and a lead that is no longer supported leaves the queue.

## Install

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
```

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Optional tools, used when they are on `PATH`: subfinder, amass, dnsx, httpx, katana, gau. If one is missing, that stage logs the gap and the built-in collector still runs where one exists. Optional dashboard: `python -m pip install -e ".[dashboard]"`.

## Run

1. Copy `config.example.yaml` to `blindspot.yaml`, or run `python -m blindspot init --name acme --program "Acme H1"`.
2. Write a real authorization statement and list only in-scope assets.
3. Collect and queue review prompts:

```powershell
python -m blindspot run --config blindspot.yaml
python -m blindspot query queue --config blindspot.yaml
python -m blindspot report --config blindspot.yaml
python -m blindspot serve --config blindspot.yaml
```

`python -m blindspot scope check app.example.com --config blindspot.yaml` answers whether a host is in scope. `python -m blindspot watch --config blindspot.yaml --interval 86400` runs the pipeline again and appends change notifications to `.blindspot/reports/notifications.jsonl`.

`python -m blindspot demo` writes a fictional offline case under `.blindspot-demo` so you can click through the viewer without sending traffic.

## Web application

`python -m blindspot app` opens http://127.0.0.1:8765/ on the machine where it is running. It works on Linux, macOS, and Windows. Create a project in the form, then run collection from that project's page.

Each project is a folder under `.blindspot/projects/<name>/`. The case database stays there, and a finished run writes reusable files under `exports/`:

- `case.json` and `events.jsonl`
- `lanes/hosts.txt`, `lanes/endpoints.txt`, `lanes/parameters.txt`
- `report.md` and `report.html`

The project page reads that same case. Discover hosts is the first step: passive names, DNS, then an HTTP probe. `hosts.txt` lists the hosts that answered. A host that does not answer a finished probe is left out of that file. Crawl, historical URLs, and review prompts are not part of this step. Use `--port` if 8765 is already taken. The application listens on loopback only.

## Scope file

Includes are OR. Excludes veto. `*.example.com` includes the apex and every subdomain. A URL prefix such as `https://api.example.com/v1` allows only that prefix, not the rest of the host and not another port. URL prefixes do not cause subdomain enumeration of the parent zone.

Scope is checked again at the network boundary. Redirect destinations are revalidated. A CNAME or address that points outside scope, including a cloud metadata address, is not requested. Provider calls use the configured origins only. Historical URLs cannot skip the scope check. With `network.enabled: false`, the HTTP client does not call its transport. Allowed and rejected requests are written to `request_log`.

## Case layout

SQLite tables keep assets, append-only events, surface URLs, endpoints, parameters, technologies, relationships, changes, hypotheses, and the request log. A reviewer can mark a hypothesis accepted, done, dismissed, or queued. Later runs refresh priority and evidence and leave that status alone. A queued lead that the current run no longer emits is marked superseded.

`blindspot report` writes:

- `case.json` and `events.jsonl`
- `lanes/hosts.txt`, `lanes/endpoints.txt`, `lanes/parameters.txt`
- `report.md` and `report.html`

## Stages

`python -m blindspot stages` prints the order: subfinder, amass, ct_logs, dns_resolve, http_probe, fingerprint, wayback, commoncrawl, urlscan, gau, crawl, js_analysis, sourcemap, openapi, change_detect, classify, correlate, hypothesize.

Run one stage with `python -m blindspot run --config blindspot.yaml --stage js_analysis`.

## Tests

```powershell
python -m unittest discover -s tests
```
