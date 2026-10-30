"""Pure parsers. Collectors store their output; they do not keep raw secrets."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin

from blindspot.normalize import query_names, strip_url, template_path
from blindspot.safety import secret_fingerprints

_HEADER_SIGNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("server", re.compile(r"cloudflare", re.I), "Cloudflare"),
    ("server", re.compile(r"nginx(?:/([\d.]+))?", re.I), "nginx"),
    ("server", re.compile(r"apache(?:/([\d.]+))?", re.I), "Apache"),
    ("server", re.compile(r"microsoft-iis(?:/([\d.]+))?", re.I), "IIS"),
    ("x-powered-by", re.compile(r"express", re.I), "Express"),
    ("x-powered-by", re.compile(r"php(?:/([\d.]+))?", re.I), "PHP"),
    ("x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET"),
    ("x-generator", re.compile(r"drupal\s*([\d.]+)?", re.I), "Drupal"),
    ("x-generator", re.compile(r"wordpress\s*([\d.]+)?", re.I), "WordPress"),
)

_BODY_SIGNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"wp-content/|wp-includes/", re.I), "WordPress"),
    (re.compile(r"__NEXT_DATA__"), "Next.js"),
    (re.compile(r"ng-version="), "Angular"),
    (re.compile(r"data-reactroot|id=\"root\".{0,80}react", re.I), "React"),
    (re.compile(r"cdn\.shopify\.com", re.I), "Shopify"),
    (re.compile(r"static\.wixstatic\.com", re.I), "Wix"),
)

_STATIC_EXT = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".css",
    ".woff",
    ".woff2",
    ".ico",
    ".map",
    ".webp",
)

_ENDPOINT_RE = re.compile(
    r"""["']((?:/(?:api|v\d+|graphql|rest|auth|oauth|admin|internal|upload|users|account|billing)"""
    r"""(?:/[A-Za-z0-9_{}.~%-]+)*)|(?:https?://[^"'\\\s]+))["']"""
)
_FETCH_RE = re.compile(
    r"""(?:fetch|(?:axios\s*\.\s*(?:get|post|put|patch|delete)))\(\s*["']([^"']+)["']""",
    re.I,
)
_FLAG_BLOCK = re.compile(r"featureFlags?\s*[:=]\s*\{([^{}]{0,600})\}", re.I)
_FLAG_KEY = re.compile(r"""["']([A-Za-z0-9_.:-]{2,60})["']\s*:""")
_FLAG_INDEX = re.compile(r"""flags\s*\[\s*["']([A-Za-z0-9_.:-]{2,60})["']\s*\]""")
_SOURCEMAP = re.compile(r"sourceMappingURL=(\S+)")
_HOST_RE = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?")
_PARAM_BLOCK = re.compile(r"(?:params|data)\s*:\s*\{([^{}]{0,400})\}")
_JSON_KEY = re.compile(r"""["']?([A-Za-z_][A-Za-z0-9_-]{0,40})["']?\s*:""")
_SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_ROBOTS_PATH = re.compile(r"(?im)^disallow:\s*(\S+)")
_ROBOTS_SITEMAP = re.compile(r"(?im)^sitemap:\s*(\S+)")

_INTERESTING_HEADERS = (
    "server",
    "x-powered-by",
    "x-generator",
    "content-type",
    "www-authenticate",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "location",
)

_SENSITIVE_NAMES = frozenset(
    {
        "file",
        "upload",
        "path",
        "url",
        "uri",
        "redirect",
        "redirect_uri",
        "next",
        "return",
        "returnurl",
        "callback",
        "continue",
        "dest",
        "destination",
        "template",
        "document",
    }
)

_VERIFY_PREFIXES = (
    ("google-site-verification", "google"),
    ("atlassian-domain-verification", "atlassian"),
    ("facebook-domain-verification", "facebook"),
    ("apple-domain-verification", "apple"),
    ("ms=", "microsoft"),
    ("stripe-verification", "stripe"),
    ("onetrust-domain-verification", "onetrust"),
    ("ahrefs-site-verification", "ahrefs"),
    ("brave-ledger-verification", "brave"),
    ("docusign", "docusign"),
)


@dataclass
class TechHit:
    name: str
    version: str = ""
    confidence: float = 0.6
    evidence: str = ""


@dataclass
class PageFacts:
    title: str = ""
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)


@dataclass
class JsFacts:
    endpoints: list[str] = field(default_factory=list)
    parameter_names: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    feature_flags: list[str] = field(default_factory=list)
    sourcemap: str = ""
    secrets: list[dict[str, str]] = field(default_factory=list)


@dataclass
class Operation:
    method: str
    path: str
    operation_id: str
    parameters: list[dict[str, str]]
    security: list
    tags: list[str]


def interesting_headers(headers: dict[str, str]) -> dict[str, str]:
    kept: dict[str, str] = {}
    for name in _INTERESTING_HEADERS:
        value = headers.get(name)
        if value:
            kept[name] = value[:300]
    return kept


def cookie_flags(set_cookie: str) -> dict | None:
    parts = [part.strip() for part in set_cookie.split(";") if part.strip()]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    flags = {part.lower().split("=", 1)[0] for part in parts[1:]}
    samesite = ""
    for part in parts[1:]:
        if part.lower().startswith("samesite="):
            samesite = part.split("=", 1)[1].strip()
    return {
        "name": name[:80],
        "secure": "secure" in flags,
        "httponly": "httponly" in flags,
        "samesite": samesite[:40],
    }


def csp_hosts(policy: str) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in policy.split():
        token = raw.strip().strip(";").strip("'").strip('"')
        if not token or token in {"self", "none", "unsafe-inline", "unsafe-eval", "strict-dynamic"}:
            continue
        if token.startswith(("data:", "blob:", "filesystem:")):
            continue
        host = ""
        if token.startswith("*."):
            host = token[2:]
        elif "://" in token:
            host = token.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        elif re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", token):
            host = token
        host = host.lower().rstrip(".")
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


def fingerprint(headers: dict[str, str], body: str) -> list[TechHit]:
    hits: list[TechHit] = []
    seen: set[str] = set()
    lowered = {key.lower(): value for key, value in headers.items()}
    for header, pattern, name in _HEADER_SIGNS:
        value = lowered.get(header, "")
        match = pattern.search(value)
        if not match or name in seen:
            continue
        seen.add(name)
        version = ""
        if match.lastindex:
            version = match.group(1) or ""
        hits.append(TechHit(name=name, version=version, confidence=0.8, evidence=f"header:{header}"))
    sample = body[:200_000]
    for pattern, name in _BODY_SIGNS:
        if name in seen or not pattern.search(sample):
            continue
        seen.add(name)
        hits.append(TechHit(name=name, version="", confidence=0.55, evidence="body"))
    return hits


def parse_html(html: str, base_url: str) -> PageFacts:
    parser = _PageParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return PageFacts()
    title = " ".join(part.strip() for part in parser.title_parts if part.strip())[:160]

    def resolve(value: str) -> str:
        if not value or value.startswith(("javascript:", "mailto:", "data:", "#")):
            return ""
        return urljoin(base_url, value.strip())

    links = []
    link_seen: set[str] = set()
    for href in parser.links:
        absolute = resolve(href)
        if absolute and absolute not in link_seen:
            link_seen.add(absolute)
            links.append(absolute)
    scripts = []
    script_seen: set[str] = set()
    for src in parser.scripts:
        absolute = resolve(src)
        if absolute and absolute not in script_seen:
            script_seen.add(absolute)
            scripts.append(absolute)
    forms = []
    for form in parser.forms:
        action = resolve(form["action"]) or base_url
        names = []
        known: set[str] = set()
        for name in form["inputs"]:
            if name and name not in known:
                known.add(name)
                names.append(name[:80])
        forms.append({"action": action, "method": form["method"], "inputs": names})
    return PageFacts(title=title, links=links[:200], scripts=scripts[:50], forms=forms[:40])


def extract_js(source: str) -> JsFacts:
    secrets, redacted = secret_fingerprints(source)
    facts = JsFacts(secrets=secrets)
    endpoints: list[str] = []
    seen: set[str] = set()
    for regex in (_ENDPOINT_RE, _FETCH_RE):
        for match in regex.findall(redacted):
            candidate = match[0] if isinstance(match, tuple) else match
            if not candidate or _is_static(candidate):
                continue
            if candidate not in seen:
                seen.add(candidate)
                endpoints.append(candidate)
            if len(endpoints) >= 40:
                break
    facts.endpoints = endpoints
    names: list[str] = []
    known: set[str] = set()
    for endpoint in endpoints:
        for name in query_names(endpoint):
            if name not in known:
                known.add(name)
                names.append(name)
    for name in re.findall(r"[?&]([A-Za-z_][A-Za-z0-9_-]{0,40})=", redacted):
        if name not in known:
            known.add(name)
            names.append(name)
    for block in _PARAM_BLOCK.findall(redacted):
        for name in _JSON_KEY.findall(block):
            if name not in known and name not in {"true", "false", "null"}:
                known.add(name)
                names.append(name)
    facts.parameter_names = names[:50]
    hosts: list[str] = []
    host_seen: set[str] = set()
    for host in _HOST_RE.findall(redacted):
        host = host.lower().rstrip(".")
        if host not in host_seen:
            host_seen.add(host)
            hosts.append(host)
    facts.hosts = hosts[:40]
    flags: list[str] = []
    flag_seen: set[str] = set()
    for block in _FLAG_BLOCK.findall(redacted):
        for name in _FLAG_KEY.findall(block):
            if name not in flag_seen:
                flag_seen.add(name)
                flags.append(name)
    for name in _FLAG_INDEX.findall(redacted):
        if name not in flag_seen:
            flag_seen.add(name)
            flags.append(name)
    facts.feature_flags = flags[:40]
    mapped = _SOURCEMAP.search(redacted)
    if mapped:
        facts.sourcemap = mapped.group(1).strip()
    return facts


def parse_robots(text: str) -> tuple[list[str], list[str]]:
    paths = []
    seen: set[str] = set()
    for path in _ROBOTS_PATH.findall(text):
        if path in seen or path == "/":
            continue
        seen.add(path)
        paths.append(path[:200])
        if len(paths) >= 50:
            break
    sitemaps = []
    for url in _ROBOTS_SITEMAP.findall(text):
        if url not in sitemaps:
            sitemaps.append(url)
    return paths, sitemaps[:5]


def parse_sitemap(text: str) -> list[str]:
    locs = []
    seen: set[str] = set()
    for loc in _SITEMAP_LOC.findall(text):
        cleaned = loc.strip()
        if cleaned in seen:
            continue
        seen.add(cleaned)
        locs.append(cleaned)
        if len(locs) >= 50:
            break
    return locs


def parse_security_txt(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line or line.startswith("#"):
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key in {"contact", "policy", "preferred-languages", "expires"} and key not in found:
            found[key] = value.strip()[:200]
    return found


def unquote_txt(data: str) -> str:
    parts = re.findall(r'"([^"]*)"', data)
    if parts:
        return "".join(parts)
    return data.strip().strip('"')


def parse_spf(record: str) -> dict[str, list[str]]:
    includes: list[str] = []
    redirects: list[str] = []
    ips: list[str] = []
    for token in record.split():
        lowered = token.lower()
        if lowered.startswith("include:"):
            includes.append(token.split(":", 1)[1].strip().rstrip("."))
        elif lowered.startswith("redirect="):
            redirects.append(token.split("=", 1)[1].strip().rstrip("."))
        elif lowered.startswith("ip4:") or lowered.startswith("ip6:"):
            ips.append(token.split(":", 1)[1].strip())
    return {"includes": includes, "redirects": redirects, "ips": ips}


def verification_service(txt: str) -> str:
    lowered = txt.lower().strip()
    for prefix, service in _VERIFY_PREFIXES:
        if lowered.startswith(prefix):
            return service
    return ""


def dmarc_policy(txt: str) -> str:
    if "v=dmarc1" not in txt.lower():
        return ""
    match = re.search(r"(?i)\bp\s*=\s*(none|quarantine|reject)", txt)
    return match.group(1).lower() if match else "present"


def parse_openapi(document: dict) -> list[Operation]:
    if not isinstance(document, dict):
        return []
    if document.get("swagger") and not document.get("openapi"):
        return _parse_swagger2(document)
    paths = document.get("paths") or {}
    if not isinstance(paths, dict):
        return []
    global_security = document.get("security") if isinstance(document.get("security"), list) else []
    operations: list[Operation] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        for method, operation in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            if not isinstance(operation, dict):
                continue
            security = operation.get("security", global_security)
            if not isinstance(security, list):
                security = []
            operations.append(
                Operation(
                    method=method.upper(),
                    path=str(path),
                    operation_id=str(operation.get("operationId") or ""),
                    parameters=_parameters(shared + _as_list(operation.get("parameters")), operation),
                    security=security,
                    tags=[str(tag) for tag in operation.get("tags") or [] if isinstance(tag, str)],
                )
            )
    return operations


def parse_spec_document(text: str) -> dict | None:
    stripped = text.lstrip()
    if not stripped:
        return None
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None
    try:
        import yaml
    except ImportError:
        return None
    try:
        data = yaml.safe_load(stripped)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def looks_like_spec(document: dict) -> bool:
    return bool(document.get("openapi") or document.get("swagger") or document.get("paths"))


def classify_endpoint(path: str, parameter_names: list[str]) -> tuple[str, str]:
    lowered = path.lower()
    names = {name.lower() for name in parameter_names}
    if "graphql" in lowered:
        return "graphql", "api"
    if any(part in lowered for part in ("/upload", "/files", "/import")) or names & {"file", "upload"}:
        return "upload", "file_handling"
    if any(part in lowered for part in ("/admin", "/internal", "/manage", "/staff")):
        return "admin", "administration"
    if any(part in lowered for part in ("/login", "/logout", "/oauth", "/signin", "/signup", "/auth", "/session", "/token")):
        return "auth", "authentication"
    if any(part in lowered for part in ("/billing", "/invoice", "/payment", "/checkout")):
        return "billing", "billing"
    if any(part in lowered for part in ("/account", "/users", "/profile", "/me")):
        return "account", "account"
    if lowered.startswith("/api") or "/rest/" in lowered or "/v1/" in lowered or "/v2/" in lowered or "/v3/" in lowered:
        return "api", "api"
    if _is_static(lowered):
        return "static", "static"
    return "unknown", "other"


def is_sensitive_parameter(name: str) -> bool:
    return name.lower() in _SENSITIVE_NAMES


def normalize_endpoint(value: str, base_url: str = "") -> str:
    candidate = value.strip()
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return strip_url(candidate)
    if candidate.startswith("/"):
        path = candidate.split("?", 1)[0].split("#", 1)[0]
        return template_path(path)
    if base_url:
        joined = urljoin(base_url, candidate)
        return strip_url(joined)
    return ""


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict] = []
        self.title_parts: list[str] = []
        self._in_title = False
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        elif tag in {"link", "area"} and attributes.get("href"):
            self.links.append(attributes["href"])
        elif tag == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"])
        elif tag == "iframe" and attributes.get("src"):
            self.links.append(attributes["src"])
        elif tag == "form":
            self._form = {
                "action": attributes.get("action") or "",
                "method": (attributes.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            name = attributes.get("name")
            if name:
                self._form["inputs"].append(name)
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)


def _parameters(parameters: list, operation: dict) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in parameters:
        if not isinstance(item, dict) or not item.get("name") or "$ref" in item:
            continue
        name = str(item["name"])[:80]
        location = str(item.get("in") or "query")[:20]
        key = (name, location)
        if key in seen:
            continue
        seen.add(key)
        found.append({"name": name, "location": location})
    body = operation.get("requestBody") if isinstance(operation.get("requestBody"), dict) else {}
    content = body.get("content") if isinstance(body.get("content"), dict) else {}
    for media in content.values():
        if not isinstance(media, dict):
            continue
        schema = media.get("schema") if isinstance(media.get("schema"), dict) else {}
        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        for name in list(properties)[:40]:
            key = (str(name), "body")
            if key in seen:
                continue
            seen.add(key)
            found.append({"name": str(name)[:80], "location": "body"})
    return found


def _parse_swagger2(document: dict) -> list[Operation]:
    base = str(document.get("basePath") or "")
    paths = document.get("paths") or {}
    operations: list[Operation] = []
    if not isinstance(paths, dict):
        return operations
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        full_path = f"{base.rstrip('/')}/{str(path).lstrip('/')}"
        for method, operation in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            if not isinstance(operation, dict):
                continue
            security = operation.get("security") if isinstance(operation.get("security"), list) else []
            operations.append(
                Operation(
                    method=method.upper(),
                    path=full_path,
                    operation_id=str(operation.get("operationId") or ""),
                    parameters=_parameters(_as_list(operation.get("parameters")), operation),
                    security=security,
                    tags=[str(tag) for tag in operation.get("tags") or []],
                )
            )
    return operations


def _as_list(value: object) -> list:
    return value if isinstance(value, list) else []


def _is_static(value: str) -> bool:
    path = value.split("?", 1)[0].split("#", 1)[0].lower()
    return path.endswith(_STATIC_EXT)
