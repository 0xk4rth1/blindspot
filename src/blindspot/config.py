"""YAML configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from blindspot.safety import PLACEHOLDER_AUTHORIZATIONS
from blindspot.scope import ScopeManager


class ConfigError(ValueError):
    pass


@dataclass
class Limits:
    concurrency: int = 5
    request_delay_ms: int = 250
    timeout_seconds: int = 20
    tool_timeout_seconds: int = 90
    max_body_bytes: int = 1_000_000
    max_urls: int = 400
    max_js_files: int = 15
    max_historical: int = 200
    crawl_depth: int = 2
    crawl_pages: int = 25
    spec_fetches: int = 8


@dataclass
class ToolToggle:
    enabled: bool = True
    path: str = ""
    extra_args: list[str] = field(default_factory=list)


@dataclass
class Tools:
    subfinder: ToolToggle = field(default_factory=lambda: ToolToggle(path="subfinder"))
    amass: ToolToggle = field(default_factory=lambda: ToolToggle(enabled=False, path="amass"))
    dnsx: ToolToggle = field(default_factory=lambda: ToolToggle(path="dnsx"))
    httpx: ToolToggle = field(default_factory=lambda: ToolToggle(path="httpx"))
    katana: ToolToggle = field(default_factory=lambda: ToolToggle(path="katana"))
    gau: ToolToggle = field(default_factory=lambda: ToolToggle(path="gau"))


@dataclass
class Providers:
    doh: str = "https://cloudflare-dns.com/dns-query"
    crtsh: str = "https://crt.sh/"
    wayback: str = "https://web.archive.org/cdx/search/cdx"
    commoncrawl_collinfo: str = "https://index.commoncrawl.org/collinfo.json"
    urlscan: str = "https://urlscan.io/api/v1/search/"


@dataclass
class Notify:
    webhook: str = ""


@dataclass
class Output:
    database: str = ".blindspot/blindspot.sqlite"
    report_dir: str = ".blindspot/reports"


@dataclass
class Network:
    enabled: bool = True


@dataclass
class AppConfig:
    path: Path
    engagement: str
    program: str
    authorization: str
    network: Network
    seeds: list[str]
    include: list[str]
    exclude: list[str]
    limits: Limits
    tools: Tools
    providers: Providers
    notify: Notify
    output: Output

    def scope(self) -> ScopeManager:
        return ScopeManager.from_lists(self.include, self.exclude)

    def database_path(self) -> Path:
        return _resolve(self.path.parent, self.output.database)

    def report_dir(self) -> Path:
        return _resolve(self.path.parent, self.output.report_dir)

    def validate_for_run(self) -> None:
        statement = self.authorization.strip().lower()
        if statement in PLACEHOLDER_AUTHORIZATIONS:
            raise ConfigError(
                "authorization must be a real statement that this engagement is in scope for you"
            )
        if not self.include:
            raise ConfigError("scope.include must list at least one asset")
        if not self.seeds:
            raise ConfigError("at least one seed is required")
        self.scope().assert_seeds(self.seeds)


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path).resolve()
    if not config_path.is_file():
        raise ConfigError(f"config not found: {config_path}")
    try:
        import yaml
    except ImportError as exc:
        raise ConfigError("PyYAML is required. Install with: python -m pip install -e .") from exc
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")
    scope = raw.get("scope") or {}
    include = _str_list(scope.get("include"))
    exclude = _str_list(scope.get("exclude"))
    return AppConfig(
        path=config_path,
        engagement=str(raw.get("engagement") or "engagement").strip(),
        program=str(raw.get("program") or "").strip(),
        authorization=str(raw.get("authorization") or "").strip(),
        network=Network(enabled=_bool((raw.get("network") or {}).get("enabled", True))),
        seeds=_str_list(raw.get("seeds")),
        include=include,
        exclude=exclude,
        limits=_limits(raw.get("limits") or {}),
        tools=_tools(raw.get("tools") or {}),
        providers=_providers(raw.get("providers") or {}),
        notify=Notify(webhook=str((raw.get("notify") or {}).get("webhook") or "").strip()),
        output=_output(raw.get("output") or {}),
    )


def write_starter(directory: Path, engagement: str, program: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "blindspot.yaml"
    if target.exists():
        raise ConfigError(f"config already exists: {target}")
    example = Path(__file__).resolve().parents[2] / "config.example.yaml"
    text = example.read_text(encoding="utf-8")
    text = text.replace("engagement: example", f"engagement: {engagement}", 1)
    text = text.replace(
        'program: "Replace with the bug bounty program name"',
        f'program: "{program}"',
        1,
    )
    target.write_text(text, encoding="utf-8")
    return target


def _limits(raw: dict) -> Limits:
    return Limits(
        concurrency=_int(raw, "concurrency", 5, 1, 20),
        request_delay_ms=_int(raw, "request_delay_ms", 250, 0, 10_000),
        timeout_seconds=_int(raw, "timeout_seconds", 20, 2, 120),
        tool_timeout_seconds=_int(raw, "tool_timeout_seconds", 90, 5, 600),
        max_body_bytes=_int(raw, "max_body_bytes", 1_000_000, 10_000, 5_000_000),
        max_urls=_int(raw, "max_urls", 400, 1, 5000),
        max_js_files=_int(raw, "max_js_files", 15, 0, 100),
        max_historical=_int(raw, "max_historical", 200, 0, 5000),
        crawl_depth=_int(raw, "crawl_depth", 2, 0, 3),
        crawl_pages=_int(raw, "crawl_pages", 25, 0, 200),
        spec_fetches=_int(raw, "spec_fetches", 8, 0, 20),
    )


def _tools(raw: dict) -> Tools:
    defaults = Tools()
    return Tools(
        subfinder=_toggle(raw.get("subfinder"), defaults.subfinder),
        amass=_toggle(raw.get("amass"), defaults.amass),
        dnsx=_toggle(raw.get("dnsx"), defaults.dnsx),
        httpx=_toggle(raw.get("httpx"), defaults.httpx),
        katana=_toggle(raw.get("katana"), defaults.katana),
        gau=_toggle(raw.get("gau"), defaults.gau),
    )


def _toggle(raw: object, default: ToolToggle) -> ToolToggle:
    if not isinstance(raw, dict):
        return default
    extra = raw.get("extra_args") or []
    if not isinstance(extra, list):
        extra = []
    return ToolToggle(
        enabled=_bool(raw.get("enabled", default.enabled)),
        path=str(raw.get("path") or default.path),
        extra_args=[str(item) for item in extra],
    )


def _providers(raw: dict) -> Providers:
    base = Providers()
    return Providers(
        doh=str(raw.get("doh") or base.doh),
        crtsh=str(raw.get("crtsh") or base.crtsh),
        wayback=str(raw.get("wayback") or base.wayback),
        commoncrawl_collinfo=str(raw.get("commoncrawl_collinfo") or base.commoncrawl_collinfo),
        urlscan=str(raw.get("urlscan") or base.urlscan),
    )


def _output(raw: dict) -> Output:
    base = Output()
    return Output(
        database=str(raw.get("database") or base.database),
        report_dir=str(raw.get("report_dir") or base.report_dir),
    )


def _str_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    raise ConfigError("expected a list of strings")


def _bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _int(raw: dict, key: str, default: int, low: int, high: int) -> int:
    value = raw.get(key, default)
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"limits.{key} must be an integer") from exc
    return max(low, min(high, number))


def _resolve(base: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (base / path).resolve()
