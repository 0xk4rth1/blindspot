"""One folder per project: the case database plus JSON and text exports."""

from __future__ import annotations

import re
import shutil
import sqlite3
from pathlib import Path

import yaml

from blindspot.config import ConfigError, load_config
from blindspot.db import Database
from blindspot.safety import PLACEHOLDER_AUTHORIZATIONS, PolicyError

_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
EXPORT_FILES = {
    "case.json": "case.json",
    "events.jsonl": "events.jsonl",
    "report.md": "report.md",
    "report.html": "report.html",
    "hosts.txt": "lanes/hosts.txt",
    "endpoints.txt": "lanes/endpoints.txt",
    "parameters.txt": "lanes/parameters.txt",
}


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")[:41].strip("-")
    if not _SLUG.match(slug):
        raise ConfigError("project name needs a letter or number")
    return slug


def create_project(
    root: Path,
    *,
    name: str,
    program: str,
    authorization: str,
    seeds: list[str],
    include: list[str],
    exclude: list[str],
    network_enabled: bool = True,
) -> dict:
    cleaned_name = name.strip()
    statement = authorization.strip()
    if statement.lower() in PLACEHOLDER_AUTHORIZATIONS:
        raise ConfigError("authorization must be a real statement that this target is in scope for you")
    if not cleaned_name:
        raise ConfigError("project name is required")
    slug = slugify(cleaned_name)
    root_resolved = root.resolve()
    folder = (root_resolved / slug).resolve()
    if folder.parent != root_resolved:
        raise ConfigError("project path is not inside the projects folder")
    if folder.exists():
        raise ConfigError(f"project already exists: {slug}")
    example = Path(__file__).resolve().parents[2] / "config.example.yaml"
    document = yaml.safe_load(example.read_text(encoding="utf-8"))
    document["engagement"] = cleaned_name
    document["program"] = program.strip()
    document["authorization"] = statement
    document["network"] = {"enabled": bool(network_enabled)}
    document["seeds"] = _lines(seeds)
    document["scope"] = {"include": _lines(include), "exclude": _lines(exclude)}
    document["output"] = {"database": "case.sqlite", "report_dir": "exports"}
    folder.mkdir(parents=True)
    config_path = folder / "blindspot.yaml"
    config_path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    try:
        load_config(config_path).validate_for_run()
    except (ConfigError, PolicyError) as exc:
        shutil.rmtree(folder)
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(str(exc)) from exc
    return describe(folder)


def list_projects(root: Path) -> list[dict]:
    if not root.exists():
        return []
    projects = []
    for folder in sorted(path for path in root.iterdir() if path.is_dir()):
        if (folder / "blindspot.yaml").is_file() and _SLUG.match(folder.name):
            projects.append(describe(folder))
    return projects


def project_dir(root: Path, slug: str) -> Path:
    if not _SLUG.match(slug):
        raise ConfigError("unknown project")
    root_resolved = root.resolve()
    folder = (root_resolved / slug).resolve()
    if folder.parent != root_resolved or not folder.is_dir():
        raise ConfigError("unknown project")
    if not (folder / "blindspot.yaml").is_file():
        raise ConfigError("unknown project")
    return folder


def describe(folder: Path) -> dict:
    config = load_config(folder / "blindspot.yaml")
    summary = {"assets": 0, "endpoints": 0, "queued": 0}
    database = config.database_path()
    if database.is_file():
        db = Database(database, readonly=True)
        try:
            engagement_id = db.find_engagement(config.engagement)
            if engagement_id is not None:
                summary = db.summary(engagement_id)
        except sqlite3.OperationalError:
            summary = {"assets": 0, "endpoints": 0, "queued": 0}
        finally:
            db.close()
    return {
        "slug": folder.name,
        "name": config.engagement,
        "program": config.program,
        "network": config.network.enabled,
        "seeds": config.seeds,
        "include": config.include,
        "exclude": config.exclude,
        "summary": {key: summary.get(key, 0) for key in ("assets", "endpoints", "queued")},
        "exports": available_exports(folder),
    }


def available_exports(folder: Path) -> list[str]:
    export_dir = folder / "exports"
    return [name for name, relative in EXPORT_FILES.items() if (export_dir / relative).is_file()]


def export_file(folder: Path, name: str) -> Path:
    relative = EXPORT_FILES.get(name)
    if not relative:
        raise ConfigError("unknown export")
    export_root = (folder / "exports").resolve()
    path = (export_root / relative).resolve()
    if not path.is_relative_to(export_root) or not path.is_file():
        raise ConfigError("unknown export")
    return path


def _lines(values: list[str]) -> list[str]:
    lines = []
    for value in values:
        for part in str(value).splitlines():
            item = part.strip()
            if item:
                lines.append(item)
    return lines
