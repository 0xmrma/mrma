from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import tomllib  # py3.11+
except Exception:  # pragma: no cover
    tomllib = None  # type: ignore


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if tomllib is None:
        raise RuntimeError("tomllib not available (need Python 3.11+)")
    data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    if isinstance(data, dict):
        return data
    return {}


def _deep_merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """
    Return a merged dict where b overrides a.
    """
    out: dict[str, Any] = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)  # type: ignore[arg-type]
        else:
            out[k] = v
    return out


def default_config_paths() -> dict[str, Path]:
    home = Path.home()
    return {
        "local": Path.cwd() / "mrma.toml",
        "global": home / ".config" / "mrma" / "config.toml",
    }


def load_config(explicit_path: str | None = None, use_config: bool = True) -> dict[str, Any]:
    """
    Load config from:
      - explicit_path (if provided), else
      - local mrma.toml, then global ~/.config/mrma/config.toml
    Local overrides global.
    """
    if not use_config:
        return {}

    paths = default_config_paths()

    if explicit_path:
        p = Path(explicit_path).expanduser()
        return _read_toml(p)

    global_cfg = _read_toml(paths["global"])
    local_cfg = _read_toml(paths["local"])
    return _deep_merge(global_cfg, local_cfg)


def cfg_get(cfg: dict[str, Any], dotted: str, default: Any = None) -> Any:
    """
    cfg_get(cfg, "impact.delay", 0.0)
    """
    cur: Any = cfg
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def cfg_defaults(cfg: dict[str, Any], section: str) -> dict[str, Any]:
    """
    Merge [defaults] with [<section>].
    Example: cfg_defaults(cfg, "impact") merges defaults + impact.
    """
    base = cfg.get("defaults", {}) if isinstance(cfg.get("defaults"), dict) else {}
    sec = cfg.get(section, {}) if isinstance(cfg.get(section), dict) else {}
    return _deep_merge(base, sec)
