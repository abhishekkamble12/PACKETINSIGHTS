from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable, Tuple


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def top_items(counter: Counter[str], limit: int = 5) -> list[Tuple[str, int]]:
    return counter.most_common(limit)


def clean_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").strip()
    return str(value).strip()


def normalize_domain(name: str) -> str:
    return name.rstrip(".").lower()


def format_items(items: Iterable[Tuple[str, int]]) -> list[str]:
    return [f"{name}: {count}" for name, count in items]

