from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from wsa.tools.fs import sha256


@dataclass
class JarEntry:
    path: str
    data: bytes
    is_class: bool
    metadata: dict


_WHITELIST: list[dict] | None = None


def _load_whitelist() -> list[dict]:
    global _WHITELIST
    if _WHITELIST is not None:
        return _WHITELIST
    wl_path = Path("rules/java_lib_whitelist.yaml")
    if wl_path.exists():
        with open(wl_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        _WHITELIST = data.get("whitelist", []) if data else []
    else:
        _WHITELIST = []
    return _WHITELIST


def _is_whitelisted(entry_path: str, data: bytes) -> bool:
    wl = _load_whitelist()
    h = sha256(data)
    for rule in wl:
        if rule.get("sha256") and rule["sha256"] == h:
            return True
        gid = rule.get("group_id", "")
        if gid and gid.replace(".", "/") in entry_path:
            return True
    return False


def _is_class_dir(path: str) -> bool:
    return any(path.startswith(p) for p in ("BOOT-INF/classes/", "WEB-INF/classes/", "classes/"))


def _is_lib_dir(path: str) -> bool:
    return any(path.startswith(p) for p in ("BOOT-INF/lib/", "WEB-INF/lib/", "lib/"))


def scan_jar(jar_path: str | Path) -> list[JarEntry]:
    jar_path = Path(jar_path)
    if not jar_path.exists():
        raise FileNotFoundError(f"JAR not found: {jar_path}")

    entries: list[JarEntry] = []
    try:
        with zipfile.ZipFile(jar_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename

                if name.endswith(".class") and _is_class_dir(name):
                    data = zf.read(name)
                    entries.append(JarEntry(
                        path=name, data=data, is_class=True,
                        metadata={"size": len(data), "sha256": sha256(data)},
                    ))

                elif name.endswith(".jar") and _is_lib_dir(name):
                    data = zf.read(name)
                    if _is_whitelisted(name, data):
                        continue
                    nested = _scan_nested_jar(data, name)
                    entries.extend(nested)

                elif name.endswith((".jsp", ".jspx")):
                    data = zf.read(name)
                    entries.append(JarEntry(
                        path=name, data=data, is_class=False,
                        metadata={"size": len(data), "sha256": sha256(data)},
                    ))
    except zipfile.BadZipFile:
        pass

    return entries


def _scan_nested_jar(data: bytes, parent_path: str) -> list[JarEntry]:
    import io
    entries: list[JarEntry] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.filename.endswith(".class"):
                    cls_data = zf.read(info.filename)
                    entries.append(JarEntry(
                        path=f"{parent_path}!/{info.filename}",
                        data=cls_data, is_class=True,
                        metadata={"size": len(cls_data), "sha256": sha256(cls_data), "nested_in": parent_path},
                    ))
    except zipfile.BadZipFile:
        pass
    return entries
