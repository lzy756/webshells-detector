from __future__ import annotations

import base64
import re

from wsa.state import ScanState


def _try_base64_decode(content: str) -> str:
    def replacer(m: re.Match) -> str:
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            return decoded
        except Exception:
            return m.group(0)

    return re.sub(r'(?:Base64\.getDecoder\(\)\.decode|base64Decode|atob)\s*\(\s*"([A-Za-z0-9+/=]+)"\s*\)', replacer, content)


def _try_hex_decode(content: str) -> str:
    def replacer(m: re.Match) -> str:
        try:
            return bytes.fromhex(m.group(1).replace("\\x", "")).decode("utf-8", errors="replace")
        except Exception:
            return m.group(0)

    return re.sub(r'(?:\\x[0-9a-fA-F]{2}){4,}', lambda m: bytes(
        int(m.group(0)[i + 2:i + 4], 16) for i in range(0, len(m.group(0)), 4)
    ).decode("utf-8", errors="replace"), content)


def deobfuscate_node(state: ScanState) -> dict:
    raw = state.get("file_bytes", b"")
    try:
        content = raw.decode("utf-8", errors="replace")
    except Exception:
        return {"deobfuscated": None, "deobfuscation_layers": 0}

    layers = 0
    for _ in range(5):
        prev = content
        content = _try_base64_decode(content)
        content = _try_hex_decode(content)
        if content == prev:
            break
        layers += 1

    if layers == 0:
        return {"deobfuscated": None, "deobfuscation_layers": 0}
    return {"deobfuscated": content, "deobfuscation_layers": layers}
