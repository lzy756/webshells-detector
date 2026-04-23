from __future__ import annotations

import logging
import re
from pathlib import Path

import yaml

from wsa.config import settings
from wsa.rag.corpus import CorpusDocument
from wsa.rag.embedder import get_embedder
from wsa.rag.store import VectorStore

logger = logging.getLogger(__name__)

FIXTURE_LABEL_MAP = {
    "malicious": "malicious",
    "benign": "benign",
    "hard_negatives": "hard_negative",
}

STACK_BY_EXT = {
    ".jsp": "jsp",
    ".jspx": "jsp",
    ".java": "java_class",
    ".class": "java_class",
    ".php": "php",
    ".phtml": "php",
}


def _detect_stack(path: Path) -> str:
    return STACK_BY_EXT.get(path.suffix.lower(), "unknown")


def _match_regex_rules(code: str, rules_dir: Path) -> tuple[list[str], list[str]]:
    matched_ids: list[str] = []
    tags: set[str] = set()
    for yaml_file in sorted(rules_dir.glob("*.yaml")):
        with open(yaml_file, encoding="utf-8") as f:
            rules = yaml.safe_load(f) or []
        for rule in rules:
            pattern = rule.get("pattern", "")
            try:
                if re.search(pattern, code):
                    matched_ids.append(rule["id"])
                    tags.update(rule.get("tags", []))
            except re.error:
                continue
    return matched_ids, sorted(tags)


def _scan_fixture_dir(fixture_dir: Path, rules_dir: Path) -> list[CorpusDocument]:
    docs: list[CorpusDocument] = []
    for label_dir_name, label in FIXTURE_LABEL_MAP.items():
        label_dir = fixture_dir / label_dir_name
        if not label_dir.is_dir():
            continue
        for f in sorted(label_dir.iterdir()):
            if not f.is_file():
                continue
            try:
                code = f.read_text(encoding="utf-8", errors="replace")[:4000]
            except Exception:
                continue
            stack = _detect_stack(f)
            matched_ids, tags = _match_regex_rules(code, rules_dir)
            docs.append(
                CorpusDocument(
                    source_path=str(f),
                    label=label,
                    tech_stack=stack,
                    tags=tags,
                    code_snippet=code,
                    matched_rules=matched_ids,
                )
            )
    return docs


def _scan_rules(rules_dir: Path) -> list[CorpusDocument]:
    docs: list[CorpusDocument] = []
    for yaml_file in sorted(rules_dir.glob("*.yaml")):
        with open(yaml_file, encoding="utf-8") as f:
            rules = yaml.safe_load(f) or []
        for rule in rules:
            rid = rule.get("id", "")
            desc = rule.get("description", "")
            stack = rule.get("stack", "unknown")
            tags = rule.get("tags", [])
            severity = rule.get("severity", "medium")
            summary = f"[rule] {stack} detection rule\nID: {rid}\nDescription: {desc}\nSeverity: {severity}\nTags: {', '.join(tags)}"
            docs.append(
                CorpusDocument(
                    source_path=f"rule:{rid}",
                    label="malicious",
                    tech_stack=stack,
                    tags=tags,
                    code_snippet=rule.get("pattern", ""),
                    feature_summary=summary,
                    matched_rules=[rid],
                )
            )
    return docs


def build_index(
    fixture_dir: Path | None = None,
    rules_dir: Path | None = None,
    index_dir: Path | None = None,
) -> int:
    if fixture_dir is None:
        fixture_dir = Path("tests/fixtures")
    if rules_dir is None:
        rules_dir = settings.regex_dir
    if index_dir is None:
        index_dir = settings.rag_index_dir

    docs: list[CorpusDocument] = []
    if fixture_dir.is_dir():
        docs.extend(_scan_fixture_dir(fixture_dir, rules_dir))
        logger.info("Scanned fixtures: %d documents", len(docs))
    if rules_dir.is_dir():
        rule_docs = _scan_rules(rules_dir)
        docs.extend(rule_docs)
        logger.info("Scanned rules: %d documents", len(rule_docs))

    if not docs:
        logger.warning("No documents found to index")
        return 0

    embedder = get_embedder()
    summaries = [d.feature_summary for d in docs]
    embeddings = embedder.embed(summaries)

    store = VectorStore()
    store.add(docs, embeddings)
    store.save(index_dir)
    logger.info("Built RAG index: %d documents at %s", len(docs), index_dir)
    return len(docs)


def add_file(
    file_path: Path,
    label: str,
    tags: list[str] | None = None,
    index_dir: Path | None = None,
) -> CorpusDocument:
    if index_dir is None:
        index_dir = settings.rag_index_dir

    code = file_path.read_text(encoding="utf-8", errors="replace")[:4000]
    stack = _detect_stack(file_path)
    matched_ids, auto_tags = _match_regex_rules(code, settings.regex_dir)
    all_tags = sorted(set((tags or []) + auto_tags))

    doc = CorpusDocument(
        source_path=str(file_path),
        label=label,
        tech_stack=stack,
        tags=all_tags,
        code_snippet=code,
        matched_rules=matched_ids,
    )

    embedder = get_embedder()
    emb = embedder.embed([doc.feature_summary])

    store = VectorStore()
    store.load(index_dir)
    store.add([doc], emb)
    store.save(index_dir)
    return doc
