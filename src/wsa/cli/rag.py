from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

rag_app = typer.Typer(name="rag", help="RAG index management for LLM judge")
console = Console()


@rag_app.command()
def build(
    fixture_dir: Optional[str] = typer.Option(None, "--fixtures", help="Fixture directory"),
    rules_dir: Optional[str] = typer.Option(None, "--rules", help="Regex rules directory"),
    index_dir: Optional[str] = typer.Option(None, "--index-dir", help="Output index directory"),
):
    """Build RAG index from fixtures and rules."""
    from wsa.rag.index_builder import build_index

    count = build_index(
        fixture_dir=Path(fixture_dir) if fixture_dir else None,
        rules_dir=Path(rules_dir) if rules_dir else None,
        index_dir=Path(index_dir) if index_dir else None,
    )
    console.print(f"[green]Built index with {count} documents[/green]")


@rag_app.command()
def add(
    file: str = typer.Argument(help="File to add to corpus"),
    label: str = typer.Option("malicious", "--label", "-l", help="Label: malicious, benign, hard_negative"),
    tags: Optional[str] = typer.Option(None, "--tags", "-t", help="Comma-separated tags"),
    index_dir: Optional[str] = typer.Option(None, "--index-dir", help="Index directory"),
):
    """Add a single file to the RAG corpus."""
    from wsa.rag.index_builder import add_file

    tag_list = [t.strip() for t in tags.split(",")] if tags else None
    doc = add_file(
        file_path=Path(file),
        label=label,
        tags=tag_list,
        index_dir=Path(index_dir) if index_dir else None,
    )
    console.print(f"[green]Added {doc.doc_id} ({doc.label}/{doc.tech_stack})[/green]")


@rag_app.command()
def stats(
    index_dir: Optional[str] = typer.Option(None, "--index-dir", help="Index directory"),
):
    """Show corpus statistics."""
    from wsa.config import settings
    from wsa.rag.store import VectorStore

    idx = Path(index_dir) if index_dir else settings.rag_index_dir
    store = VectorStore()
    store.load(idx)
    if store.size == 0:
        console.print("[yellow]No index found. Run 'wsa rag build' first.[/yellow]")
        return

    by_label: dict[str, int] = {}
    by_stack: dict[str, int] = {}
    for doc in store._docs:
        by_label[doc.label] = by_label.get(doc.label, 0) + 1
        by_stack[doc.tech_stack] = by_stack.get(doc.tech_stack, 0) + 1

    table = Table(title=f"RAG Corpus ({store.size} documents)")
    table.add_column("Dimension")
    table.add_column("Value")
    table.add_column("Count", justify="right")
    for label, count in sorted(by_label.items()):
        table.add_row("label", label, str(count))
    for stack, count in sorted(by_stack.items()):
        table.add_row("tech_stack", stack, str(count))
    console.print(table)


@rag_app.command()
def search(
    query: str = typer.Argument(help="Search query text"),
    top_k: int = typer.Option(5, "--top-k", "-k", help="Number of results"),
    stack: Optional[str] = typer.Option(None, "--stack", help="Filter by tech_stack"),
    index_dir: Optional[str] = typer.Option(None, "--index-dir", help="Index directory"),
):
    """Search the RAG corpus (debug tool)."""
    from wsa.config import settings
    from wsa.rag.embedder import get_embedder
    from wsa.rag.store import VectorStore

    idx = Path(index_dir) if index_dir else settings.rag_index_dir
    store = VectorStore()
    store.load(idx)
    if store.size == 0:
        console.print("[yellow]No index found. Run 'wsa rag build' first.[/yellow]")
        return

    embedder = get_embedder()
    q_emb = embedder.embed([query])
    results = store.search(q_emb[0], top_k=top_k, filter_stack=stack, threshold=0.0)

    table = Table(title=f"Search results for: {query[:60]}")
    table.add_column("Score", justify="right")
    table.add_column("Label")
    table.add_column("Stack")
    table.add_column("Source", max_width=40)
    table.add_column("Tags")
    for doc, score in results:
        table.add_row(
            f"{score:.3f}",
            doc.label,
            doc.tech_stack,
            Path(doc.source_path).name,
            ", ".join(doc.tags[:5]),
        )
    console.print(table)
