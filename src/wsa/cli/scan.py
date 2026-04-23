from __future__ import annotations

import json
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

app = typer.Typer(name="wsa", help="Webshell Agent - LangGraph-based malicious file detector")
console = Console()

SCAN_EXTENSIONS = {".jsp", ".jspx", ".class", ".jar", ".war", ".php", ".phtml", ".phar", ".sh", ".bat", ".ps1", ".py"}


def _collect_files(target: Path, include: str | None, exclude: str | None) -> list[Path]:
    files: list[Path] = []
    if target.is_file():
        if target.suffix == ".zip":
            return _extract_zip(target)
        files.append(target)
    elif target.is_dir():
        for f in sorted(target.rglob("*")):
            if not f.is_file():
                continue
            if f.suffix.lower() not in SCAN_EXTENSIONS:
                continue
            if include and not f.match(include):
                continue
            if exclude and f.match(exclude):
                continue
            files.append(f)
    return files


def _extract_zip(zip_path: Path) -> list[Path]:
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="wsa_"))
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(tmp)
    return _collect_files(tmp, None, None)


def _scan_single(file_path: Path, no_llm: bool) -> dict:
    from wsa.graph import get_app_no_checkpoint

    app_graph = get_app_no_checkpoint()
    result = app_graph.invoke({"file_path": str(file_path), "no_llm": no_llm})
    return result


def _verdict_style(verdict: str) -> str:
    return {
        "malicious": "[bold red]MALICIOUS[/bold red]",
        "suspicious": "[bold yellow]SUSPICIOUS[/bold yellow]",
        "benign": "[bold green]BENIGN[/bold green]",
        "unknown": "[dim]UNKNOWN[/dim]",
    }.get(verdict, verdict)


@app.command()
def scan(
    target: str = typer.Argument(help="File, directory, or ZIP to scan"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, jsonl"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    workers: int = typer.Option(4, "--workers", "-w", help="Parallel workers"),
    include: Optional[str] = typer.Option(None, "--include", help="Glob include pattern"),
    exclude: Optional[str] = typer.Option(None, "--exclude", help="Glob exclude pattern"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM analysis"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Scan files for webshells and malicious code."""
    target_path = Path(target)
    if not target_path.exists():
        console.print(f"[red]Error: {target} not found[/red]")
        raise typer.Exit(3)

    files = _collect_files(target_path, include, exclude)
    if not files:
        console.print("[yellow]No scannable files found[/yellow]")
        raise typer.Exit(0)

    console.print(f"[dim]Scanning {len(files)} file(s)...[/dim]")

    results: list[dict] = []
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TaskProgressColumn(), console=console,
    ) as progress:
        task = progress.add_task("Scanning", total=len(files))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_scan_single, f, no_llm): f for f in files}
            for future in as_completed(futures):
                f = futures[future]
                try:
                    r = future.result()
                    results.append(r)
                except Exception as e:
                    results.append({"file_path": str(f), "verdict": "error", "confidence": 0, "errors": [str(e)], "evidences": []})
                progress.advance(task)

    _output_results(results, format, output, verbose)

    counts = {"malicious": 0, "suspicious": 0, "benign": 0, "unknown": 0, "error": 0}
    for r in results:
        v = r.get("verdict", "unknown")
        counts[v] = counts.get(v, 0) + 1

    _print_summary(counts, len(results))

    if counts["malicious"] > 0:
        raise typer.Exit(1)
    if counts["suspicious"] > 0:
        raise typer.Exit(2)
    if counts["error"] > 0:
        raise typer.Exit(3)
    raise typer.Exit(0)


def _output_results(results: list[dict], fmt: str, output_path: str | None, verbose: bool):
    if fmt == "json":
        data = json.dumps([_serialize(r) for r in results], indent=2, ensure_ascii=False)
        if output_path:
            Path(output_path).write_text(data, encoding="utf-8")
        else:
            console.print(data)
    elif fmt == "jsonl":
        lines = [json.dumps(_serialize(r), ensure_ascii=False) for r in results]
        text = "\n".join(lines)
        if output_path:
            Path(output_path).write_text(text, encoding="utf-8")
        else:
            for line in lines:
                console.print(line)
    else:
        _print_table(results, verbose)


def _print_table(results: list[dict], verbose: bool):
    table = Table(title="Scan Results", show_lines=True)
    table.add_column("File", style="cyan", max_width=50)
    table.add_column("Stack", style="dim")
    table.add_column("Verdict", justify="center")
    table.add_column("Confidence", justify="right")
    table.add_column("Evidence", justify="right")
    if verbose:
        table.add_column("Top Evidence", max_width=60)

    for r in sorted(results, key=lambda x: x.get("confidence", 0), reverse=True):
        fp = Path(r.get("file_path", "")).name
        stack = r.get("tech_stack", "?")
        verdict = _verdict_style(r.get("verdict", "unknown"))
        conf = f"{r.get('confidence', 0):.1%}"
        ev_count = str(len(r.get("evidences", [])))
        row = [fp, stack, verdict, conf, ev_count]
        if verbose:
            top = r.get("evidences", [])[:2]
            top_str = "; ".join(f"{e.get('source')}/{e.get('rule_id')}" for e in top)
            row.append(top_str)
        table.add_row(*row)

    console.print(table)


def _print_summary(counts: dict, total: int):
    parts = []
    if counts["malicious"]:
        parts.append(f"[red]{counts['malicious']} malicious[/red]")
    if counts["suspicious"]:
        parts.append(f"[yellow]{counts['suspicious']} suspicious[/yellow]")
    if counts["benign"]:
        parts.append(f"[green]{counts['benign']} benign[/green]")
    if counts["unknown"]:
        parts.append(f"[dim]{counts['unknown']} unknown[/dim]")
    if counts["error"]:
        parts.append(f"[red]{counts['error']} errors[/red]")

    summary = f"Total: {total} | " + " | ".join(parts)
    console.print(Panel(summary, title="Summary"))


def _serialize(result: dict) -> dict:
    return {
        "file_path": result.get("file_path", ""),
        "tech_stack": result.get("tech_stack", ""),
        "verdict": result.get("verdict", "unknown"),
        "confidence": result.get("confidence", 0),
        "evidence_count": len(result.get("evidences", [])),
        "evidences": result.get("evidences", []),
        "errors": result.get("errors", []),
    }


def main():
    app()


if __name__ == "__main__":
    main()
