"""
Demo runner — fires all prompts from data/demo_prompts.json against the
running Shadow Developer Interceptor and pretty-prints the results.

Usage:
    python scripts/run_demo.py [--url http://localhost:8000]
"""
import json
import sys
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

console = Console()
cli = typer.Typer()

STATUS_STYLE = {
    "passed": "green",
    "needs_revision": "yellow",
    "failed": "bold red",
    "in_progress": "blue",
    "pending": "dim",
}


@cli.command()
def main(url: str = typer.Argument("http://localhost:8000", help="Base URL of the Shadow Developer server")):
    """Run all demo prompts and display results."""
    demo_file = Path(__file__).parent.parent / "data" / "demo_prompts.json"
    demos = json.loads(demo_file.read_text())

    console.rule("[bold cyan]Shadow Developer — Demo Run[/bold cyan]")

    for i, demo in enumerate(demos, 1):
        label = demo["label"]
        payload = demo["request"]

        console.print(f"\n[bold]{i}. {label}[/bold]")
        console.print(f"   Prompt: [dim]{payload['prompt'][:80]}...[/dim]" if len(payload["prompt"]) > 80 else f"   Prompt: [dim]{payload['prompt']}[/dim]")

        try:
            resp = httpx.post(f"{url}/api/v1/intercept", json=payload, timeout=30)
            if resp.status_code != 200:
                console.print(f"   [red]HTTP {resp.status_code}: {resp.text}[/red]")
                continue

            data = resp.json()
            status = data["status"]
            style = STATUS_STYLE.get(status, "white")
            console.print(f"   Status:  [{style}]{status.upper()}[/{style}]")
            console.print(f"   Message: {data['message']}")

            if data["conflicts"]:
                table = Table(show_header=True, header_style="bold magenta", padding=(0, 1))
                table.add_column("Severity", style="bold", width=10)
                table.add_column("Category", width=18)
                table.add_column("Description")
                for c in data["conflicts"]:
                    sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}.get(c["severity"], "white")
                    table.add_row(
                        f"[{sev_style}]{c['severity']}[/{sev_style}]",
                        c["category"],
                        c["description"][:90],
                    )
                console.print(table)

            if data["recommended_tests"]:
                console.print("   [cyan]Recommended Tests:[/cyan]")
                for t in data["recommended_tests"][:3]:
                    console.print(f"     • {t}")

        except httpx.ConnectError:
            console.print(f"   [red]Cannot connect to {url} — is the server running? Run: make run[/red]")
            sys.exit(1)

    console.rule("[bold cyan]Demo Complete[/bold cyan]")


if __name__ == "__main__":
    cli()
