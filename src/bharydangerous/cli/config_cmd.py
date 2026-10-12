"""Configuration management CLI commands."""
import typer
from rich.console import Console
from rich.table import Table

from bharydangerous.core.config import (
    CONFIG_FILE,
    get_gemini_api_key,
    get_gemini_model,
    get_local_ai_url,
    load_user_config,
    save_user_config,
)

app = typer.Typer(help="Inspect and configure API keys and forensic settings.")
console = Console()

@app.command("show")
def show_config():
    """Display current environment and stored user configuration."""
    cfg = load_user_config()
    api_key = get_gemini_api_key()
    model = get_gemini_model()
    local_url = get_local_ai_url()

    table = Table(title="BHARYDANGEROUS-Investigator Configuration", show_header=True, header_style="bold cyan")
    table.add_column("Setting")
    table.add_column("Configured Value")
    table.add_column("Source")

    if api_key:
        masked = api_key[:6] + "..." + api_key[-4:] if len(api_key) > 10 else "******"
        source = "Environment (GEMINI_API_KEY)" if "GEMINI_API_KEY" in repr(get_gemini_api_key) else "Config File"
        table.add_row("Gemini API Key", f"[green]{masked}[/green]", source)
    else:
        table.add_row("Gemini API Key", "[dim yellow]Not Set (Offline Mock fallback active)[/dim yellow]", "Default")

    table.add_row("Gemini Model", model, "Configured")
    table.add_row("Local AI URL", local_url, "Configured")
    table.add_row("Config File Path", str(CONFIG_FILE), "Local User Profile")

    console.print(table)

@app.command("set-api-key")
def set_api_key(
    key: str = typer.Argument(..., help="Google Gemini API key (e.g., AIzaSy...)."),
):
    """Securely store Gemini API key in local user configuration (~/.bharydangerous/config.json)."""
    cfg = load_user_config()
    cfg["gemini_api_key"] = key.strip()
    save_user_config(cfg)
    masked = key[:6] + "..." + key[-4:] if len(key) > 10 else "******"
    console.print(f"[bold green]✓[/bold green] Gemini API key saved successfully: [bold]{masked}[/bold]")
    console.print(f"[dim]Stored in restricted config: {CONFIG_FILE}[/dim]")

@app.command("set-model")
def set_model(
    model_name: str = typer.Argument(..., help="Model name (e.g., gemini-2.5-flash)."),
):
    """Set default Gemini reasoning model."""
    cfg = load_user_config()
    cfg["gemini_model"] = model_name.strip()
    save_user_config(cfg)
    console.print(f"[bold green]✓[/bold green] Default model updated to: [bold]{model_name}[/bold]")
