import typer
from enum import Enum
from rich.console import Console

cli = typer.Typer()
console = Console()

class Algorithm(str, Enum):
    aes = "AES"
    rsa = "RSA"
    ecc = "ECC"

@cli.command()
def run(
    file_path: str = typer.Argument(..., help="Path to the JPEG file to benchmark."),
    algorithm: Algorithm = typer.Option(..., "--algorithm", help="Encryption algorithm to benchmark."),
    rounds: int = typer.Option(5, "--rounds", help="Number of benchmarking rounds."),
):
    """Test argument parsing."""
    console.print(f"File Path: {file_path}")
    console.print(f"Algorithm: {algorithm}")
    console.print(f"Rounds: {rounds}")

if __name__ == "__main__":
    cli()