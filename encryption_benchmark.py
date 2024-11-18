import os
import time
import tracemalloc
from enum import Enum
from typing import List, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, derive_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.table import Table

import typer

# CLI application
cli = typer.Typer()
console = Console()


class Algorithm(str, Enum):
    """Supported encryption algorithms."""
    aes = "AES"
    rsa = "RSA"
    ecc = "ECC"


def generate_aes_key() -> bytes:
    return os.urandom(32)


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    return private_key, private_key.public_key()


def generate_ecc_keys():
    private_key = derive_private_key(
        private_value=1, curve=SECP256R1(), backend=default_backend()
    )
    return private_key, private_key.public_key()


def encrypt_aes(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()


def decrypt_aes(key: bytes, ciphertext: bytes) -> bytes:
    iv, actual_ciphertext = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(actual_ciphertext) + decryptor.finalize()


def encrypt_rsa(public_key, plaintext: bytes) -> Tuple[bytes, bytes]:
    aes_key = generate_aes_key()
    ciphertext = encrypt_aes(aes_key, plaintext)

    # Encrypt the AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_key, ciphertext



def decrypt_rsa(private_key, encrypted_key: bytes, ciphertext: bytes) -> bytes:
    # Decrypt the AES key
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypt_aes(aes_key, ciphertext)


def encrypt_ecc(public_key, plaintext: bytes) -> bytes:
    """Encrypt data using ECC (simulated via shared key derived from the public key)."""
    shared_key = public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )  # Serialize the public key
    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"ECC", backend=default_backend()
    ).derive(shared_key)
    return encrypt_aes(aes_key, plaintext)


def decrypt_ecc(private_key, ciphertext: bytes) -> bytes:
    """Decrypt data using ECC (simulated via shared key derived from the private key)."""
    shared_key = private_key.public_key().public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )  # Serialize the public key from the private key
    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"ECC", backend=default_backend()
    ).derive(shared_key)
    return decrypt_aes(aes_key, ciphertext)


def benchmark_encryption(
    algorithm: Algorithm, file_path: str, rounds: int
) -> List[Tuple[int, float, float, float]]:
    results = []
    with open(file_path, "rb") as f:
        plaintext = f.read()

    for _ in range(rounds):
        tracemalloc.start()
        start_time = time.time()

        if algorithm == Algorithm.aes:
            key = generate_aes_key()
            ciphertext = encrypt_aes(key, plaintext)
            decrypted = decrypt_aes(key, ciphertext)
        elif algorithm == Algorithm.rsa:
            private_key, public_key = generate_rsa_keys()

            # Hybrid encryption: RSA for AES key, AES for data
            encrypted_key, ciphertext = encrypt_rsa(public_key, plaintext)
            decrypted = decrypt_rsa(private_key, encrypted_key, ciphertext)
        elif algorithm == Algorithm.ecc:
            private_key, public_key = generate_ecc_keys()
            ciphertext = encrypt_ecc(public_key, plaintext)
            decrypted = decrypt_ecc(private_key, ciphertext)
        else:
            raise ValueError("Unsupported algorithm")

        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert plaintext == decrypted, "Decryption failed!"
        results.append((len(plaintext), end_time - start_time, current / (1024**2), peak / (1024**2)))

    return results

def print_results(algorithm: Algorithm, results: List[Tuple[int, float, float, float]]) -> None:
    table = Table(title=f"{algorithm.value} Benchmark Results")
    table.add_column("File Size (bytes)", justify="right", style="cyan")
    table.add_column("Time (s)", justify="right", style="magenta")
    table.add_column("Current Memory (MiB)", justify="right", style="green")
    table.add_column("Peak Memory (MiB)", justify="right", style="green")

    for result in results:
        table.add_row(str(result[0]), f"{result[1]:.6f}", f"{result[2]:.6f}", f"{result[3]:.6f}")

    console.print(table)


@cli.command()
def run(
    file_path: str = typer.Option(..., "--file-path", help="Path to the JPEG file to benchmark."),
    algorithm: Algorithm = typer.Option(..., "--algorithm", help="Encryption algorithm to benchmark."),
    rounds: int = typer.Option(5, "--rounds", help="Number of benchmarking rounds."),
):
    """
    Run encryption benchmarking for the specified algorithm and file.
    """
    console.print(f"Benchmarking {algorithm.value} with file: {file_path}")
    results = benchmark_encryption(algorithm, file_path, rounds)
    print_results(algorithm, results)


if __name__ == "__main__":
    cli()