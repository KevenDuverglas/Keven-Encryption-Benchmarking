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
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_pem_private_key, PublicFormat
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

    @staticmethod
    def from_string(value: str):
        try:
            return Algorithm[value.lower()]
        except KeyError:
            raise ValueError(f"Unsupported algorithm '{value}'")

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

def decrypt_aes(key: bytes, ciphertext: bytes) -> Tuple[bytes, float]:
    iv, actual_ciphertext = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    start_time = time.time()
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    decryption_time = time.time() - start_time
    return plaintext, decryption_time

def encrypt_rsa(public_key, plaintext: bytes) -> Tuple[bytes, bytes]:
    aes_key = generate_aes_key()
    ciphertext = encrypt_aes(aes_key, plaintext)
    # Encrypt the AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_key, ciphertext

def decrypt_rsa(private_key, encrypted_key: bytes, ciphertext: bytes) -> Tuple[bytes, float]:
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    plaintext, decryption_time = decrypt_aes(aes_key, ciphertext)
    return plaintext, decryption_time

def encrypt_ecc(public_key, plaintext: bytes) -> bytes:
    """Encrypt data using ECC (simulated via shared key derived from the public key)."""
    shared_key = public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )  # Serialize the public key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ECC",
        backend=default_backend()
    ).derive(shared_key)
    return encrypt_aes(aes_key, plaintext)

def decrypt_ecc(private_key, ciphertext: bytes) -> Tuple[bytes, float]:
    shared_key = private_key.public_key().public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )  # Serialize the public key from the private key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ECC",
        backend=default_backend()
    ).derive(shared_key)
    plaintext, decryption_time = decrypt_aes(aes_key, ciphertext)
    return plaintext, decryption_time

def benchmark_encryption(
    algorithm: Algorithm, file_path: str
) -> List[Tuple[int, float, float, float, float]]:
    results = []
    with open(file_path, "rb") as f:
        plaintext = f.read()

    output_dir = f"encrypted_files_{algorithm.value.lower()}"
    os.makedirs(output_dir, exist_ok=True)

    tracemalloc.start()
    start_time = time.time()

    if algorithm == Algorithm.aes:
        key = generate_aes_key()
        ciphertext = encrypt_aes(key, plaintext)

        # Save AES key
        aes_key_path = os.path.join(output_dir, "aes_key.bin")
        with open(aes_key_path, "wb") as key_file:
            key_file.write(key)
        console.print(f"AES key saved: {aes_key_path}")

        # Save AES ciphertext
        ciphertext_file_path = os.path.join(output_dir, "encrypted_file.bin")
        with open(ciphertext_file_path, "wb") as encrypted_file:
            encrypted_file.write(ciphertext)
        console.print(f"Encrypted file saved: {ciphertext_file_path}")

        _, decryption_time = decrypt_aes(key, ciphertext)

    elif algorithm == Algorithm.rsa:
        private_key, public_key = generate_rsa_keys()

        # Save RSA private key
        private_key_path = os.path.join(output_dir, "private_key.pem")
        with open(private_key_path, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption()
            ))
        console.print(f"Private key saved: {private_key_path}")

        # Encrypt the data
        encrypted_key, ciphertext = encrypt_rsa(public_key, plaintext)

        # Save RSA encrypted key
        encrypted_key_file_path = os.path.join(output_dir, "encrypted_key.bin")
        with open(encrypted_key_file_path, "wb") as key_file:
            key_file.write(encrypted_key)
        console.print(f"Encrypted key saved: {encrypted_key_file_path}")

        # Save RSA ciphertext
        ciphertext_file_path = os.path.join(output_dir, "encrypted_file.bin")
        with open(ciphertext_file_path, "wb") as encrypted_file:
            encrypted_file.write(ciphertext)
        console.print(f"Encrypted file saved: {ciphertext_file_path}")

        _, decryption_time = decrypt_rsa(private_key, encrypted_key, ciphertext)

    elif algorithm == Algorithm.ecc:
        private_key, public_key = generate_ecc_keys()

        # Save ECC private key
        private_key_path = os.path.join(output_dir, "ecc_private_key.pem")
        with open(private_key_path, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))
        console.print(f"ECC private key saved: {private_key_path}")

        ciphertext = encrypt_ecc(public_key, plaintext)

        # Save ECC ciphertext
        ciphertext_file_path = os.path.join(output_dir, "encrypted_file.bin")
        with open(ciphertext_file_path, "wb") as encrypted_file:
            encrypted_file.write(ciphertext)
        console.print(f"Encrypted file saved: {ciphertext_file_path}")

        _, decryption_time = decrypt_ecc(private_key, ciphertext)

    else:
        raise ValueError("Unsupported algorithm")

    end_time = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    results.append((len(plaintext), end_time - start_time, current / (1024**2), peak / (1024**2), decryption_time))

    return results


def print_combined_results(all_results: List[Tuple[str, int, float, float, float, int, int, float, str]]) -> None:
    table = Table(title="Encryption Benchmark Results")
    table.add_column("Algorithm", justify="left", style="cyan")
    table.add_column("File Size (bytes)", justify="right", style="cyan")
    table.add_column("Time (s)", justify="right", style="magenta")
    table.add_column("Current Memory (MiB)", justify="right", style="green")
    table.add_column("Peak Memory (MiB)", justify="right", style="green")
    table.add_column("Key Size (bits)", justify="right", style="blue")
    table.add_column("Encrypted File Size (bytes)", justify="right", style="green")
    table.add_column("Throughput (MB/s)", justify="right", style="green")
    table.add_column("Algorithm Strength", justify="left", style="cyan")

    for result in all_results:
        table.add_row(
            result[0],
            str(result[1]),
            f"{result[2]:.6f}",
            f"{result[3]:.6f}",
            f"{result[4]:.6f}",
            str(result[5]),
            str(result[6]),
            f"{result[7]:.2f}",
            result[8]
        )
    console.print(table)


@cli.command()
def encrypt(
    file_path: str = typer.Option(..., "--file-path", help="Path to the file to benchmark."),
    algorithm: str = typer.Option("ALL", "--algorithm", help="Encryption algorithm to benchmark. Use 'ALL' to test all algorithms."),
):
    """
    Encrypt files and benchmark the algorithms.
    """
    if algorithm.upper() == "ALL":
        all_results = []
        for alg in Algorithm:
            console.print(f"Benchmarking {alg.value} with file: {file_path}")
            results = benchmark_encryption(alg, file_path)

            for result in results:
                encryption_time = result[1]
                current_memory = result[2]
                peak_memory = result[3]
                plaintext = open(file_path, "rb").read()
                ciphertext_path = f"encrypted_files_{alg.value.lower()}/encrypted_file.bin"
                
                # Ensure ciphertext file is read correctly
                with open(ciphertext_path, "rb") as ct_file:
                    ciphertext = ct_file.read()

                encrypted_file_size = len(ciphertext)

                all_results.append(
                    (
                        alg.value,
                        len(plaintext),
                        encryption_time,
                        current_memory / (1024**2),
                        peak_memory / (1024**2),
                        256 if alg == Algorithm.aes else (2048 if alg == Algorithm.rsa else 256),
                        encrypted_file_size,
                        len(plaintext) / encryption_time / (1024**2),
                        "High" if alg != Algorithm.rsa else "Moderate"
                    )
                )
        print_combined_results(all_results)
    else:
        try:
            alg = Algorithm.from_string(algorithm)
        except ValueError as e:
            console.print(f"[red]{str(e)}[/red]")
            return

        console.print(f"Benchmarking {alg.value} with file: {file_path}")
        results = benchmark_encryption(alg, file_path)
        for result in results:
            ciphertext_path = f"encrypted_files_{alg.value.lower()}/encrypted_file.bin"
            with open(ciphertext_path, "rb") as ct_file:
                ciphertext = ct_file.read()
            encrypted_file_size = len(ciphertext)
            throughput = result[0] / result[1] / (1024**2)
            all_results = [(alg.value, result[0], result[1], result[2], result[3], 256, encrypted_file_size, throughput, "High")]
        print_combined_results(all_results)



@cli.command()
def decrypt(
    algorithm: Algorithm = typer.Option(..., "--algorithm", help="Encryption algorithm used."),
    input_folder: str = typer.Option(..., "--input-folder", help="Folder containing encrypted files."),
    output_folder: str = typer.Option("./decrypted_files", "--output-folder", help="Folder to save decrypted files."),
    original_file: str = typer.Option(None, "--original-file", help="Path to the original file for comparison."),
):
    """
    Decrypt all encrypted files in the specified folder.
    """
    os.makedirs(output_folder, exist_ok=True)
    console.print(f"Decrypting files in folder: {input_folder} using {algorithm.value}")

    if algorithm == Algorithm.aes:
        aes_key_path = os.path.join(input_folder, "aes_key.bin")
        ciphertext_file_path = os.path.join(input_folder, "encrypted_file.bin")

        if not os.path.exists(aes_key_path):
            console.print(f"AES key file missing: {aes_key_path}", style="red")
            return

        if not os.path.exists(ciphertext_file_path):
            console.print(f"AES ciphertext file missing: {ciphertext_file_path}", style="red")
            return

        with open(aes_key_path, "rb") as key_file:
            aes_key = key_file.read()

        with open(ciphertext_file_path, "rb") as ciphertext_file:
            ciphertext = ciphertext_file.read()

        console.print(f"AES key loaded from: {aes_key_path}")

        decrypted, decryption_time = decrypt_aes(aes_key, ciphertext)

        output_file_path = os.path.join(output_folder, "decrypted_file")
        with open(output_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted)

        console.print(f"Decrypted file saved: {output_file_path}")

    elif algorithm == Algorithm.rsa:
        private_key_path = os.path.join(input_folder, "private_key.pem")
        if not os.path.exists(private_key_path):
            console.print(f"RSA private key file missing: {private_key_path}", style="red")
            return
        with open(private_key_path, "rb") as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        console.print(f"RSA private key loaded from: {private_key_path}")

        key_file_path = os.path.join(input_folder, "encrypted_key.bin")
        ciphertext_file_path = os.path.join(input_folder, "encrypted_file.bin")

        if not os.path.exists(key_file_path) or not os.path.exists(ciphertext_file_path):
            console.print(f"Missing key or ciphertext file: {key_file_path} or {ciphertext_file_path}", style="red")
            return

        with open(key_file_path, "rb") as key_file, open(ciphertext_file_path, "rb") as ciphertext_file:
            encrypted_key = key_file.read()
            ciphertext = ciphertext_file.read()

        decrypted, decryption_time = decrypt_rsa(private_key, encrypted_key, ciphertext)

        output_file_path = os.path.join(output_folder, "decrypted_file")
        with open(output_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted)

        console.print(f"Decrypted file saved: {output_file_path}")

    elif algorithm == Algorithm.ecc:
        ecc_private_key_path = os.path.join(input_folder, "ecc_private_key.pem")
        if not os.path.exists(ecc_private_key_path):
            console.print(f"ECC private key file missing: {ecc_private_key_path}", style="red")
            return
        with open(ecc_private_key_path, "rb") as key_file:
            ecc_private_key = load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        console.print(f"ECC private key loaded from: {ecc_private_key_path}")

        ciphertext_file_path = os.path.join(input_folder, "encrypted_file.bin")

        if not os.path.exists(ciphertext_file_path):
            console.print(f"Missing ciphertext file: {ciphertext_file_path}", style="red")
            return

        with open(ciphertext_file_path, "rb") as ciphertext_file:
            ciphertext = ciphertext_file.read()

        # Unpack the tuple returned by decrypt_ecc
        decrypted, _ = decrypt_ecc(ecc_private_key, ciphertext)

        output_file_path = os.path.join(output_folder, "decrypted_file")
        with open(output_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted)

        console.print(f"Decrypted file saved: {output_file_path}")


    if original_file:
        with open(original_file, "rb") as original, open(output_file_path, "rb") as decrypted:
            original_data = original.read()
            decrypted_data = decrypted.read()

        if original_data == decrypted_data:
            console.print("[green]Success: The decrypted file matches the original file.")
        else:
            console.print("[red]Error: The decrypted file does not match the original file.")

if __name__ == "__main__":
    cli()