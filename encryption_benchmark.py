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
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ECC",
        backend=default_backend()
    ).derive(shared_key)
    return encrypt_aes(aes_key, plaintext)
def decrypt_ecc(private_key, ciphertext: bytes) -> bytes:
    """Decrypt data using ECC (simulated via shared key derived from the private key)."""
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
    return decrypt_aes(aes_key, ciphertext)


def benchmark_encryption(
    algorithm: Algorithm, file_path: str, rounds: int
) -> List[Tuple[int, float, float, float]]:
    results = []
    with open(file_path, "rb") as f:
        plaintext = f.read()

    output_dir = f"encrypted_files_{algorithm.value.lower()}"
    os.makedirs(output_dir, exist_ok=True)

    for round_number in range(rounds):
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
            ciphertext_file_path = os.path.join(output_dir, f"round_{round_number + 1}.bin")
            with open(ciphertext_file_path, "wb") as encrypted_file:
                encrypted_file.write(ciphertext)
            console.print(f"Encrypted file saved: {ciphertext_file_path}")

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
            encrypted_key_file_path = os.path.join(output_dir, f"round_{round_number + 1}_key.bin")
            with open(encrypted_key_file_path, "wb") as key_file:
                key_file.write(encrypted_key)
            console.print(f"Encrypted key saved: {encrypted_key_file_path}")

            # Save RSA ciphertext
            ciphertext_file_path = os.path.join(output_dir, f"round_{round_number + 1}.bin")
            with open(ciphertext_file_path, "wb") as encrypted_file:
                encrypted_file.write(ciphertext)
            console.print(f"Encrypted file saved: {ciphertext_file_path}")

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
            ciphertext_file_path = os.path.join(output_dir, f"round_{round_number + 1}.bin")
            with open(ciphertext_file_path, "wb") as encrypted_file:
                encrypted_file.write(ciphertext)
            console.print(f"Encrypted file saved: {ciphertext_file_path}")

        else:
            raise ValueError("Unsupported algorithm")

        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

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
def encrypt(
    file_path: str = typer.Option(..., "--file-path", help="Path to the JPEG file to benchmark."),
    algorithm: Algorithm = typer.Option(..., "--algorithm", help="Encryption algorithm to benchmark."),
    rounds: int = typer.Option(5, "--rounds", help="Number of benchmarking rounds."),
):
    """
    Encrypt all encrypted files in the specified folder.
    """
    console.print(f"Benchmarking {algorithm.value} with file: {file_path}")
    results = benchmark_encryption(algorithm, file_path, rounds)
    print_results(algorithm, results)
@cli.command()
def decrypt(
    algorithm: Algorithm = typer.Option(..., "--algorithm", help="Encryption algorithm used."),
    input_folder: str = typer.Option(..., "--input-folder", help="Folder containing encrypted files."),
    output_folder: str = typer.Option("./decrypted_files", "--output-folder", help="Folder to save decrypted files."),
):
    """
    Decrypt all encrypted files in the specified folder.
    """
    os.makedirs(output_folder, exist_ok=True)
    console.print(f"Decrypting files in folder: {input_folder} using {algorithm.value}")

    if algorithm == Algorithm.aes:
        aes_key_path = os.path.join(input_folder, "aes_key.bin")
        if not os.path.exists(aes_key_path):
            console.print(f"AES key file missing: {aes_key_path}", style="red")
            return
        with open(aes_key_path, "rb") as key_file:
            aes_key = key_file.read()
        console.print(f"AES key loaded from: {aes_key_path}")

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

    else:
        console.print(f"Unsupported algorithm: {algorithm.value}", style="red")
        return

    for file_name in os.listdir(input_folder):
        if file_name.endswith("_key.bin") and algorithm == Algorithm.rsa:
            key_file_path = os.path.join(input_folder, file_name)
            ciphertext_file_path = key_file_path.replace("_key.bin", ".bin")

            if not os.path.exists(ciphertext_file_path):
                console.print(f"Missing ciphertext file for key: {key_file_path}", style="red")
                continue

            # Read both the key and the ciphertext
            with open(key_file_path, "rb") as key_file, open(ciphertext_file_path, "rb") as ciphertext_file:
                encrypted_key = key_file.read()
                ciphertext = ciphertext_file.read()

            # Perform decryption
            decrypted = decrypt_rsa(private_key, encrypted_key, ciphertext)

            # Save the decrypted output
            output_file_path = os.path.join(output_folder, f"decrypted_{file_name.replace('_key.bin', '')}")
            with open(output_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted)

            console.print(f"Decrypted file saved: {output_file_path}")

        elif algorithm == Algorithm.aes:
            ciphertext_file_path = os.path.join(input_folder, file_name)

            # Read the ciphertext
            with open(ciphertext_file_path, "rb") as ciphertext_file:
                ciphertext = ciphertext_file.read()

            # Perform decryption
            decrypted = decrypt_aes(aes_key, ciphertext)

            # Save the decrypted output
            output_file_path = os.path.join(output_folder, f"decrypted_{file_name}")
            with open(output_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted)

            console.print(f"Decrypted file saved: {output_file_path}")

        elif algorithm == Algorithm.ecc:
            ciphertext_file_path = os.path.join(input_folder, file_name)

            # Read the ciphertext
            with open(ciphertext_file_path, "rb") as ciphertext_file:
                ciphertext = ciphertext_file.read()

            # Perform decryption
            decrypted = decrypt_ecc(ecc_private_key, ciphertext)

            # Save the decrypted output
            output_file_path = os.path.join(output_folder, f"decrypted_{file_name}")
            with open(output_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted)

            console.print(f"Decrypted file saved: {output_file_path}")

    console.print("Decryption process completed.")


if __name__ == "__main__":
    cli()