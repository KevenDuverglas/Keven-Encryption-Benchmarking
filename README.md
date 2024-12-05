# Encryption Benchmarking Tool

An **Encryption Benchmarking Tool** designed to evaluate and compare the performance of various encryption algorithms. This tool provides insights into encryption speed, memory usage, and resource efficiency, aiding in selecting the most suitable algorithm for specific applications and environments.

## Supported Algorithms

- **AES** (Advanced Encryption Standard)
- **RSA** (Rivest–Shamir–Adleman)
- **ECC** (Elliptic Curve Cryptography)

---

## Features

- **Encryption**: Secure files using AES, RSA, or ECC.
- **Decryption**: Recover encrypted files to their original state.
- **Benchmarking**: Evaluate algorithms based on speed, memory usage, and efficiency.
- **Cross-Algorithm Comparison**: Understand trade-offs between different encryption techniques.

---

## Installation

```bash
git clone git@github.com:KevenDuverglas/Keven-Encryption-Benchmarking.git 
```

### Install dependencies using Poetry:

```bash
poetry install
```

## Usage

## Encrypt and Benchmark

Encrypt a file and benchmark the performance of a selected algorithm:

```bash
poetry run encryption_benchmark encrypt --file-path /path/to/your/file.jpg --algorithm AES --rounds 5
```

### Options:
* `--file-path`: Path to the input file.
* `--algorithm`: The encryption algorithm to use (AES, RSA, or ECC).
* `--rounds`: Number of benchmarking rounds.

## Decrypt Files

Decrypt previously encrypted files:

```bash
poetry run encryption_benchmark decrypt --algorithm AES --input-folder /path/to/encrypted_files --output-folder /path/to/decrypted_files
```

### Options:
* `--algorithm`: The decryption algorithm used (AES, RSA, or ECC).
* `--input-folder`: Folder containing encrypted files.
* `--output-folder` : Destination folder for decrypted files.

## Examples

### Encrypt and Benchmark with RSA

```bash
poetry run encryption_benchmark encrypt --file-path /home/user/sample.jpg --algorithm RSA --rounds 3
```

### Decrypt Files Encrypted with AES

```bash
poetry run encryption_benchmark decrypt --algorithm AES --input-folder encrypted_files_aes --output-folder decrypted_files
```

    