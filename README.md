# Encryption Benchmark Tool 

## Overview
This project provides a command-line interface (CLI) tool for benchmarking encryption and decryption operations using three algorithms: AES, RSA, and ECC. The tool evaluates their performance and outputs the results in a tabular format for easy comparison.

### Features Added:
1. **Support for Multiple Encryption Algorithms**:
   - AES
   - RSA
   - ECC

2. **Detailed Benchmark Table**:
   - Algorithm
   - File Size (bytes)
   - Encryption Time (s)
   - Current Memory Usage (MiB)
   - Peak Memory Usage (MiB)
   - Key Size (bits)
   - Encrypted File Size (bytes)
   - Throughput (MB/s)
   - Algorithm Strength

3. **Decryption with Validation**:
   - Supports decryption for all algorithms.
   - Validates the decrypted file against the original file for accuracy.

4. **Enhanced File Size Metrics**:
   - Includes encrypted file size in the output table.

## Usage

### Encryption
Run the encryption benchmark for a specific algorithm or all algorithms.

```bash
# Benchmark all algorithms
poetry run encryption_benchmark encrypt --file-path sample.jpg --algorithm ALL

# Benchmark AES algorithm
poetry run encryption_benchmark encrypt --file-path sample.jpg --algorithm AES

# Benchmark RSA algorithm
poetry run encryption_benchmark encrypt --file-path sample.jpg --algorithm RSA

# Benchmark ECC algorithm
poetry run encryption_benchmark encrypt --file-path sample.jpg --algorithm ECC
```

### Decryption
Decrypt files for a specific algorithm and validate against the original file.

```bash
# Decrypt AES encrypted files
poetry run encryption_benchmark decrypt --algorithm AES --input-folder encrypted_files_aes --output-folder decrypted_files_aes --original-file sample.jpg

# Decrypt RSA encrypted files
poetry run encryption_benchmark decrypt --algorithm RSA --input-folder encrypted_files_rsa --output-folder decrypted_files_rsa --original-file sample.jpg

# Decrypt ECC encrypted files
poetry run encryption_benchmark decrypt --algorithm ECC --input-folder encrypted_files_ecc --output-folder decrypted_files_ecc --original-file sample.jpg
```

## Output
The results are presented in a rich table format, including the following columns:

- **Algorithm**: The encryption algorithm used (AES, RSA, ECC).
- **File Size (bytes)**: Size of the input file.
- **Time (s)**: Time taken for encryption.
- **Current Memory (MiB)**: Memory usage during the process.
- **Peak Memory (MiB)**: Peak memory usage during the process.
- **Key Size (bits)**: Size of the encryption key.
- **Encrypted File Size (bytes)**: Size of the encrypted file.
- **Throughput (MB/s)**: Encryption throughput in MB/s.
- **Algorithm Strength**: Qualitative assessment of algorithm security (High/Moderate).

## Dependencies
- Python 3.7+
- Typer
- Rich
- Cryptography
- Poetry

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/encryption-benchmark.git
   cd encryption-benchmark
   ```

2. Install dependencies:
   ```bash
   poetry install
   ```

## Example Workflow
```bash
# Encrypt a file using all algorithms
poetry run encryption_benchmark encrypt --file-path sample.jpg --algorithm ALL

# Decrypt a file encrypted with AES
poetry run encryption_benchmark decrypt --algorithm AES --input-folder encrypted_files_aes --output-folder decrypted_files_aes --original-file sample.jpg
```

## Contributions
Contributions are welcome! Feel free to fork the repository and submit pull requests.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
