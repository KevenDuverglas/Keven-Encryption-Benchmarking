import os
import pytest
from encryption_benchmark import (
    Algorithm,
    generate_aes_key,
    generate_rsa_keys,
    generate_ecc_keys,
    encrypt_aes,
    decrypt_aes,
    encrypt_rsa,
    decrypt_rsa,
    encrypt_ecc,
    decrypt_ecc,
)

@pytest.fixture
def sample_data():
    return b"Test data for encryption benchmarking."

@pytest.fixture
def aes_key():
    return generate_aes_key()

@pytest.fixture
def rsa_keys():
    return generate_rsa_keys()

@pytest.fixture
def ecc_keys():
    return generate_ecc_keys()

def test_aes_encryption_decryption(sample_data, aes_key):
    ciphertext = encrypt_aes(aes_key, sample_data)
    plaintext = decrypt_aes(aes_key, ciphertext)
    assert plaintext == sample_data, "AES encryption/decryption failed."

def test_rsa_encryption_decryption(sample_data, rsa_keys):
    private_key, public_key = rsa_keys
    encrypted_key, ciphertext = encrypt_rsa(public_key, sample_data)
    plaintext = decrypt_rsa(private_key, encrypted_key, ciphertext)
    assert plaintext == sample_data, "RSA encryption/decryption failed."

def test_ecc_encryption_decryption(sample_data, ecc_keys):
    private_key, public_key = ecc_keys
    ciphertext = encrypt_ecc(public_key, sample_data)
    plaintext = decrypt_ecc(private_key, ciphertext)
    assert plaintext == sample_data, "ECC encryption/decryption failed."

def test_invalid_aes_decryption(sample_data, aes_key):
    ciphertext = encrypt_aes(aes_key, sample_data)
    invalid_key = generate_aes_key()
    print(f"Valid Key: {aes_key}")
    print(f"Invalid Key: {invalid_key}")
    print(f"Ciphertext: {ciphertext}")
    with pytest.raises(ValueError, match="Invalid AES key or ciphertext"):
        decrypt_aes(invalid_key, ciphertext)

def test_invalid_rsa_decryption(sample_data, rsa_keys):
    private_key, public_key = rsa_keys
    another_private_key, _ = generate_rsa_keys()
    encrypted_key, ciphertext = encrypt_rsa(public_key, sample_data)
    with pytest.raises(Exception):
        decrypt_rsa(another_private_key, encrypted_key, ciphertext)

def test_invalid_ecc_decryption(sample_data, ecc_keys):
    private_key, public_key = ecc_keys
    another_private_key, _ = generate_ecc_keys()
    ciphertext = encrypt_ecc(public_key, sample_data)
    with pytest.raises(ValueError, match="Invalid ECC key or ciphertext"):
        decrypt_ecc(another_private_key, ciphertext)


def test_aes_key_generation():
    key1 = generate_aes_key()
    key2 = generate_aes_key()
    assert key1 != key2, "AES key generation failed."

def test_rsa_key_generation():
    private_key1, public_key1 = generate_rsa_keys()
    private_key2, public_key2 = generate_rsa_keys()
    assert private_key1 != private_key2, "RSA key generation failed."

def test_ecc_key_generation():
    private_key1, public_key1 = generate_ecc_keys()
    private_key2, public_key2 = generate_ecc_keys()
    assert private_key1 != private_key2, "ECC key generation failed."
