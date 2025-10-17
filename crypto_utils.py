"""Utilidades criptograficas: AES-GCM, HMAC y certificados X.509."""

from __future__ import annotations

import base64
import binascii
import datetime
import os
from pathlib import Path
from typing import Iterable, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def generate_aes_key(length: int = 32) -> bytes:
    """Genera una clave aleatoria para AES-GCM."""
    if length not in (16, 24, 32):
        raise ValueError("La clave AES debe tener 16, 24 o 32 bytes.")
    return os.urandom(length)


def encrypt_message(
    key: bytes, plaintext: str, associated_data: bytes | None = None
) -> dict:
    """Cifra un mensaje con AES-GCM usando datos asociados opcionales."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        associated_data if associated_data is not None else None,
    )
    return {
        "key": base64.b64encode(key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_message(
    key: bytes, nonce_b64: str, ciphertext_b64: str, associated_data: bytes | None = None
) -> str:
    """Descifra un mensaje cifrado con AES-GCM."""
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        associated_data if associated_data is not None else None,
    )
    return plaintext.decode("utf-8")


def generate_hmac_key(length: int = 32) -> bytes:
    """Genera una clave aleatoria para HMAC-SHA256."""
    if length < 16:
        raise ValueError("La clave HMAC debe tener al menos 16 bytes.")
    return os.urandom(length)


def create_hmac(key: bytes, message: str) -> str:
    """Genera un HMAC-SHA256 codificado en base64."""
    hmac_ctx = hmac.HMAC(key, hashes.SHA256())
    hmac_ctx.update(message.encode("utf-8"))
    tag = hmac_ctx.finalize()
    return base64.b64encode(tag).decode("ascii")


def verify_hmac(key: bytes, message: str, tag_b64: str) -> bool:
    """Verifica un HMAC-SHA256 codificado en base64."""
    try:
        tag = base64.b64decode(tag_b64, validate=True)
    except (ValueError, binascii.Error):
        return False

    hmac_ctx = hmac.HMAC(key, hashes.SHA256())
    hmac_ctx.update(message.encode("utf-8"))
    try:
        hmac_ctx.verify(tag)
    except InvalidSignature:
        return False
    return True


def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """Genera una pareja de claves Ed25519 serializadas en formato PEM."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_bytes, public_bytes


def sign_file(private_key_pem: bytes, file_path: Path) -> bytes:
    """Firma el contenido de un archivo usando Ed25519."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    data = Path(file_path).read_bytes()
    signature = private_key.sign(data)
    return signature


def verify_file_signature(public_key_pem: bytes, file_path: Path, signature: bytes) -> bool:
    """Verifica la firma Ed25519 de un archivo."""
    public_key = serialization.load_pem_public_key(public_key_pem)
    data = Path(file_path).read_bytes()
    try:
        public_key.verify(signature, data)
    except Exception:
        return False
    return True


def _generate_rsa_private_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def create_root_ca(common_name: str, days_valid: int = 3650) -> Tuple[bytes, bytes]:
    """Crea una CA raiz autofirmada (RSA 4096, SHA-256)."""
    private_key = _generate_rsa_private_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )
    certificate = builder.sign(private_key, hashes.SHA256())
    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        certificate.public_bytes(serialization.Encoding.PEM),
    )


def create_subordinate_ca(
    common_name: str,
    issuer_private_key_pem: bytes,
    issuer_cert_pem: bytes,
    days_valid: int = 3650,
) -> Tuple[bytes, bytes]:
    """Crea una CA subordinada firmada por la CA raiz."""
    issuer_private_key = serialization.load_pem_private_key(
        issuer_private_key_pem, password=None
    )
    issuer_cert = x509.load_pem_x509_certificate(issuer_cert_pem)
    private_key = _generate_rsa_private_key()
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )
    certificate = builder.sign(issuer_private_key, hashes.SHA256())
    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        certificate.public_bytes(serialization.Encoding.PEM),
    )


def issue_user_certificate(
    common_name: str,
    user_public_key_pem: bytes,
    issuer_private_key_pem: bytes,
    issuer_cert_pem: bytes,
    days_valid: int = 825,
) -> bytes:
    """Emite un certificado X.509 para el usuario firmado por la CA subordinada."""
    user_public_key = serialization.load_pem_public_key(user_public_key_pem)
    issuer_private_key = serialization.load_pem_private_key(
        issuer_private_key_pem, password=None
    )
    issuer_cert = x509.load_pem_x509_certificate(issuer_cert_pem)
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CODE_SIGNING, ExtendedKeyUsageOID.EMAIL_PROTECTION]
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(user_public_key),
            critical=False,
        )
    )
    certificate = builder.sign(issuer_private_key, hashes.SHA256())
    return certificate.public_bytes(serialization.Encoding.PEM)


def verify_certificate_chain(
    leaf_cert_pem: bytes,
    intermediate_pems: Iterable[bytes],
    root_cert_pem: bytes,
) -> bool:
    """Verifica una cadena simple leaf -> intermediarios -> raiz."""
    try:
        leaf_cert = x509.load_pem_x509_certificate(leaf_cert_pem)
        intermediates = [x509.load_pem_x509_certificate(pem) for pem in intermediate_pems]
        root_cert = x509.load_pem_x509_certificate(root_cert_pem)
    except ValueError:
        return False

    chain = intermediates + [root_cert]
    current = leaf_cert
    for issuer in chain:
        if current.issuer != issuer.subject:
            return False
        if not _verify_certificate_signature(current, issuer):
            return False
        current = issuer

    # Verificar que la raiz es autofirmada
    if root_cert.issuer != root_cert.subject:
        return False
    if not _verify_certificate_signature(root_cert, root_cert):
        return False
    return True


def _verify_certificate_signature(
    certificate: x509.Certificate, issuer_cert: x509.Certificate
) -> bool:
    public_key = issuer_cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        elif isinstance(public_key, Ed25519PublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
        else:
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
    except InvalidSignature:
        return False
    except TypeError:
        return False
    return True
