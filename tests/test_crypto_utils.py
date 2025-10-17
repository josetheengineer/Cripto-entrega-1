import base64
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from crypto_utils import (
    create_hmac,
    create_root_ca,
    create_subordinate_ca,
    decrypt_message,
    encrypt_message,
    generate_aes_key,
    generate_ed25519_keypair,
    generate_hmac_key,
    issue_user_certificate,
    sign_file,
    verify_certificate_chain,
    verify_file_signature,
    verify_hmac,
)


def test_encrypt_decrypt_roundtrip():
    key = generate_aes_key()
    message = "mensaje de prueba"
    encrypted = encrypt_message(key, message)
    recovered = decrypt_message(
        base64.b64decode(encrypted["key"]),
        encrypted["nonce"],
        encrypted["ciphertext"],
    )
    assert recovered == message


def test_sign_and_verify(tmp_path):
    private_key, public_key = generate_ed25519_keypair()
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("contenido", encoding="utf-8")
    signature = sign_file(private_key, sample_file)
    assert verify_file_signature(public_key, Path(sample_file), signature)


def test_hmac_generation_and_verification():
    key = generate_hmac_key()
    message = "valor importante"
    tag = create_hmac(key, message)
    assert verify_hmac(key, message, tag)
    assert not verify_hmac(key, message + "x", tag)


def test_certificate_chain_verification():
    root_key, root_cert = create_root_ca("Root Test CA")
    sub_key, sub_cert = create_subordinate_ca("Sub Test CA", root_key, root_cert)
    user_private, user_public = generate_ed25519_keypair()
    user_cert = issue_user_certificate("usuario", user_public, sub_key, sub_cert)
    assert verify_certificate_chain(user_cert, [sub_cert], root_cert)
