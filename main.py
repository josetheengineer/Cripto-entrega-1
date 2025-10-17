"""Aplicacion interactiva para practicar conceptos de criptografia aplicada."""

from __future__ import annotations

import base64
import binascii
import logging
import sys
from getpass import getpass
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag

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
from user_manager import UserManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
# logging.getLogger().setLevel(logging.DEBUG)

DATA_DIR = Path("data")
KEYS_DIR = Path("keys")
PKI_DIR = Path("pki")
CERTS_DIR = PKI_DIR / "certs"
ROOT_CA_KEY_PATH = PKI_DIR / "root_ca_key.pem"
ROOT_CA_CERT_PATH = PKI_DIR / "root_ca_cert.pem"
SUB_CA_KEY_PATH = PKI_DIR / "sub_ca_key.pem"
SUB_CA_CERT_PATH = PKI_DIR / "sub_ca_cert.pem"
USER_STORAGE_PATH = DATA_DIR / "users.json"
OUT_DIR = Path("out")
logged_in_user: Optional[str] = None


def ensure_directories() -> None:
    for directory in (DATA_DIR, KEYS_DIR, PKI_DIR, CERTS_DIR, OUT_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def show_menu() -> None:
    print("\n=== Menu Principal ===")
    print("0. Salir")
    print("1. Registrar usuario")
    print("2. Iniciar sesion")
    print("3. Cifrar mensaje (requiere sesion)")
    print("4. Descifrar mensaje (requiere sesion)")
    print("5. Firmar archivo (requiere sesion)")
    print("6. Verificar firma (requiere sesion)")
    print("7. Generar etiqueta HMAC (requiere sesion)")
    print("8. Verificar etiqueta HMAC (requiere sesion)")
    print("9. Verificar certificado de usuario")


def ensure_pki() -> None:
    """Crea la infraestructura PKI local si no existe."""
    if not ROOT_CA_KEY_PATH.exists() or not ROOT_CA_CERT_PATH.exists():
        root_key, root_cert = create_root_ca("Cripto-Entrega1 Root CA")
        ROOT_CA_KEY_PATH.write_bytes(root_key)
        ROOT_CA_CERT_PATH.write_bytes(root_cert)
        logging.info("Generada CA raiz (RSA 4096, SHA-256).")

    if not SUB_CA_KEY_PATH.exists() or not SUB_CA_CERT_PATH.exists():
        root_key = ROOT_CA_KEY_PATH.read_bytes()
        root_cert = ROOT_CA_CERT_PATH.read_bytes()
        sub_key, sub_cert = create_subordinate_ca(
            "Cripto-Entrega1 Sub CA", root_key, root_cert
        )
        SUB_CA_KEY_PATH.write_bytes(sub_key)
        SUB_CA_CERT_PATH.write_bytes(sub_cert)
        logging.info("Generada CA subordinada (RSA 4096, SHA-256).")

def pause() -> None:
    input("\nPulsa [Enter] para volver al menú...")


def safe_getpass(prompt: str) -> str:
    try:
        return getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        raise
    except Exception:
        return input(prompt)


def require_session() -> bool:
    if logged_in_user is None:
        logging.warning("Debes iniciar sesión antes de esta operación.")
        return False
    return True


def handle_register(user_manager: UserManager) -> None:
    username = input("Nombre de usuario: ").strip()
    if not username:
        logging.error("El nombre de usuario no puede estar vacío.")
        return
    password = safe_getpass("Contrasena: ")
    confirm = safe_getpass("Confirma la contrasena: ")
    if password != confirm:
        logging.warning("Las contraseñas no coinciden.")
        return

    created = user_manager.create_user(username, password)
    if not created:
        if user_manager.user_exists(username):
            logging.warning("El usuario '%s' ya existe.", username)
        else:
            logging.error("No se pudo registrar al usuario '%s'.", username)
        return

    ensure_pki()
    private_key, public_key = generate_ed25519_keypair()
    private_path = KEYS_DIR / f"{username}_ed25519_private.pem"
    public_path = KEYS_DIR / f"{username}_ed25519_public.pem"
    private_path.write_bytes(private_key)
    public_path.write_bytes(public_key)

    sub_key = SUB_CA_KEY_PATH.read_bytes()
    sub_cert = SUB_CA_CERT_PATH.read_bytes()
    user_cert = issue_user_certificate(username, public_key, sub_key, sub_cert)
    cert_path = CERTS_DIR / f"{username}_cert.pem"
    cert_path.write_bytes(user_cert)

    logging.info("Usuario '%s' registrado correctamente.", username)
    print(f"Clave privada guardada en: {private_path}")
    print(f"Clave publica guardada en: {public_path}")
    print(f"Certificado emitido guardado en: {cert_path}")


def handle_login(user_manager: UserManager) -> Optional[str]:
    global logged_in_user

    username = input("Nombre de usuario: ").strip()
    password = safe_getpass("Contrasena: ")
    ok = bool(user_manager.authenticate_user(username, password))
    if ok:
        logged_in_user = username
        logging.info("Inicio de sesión correcto para '%s'.", username)
    else:
        logging.warning("Credenciales inválidas.")
        logged_in_user = None
    return logged_in_user


def handle_encrypt() -> None:
    ensure_directories()
    source = input("Introduce el mensaje o '@ruta' para archivo: ").strip()
    if source.startswith("@"):
        file_path = Path(source[1:])
        if not file_path.exists():
            logging.error("Archivo '%s' no encontrado.", file_path)
            return
        plaintext = file_path.read_text(encoding="utf-8")
    else:
        plaintext = source

    key = generate_aes_key()
    result = encrypt_message(key, plaintext)

    ciphertext_bytes = base64.b64decode(result["ciphertext"])
    nonce_bytes = base64.b64decode(result["nonce"])
    key_b64 = base64.b64encode(key).decode("ascii")

    cipher_path = OUT_DIR / "ciphertext.bin"
    nonce_path = OUT_DIR / "nonce.bin"
    key_path = OUT_DIR / "key.b64"

    cipher_path.write_bytes(ciphertext_bytes)
    nonce_path.write_bytes(nonce_bytes)
    key_path.write_text(key_b64, encoding="utf-8")

    logging.info("Mensaje cifrado con AES-GCM.")
    logging.info("Salida guardada en: out/ciphertext.bin")
    print(f"Clave AES (base64): {key_b64}")
    print(f"Nonce (base64): {result['nonce']}")


def handle_decrypt() -> None:
    ensure_directories()
    default_cipher = OUT_DIR / "ciphertext.bin"
    default_nonce = OUT_DIR / "nonce.bin"
    default_plain = OUT_DIR / "plain.txt"
    default_key = OUT_DIR / "key.b64"
    cipher_input = input(f"Ruta del fichero cifrado (por defecto: {default_cipher}): ").strip()
    cipher_path = Path(cipher_input) if cipher_input else default_cipher

    nonce_input = input(f"Ruta del nonce (por defecto: {default_nonce}): ").strip()
    nonce_path = Path(nonce_input) if nonce_input else default_nonce

    plain_input = input(f"Ruta de salida del texto plano (por defecto: {default_plain}): ").strip()
    plain_path = Path(plain_input) if plain_input else default_plain

    key_b64 = input(
        f"Clave AES (base64) (por defecto, leera {default_key} si existe): "
    ).strip()
    if not key_b64:
        if default_key.exists():
            key_b64 = default_key.read_text(encoding="utf-8").strip()
        else:
            logging.error("Debe proporcionar la clave AES en base64.")
            return

    try:
        key = base64.b64decode(key_b64, validate=True)
    except (ValueError, binascii.Error):
        logging.error("Clave AES en base64 inválida.")
        return

    try:
        ciphertext_bytes = cipher_path.read_bytes()
        nonce_bytes = nonce_path.read_bytes()
    except FileNotFoundError as exc:
        logging.error("Archivo '%s' no encontrado.", exc.filename)
        return

    ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode("ascii")
    nonce_b64 = base64.b64encode(nonce_bytes).decode("ascii")

    try:
        plaintext = decrypt_message(key, nonce_b64, ciphertext_b64)
    except InvalidTag:
        logging.error(
            "No se pudo descifrar: autenticación GCM fallida (datos corruptos o clave incorrecta)."
        )
        return
    except Exception:
        logging.error(
            "No se pudo descifrar: autenticación GCM fallida (datos corruptos o clave incorrecta)."
        )
        return

    plain_path.write_text(plaintext, encoding="utf-8")
    logging.info("Descifrado correcto. Guardado en: out/plain.txt")
    if plain_path != default_plain:
        logging.info("Descifrado correcto. Guardado en: %s", plain_path)


def handle_sign() -> None:
    assert logged_in_user is not None
    ensure_directories()
    default_file = OUT_DIR / "plain.txt"
    file_input = input(f"Ruta del archivo a firmar (por defecto: {default_file}): ").strip()
    file_path = Path(file_input) if file_input else default_file
    if not file_path.exists():
        logging.error("Archivo '%s' no encontrado.", file_path)
        return

    private_path = KEYS_DIR / f"{logged_in_user}_ed25519_private.pem"
    if not private_path.exists():
        logging.error(
            "Clave privada no encontrada para el usuario '%s'.", logged_in_user
        )
        return

    signature_path = file_path.with_suffix(file_path.suffix + ".sig")
    private_key_pem = private_path.read_bytes()
    signature = sign_file(private_key_pem, file_path)
    signature_b64 = base64.b64encode(signature).decode("ascii")
    signature_path.write_text(signature_b64, encoding="utf-8")
    logging.info("Firma generada.")
    logging.info("Guardada en: %s", signature_path)


def handle_verify() -> None:
    assert logged_in_user is not None
    ensure_directories()
    default_file = OUT_DIR / "plain.txt"
    default_sig = default_file.with_suffix(default_file.suffix + ".sig")
    file_input = input(f"Ruta del archivo a verificar (por defecto: {default_file}): ").strip()
    file_path = Path(file_input) if file_input else default_file
    sig_input = input(
        f"Ruta de la firma (por defecto: {default_sig}): "
    ).strip()
    signature_path = Path(sig_input) if sig_input else default_sig

    public_default = KEYS_DIR / f"{logged_in_user}_ed25519_public.pem"
    public_input = input(
        f"Ruta de la clave publica (por defecto: {public_default}): "
    ).strip()
    public_path = Path(public_input) if public_input else public_default

    try:
        signature_b64 = signature_path.read_text(encoding="utf-8").strip()
        signature = base64.b64decode(signature_b64, validate=True)
        public_key_pem = public_path.read_bytes()
    except (ValueError, binascii.Error):
        logging.error("La firma debe estar en base64 válido.")
        return
    except FileNotFoundError as exc:
        logging.error("Archivo '%s' no encontrado.", exc.filename)
        return

    is_valid = verify_file_signature(public_key_pem, file_path, signature)
    if is_valid:
        logging.info("Firma válida para '%s'.", file_path)
    else:
        logging.error("Firma inválida para '%s'.", file_path)


def handle_hmac_generate() -> None:
    ensure_directories()
    message = input("Mensaje a proteger con HMAC: ")
    key = generate_hmac_key()
    tag = create_hmac(key, message)
    logging.info("Etiqueta HMAC generada.")
    print(f"Clave HMAC (base64): {base64.b64encode(key).decode('ascii')}")
    print(f"Etiqueta HMAC (base64): {tag}")
    print("Algoritmo: HMAC-SHA256.")


def handle_hmac_verify() -> None:
    ensure_directories()
    key_b64 = input("Clave HMAC (base64): ").strip()
    message = input("Mensaje original: ")
    tag = input("Etiqueta HMAC (base64): ").strip()
    try:
        key = base64.b64decode(key_b64, validate=True)
    except (ValueError, binascii.Error):
        logging.error("Clave HMAC en base64 inválida.")
        return

    if verify_hmac(key, message, tag):
        logging.info("HMAC válido.")
    else:
        logging.error("HMAC inválido.")


def handle_verify_certificate() -> None:
    ensure_directories()
    username = input("Usuario del certificado (enter para especificar ruta manual): ").strip()

    cert_path: Optional[Path]
    if username:
        cert_path = CERTS_DIR / f"{username}_cert.pem"
    else:
        cert_path_input = input("Ruta completa al certificado: ").strip()
        if not cert_path_input:
            logging.error("Debes indicar la ruta del certificado o el nombre de usuario.")
            return
        cert_path = Path(cert_path_input)

    if not cert_path.exists():
        logging.error("Archivo '%s' no encontrado.", cert_path)
        return

    try:
        leaf_cert = cert_path.read_bytes()
        sub_cert = SUB_CA_CERT_PATH.read_bytes()
        root_cert = ROOT_CA_CERT_PATH.read_bytes()
        if not verify_certificate_chain(leaf_cert, [sub_cert], root_cert):
            raise ValueError("No se pudo validar la cadena de certificados.")
    except FileNotFoundError as exc:
        missing = exc.filename or ""
        if missing in {str(SUB_CA_CERT_PATH), str(ROOT_CA_CERT_PATH)}:
            logging.error("PKI no inicializada. Registre un usuario para generar la infraestructura.")
        else:
            logging.error("Archivo '%s' no encontrado.", missing)
        return
    except Exception as error:
        logging.error("Certificado inválido: %s", error)
        return

    logging.info("Certificado válido para '%s'.", cert_path)


def main() -> None:
    ensure_directories()
    ensure_pki()
    user_manager = UserManager(USER_STORAGE_PATH)
    def run_with_session(func):
        def wrapper() -> None:
            if require_session():
                func()

        return wrapper

    actions = {
        "1": lambda: handle_register(user_manager),
        "2": lambda: handle_login(user_manager),
        "3": run_with_session(handle_encrypt),
        "4": run_with_session(handle_decrypt),
        "5": run_with_session(handle_sign),
        "6": run_with_session(handle_verify),
        "7": run_with_session(handle_hmac_generate),
        "8": run_with_session(handle_hmac_verify),
        "9": handle_verify_certificate,
    }

    while True:
        show_menu()
        choice = input("> ").strip()
        if choice == "0":
            logging.info("Saliendo...")
            pause()
            break

        action = actions.get(choice)
        if action:
            action()
        else:
            logging.warning("Opción no válida.")
        pause()

    sys.exit(0)


if __name__ == "__main__":
    main()
