# security.py
"""
보안 관련 유틸 모듈

- RSA 키 파일 로드/생성
- base64로 인코딩된 암호문 복호화
- 로그인 시도 콘솔 로그
"""

import os
import base64
import datetime
from typing import Tuple

from crypto.rsa_crypto import generate_keypair, decrypt


# 키 파일 경로
KEY_DIR = "keys"
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "rsa_public.txt")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "rsa_private.txt")


def load_or_create_keys(bit_length: int = 2048) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """RSA 공개키/개인키 불러오기 또는 생성"""
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR, exist_ok=True)

    if os.path.exists(PUBLIC_KEY_PATH) and os.path.exists(PRIVATE_KEY_PATH):
        # 기존 키 로드
        with open(PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
            n_str = f.readline().strip()
            e_str = f.readline().strip()

        with open(PRIVATE_KEY_PATH, "r", encoding="utf-8") as f:
            n_str2 = f.readline().strip()
            d_str = f.readline().strip()

        if n_str != n_str2:
            raise ValueError("공개키/개인키 파일의 n 값이 일치하지 않습니다.")

        n = int(n_str)
        e = int(e_str)
        d = int(d_str)

        print("[RSA] 기존 키 파일을 로드했습니다.")
        return (n, e), (n, d)

    # 키 파일이 없으면 새로 생성
    print("[RSA] 키 파일이 없어 새로 생성합니다...")
    public_key, private_key = generate_keypair(bit_length)
    n, e = public_key
    _, d = private_key

    with open(PUBLIC_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(str(n) + "\n")
        f.write(str(e) + "\n")

    with open(PRIVATE_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(str(n) + "\n")
        f.write(str(d) + "\n")

    print(f"[RSA] {bit_length}비트 키를 생성하고 파일에 저장했습니다.")
    return public_key, private_key


def decrypt_password_base64(cipher_b64: str, private_key: Tuple[int, int]) -> str:
    if not cipher_b64:
        raise ValueError("EMPTY_CIPHER")

    try:
        cipher_bytes = base64.b64decode(cipher_b64)
    except Exception as e:
        raise ValueError("BASE64_DECODE_ERROR") from e

    if not cipher_bytes:
        raise ValueError("EMPTY_CIPHER_BYTES")

    cipher_int = int.from_bytes(cipher_bytes, byteorder="big")

    try:
        plain_int = decrypt(cipher_int, private_key)     # 🔥 정수로 반환
    except Exception as e:
        raise ValueError("RSA_DECRYPT_ERROR") from e

    # --- 🔥 여기서 leading zero 제거 ---
    # 정수 → bytes
    length = (plain_int.bit_length() + 7) // 8
    plain_bytes = plain_int.to_bytes(length, "big")

    # 앞자리 0 제거
    while plain_bytes.startswith(b"\x00"):
        plain_bytes = plain_bytes[1:]

    # UTF-8로 디코딩
    try:
        return plain_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("UTF8_DECODE_ERROR") from e


def log_login_attempt(username: str, success: bool, reason: str) -> None:
    """로그인 시도 로그"""
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")
    status = "SUCCESS" if success else "FAIL"
    user_str = username if username is not None else "(none)"
    print(f"[LOGIN] {timestamp} user={user_str!r} status={status} reason={reason}")


# ----------------------------------------------------------
# 키 로테이션 기능
# ----------------------------------------------------------
def rotate_keys(bit_length: int = 2048) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """기존 키를 백업 후 새 RSA 키 생성"""

    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # 백업
    if os.path.exists(PUBLIC_KEY_PATH):
        os.replace(PUBLIC_KEY_PATH, os.path.join(KEY_DIR, f"rsa_public_{timestamp}.bak"))

    if os.path.exists(PRIVATE_KEY_PATH):
        os.replace(PRIVATE_KEY_PATH, os.path.join(KEY_DIR, f"rsa_private_{timestamp}.bak"))

    # 새 키 생성
    print(f"[RSA] 키 로테이션 실행 중... (새 {bit_length}비트 키 생성)")
    public_key, private_key = generate_keypair(bit_length)
    n, e = public_key
    _, d = private_key

    with open(PUBLIC_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(str(n) + "\n")
        f.write(str(e) + "\n")

    with open(PRIVATE_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(str(n) + "\n")
        f.write(str(d) + "\n")

    print("[RSA] 키 로테이션 완료. 새 키 저장됨.")
    return public_key, private_key
