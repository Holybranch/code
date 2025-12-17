#RSA 수학 그 자체

# rsa_crypto.py
"""
간단한 RSA 구현 + 데모용 실행 스크립트

- import 해서 쓸 때:
    from rsa_crypto import generate_keypair, encrypt, decrypt

- 직접 실행할 때:
    python rsa_crypto.py
  -> 키 생성 후, 사용자가 입력한 문자열을 암호화/복호화해서 보여줌
"""

import random
from typing import Tuple
import sys

def decrypt_to_text_strict(cipher_int: int, private_key: Tuple[int, int]) -> str:
    """
    cipher_int를 복호화하여 문자열을 반환한다.
    - UTF-8로 엄격하게 디코딩(errors='strict')하고,
    - 디코딩한 문자열을 다시 UTF-8로 인코딩한 결과의 정수값이
      원래 복호화된 정수와 일치하는지(무결성) 확인한다.
    - 문제가 있으면 ValueError를 던진다.
    """
    n, d = private_key
    # 1) 정수 복호화
    m = pow(cipher_int, d, n)

    # 2) 정수 -> 바이트
    if m == 0:
        data = b'\x00'
    else:
        length = (m.bit_length() + 7) // 8
        data = m.to_bytes(length, byteorder='big')

    # 3) 엄격한 UTF-8 디코딩 (문제가 있으면 예외)
    try:
        text = data.decode('utf-8', errors='strict')
    except Exception as e:
        raise ValueError("복호화된 바이트가 유효한 UTF-8 문자열이 아닙니다.") from e

    # 4) 재인코딩 -> 정수로 바꿔 무결성 체크
    re_m = int.from_bytes(text.encode('utf-8'), byteorder='big')
    if re_m != m:
        # 디코딩-인코딩 과정에서 바이트가 손실/변형된 경우
        raise ValueError("복호화된 문자열의 재인코딩 결과가 일치하지 않습니다. 무결성 실패.")

    return text

# ================== 기본 수학 유틸 ==================

def gcd(a: int, b: int) -> int:
    """a, b의 최대공약수"""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int):
    """
    확장 유클리드 알고리즘
    a*x + b*y = g = gcd(a, b)를 만족하는 (g, x, y)를 반환
    """
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def modinv(a: int, m: int) -> int:
    """
    모듈러 역원: a * x ≡ 1 (mod m)를 만족하는 x를 구함
    (존재하지 않으면 에러)
    """
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("모듈러 역원이 존재하지 않습니다.")
    return x % m


# ================== 소수 판별 & 생성 ==================

def is_probable_prime(n: int, k: int = 5) -> bool:
    """
    Miller-Rabin 기반의 확률적 소수 판별 (교육용 간단 버전)
    n이 소수일 확률이 높으면 True
    """
    if n < 2:
        return False
    # 작은 소수들로 먼저 나눠보기
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23]
    if n in small_primes:
        return True
    for p in small_primes:
        if n % p == 0:
            return False

    # n-1 = 2^r * d 꼴로 분해
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Miller-Rabin 테스트 k번 반복
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """
    지정한 비트 수의 소수를 랜덤으로 생성 (교육용)
    실제 서비스용으로 쓰면 안 되고, 과제/탐구용으로만 사용.
    """
    while True:
        # 최상위 비트와 최하위 비트가 1이 되도록 해서 대충 크기 보장
        candidate = random.getrandbits(bits) | 1 | (1 << (bits - 1))
        if is_probable_prime(candidate):
            return candidate


# ================== RSA 핵심 로직 ==================

def generate_keypair(bit_length: int = 64) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    RSA 키쌍 생성 (PUBLIC_KEY, PRIVATE_KEY 반환)

    bit_length는 n의 대략적인 비트 수.
    - 탐구/테스트용: 64, 128비트 정도
    - 실제 보안용: 2048 이상 (하지만 여기 구현은 교육용이므로 추천 X)
    """
    # 1. 두 소수 p, q 생성 (대략 반씩 나눠서)
    half_bits = bit_length // 2
    p = generate_prime(half_bits)
    q = generate_prime(half_bits)
    while p == q:
        q = generate_prime(half_bits)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    # 2. 공개 지수 e 선택 (phi_n과 서로소)
    e = 65537  # 보통 많이 쓰는 값
    if gcd(e, phi_n) != 1:
        # 혹시 안 맞으면 다른 e를 찾음 (드문 케이스)
        e = 3
        while e < phi_n and gcd(e, phi_n) != 1:
            e += 2

    # 3. 개인 지수 d 계산: e*d ≡ 1 (mod φ(n))
    d = modinv(e, phi_n)

    public_key = (n, e)
    private_key = (n, d)
    return public_key, private_key


def text_to_int(text: str) -> int:
    """
    문자열 -> 정수 변환 (UTF-8 기준)
    """
    data = text.encode("utf-8")
    return int.from_bytes(data, byteorder="big")


def int_to_text(value: int) -> str:
    """
    정수 -> 문자열 (UTF-8 기준)
    """
    if value == 0:
        return ""
    length = (value.bit_length() + 7) // 8
    data = value.to_bytes(length, byteorder="big")
    return data.decode("utf-8", errors="ignore")


def encrypt(plaintext: str, public_key: Tuple[int, int]) -> int:
    """
    문자열 평문을 RSA 공개키로 암호화해서 '정수 암호문'을 반환
    C = M^e mod n
    """
    n, e = public_key
    m = text_to_int(plaintext)
    if m >= n:
        raise ValueError("메시지가 너무 깁니다 (정수 값이 n 이상). bit_length를 늘려야 합니다.")
    c = pow(m, e, n)
    return c

def decrypt(cipher_int: int, private_key: Tuple[int, int]) -> int:
    n, d = private_key
    return pow(cipher_int, d, n)

if __name__ == "__main__":
    print("=== RSA 데모 실행 ===")
    print("키를 생성하는 중입니다...")

    # 데모용 키 생성
    public_key, private_key = generate_keypair(bit_length=512)

    n, e = public_key
    _, d = private_key

    print(f"\n[공개키] n = {n}")
    print(f"[공개키] e = {e}")
    print(f"[개인키] d = {d}")

    print("\n암호화할 메시지를 입력하세요.")
    plaintext = input("평문 입력: ")

    # 원본 정수값 보관
    original_m = text_to_int(plaintext)

    # 암호화
    cipher_int = encrypt(plaintext, public_key)
    print(f"\n[암호문 (정수)] {cipher_int}")

    decrypted_int = decrypt(cipher_int, private_key)

    # 참고용 텍스트 출력
    decrypted_text = int_to_text(decrypted_int)
    print(f"\n[복호화 결과] {decrypted_text}")


    if decrypted_int == original_m:
        print("\n✅ 복호화 결과가 원본과 정확히 일치합니다.")
    else:
        print("\n⚠ 복호화 결과가 원본과 다릅니다.")
