# app.py
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import pymysql
import webbrowser
import threading
import os
import hashlib
import bcrypt
import datetime

from security import (
    load_or_create_keys,
    decrypt_password_base64,
    log_login_attempt,
    rotate_keys,   # 🔹 새로 추가
)

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app)

# ============================
#        로그 저장 함수
# ============================
def log_event(message):
    """log.txt 파일에 로그 저장"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}\n"
    with open("log.txt", "a", encoding="utf-8") as f:
        f.write(line)

# ============================
#       DB 연결
# ============================
db = pymysql.connect(
    host='127.0.0.1',
    user='root',
    password='jeeto3000@',
    database='code',
    charset='utf8mb4'
)
cursor = db.cursor()

# ============================
#       RSA 키 준비
# ============================
public_key, private_key = load_or_create_keys(bit_length=1024)

@app.route('/public-key', methods=['GET'])
def get_public_key():
    n, e = public_key
    return jsonify({
        "n": str(n),  # modulus
        "e": str(e)   # 공개 지수
    })

# ============================
#       HTML 페이지
# ============================
@app.route('/')
def login_page():
    return render_template('index.html')

@app.route('/signup')
def signup_page():
    return render_template('index4.html')

# ============================
#        회원가입
# ============================
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('id')
    cipher_b64 = data.get('pw')

    if not username or not cipher_b64:
        return jsonify({'message': '아이디와 비밀번호를 모두 입력하세요'}), 400

    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    if cursor.fetchone():
        return jsonify({'message': '이미 존재하는 아이디입니다'}), 400

    # RSA 복호화
    try:
        plain_pw = decrypt_password_base64(cipher_b64, private_key)
    except ValueError as e:
        log_login_attempt(username, False, str(e))
        log_event(f"REGISTER FAIL: username={username}, reason=decrypt_fail")
        return jsonify({'message': '비밀번호 복호화 실패', 'error': str(e)}), 400

    # SHA256 → bcrypt
    sha_pw = hashlib.sha256(plain_pw.encode()).digest()
    hashed_pw = bcrypt.hashpw(sha_pw, bcrypt.gensalt()).decode()

    cursor.execute(
        "INSERT INTO users (username, password) VALUES (%s, %s)",
        (username, hashed_pw)
    )
    db.commit()

    log_login_attempt(username, True, "REGISTER_SUCCESS")
    log_event(f"REGISTER SUCCESS: username={username}")

    return jsonify({'message': '회원가입 완료!'}), 200

# ============================
#           로그인
# ============================
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('id')
    cipher_b64 = data.get('pw')

    if not username or not cipher_b64:
        return jsonify({'message': '아이디와 비밀번호를 모두 입력하세요'}), 400

    cursor.execute("SELECT password FROM users WHERE username=%s", (username,))
    result = cursor.fetchone()
    if not result:
        log_login_attempt(username, False, "USER_NOT_FOUND")
        log_event(f"LOGIN FAIL: username={username}, reason=user_not_found")
        return jsonify({'message': '아이디 또는 비밀번호가 틀렸습니다'}), 400

    stored_hash = result[0]

    # RSA 복호화
    try:
        plain_pw = decrypt_password_base64(cipher_b64, private_key)
    except ValueError as e:
        log_login_attempt(username, False, str(e))
        log_event(f"LOGIN FAIL: username={username}, reason=decrypt_fail")
        return jsonify({'message': '비밀번호 복호화 실패', 'error': str(e)}), 400

    sha_pw = hashlib.sha256(plain_pw.encode()).digest()

    if bcrypt.checkpw(sha_pw, stored_hash.encode()):
        log_login_attempt(username, True, "LOGIN_SUCCESS")
        log_event(f"LOGIN SUCCESS: username={username}")
        return jsonify({'message': '로그인 성공!'}), 200
    else:
        log_login_attempt(username, False, "WRONG_PASSWORD")
        log_event(f"LOGIN FAIL: username={username}, reason=wrong_password")
        return jsonify({'message': '아이디 또는 비밀번호가 틀렸습니다'}), 400
    

# ============================
#       RSA 키 로테이션 (임시 관리자용)
# ============================
@app.route('/admin/rotate-keys', methods=['POST'])
def admin_rotate_keys():
    """
    RSA 키를 새로 생성해서 교체하는 임시 관리자용 API.

    - 실제 서비스라면:
        * 인증(토큰 / 세션) 필요
        * 키 ID 관리, 구 키와의 호환 기간 등 복잡한 설계가 필요하지만
      지금은 탐구/실습용이라 단순하게 구현함.
    """
    # 위에서 만든 전역 변수 public_key, private_key를 교체해야 하므로 global 선언
    global public_key, private_key

    # 새 RSA 키쌍 생성 + 파일에 저장 (security.rotate_keys 사용)
    # 현재 서버 시작할 때도 1024비트로 키를 만들고 있으니 맞춰 줌
    public_key, private_key = rotate_keys(bit_length=1024)

    # 로그 파일에도 기록 남기기
    log_event("KEY_ROTATION: new RSA keypair generated")

    # 새 공개키 정보도 바로 응답으로 보내줌 (원하면 클라이언트가 즉시 갱신 가능)
    n, e = public_key
    return jsonify({
        'message': 'RSA 키를 새로 생성했습니다.',
        'n': str(n),
        'e': str(e),
    }), 200

# ============================
#     브라우저 자동 실행
# ============================
def open_browser():
    webbrowser.open("http://127.0.0.1:5000/")

# ============================
#     웹소켓 이벤트
# ============================
@socketio.on('back_to_login')
def handle_back_to_login():
    emit('redirect', {'url': '/'})

if __name__ == '__main__':
    threading.Timer(1.0, open_browser).start()
    socketio.run(app, debug=True, use_reloader=False)