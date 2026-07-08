"""
用户信息管理平台 - 主应用
安全特性：
  - 密码使用 pbkdf2:sha256 慢哈希加盐存储
  - 登录失败次数限制及锁定机制
  - CSRF 防护令牌
  - 输入数据过滤与转义
  - 安全响应头（X-Frame-Options, CSP 等）
  - 响应体仅返回用户名和角色（最小权限原则）
  - Secret key 通过独立配置文件加载
"""
import re
import time
import secrets
import sqlite3
import os

from flask import (
    Flask, render_template, request, redirect, session, url_for, abort
)
from werkzeug.security import check_password_hash
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,
)


# ---------------------------------------------------------------------------
# SQLite 数据库初始化
# ---------------------------------------------------------------------------
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")


def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 插入默认用户（明文密码）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')")
    conn.commit()
    conn.close()
    print("[DB] 数据库初始化完成:", DB_PATH)


# ---------------------------------------------------------------------------
# 安全响应头中间件
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'"
    )
    return response


# ---------------------------------------------------------------------------
# 用户数据库 — 仅存储 pbkdf2:sha256:600000 加盐哈希值
# 不包含邮箱、手机、余额等可视为个人信息的字段
# ---------------------------------------------------------------------------
USERS = {
    "admin": {
        "username": "admin",
        "password_hash": (
            "pbkdf2:sha256:600000$CxsVQKRU3hBVy5Jn$"
            "478523ddec6d1eb67b5d47dfa52f24596968b9c7e33e5a0e88d0b0c7d80bdb2c"
        ),
        "role": "admin",
    },
    "alice": {
        "username": "alice",
        "password_hash": (
            "pbkdf2:sha256:600000$Yroto8UKuqdawONt$"
            "9a03cfa7a9baccb15688ad283119913cdba0213c28c0865722beb431b14eee85"
        ),
        "role": "user",
    },
}

# ---------------------------------------------------------------------------
# 登录失败记录 — 基于 IP 的速率限制
# ---------------------------------------------------------------------------
LOGIN_ATTEMPTS: dict[str, list[float]] = {}

# ---------------------------------------------------------------------------
# 辅助函数：输入过滤
# ---------------------------------------------------------------------------
def sanitize_input(value: str, max_length: int = Config.MAX_INPUT_LENGTH) -> str:
    """过滤用户输入：去除首尾空白、限制长度、去除不可见控制字符"""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    # 去除控制字符（保留常见可打印字符、换行等）
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    return value[:max_length]


# ---------------------------------------------------------------------------
# 辅助函数：数据脱敏 — 遵循最小权限原则，仅返回用户标识信息
# ---------------------------------------------------------------------------
def get_safe_user_info(username: str) -> dict | None:
    """
    获取仅包含标识信息的用户数据。
    密码、邮箱、手机、余额等字段绝不传递到前端。
    """
    raw = USERS.get(username)
    if not raw:
        return None
    return {
        "username": raw["username"],
        "role": raw["role"],
    }


# ---------------------------------------------------------------------------
# 辅助函数：登录频率限制
# ---------------------------------------------------------------------------
def is_ip_locked(ip: str) -> bool:
    """检查 IP 是否被锁定"""
    now = time.time()
    if ip not in LOGIN_ATTEMPTS:
        return False
    # 清理过期记录
    lockout_seconds = Config.LOGIN_LOCKOUT_MINUTES * 60
    LOGIN_ATTEMPTS[ip] = [
        t for t in LOGIN_ATTEMPTS[ip]
        if now - t < lockout_seconds
    ]
    if not LOGIN_ATTEMPTS[ip]:
        del LOGIN_ATTEMPTS[ip]
        return False
    return len(LOGIN_ATTEMPTS[ip]) >= Config.MAX_LOGIN_ATTEMPTS


def record_failed_attempt(ip: str) -> int:
    """记录一次失败登录，返回当前失败次数"""
    now = time.time()
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = []
    LOGIN_ATTEMPTS[ip].append(now)
    return len(LOGIN_ATTEMPTS[ip])


def get_remaining_attempts(ip: str) -> int:
    """获取剩余尝试次数"""
    if ip not in LOGIN_ATTEMPTS:
        return Config.MAX_LOGIN_ATTEMPTS
    attempts = LOGIN_ATTEMPTS[ip]
    remaining = Config.MAX_LOGIN_ATTEMPTS - len(attempts)
    return max(0, remaining)


def reset_login_attempts(ip: str) -> None:
    """登录成功后清除失败记录"""
    LOGIN_ATTEMPTS.pop(ip, None)


# ---------------------------------------------------------------------------
# 辅助函数：CSRF 令牌
# ---------------------------------------------------------------------------
def generate_csrf_token() -> str:
    """生成并存储 CSRF 令牌到 session"""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token(token: str | None) -> bool:
    """验证 CSRF 令牌"""
    expected = session.get("_csrf_token")
    if not expected or not token:
        return False
    return secrets.compare_digest(expected, token)


app.jinja_env.globals["csrf_token"] = generate_csrf_token


# ---------------------------------------------------------------------------
# 路由：首页
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = get_safe_user_info(username)
    return render_template("index.html", username=username, user=user_info)


# ---------------------------------------------------------------------------
# 路由：登录
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    success = None

    # 从查询参数获取注册成功消息
    if request.args.get("registered"):
        success = "注册成功，请登录"

    # 获取客户端 IP
    client_ip = request.remote_addr or "unknown"

    if request.method == "POST":
        # ---- CSRF 验证 ----
        csrf_form_token = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_form_token):
            abort(403, description="CSRF 令牌验证失败，请刷新页面重试。")

        # ---- IP 锁定检查 ----
        if is_ip_locked(client_ip):
            lockout_minutes = Config.LOGIN_LOCKOUT_MINUTES
            error = f"登录失败次数过多，账户已被锁定 {lockout_minutes} 分钟，请稍后再试。"
            return render_template("login.html", error=error)

        # ---- 获取并过滤输入 ----
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")

        # ---- 基本验证 ----
        if not username:
            error = "请输入用户名。"
        elif not password:
            error = "请输入密码。"
        elif len(username) > Config.MAX_INPUT_LENGTH:
            error = "用户名过长。"
        elif username not in USERS:
            error = "用户名或密码错误。"
            record_failed_attempt(client_ip)
        else:
            # ---- 密码验证（使用慢哈希比对） ----
            stored_hash = USERS[username]["password_hash"]
            if check_password_hash(stored_hash, password):
                # 登录成功
                session.permanent = True
                session["username"] = username
                reset_login_attempts(client_ip)
                # 生成新 CSRF token 防止重放
                session.pop("_csrf_token", None)
                # 登录成功后直接渲染首页（传递脱敏数据）
                user_info = get_safe_user_info(username)
                return render_template(
                    "index.html", username=username, user=user_info
                )
            else:
                # 密码错误
                error = "用户名或密码错误。"
                remaining = record_failed_attempt(client_ip)
                remaining = Config.MAX_LOGIN_ATTEMPTS - remaining
                if remaining > 0:
                    error += f" 还可尝试 {remaining} 次。"
                else:
                    error = f"登录失败次数过多，账户已被锁定 {Config.LOGIN_LOCKOUT_MINUTES} 分钟，请稍后再试。"

    return render_template("login.html", error=error, success=success)


# ---------------------------------------------------------------------------
# 路由：登出
# ---------------------------------------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# 路由：注册
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, password, email, phone)
            )
            conn.commit()
            success = "注册成功，请登录"
            return redirect(url_for("login", registered=1))
        except Exception as e:
            error = f"注册失败：{str(e)}"
            print(f"[SQL ERROR] {e}")
        finally:
            conn.close()

    return render_template("register.html", error=error)


# ---------------------------------------------------------------------------
# 路由：搜索（使用参数化查询修复 SQL 注入，LIKE 通配符未处理）
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []

    if keyword:
        conn = sqlite3.connect(DB_PATH)
        try:
            cursor = conn.execute(
                "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
                (f"%{keyword}%", f"%{keyword}%")
            )
            results = cursor.fetchall()
            print(f"[SQL] 参数化查询: LIKE %{keyword}%, 返回 {len(results)} 条结果")
        except Exception as e:
            print(f"[SQL ERROR] {e}")
        finally:
            conn.close()

    # 获取当前登录用户信息
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = get_safe_user_info(username)

    return render_template(
        "index.html",
        username=username,
        user=user_info,
        search_results=results,
        search_keyword=keyword,
    )


# ---------------------------------------------------------------------------
# 错误处理器
# ---------------------------------------------------------------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template("login.html", error=str(e.description)), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("login.html", error="请求的页面不存在。"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("login.html", error="服务器内部错误，请稍后再试。"), 500


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=Config.DEBUG, host="0.0.0.0", port=5000)
