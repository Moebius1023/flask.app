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
import uuid
import base64
import urllib.request
import urllib.error
import socket
import subprocess
import platform

from flask import (
    Flask, render_template, request, redirect, session, url_for, abort,
    send_from_directory
)
from werkzeug.security import check_password_hash
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)


# ---------------------------------------------------------------------------
# SQLite 数据库初始化
# ---------------------------------------------------------------------------
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "uploads")
PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")

def init_db():
    """初始化 SQLite 数据库并创建所需目录"""
    os.makedirs(DB_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            balance REAL DEFAULT 0.0,
            role TEXT DEFAULT 'user'
        )
    """)
    # 尝试添加列（兼容旧表）
    for col in ["balance REAL DEFAULT 0.0", "role TEXT DEFAULT 'user'"]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN {col}")
        except sqlite3.OperationalError:
            pass
    # 插入默认用户（密码使用 pbkdf2 哈希）
    from werkzeug.security import generate_password_hash
    default_users = [
        ("admin", generate_password_hash("admin123", method="pbkdf2:sha256"), "admin@example.com", "13800138000", 99999, "admin"),
        ("alice", generate_password_hash("alice2025", method="pbkdf2:sha256"), "alice@example.com", "13900139001", 100, "user"),
    ]
    for u in default_users:
        c.execute(
            "INSERT OR IGNORE INTO users (username, password, email, phone, balance, role) VALUES (?, ?, ?, ?, ?, ?)",
            u
        )
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
    获取仅包含标识信息的用户数据（从 SQLite 查询）。
    密码、邮箱、手机、余额等字段绝不传递到前端。
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT username, role FROM users WHERE username = ?", (username,)
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            return {"username": row["username"], "role": row["role"]}
    except sqlite3.Error:
        pass
    return None


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
    user_info = get_safe_user_info(username) if username else None
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
        else:
            # ---- 从 SQLite 查询用户（密码使用慢哈希比对） ----
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.execute(
                "SELECT password FROM users WHERE username = ?", (username,)
            )
            row = cursor.fetchone()
            conn.close()

            if row is None:
                error = "用户名或密码错误。"
                record_failed_attempt(client_ip)
            elif check_password_hash(row[0], password):
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
        # ---- CSRF 验证 ----
        csrf_form_token = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_form_token):
            abort(403, description="CSRF 令牌验证失败，请刷新页面重试。")

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        conn = sqlite3.connect(DB_PATH)
        try:
            from werkzeug.security import generate_password_hash
            hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")
            conn.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, hashed_pw, email, phone)
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
            # 转义 LIKE 通配符，防止 % 和 _ 泄露数据
            safe_keyword = keyword.replace("%", r"\%").replace("_", r"\_")
            cursor = conn.execute(
                "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ? ESCAPE '\\'",
                (f"%{safe_keyword}%", f"%{safe_keyword}%")
            )
            results = cursor.fetchall()
            print(f"[SQL] 参数化查询: LIKE %{keyword}%, 返回 {len(results)} 条结果")
        except Exception as e:
            print(f"[SQL ERROR] {e}")
        finally:
            conn.close()

    # 获取当前登录用户信息
    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None

    return render_template(
        "index.html",
        username=username,
        user=user_info,
        search_results=results,
        search_keyword=keyword,
    )


# ---------------------------------------------------------------------------
# 文件上传配置
# ---------------------------------------------------------------------------
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}
# 常见图片文件魔数（文件头签名）
IMAGE_SIGNATURES = {
    b"\xff\xd8\xff": "jpeg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",  # WEBP 以 RIFF 开头
}


def check_image_content(file_bytes: bytes) -> bool:
    """通过魔数校验文件内容是否为真实图片"""
    for sig in IMAGE_SIGNATURES:
        if file_bytes.startswith(sig):
            return True
    return False


# ---------------------------------------------------------------------------
# 路由：头像上传（安全加固版）
# ---------------------------------------------------------------------------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    """文件上传路由，需要登录才能访问"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    message = None
    message_type = None
    file_url = None
    preview_data_url = None
    raw_filename = None

    if request.method == "POST":
        # ---- CSRF 验证 ----
        csrf_form_token = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_form_token):
            abort(403, description="CSRF 令牌验证失败，请刷新页面重试。")

        if "file" not in request.files:
            message = "请选择要上传的文件"
            message_type = "error"
        else:
            f = request.files["file"]
            if f.filename == "":
                message = "请选择要上传的文件"
                message_type = "error"
            else:
                # ---- 安全检查 1：路径穿越防护 ----
                original_filename = os.path.basename(f.filename)

                # ---- 安全检查 2：后缀白名单 ----
                ext = ""
                if "." in original_filename:
                    ext = original_filename.rsplit(".", 1)[1].lower()
                if ext not in ALLOWED_EXTENSIONS:
                    message = f"不允许的文件类型（仅支持：{', '.join(sorted(ALLOWED_EXTENSIONS))}）"
                    message_type = "error"
                    return render_template(
                        "upload.html",
                        username=username,
                        message=message,
                        message_type=message_type,
                    )

                # ---- 安全检查 3：内容真实性校验（魔数） ----
                file_bytes = f.read()
                if not check_image_content(file_bytes):
                    message = "文件内容不是有效的图片格式，请上传真实图片文件"
                    message_type = "error"
                    return render_template(
                        "upload.html",
                        username=username,
                        message=message,
                        message_type=message_type,
                    )

                try:
                    # ---- 安全检查 4：UUID 随机文件名 ----
                    unique_name = f"{uuid.uuid4().hex}.{ext}"
                    save_path = os.path.join(UPLOAD_DIR, unique_name)

                    # 写入文件
                    with open(save_path, "wb") as fp:
                        fp.write(file_bytes)

                    # 生成安全的文件访问 URL（通过 /media/ 路由）
                    file_url = url_for("media_file", filename=unique_name)

                    # 生成 base64 data URL 用于页面预览
                    mime_type = f"image/{ext}" if ext != "jpg" else "image/jpeg"
                    b64_data = base64.b64encode(file_bytes).decode("ascii")
                    preview_data_url = f"data:{mime_type};base64,{b64_data}"

                    message = "文件上传成功！"
                    message_type = "success"
                except Exception as e:
                    message = f"上传失败：{str(e)}"
                    message_type = "error"

    return render_template(
        "upload.html",
        username=username,
        message=message,
        message_type=message_type,
        file_url=file_url,
        preview_data_url=preview_data_url,
    )


# ---------------------------------------------------------------------------
# 路由：安全文件访问（强制纯文本解析，禁止脚本执行）
# ---------------------------------------------------------------------------
@app.route("/media/<filename>")
def media_file(filename):
    """
    安全地提供上传文件。
    - 使用 send_from_directory 限定目录范围（防路径穿越）
    - 强制 Content-Type: text/plain（防 XSS / 脚本执行）
    - 浏览器不会渲染 HTML / 执行 PHP / 运行脚本
    """
    return send_from_directory(UPLOAD_DIR, filename, mimetype="text/plain")


# ---------------------------------------------------------------------------
# 路由：个人中心（根据当前登录用户查询本人资料）
# ---------------------------------------------------------------------------
@app.route("/profile")
def profile():
    """个人中心，根据 session 中的用户名查询当前用户资料"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    user_data = None
    error = None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT id, username, email, phone, balance FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    if row:
        user_data = {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "phone": row["phone"],
            "balance": row["balance"],
        }
    else:
        error = "无法获取用户信息"
    conn.close()

    return render_template(
        "profile.html",
        username=username,
        user_data=user_data,
        error=error,
    )


# ---------------------------------------------------------------------------
# 路由：充值（校验充值金额必须为正数）
# ---------------------------------------------------------------------------
@app.route("/recharge", methods=["POST"])
def recharge():
    """充值接口，金额必须大于 0"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    # ---- CSRF 验证 ----
    csrf_form_token = request.form.get("_csrf_token", "")
    if not validate_csrf_token(csrf_form_token):
        abort(403, description="CSRF 令牌验证失败，请刷新页面重试。")

    user_id = request.form.get("user_id")
    amount = request.form.get("amount")

    if not user_id or not amount:
        return redirect(url_for("profile"))

    try:
        user_id = int(user_id)
        amount = float(amount)
        if amount <= 0:
            return redirect(url_for("profile"))

        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "UPDATE users SET balance = balance + ? WHERE id = ?",
            (amount, user_id)
        )
        conn.commit()
        conn.close()
    except (ValueError, TypeError, sqlite3.Error) as e:
        print(f"[RECHARGE ERROR] {e}")

    return redirect(url_for("profile"))


# ---------------------------------------------------------------------------
# 路由：修改密码（无 CSRF、无原密码校验、可修改任意用户密码）
# ---------------------------------------------------------------------------
@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码，需验证原密码和 CSRF"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    # ---- CSRF 验证 ----
    csrf_form_token = request.form.get("_csrf_token", "")
    if not validate_csrf_token(csrf_form_token):
        abort(403, description="CSRF 令牌验证失败，请刷新页面重试。")

    target_user = request.form.get("username", "")
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    # 只能修改自己的密码
    if target_user != username:
        return redirect(url_for("profile"))

    # 验证原密码
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return redirect(url_for("profile"))

    from werkzeug.security import check_password_hash, generate_password_hash
    if not check_password_hash(row[0], old_password):
        conn.close()
        return redirect(url_for("profile"))

    # 验证两次新密码一致
    if not new_password or new_password != confirm_password:
        conn.close()
        return redirect(url_for("profile"))

    # 更新密码
    try:
        hashed = generate_password_hash(new_password, method="pbkdf2:sha256")
        conn.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, target_user))
        conn.commit()
        print(f"[CHANGE-PASSWORD] 用户 {target_user} 密码已修改")
    except sqlite3.Error as e:
        print(f"[CHANGE-PASSWORD ERROR] {e}")
    finally:
        conn.close()

    return redirect(url_for("profile"))


# ---------------------------------------------------------------------------
# 路由：动态页面加载
# ---------------------------------------------------------------------------
@app.route("/page")
def dynamic_page():
    """根据 URL 参数 name 加载 pages/ 目录下的文件"""
    name = request.args.get("name", "")
    page_content = None
    error_msg = None

    if name:
        # 安全校验：仅允许访问 pages/ 目录内的文件
        safe_name = name.replace("..", "").replace("/", "").replace("\\", "")
        if not safe_name:
            error_msg = "页面不存在"
        else:
            file_path = os.path.join(PAGES_DIR, safe_name)
            if os.path.isfile(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                # 尝试加 .html 后缀
                file_path_html = file_path + ".html"
                if os.path.isfile(file_path_html):
                    with open(file_path_html, "r", encoding="utf-8") as f:
                        page_content = f.read()
                else:
                    error_msg = "页面不存在"

    # 获取当前用户信息
    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None

    return render_template(
        "index.html",
        username=username,
        user=user_info,
        page_content=page_content,
        page_error=error_msg,
    )


# ---------------------------------------------------------------------------
# 路由：URL 抓取（SSRF 安全防护版）
# ---------------------------------------------------------------------------
def is_private_ip(ip: str) -> bool:
    """检查 IP 是否为私有/保留地址"""
    try:
        addr = int(socket.inet_aton(ip).hex(), 16)
    except OSError:
        return False
    # 127.0.0.0/8
    if (addr >> 24) == 0x7F:
        return True
    # 10.0.0.0/8
    if (addr >> 24) == 0x0A:
        return True
    # 172.16.0.0/12
    if (addr >> 20) & 0xFFF == 0xAC1:
        return True
    # 192.168.0.0/16
    if (addr >> 16) == 0xC0A8:
        return True
    # 169.254.0.0/16 (link-local)
    if (addr >> 16) == 0xA9FE:
        return True
    # 0.0.0.0/8
    if (addr >> 24) == 0x00:
        return True
    # ::1 (IPv6 loopback)
    if ip == "::1":
        return True
    return False

def resolve_and_check(url: str) -> tuple[bool, str]:
    """解析域名并检查目标是否为内网地址，返回(是否安全, 错误信息)"""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False, "无效的 URL"
        # 检查 host 是否为 IP 地址
        try:
            socket.inet_aton(host)
            ip = host
        except OSError:
            # 域名解析
            ip = socket.gethostbyname(host)
        if is_private_ip(ip):
            return False, f"目标地址 {ip} 为内网地址，已拦截"
        return True, ip
    except socket.gaierror:
        return False, "域名解析失败"
    except Exception as e:
        return False, f"地址检查失败：{str(e)}"


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    """抓取用户提交的 URL，带 SSRF 和 CSRF 防护"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    # ---- CSRF 验证 ----
    csrf_form_token = request.form.get("_csrf_token", "")
    if not validate_csrf_token(csrf_form_token):
        abort(403, description="CSRF 令牌验证失败，请刷新页面重试。")

    url = request.form.get("url", "")
    fetch_status = None
    fetch_content = None
    fetch_error = None
    fetch_url_input = url

    if url:
        # ---- 安全检查 1：协议白名单（仅允许 http/https） ----
        if not url.startswith("http://") and not url.startswith("https://"):
            fetch_error = "仅支持 http:// 和 https:// 协议"
            return render_template_with_fetch(username, fetch_error, fetch_url_input)

        # ---- 安全检查 2：DNS 解析 + 内网 IP 拦截 ----
        safe, result = resolve_and_check(url)
        if not safe:
            fetch_error = result
            return render_template_with_fetch(username, fetch_error, fetch_url_input)

        # ---- 安全检查 3：发起请求（禁用自动重定向，10 秒超时） ----
        try:
            req = urllib.request.Request(url)
            req.method = "GET"
            # 禁用自动重定向，防止通过重定向跳转到内网
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(NoRedirectHandler)
            with opener.open(req, timeout=10) as response:
                fetch_status = response.status if response.status else 200
                raw = response.read()
                content = raw.decode("utf-8", errors="replace")
                fetch_content = content[:5000]
        except urllib.error.HTTPError as e:
            # 3xx 重定向被拦截，状态码仍然返回
            fetch_status = e.code
            fetch_content = f"请求被拦截（HTTP {e.code}），不跟随重定向。Location: {e.headers.get('Location', '无')}"
        except Exception as e:
            fetch_error = f"抓取失败：{str(e)}"

    return render_template_with_fetch(username, fetch_error, fetch_url_input,
                                      fetch_status, fetch_content)


def render_template_with_fetch(username, fetch_error=None, fetch_url=None,
                                fetch_status=None, fetch_content=None):
    """统一渲染首页并传递抓取结果"""
    user_info = get_safe_user_info(username) if username else None
    return render_template(
        "index.html",
        username=username,
        user=user_info,
        fetch_status=fetch_status,
        fetch_content=fetch_content,
        fetch_error=fetch_error,
        fetch_url=fetch_url,
    )


# ---------------------------------------------------------------------------
# 路由：Ping 网络诊断（使用 shell=True，存在命令注入风险）
# ---------------------------------------------------------------------------
@app.route("/ping", methods=["GET", "POST"])
def ping():
    """Ping 测试，使用列表传参防止命令注入，带 CSRF 防护"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    result = None
    ip_input = None

    if request.method == "POST":
        # ---- CSRF 验证 ----
        csrf_form_token = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_form_token):
            abort(403, description="CSRF 令牌验证失败，请刷新页面重试。")

        ip = request.form.get("ip", "")
        ip_input = ip
        if ip:
            try:
                # 使用列表传参，禁止 shell=True，彻底防止命令注入
                output = subprocess.check_output(
                    ["ping", "-c", "3", ip],
                    stderr=subprocess.STDOUT,
                    timeout=30
                )
                result = output.decode("utf-8", errors="replace")
            except subprocess.CalledProcessError as e:
                result = e.output.decode("utf-8", errors="replace") if e.output else f"Ping 失败（返回码：{e.returncode}）"
            except subprocess.TimeoutExpired:
                result = "Ping 超时（30秒）"
            except Exception as e:
                result = f"Ping 执行错误：{str(e)}"

    return render_template("ping.html", username=username, result=result, ip_input=ip_input)


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
