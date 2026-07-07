"""
配置文件 - 从环境变量或 .env 文件加载敏感配置
"""
import os

# 从环境变量加载 SECRET_KEY，如果不存在则尝试读取 .env 文件
def load_secret_key():
    """加载密钥，优先级：环境变量 > .env 文件"""
    key = os.environ.get("FLASK_SECRET_KEY")
    if key:
        return key

    # 尝试从 .env 文件读取
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.isfile(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("FLASK_SECRET_KEY="):
                    key = line.split("=", 1)[1].strip().strip("\"'")
                    return key

    raise RuntimeError(
        "SECRET_KEY 未设置！请设置环境变量 FLASK_SECRET_KEY "
        "或在项目根目录创建 .env 文件，内容为：\n"
        "FLASK_SECRET_KEY=<你的随机密钥>"
    )


class Config:
    """应用配置"""
    SECRET_KEY = load_secret_key()

    # 登录安全配置
    MAX_LOGIN_ATTEMPTS = 5          # 最大允许失败次数
    LOGIN_LOCKOUT_MINUTES = 15      # 锁定时间（分钟）

    # 密码复杂度要求
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPER = False
    PASSWORD_REQUIRE_LOWER = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = False

    # 输入限制
    MAX_INPUT_LENGTH = 64

    # 会话配置
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 1800  # 30分钟

    # 运行模式（通过环境变量控制，不硬编码）
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
