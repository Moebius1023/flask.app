# 用户信息管理平台

基于 Flask 的安全登录管理系统，具备企业级 Web 安全防护机制。
支持用户注册、登录、搜索、头像上传等完整功能。

---

## 功能特性

| 功能 | 说明 |
|------|------|
| **用户登录** | 表单登录，CSRF 令牌防护，频率限制 |
| **用户注册** | 新用户注册，数据存储到 SQLite 数据库 |
| **用户搜索** | 关键词模糊搜索，结果以表格展示 |
| **头像上传** | 安全文件上传，UUID 重命名，内容真实性校验 |

## 安全特性

| 防护维度 | 实现方式 |
|---------|---------|
| **密码存储** | pbkdf2:sha256:600000 慢哈希加盐，每个用户独立随机盐值 |
| **最小数据暴露** | 响应体仅返回 `username` 和 `role`，密码/邮箱/手机/余额绝不传递 |
| **CSRF 防护** | 表单绑定唯一令牌，`secrets.compare_digest()` 时序安全比对，登录后销毁旧令牌 |
| **登录频率限制** | 单 IP 连续 5 次错误锁定 15 分钟 |
| **防用户名枚举** | 用户不存在和密码错误返回统一提示 |
| **输入过滤** | 去除控制字符、首尾空白，限制长度 64 字符 |
| **输出转义** | Jinja2 自动 HTML 转义，防御 XSS |
| **安全响应头** | X-Content-Type-Options、X-Frame-Options: DENY、CSP 严格策略 |
| **Session 安全** | HttpOnly、SameSite=Lax、30 分钟过期 |
| **密钥外部化** | SECRET_KEY 通过 `.env` 文件或环境变量加载，不硬编码 |
| **参数化查询** | SQL 语句使用 `?` 占位符，防止 UNION/OR/堆叠注入 |
| **错误处理** | 统一 403/404/500 页面，不泄露内部信息 |

### 文件上传安全

| 防护措施 | 说明 |
|---------|------|
| **后缀白名单** | 仅允许 jpg/jpeg/png/gif/webp |
| **魔数校验** | 检查文件头签名，拒绝伪装图片木马 |
| **UUID 文件名** | `uuid.uuid4().hex` 随机命名，防路径穿越和文件覆盖 |
| **路径穿越防护** | `os.path.basename()` 过滤，拒绝 `../../` 攻击 |
| **强制纯文本输出** | 通过 `/media/` 路由以 `text/plain` 输出，禁止脚本执行 |
| **Base64 预览** | 上传后通过 data URL 预览，不依赖直接文件访问 |
| **.htaccess 防护** | 上传目录配置禁止脚本引擎解析 |

---

## 快速开始

### 环境要求

- Python 3.9+
- Flask

### 安装与启动

```bash
# 1. 安装依赖
pip install flask

# 2. 配置密钥（项目已自带随机生成的 .env，如需重新生成）
python3 -c "import secrets; print(f'FLASK_SECRET_KEY={secrets.token_hex(32)}')" > .env

# 3. 启动服务
python3 app.py
```

访问 `http://192.168.28.128:5000`

### 测试账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| `admin` | `admin123` | 管理员 |
| `alice` | `alice2025` | 普通用户 |

> ⚠️ 密码已通过 pbkdf2 慢哈希处理，原始明文仅在用户输入时存在于内存中。

---

## 项目结构

```
├── app.py              # 主应用 — 路由、安全逻辑、中间件
├── config.py           # 配置加载 — 密钥外部化、安全策略参数
├── .env                # 环境变量（FLASK_SECRET_KEY，已加入 .gitignore）
├── .gitignore
├── README.md
├── data/
│   ├── users.db        # SQLite 用户数据库（运行时自动生成）
│   └── uploads/
│       └── .htaccess   # 上传目录安全配置
├── templates/
│   ├── base.html       # 基础模板 — 导航栏、布局
│   ├── login.html      # 登录页面 — CSRF 令牌、输入校验
│   ├── register.html   # 注册页面
│   ├── index.html      # 首页 — 用户信息 + 搜索功能
│   └── upload.html     # 文件上传页面
└── static/
    └── css/
        └── style.css   # 样式表 — 渐变导航栏、卡片布局
```

---

## API 端点

| 方法 | 路径 | 说明 | 身份验证 |
|------|------|------|---------|
| GET | `/` | 首页 | 可选 |
| GET | `/login` | 登录页面 | 否 |
| POST | `/login` | 提交登录请求（需 `_csrf_token`） | 否 |
| GET | `/logout` | 登出 | 是 |
| GET | `/register` | 注册页面 | 否 |
| POST | `/register` | 提交注册信息 | 否 |
| GET | `/search?keyword=` | 搜索用户 | 是 |
| GET | `/upload` | 上传页面 | 是 |
| POST | `/upload` | 提交上传文件 | 是 |
| GET | `/media/<filename>` | 获取上传文件（text/plain） | 是 |

---

## 安全配置参考 (`config.py`)

```python
MAX_LOGIN_ATTEMPTS = 5        # 最大失败尝试次数
LOGIN_LOCKOUT_MINUTES = 15    # 锁定时长（分钟）
MAX_INPUT_LENGTH = 64         # 输入最大长度
PERMANENT_SESSION_LIFETIME = 1800  # Session 过期时间（秒）
```

---

## SQL 注入修复记录

| 漏洞类型 | 位置 | 修复方式 | 状态 |
|---------|------|---------|------|
| UNION 注入 | `/search?keyword=` | 参数化查询 `?` 占位符 | ✅ |
| OR 注入 / 布尔盲注 | `/search?keyword=` | 参数化查询 `?` 占位符 | ✅ |
| 堆叠查询注入 | `/search?keyword=` | 参数化查询 `?` 占位符 | ✅ |
| INSERT 注入 | `/register` POST | 参数化查询 `?` 占位符 | ✅ |

---

## 文件上传漏洞修复记录

| 漏洞类型 | 修复方式 | 状态 |
|---------|---------|------|
| 任意文件上传 | 后缀白名单（jpg/png/gif/webp） | ✅ |
| 图片木马 | 魔数校验文件头签名 | ✅ |
| 路径穿越 | `os.path.basename()` + UUID 命名 | ✅ |
| 文件覆盖 | UUID 随机文件名 | ✅ |
| 存储型 XSS | `/media/` 路由强制 `text/plain` 输出 | ✅ |
| 脚本执行 | `.htaccess` 禁止引擎解析 | ✅ |

---

## 生产环境部署清单

- [ ] 关闭 Debug：`export FLASK_DEBUG=0`（默认已关闭）
- [ ] 更换密钥：生成新的 `FLASK_SECRET_KEY` 写入 `.env`
- [ ] 重新生成密码哈希，替换 `USERS` 字典中的预置值
- [ ] 配置 HTTPS 反向代理（Nginx/Caddy）
- [ ] 将 `SESSION_COOKIE_SECURE` 设为 `True`
- [ ] 将 `USERS` 字典迁移至数据库（如 SQLite/PostgreSQL）
- [ ] 添加登录审计日志
- [ ] 添加 Web 应用防火墙（WAF）

---

## 技术栈

| 组件 | 技术 |
|------|------|
| 框架 | Flask |
| 数据库 | SQLite3 |
| 密码哈希 | pbkdf2:sha256:600000（Werkzeug Security） |
| 模板引擎 | Jinja2（自动转义） |
| 前端 | HTML5 + CSS3（Flexbox） |
