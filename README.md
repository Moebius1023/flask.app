# 用户信息管理平台

基于 Flask 的安全登录管理系统，具备企业级 Web 安全防护机制。
支持用户登录、注册、搜索、头像上传、个人中心、充值、密码修改、URL 抓取、Ping 测试等完整功能。

---

## 功能特性

| 功能 | 说明 |
|------|------|
| **用户登录** | 表单登录，CSRF 令牌防护，登录频率限制 |
| **用户注册** | 新用户注册，密码哈希后存入 SQLite |
| **用户搜索** | 关键词模糊搜索，结果以表格展示 |
| **头像上传** | 安全文件上传，白名单 + 魔数校验 + UUID 重命名 |
| **个人中心** | 查看个人资料（ID、用户名、邮箱、手机、余额） |
| **余额充值** | 个人中心页面充值，金额正负校验 |
| **修改密码** | 需验证原密码 + 确认密码 + CSRF 令牌 |
| **帮助中心** | 动态页面加载，显示帮助内容 |
| **URL 抓取** | 抓取外部 URL，具备 SSRF 防护 |
| **Ping 测试** | 网络诊断工具，具备命令注入防护 |

---

## 安全防护体系

| 防护维度 | 实现方式 |
|---------|---------|
| **密码存储** | pbkdf2:sha256 慢哈希加盐存储 |
| **CSRF 防护** | 全部 POST 接口绑定唯一令牌，`secrets.compare_digest()` 时序安全比对 |
| **登录频率限制** | 单 IP 连续 5 次错误锁定 15 分钟 |
| **防用户名枚举** | 用户不存在和密码错误返回统一提示 |
| **参数化查询** | SQL 语句使用 `?` 占位符，防御 UNION/OR/堆叠注入 |
| **SSRF 防护** | 协议白名单 + DNS 解析后二次校验 + 内网 IP 拦截 + 禁用自动重定向 |
| **命令注入防护** | 禁止 `shell=True`，使用列表传参执行系统命令 |
| **文件上传安全** | 后缀白名单 + 魔数校验 + UUID 命名 + `text/plain` 输出 |
| **文件包含防护** | 过滤 `../` 路径穿越，限定 `PAGES_DIR` 目录范围 |
| **XSS 防护** | Jinja2 自动 HTML 转义，移除 `| safe` 过滤器 |
| **水平越权防护** | 个人中心通过 session 查询本人资料 |
| **修改密码安全** | 校验原密码 + 确认密码 + session 用户身份 |
| **安全响应头** | X-Content-Type-Options、X-Frame-Options: DENY、CSP |
| **Session 安全** | HttpOnly、SameSite=Lax、30 分钟过期 |
| **密钥外部化** | SECRET_KEY 通过 `.env` 文件或环境变量加载 |

---

## 快速开始

### 安装与启动

```bash
pip install flask
python3 -c "import secrets; print(f'FLASK_SECRET_KEY={secrets.token_hex(32)}')" > .env
python3 app.py
```

访问 `http://192.168.28.128:5000`

### 测试账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| `admin` | `admin123` | 管理员 |
| `alice` | `alice2025` | 普通用户 |

---

## 项目结构

```
├── app.py              # 主应用
├── config.py           # 配置加载
├── .env                # 环境变量
├── README.md
├── data/
│   ├── users.db        # SQLite 数据库
│   └── uploads/
│       └── .htaccess
├── pages/
│   └── help.html       # 帮助中心
├── templates/
│   ├── base.html       # 基础模板
│   ├── login.html      # 登录
│   ├── register.html   # 注册
│   ├── index.html      # 首页
│   ├── profile.html    # 个人中心
│   ├── upload.html     # 文件上传
│   └── ping.html       # Ping 测试
└── static/
    └── css/
        └── style.css
```

---

## API 端点

| 方法 | 路径 | 说明 | 登录要求 |
|------|------|------|---------|
| GET | `/` | 首页 | 可选 |
| GET | `/login` | 登录页面 | 否 |
| POST | `/login` | 登录提交 | 否 |
| GET | `/logout` | 登出 | 是 |
| GET | `/register` | 注册页面 | 否 |
| POST | `/register` | 注册提交 | 否 |
| GET | `/search?keyword=` | 搜索用户 | 是 |
| GET | `/profile` | 个人中心 | 是 |
| POST | `/recharge` | 充值 | 是 |
| POST | `/change-password` | 修改密码 | 是 |
| GET | `/upload` | 上传页面 | 是 |
| POST | `/upload` | 上传文件 | 是 |
| GET | `/media/<filename>` | 查看上传文件 | 是 |
| GET | `/page?name=` | 动态页面 | 是 |
| POST | `/fetch-url` | URL 抓取 | 是 |
| GET | `/ping` | Ping 页面 | 是 |
| POST | `/ping` | 执行 Ping | 是 |

---

## 漏洞修复记录

| 漏洞类型 | 修复方式 | 状态 |
|---------|---------|:----:|
| SSRF（URL 抓取） | 协议白名单 + DNS 二次校验 + 内网拦截 + 禁重定向 | ✅ |
| 命令注入（Ping） | 列表传参替代 shell=True | ✅ |
| SQL 注入 | 参数化查询 `?` 占位符（全部 SQL 语句） | ✅ |
| 文件包含 LFI | 过滤 `../` + PAGES_DIR 目录限定 | ✅ |
| 存储型 XSS | 移除 `| safe` 过滤器 | ✅ |
| 水平越权 IDOR | session 查询本人资料 | ✅ |
| 密码明文存储 | pbkdf2:sha256 哈希 | ✅ |
| 密码哈希硬编码 | 删除 USERS 字典，全部查询 SQLite | ✅ |
| 任意文件上传 | 后缀白名单 + 魔数校验 + UUID 命名 | ✅ |
| 上传文件 XSS | /media/ 路由强制 text/plain 输出 | ✅ |
| LIKE 通配符泄露 | ESCAPE `\` 转义 % 和 _ | ✅ |
| 充值负值业务漏洞 | amount > 0 校验 | ✅ |
| 越权改密 | 校验 session + 原密码 + 确认密码 | ✅ |
| CSRF 防护缺失 | 全部 POST 接口添加令牌验证（7 个接口） | ✅ |

---

## 生产环境部署清单

- [ ] 关闭 Debug：`export FLASK_DEBUG=0`（默认已关闭）
- [ ] 更换密钥：重新生成 `FLASK_SECRET_KEY`
- [ ] 配置 HTTPS 反向代理（Nginx/Caddy）
- [ ] 将 `SESSION_COOKIE_SECURE` 设为 `True`
- [ ] 添加登录审计日志

---

## 技术栈

| 组件 | 技术 |
|------|------|
| 框架 | Flask |
| 数据库 | SQLite3 |
| 密码哈希 | pbkdf2:sha256（Werkzeug Security） |
| 模板引擎 | Jinja2 |
| 前端 | HTML5 + CSS3（Flexbox） |
