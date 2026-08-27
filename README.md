# EdgeOne Pages 短链接服务

## 项目结构

```
shortlink-service/
├── edge-functions/              # Edge Functions 目录
│   ├── api/
│   │   └── [[default]].js      # API 路由: /api/*
│   └── s/
│       └── [[default]].js      # 短链跳转: /s/*
├── public/                      # 静态文件
│   ├── index.html              # 首页
│   ├── admin.html              # 管理后台
│   ├── login.html              # 登录页
│   ├── 404.html                # 错误页面
│   └── assets/
│       └── style.css           # 公共样式
└── edgeone.json                # 配置
```

## 关键修复点

### 1. 目录名必须是 `edge-functions/`
EdgeOne Pages 的 Edge Functions 目录名是 `edge-functions/`，不是 `functions/`。

### 2. 静态资源优先级高于函数路由
EdgeOne Pages 的规则：**静态资源 > 函数路由**。因此短链使用 `/s/` 前缀，避免与静态文件冲突。

### 3. KV 作为全局变量
KV 绑定后直接使用变量名（如 `shortlink_kv`），不要从 `context.env` 读取。

## 部署步骤

### 1. 开通 KV Storage 服务
1. 登录 EdgeOne 控制台
2. 进入 Pages 项目 → KV Storage
3. 点击 "Apply now" 申请开通
4. 创建 Namespace，例如：`shortlink-data`

### 2. 绑定 KV 到项目
1. 项目页面 → KV Storage → Bind Namespace
2. Variable Name: **`shortlink_kv`**
3. Namespace: 选择创建的 namespace

### 3. 配置环境变量

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `ADMIN_USERNAME` | 管理员账号 | `admin` |
| `ADMIN_PASSWORD_HASH` | 密码 SHA-256 哈希 | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` |
| `ADMIN_TOTP_SECRET` | TOTP Base32 密钥 | `JBSWY3DPEHPK3PXP` |
| `JWT_SECRET` | JWT 签名密钥 | `your-random-secret-key-min-32-chars` |

> 密码哈希生成：`echo -n "your-password" | sha256sum`
> TOTP 密钥生成：`openssl rand -base32 20`

### 4. 部署项目
- 上传 ZIP 文件（根目录直接包含 edge-functions/ 和 public/）
- 或推送到 Git 仓库自动部署

### 5. 访问测试
- 首页: `https://your-domain.edgeone.dev/`
- 管理后台: `https://your-domain.edgeone.dev/admin`
- 短链格式: `https://your-domain.edgeone.dev/s/xxxxx`

## 功能特性

- ✅ 短链生成（支持自定义短码）
- ✅ 密码保护
- ✅ 过期时间设置
- ✅ 点击统计
- ✅ 管理员登录（账号 + 密码 + TOTP）
- ✅ JWT 会话管理
- ✅ 链接管理（启用/禁用/编辑/删除）
- ✅ 数据统计可视化
