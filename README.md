# EdgeOne Pages 短链接服务

## 项目结构

```
shortlink-service/
├── functions/
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
└── edgeone.json                # 路由配置
```

## 部署步骤

### 1. 开通 KV Storage 服务

1. 登录 [EdgeOne 控制台](https://console.cloud.tencent.com/edgeone)
2. 进入 Pages 项目 → KV Storage
3. 点击 "Apply now" 申请开通
4. 创建 Namespace，例如：`shortlink-data`

### 2. 绑定 KV 到项目

1. 在项目页面 → KV Storage → Bind Namespace
2. Variable Name: **`shortlink_kv`**
3. Namespace: 选择创建的 namespace

### 3. 配置环境变量

在项目设置 → Environment Variables 中添加：

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `ADMIN_USERNAME` | 管理员账号 | `admin` |
| `ADMIN_PASSWORD_HASH` | 密码 SHA-256 哈希 | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` |
| `ADMIN_TOTP_SECRET` | TOTP Base32 密钥 | `JBSWY3DPEHPK3PXP` |
| `JWT_SECRET` | JWT 签名密钥 | `your-random-secret-key-min-32-chars` |

> 密码哈希生成：`echo -n "your-password" | sha256sum`
> TOTP 密钥生成：`openssl rand -base32 20`

### 4. 部署项目

- 通过 Git 推送代码自动部署
- 或手动上传 ZIP 文件

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

## 注意事项

1. EdgeOne Pages 静态资源优先级高于函数路由，短链使用 `/s/` 前缀避免冲突
2. KV 变量 `shortlink_kv` 直接作为全局变量使用，不要从 `context.env` 读取
3. 环境变量从 `context.env` 读取
