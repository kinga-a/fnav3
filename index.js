// ==============================
// 工具函数：加密、TOTP、JWT、短码生成
// ==============================

// 生成随机短码
function generateShortCode(length = 6) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let result = '';
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  for (let i = 0; i < length; i++) {
    result += chars[array[i] % chars.length];
  }
  return result;
}

// PBKDF2 密码哈希验证
async function verifyPassword(password, hashString) {
  const [iterations, saltB64, hashB64] = hashString.split(':');
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const expectedHash = Uint8Array.from(atob(hashB64), c => c.charCodeAt(0));
  
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password),
    'PBKDF2', false, ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: parseInt(iterations), hash: 'SHA-256' },
    key, 256
  );
  const derivedHash = new Uint8Array(derivedBits);
  
  if (derivedHash.length !== expectedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < derivedHash.length; i++) {
    diff |= derivedHash[i] ^ expectedHash[i];
  }
  return diff === 0;
}

// Base32 解码（用于TOTP密钥）
function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of str.toUpperCase().replace(/=+$/, '')) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) throw new Error('Invalid Base32 character');
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

// TOTP 验证码验证
async function verifyTOTP(secret, code, window = 1) {
  const keyBytes = base32Decode(secret);
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' },
    false, ['sign']
  );
  
  const now = Math.floor(Date.now() / 1000);
  for (let offset = -window; offset <= window; offset++) {
    const time = Math.floor((now + offset * 30) / 30);
    const timeBuffer = new ArrayBuffer(8);
    new DataView(timeBuffer).setBigUint64(0, BigInt(time), false);
    
    const hmac = await crypto.subtle.sign('HMAC', key, timeBuffer);
    const hmacArray = new Uint8Array(hmac);
    const offsetByte = hmacArray[hmacArray.length - 1] & 0x0f;
    const binary = (
      ((hmacArray[offsetByte] & 0x7f) << 24) |
      ((hmacArray[offsetByte + 1] & 0xff) << 16) |
      ((hmacArray[offsetByte + 2] & 0xff) << 8) |
      (hmacArray[offsetByte + 3] & 0xff)
    );
    const generatedCode = (binary % 1000000).toString().padStart(6, '0');
    
    if (generatedCode === code) return true;
  }
  return false;
}

// JWT 签发
async function signJWT(payload, secret, expiresIn = 7 * 24 * 60 * 60) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  payload.exp = now + expiresIn;
  payload.iat = now;
  
  const encoder = new TextEncoder();
  const base64Header = btoa(String.fromCharCode(...encoder.encode(JSON.stringify(header))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const base64Payload = btoa(String.fromCharCode(...encoder.encode(JSON.stringify(payload))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const signature = await crypto.subtle.sign(
    'HMAC', key, encoder.encode(`${base64Header}.${base64Payload}`)
  );
  const base64Sig = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  
  return `${base64Header}.${base64Payload}.${base64Sig}`;
}

// JWT 验证
async function verifyJWT(token, secret) {
  try {
    const [headerB64, payloadB64, sigB64] = token.split('.');
    if (!headerB64 || !payloadB64 || !sigB64) return null;
    
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false, ['verify']
    );
    const sigBytes = Uint8Array.from(atob(sigB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify(
      'HMAC', key, sigBytes, encoder.encode(`${headerB64}.${payloadB64}`)
    );
    if (!valid) return null;
    
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

// 从Cookie中提取JWT
function getTokenFromCookie(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/eo_shortlink_token=([^;]+)/);
  return match ? match[1] : null;
}

// ==============================
// 页面模板
// ==============================

const HTML_HEAD = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EdgeOne 短链接服务</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f7fa; color: #333; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    .card { background: #fff; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); padding: 32px; width: 100%; max-width: 480px; }
    h1 { font-size: 24px; margin-bottom: 24px; text-align: center; color: #1a73e8; }
    h2 { font-size: 20px; margin-bottom: 20px; }
    .form-group { margin-bottom: 16px; }
    label { display: block; margin-bottom: 6px; font-size: 14px; color: #555; }
    input, textarea { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 14px; outline: none; transition: border-color 0.2s; }
    input:focus, textarea:focus { border-color: #1a73e8; }
    button { width: 100%; padding: 12px; background: #1a73e8; color: #fff; border: none; border-radius: 8px; font-size: 15px; cursor: pointer; transition: background 0.2s; }
    button:hover { background: #1557b0; }
    .btn-secondary { background: #6c757d; }
    .btn-secondary:hover { background: #5a6268; }
    .btn-danger { background: #dc3545; }
    .btn-danger:hover { background: #c82333; }
    .result { margin-top: 16px; padding: 12px; background: #e8f0fe; border-radius: 8px; word-break: break-all; }
    .error { color: #dc3545; margin-bottom: 16px; font-size: 14px; text-align: center; }
    .success { color: #28a745; margin-bottom: 16px; font-size: 14px; text-align: center; }
    .link-item { padding: 12px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; gap: 10px; }
    .link-info { flex: 1; min-width: 0; }
    .link-code { font-weight: 600; color: #1a73e8; }
    .link-target { font-size: 12px; color: #666; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .link-actions { display: flex; gap: 6px; }
    .link-actions button { width: auto; padding: 6px 10px; font-size: 12px; }
    .nav { margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
    .logout-btn { width: auto; padding: 8px 16px; font-size: 13px; }
    .stats { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; }
    .stat-card { padding: 16px; background: #f8f9fa; border-radius: 8px; text-align: center; }
    .stat-num { font-size: 24px; font-weight: 700; color: #1a73e8; }
    .stat-label { font-size: 12px; color: #666; margin-top: 4px; }
    textarea { resize: vertical; min-height: 60px; font-family: inherit; }
    .row { display: flex; gap: 10px; }
    .row > * { flex: 1; }
  </style>
</head>
<body>
`;

const HTML_FOOT = `
</body>
</html>
`;

function renderHomePage() {
  return `
  ${HTML_HEAD}
  <div class="card">
    <h1>🔗 EdgeOne 短链接</h1>
    <p style="text-align:center; color:#666; margin-bottom:24px;">基于边缘节点的极速短链接服务</p>
    <div class="form-group">
      <label>目标长链接</label>
      <input type="url" id="urlInput" placeholder="https://example.com/long-url" required>
    </div>
    <button onclick="generateLink()">生成短链接</button>
    <div id="result" class="result" style="display:none;"></div>
  </div>
  <script>
    async function generateLink() {
      const url = document.getElementById('urlInput').value.trim();
      if (!url) return alert('请输入链接');
      try {
        const res = await fetch('/api/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ targetUrl: url })
        });
        const data = await res.json();
        if (data.success) {
          const result = document.getElementById('result');
          result.style.display = 'block';
          result.innerHTML = \`
            <div>短链接：<strong>\${window.location.origin}/\${data.shortCode}</strong></div>
            <button onclick="navigator.clipboard.writeText('\${window.location.origin}/\${data.shortCode}')" style="margin-top:8px;">复制链接</button>
          \`;
        } else {
          alert(data.message || '生成失败');
        }
      } catch(e) {
        alert('请求失败');
      }
    }
  </script>
  ${HTML_FOOT}
  `;
}

function renderLoginPage(error = '') {
  return `
  ${HTML_HEAD}
  <div class="card">
    <h1>管理员登录</h1>
    ${error ? `<div class="error">${error}</div>` : ''}
    <form method="POST" action="/admin/login">
      <div class="form-group">
        <label>账号</label>
        <input type="text" name="username" required>
      </div>
      <div class="form-group">
        <label>密码</label>
        <input type="password" name="password" required>
      </div>
      <button type="submit">下一步</button>
    </form>
  </div>
  ${HTML_FOOT}
  `;
}

function renderTotpPage(challengeToken, error = '') {
  return `
  ${HTML_HEAD}
  <div class="card">
    <h1>两步验证</h1>
    <p style="text-align:center; color:#666; margin-bottom:20px;">请输入验证器中的6位验证码</p>
    ${error ? `<div class="error">${error}</div>` : ''}
    <form method="POST" action="/admin/totp">
      <input type="hidden" name="challenge" value="${challengeToken}">
      <div class="form-group">
        <label>TOTP 验证码</label>
        <input type="text" name="code" maxlength="6" pattern="\\d{6}" required autofocus>
      </div>
      <button type="submit">验证并登录</button>
    </form>
  </div>
  ${HTML_FOOT}
  `;
}

function renderAdminPage(links, stats) {
  const linksHtml = links.map(link => `
    <div class="link-item">
      <div class="link-info">
        <div class="link-code">/${link.shortCode}</div>
        <div class="link-target">${link.targetUrl}</div>
        <div style="font-size:11px; color:#999; margin-top:2px;">点击: ${link.clickCount} | ${link.status === 'active' ? '启用' : '禁用'}</div>
      </div>
      <div class="link-actions">
        <button onclick="editLink('${link.shortCode}')">编辑</button>
        <button class="btn-danger" onclick="deleteLink('${link.shortCode}')">删除</button>
      </div>
    </div>
  `).join('');

  return `
  ${HTML_HEAD}
  <div class="card" style="max-width: 640px;">
    <div class="nav">
      <h2>管理后台</h2>
      <button class="btn-secondary logout-btn" onclick="logout()">退出登录</button>
    </div>
    
    <div class="stats">
      <div class="stat-card">
        <div class="stat-num">${stats.totalLinks}</div>
        <div class="stat-label">总短链数</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">${stats.totalClicks}</div>
        <div class="stat-label">总点击量</div>
      </div>
    </div>

    <div style="margin-bottom:20px; padding:16px; background:#f8f9fa; border-radius:8px;">
      <h3 style="margin-bottom:12px; font-size:16px;">新建短链接</h3>
      <div class="form-group">
        <label>目标链接</label>
        <input type="url" id="newTarget" placeholder="https://example.com">
      </div>
      <div class="row">
        <div class="form-group">
          <label>自定义短码（可选）</label>
          <input type="text" id="newCode" placeholder="留空自动生成">
        </div>
        <div class="form-group">
          <label>过期时间（可选）</label>
          <input type="datetime-local" id="newExpire">
        </div>
      </div>
      <button onclick="createLink()">创建短链</button>
    </div>

    <h3 style="margin-bottom:12px; font-size:16px;">短链列表</h3>
    <div id="linkList">
      ${linksHtml || '<p style="text-align:center; color:#999; padding:20px;">暂无短链接</p>'}
    </div>
  </div>

  <script>
    async function createLink() {
      const targetUrl = document.getElementById('newTarget').value.trim();
      const shortCode = document.getElementById('newCode').value.trim();
      const expire = document.getElementById('newExpire').value;
      
      if (!targetUrl) return alert('请输入目标链接');
      
      const res = await fetch('/admin/api/links', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl,
          shortCode: shortCode || undefined,
          expireAt: expire ? new Date(expire).getTime() : null
        })
      });
      const data = await res.json();
      if (data.success) {
        location.reload();
      } else {
        alert(data.message || '创建失败');
      }
    }

    async function deleteLink(code) {
      if (!confirm('确定删除该短链接？')) return;
      const res = await fetch('/admin/api/links/' + code, { method: 'DELETE' });
      if (res.ok) location.reload();
      else alert('删除失败');
    }

    async function editLink(code) {
      const newTarget = prompt('输入新的目标链接：');
      if (!newTarget) return;
      const res = await fetch('/admin/api/links/' + code, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl: newTarget })
      });
      if (res.ok) location.reload();
      else alert('修改失败');
    }

    async function logout() {
      await fetch('/admin/api/logout', { method: 'POST' });
      location.href = '/admin/login';
    }
  </script>
  ${HTML_FOOT}
  `;
}

function render404Page() {
  return `
  ${HTML_HEAD}
  <div class="card" style="text-align:center;">
    <h1>404</h1>
    <p style="color:#666; margin:16px 0;">短链接不存在或已失效</p>
    <button onclick="location.href='/'">返回首页</button>
  </div>
  ${HTML_FOOT}
  `;
}

// ==============================
// 核心业务逻辑
// ==============================

async function handleRequest(event) {
  const request = event.request;
  const url = new URL(request.url);
  const path = url.pathname;
  const env = event.env;

  // 1. 管理员后台路由
  if (path.startsWith('/admin')) {
    return handleAdminRoute(event, path, env);
  }

  // 2. 公开API：生成短链（匿名）
  if (path === '/api/generate' && request.method === 'POST') {
    return handleGenerateLink(request, env);
  }

  // 3. 首页
  if (path === '/') {
    return htmlResponse(renderHomePage());
  }

  // 4. 短链跳转核心逻辑
  const shortCode = path.slice(1);
  if (shortCode && !shortCode.includes('/')) {
    return handleRedirect(shortCode, event);
  }

  // 5. 404
  return htmlResponse(render404Page(), 404);
}

// 管理员路由处理
async function handleAdminRoute(event, path, env) {
  const request = event.request;
  const token = getTokenFromCookie(request);
  const isAuth = token ? await verifyJWT(token, env.SESSION_SECRET) : null;

  // 登录相关页面无需鉴权
  if (path === '/admin/login') {
    if (request.method === 'GET') {
      if (isAuth) return redirectResponse('/admin');
      return htmlResponse(renderLoginPage());
    }
    if (request.method === 'POST') {
      return handlePasswordLogin(event, env);
    }
  }

  if (path === '/admin/totp' && request.method === 'POST') {
    return handleTotpVerify(event, env);
  }

  // 退出登录
  if (path === '/admin/api/logout' && request.method === 'POST') {
    return new Response('OK', {
      status: 302,
      headers: {
        'Location': '/admin/login',
        'Set-Cookie': 'eo_shortlink_token=; Path=/; HttpOnly; Max-Age=0'
      }
    });
  }

  // 其余管理页/接口必须鉴权
  if (!isAuth) {
    return redirectResponse('/admin/login');
  }

  // 管理后台首页
  if (path === '/admin' || path === '/admin/') {
    return handleAdminHome();
  }

  // 短链列表
  if (path === '/admin/api/links' && request.method === 'GET') {
    return handleGetLinks();
  }

  // 创建短链
  if (path === '/admin/api/links' && request.method === 'POST') {
    return handleCreateLink(request);
  }

  // 更新短链
  if (path.startsWith('/admin/api/links/') && request.method === 'PUT') {
    const code = path.split('/').pop();
    return handleUpdateLink(code, request);
  }

  // 删除短链
  if (path.startsWith('/admin/api/links/') && request.method === 'DELETE') {
    const code = path.split('/').pop();
    return handleDeleteLink(code);
  }

  return htmlResponse(render404Page(), 404);
}

// 密码登录第一步
async function handlePasswordLogin(event, env) {
  const formData = await event.request.formData();
  const username = formData.get('username');
  const password = formData.get('password');

  if (username !== env.ADMIN_USERNAME) {
    return htmlResponse(renderLoginPage('账号或密码错误'));
  }

  const valid = await verifyPassword(password, env.ADMIN_PASSWORD_HASH);
  if (!valid) {
    return htmlResponse(renderLoginPage('账号或密码错误'));
  }

  // 签发5分钟有效的挑战Token，用于TOTP步骤
  const challengeToken = await signJWT(
    { username, step: 'totp_challenge' },
    env.SESSION_SECRET,
    300
  );

  return htmlResponse(renderTotpPage(challengeToken));
}

// TOTP验证第二步
async function handleTotpVerify(event, env) {
  const formData = await event.request.formData();
  const challenge = formData.get('challenge');
  const code = formData.get('code');

  const payload = await verifyJWT(challenge, env.SESSION_SECRET);
  if (!payload || payload.step !== 'totp_challenge') {
    return htmlResponse(renderLoginPage('验证会话已过期，请重新登录'));
  }

  const valid = await verifyTOTP(env.TOTP_SECRET, code);
  if (!valid) {
    return htmlResponse(renderTotpPage(challenge, '验证码错误'));
  }

  // 签发正式会话Token，7天有效期
  const sessionToken = await signJWT(
    { username: payload.username, role: 'admin' },
    env.SESSION_SECRET,
    7 * 24 * 60 * 60
  );

  return new Response('', {
    status: 302,
    headers: {
      'Location': '/admin',
      'Set-Cookie': `eo_shortlink_token=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`
    }
  });
}

// 管理后台首页
async function handleAdminHome() {
  const list = await my_kv.list({ prefix: 'link:' });
  const links = [];
  let totalClicks = 0;

  for (const key of list.keys) {
    const data = await my_kv.get(key.name, { type: 'json' });
    if (data) {
      links.push({
        shortCode: key.name.replace('link:', ''),
        ...data
      });
      totalClicks += data.clickCount || 0;
    }
  }

  links.sort((a, b) => b.createdAt - a.createdAt);
  return htmlResponse(renderAdminPage(links, {
    totalLinks: links.length,
    totalClicks
  }));
}

// 匿名生成短链
async function handleGenerateLink(request, env) {
  try {
    const body = await request.json();
    const targetUrl = body.targetUrl?.trim();

    if (!targetUrl || !/^https?:\/\//i.test(targetUrl)) {
      return jsonResponse({ success: false, message: '无效的URL，必须以http/https开头' }, 400);
    }

    let shortCode;
    do {
      shortCode = generateShortCode(parseInt(env.SHORT_CODE_LENGTH) || 6);
    } while (await my_kv.get(`link:${shortCode}`));

    const linkData = {
      targetUrl,
      createdAt: Date.now(),
      expireAt: null,
      status: 'active',
      clickCount: 0,
      isCustom: false
    };

    await my_kv.put(`link:${shortCode}`, JSON.stringify(linkData));
    return jsonResponse({ success: true, shortCode, targetUrl });
  } catch (e) {
    return jsonResponse({ success: false, message: '生成失败' }, 500);
  }
}

// 管理员创建短链
async function handleCreateLink(request) {
  try {
    const body = await request.json();
    const { targetUrl, shortCode: customCode, expireAt } = body;

    if (!targetUrl || !/^https?:\/\//i.test(targetUrl)) {
      return jsonResponse({ success: false, message: '无效的URL' }, 400);
    }

    let shortCode = customCode?.trim();
    if (shortCode) {
      if (await my_kv.get(`link:${shortCode}`)) {
        return jsonResponse({ success: false, message: '短码已存在' }, 400);
      }
    } else {
      do {
        shortCode = generateShortCode(6);
      } while (await my_kv.get(`link:${shortCode}`));
    }

    const linkData = {
      targetUrl,
      createdAt: Date.now(),
      expireAt: expireAt || null,
      status: 'active',
      clickCount: 0,
      isCustom: !!customCode
    };

    await my_kv.put(`link:${shortCode}`, JSON.stringify(linkData));
    return jsonResponse({ success: true, shortCode });
  } catch (e) {
    return jsonResponse({ success: false, message: '创建失败' }, 500);
  }
}

// 更新短链
async function handleUpdateLink(shortCode, request) {
  try {
    const key = `link:${shortCode}`;
    const existing = await my_kv.get(key, { type: 'json' });
    if (!existing) {
      return jsonResponse({ success: false, message: '短链不存在' }, 404);
    }

    const body = await request.json();
    const updated = { ...existing, ...body };
    await my_kv.put(key, JSON.stringify(updated));
    return jsonResponse({ success: true });
  } catch (e) {
    return jsonResponse({ success: false, message: '更新失败' }, 500);
  }
}

// 删除短链
async function handleDeleteLink(shortCode) {
  try {
    await my_kv.delete(`link:${shortCode}`);
    return jsonResponse({ success: true });
  } catch (e) {
    return jsonResponse({ success: false, message: '删除失败' }, 500);
  }
}

// 短链跳转核心
async function handleRedirect(shortCode, event) {
  const key = `link:${shortCode}`;
  const data = await my_kv.get(key, { type: 'json' });

  if (!data) {
    return htmlResponse(render404Page(), 404);
  }

  // 校验状态
  if (data.status !== 'active') {
    return htmlResponse(render404Page(), 404);
  }

  // 校验过期时间
  if (data.expireAt && Date.now() > data.expireAt) {
    return htmlResponse(render404Page(), 404);
  }

  // 异步累加点击量，不阻塞跳转
  event.waitUntil((async () => {
    try {
      data.clickCount = (data.clickCount || 0) + 1;
      await my_kv.put(key, JSON.stringify(data));
    } catch (e) {}
  })());

  // 302 跳转
  return redirectResponse(data.targetUrl);
}

// ==============================
// 响应辅助函数
// ==============================

function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=UTF-8' }
  });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=UTF-8' }
  });
}

function redirectResponse(url) {
  return new Response('', {
    status: 302,
    headers: { 'Location': url }
  });
}

// ==============================
// 入口
// ==============================

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event));
});
