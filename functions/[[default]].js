// ============================================
// EdgeOne Pages 短链接服务 - 修复版
// 兼容 EdgeOne Functions 运行时
// ============================================

// KV 命名空间绑定（在控制台绑定，变量名必须匹配）
const KV = shortlink_kv;

// 环境变量
const ADMIN_USERNAME = typeof process !== 'undefined' ? process.env.ADMIN_USERNAME : '';
const ADMIN_PASSWORD_HASH = typeof process !== 'undefined' ? process.env.ADMIN_PASSWORD_HASH : '';
const ADMIN_TOTP_SECRET = typeof process !== 'undefined' ? process.env.ADMIN_TOTP_SECRET : '';
const JWT_SECRET = typeof process !== 'undefined' ? process.env.JWT_SECRET : '';
const DOMAIN = typeof process !== 'undefined' && process.env.EO_PAGES_DOMAIN 
  ? process.env.EO_PAGES_DOMAIN 
  : (typeof EdgeRuntime !== 'undefined' ? '' : 'localhost');

// ====== 工具函数 ======

// SHA-256 哈希 - 使用 Web Crypto API
async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Base32 解码（TOTP 用）
function base32Decode(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  let result = [];
  base32 = base32.toUpperCase().replace(/=+$/, '').replace(/[^A-Z2-7]/g, '');
  for (let i = 0; i < base32.length; i++) {
    const val = alphabet.indexOf(base32[i]);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    result.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(result);
}

// HOTP/TOTP 计算
async function hotp(key, counter, digits = 6) {
  const counterBuffer = new ArrayBuffer(8);
  const view = new DataView(counterBuffer);
  const bigCounter = BigInt.asUintN(64, BigInt(counter));
  view.setUint32(0, Number(bigCounter >> BigInt(32)), false);
  view.setUint32(4, Number(bigCounter & BigInt(0xFFFFFFFF)), false);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, counterBuffer);
  const hash = new Uint8Array(signature);
  
  const offset = hash[hash.length - 1] & 0x0f;
  const code = ((hash[offset] & 0x7f) << 24 |
                (hash[offset + 1] & 0xff) << 16 |
                (hash[offset + 2] & 0xff) << 8 |
                (hash[offset + 3] & 0xff)) >>> 0;
  
  return (code % Math.pow(10, digits)).toString().padStart(digits, '0');
}

async function verifyTOTP(secret, code, window = 1) {
  try {
    const key = base32Decode(secret);
    const now = Math.floor(Date.now() / 1000);
    const counter = Math.floor(now / 30);
    
    for (let i = -window; i <= window; i++) {
      const expected = await hotp(key, counter + i);
      if (expected === code) return true;
    }
  } catch (e) {
    console.error('TOTP verify error:', e);
  }
  return false;
}

// JWT 签名/验证
function base64UrlEncode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlDecode(str) {
  str += new Array(5 - str.length % 4).join('=');
  return atob(str.replace(/\-/g, '+').replace(/\_/g, '/'));
}

async function signJWT(payload) {
  const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64UrlEncode(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const sig = base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
  return `${data}.${sig}`;
}

async function verifyJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, body, signature] = parts;
    const data = `${header}.${body}`;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBytes = Uint8Array.from(atob(base64UrlDecode(signature)), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(data));
    if (!valid) return null;
    return JSON.parse(base64UrlDecode(body));
  } catch (e) {
    console.error('JWT verify error:', e);
    return null;
  }
}

// 生成随机短码
function generateShortCode(length = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  return result;
}

// JSON 响应
function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

// HTML 响应
function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// ====== KV 数据操作 ======

async function getLink(shortCode) {
  try {
    const data = await KV.get(`link:${shortCode}`);
    return data ? JSON.parse(data) : null;
  } catch (e) {
    return null;
  }
}

async function setLink(shortCode, data) {
  await KV.put(`link:${shortCode}`, JSON.stringify(data));
}

async function deleteLink(shortCode) {
  await KV.delete(`link:${shortCode}`);
}

async function incrementClicks(shortCode) {
  const key = `clicks:${shortCode}`;
  try {
    const current = await KV.get(key);
    const count = current ? parseInt(current) + 1 : 1;
    await KV.put(key, count.toString());
    return count;
  } catch (e) {
    return 0;
  }
}

async function getAllLinks() {
  const links = [];
  const listKey = 'link_index';
  try {
    const indexData = await KV.get(listKey);
    const index = indexData ? JSON.parse(indexData) : [];
    for (const code of index) {
      const link = await getLink(code);
      if (link) links.push({ ...link, shortCode: code });
    }
  } catch (e) {
    console.error('getAllLinks error:', e);
  }
  return links;
}

async function addToIndex(shortCode) {
  const listKey = 'link_index';
  try {
    const indexData = await KV.get(listKey);
    const index = indexData ? JSON.parse(indexData) : [];
    if (!index.includes(shortCode)) {
      index.push(shortCode);
      await KV.put(listKey, JSON.stringify(index));
    }
  } catch (e) {
    console.error('addToIndex error:', e);
  }
}

async function removeFromIndex(shortCode) {
  const listKey = 'link_index';
  try {
    const indexData = await KV.get(listKey);
    const index = indexData ? JSON.parse(indexData) : [];
    const filtered = index.filter(c => c !== shortCode);
    await KV.put(listKey, JSON.stringify(filtered));
  } catch (e) {
    console.error('removeFromIndex error:', e);
  }
}

// ====== 密码保护页面 ======
function passwordPage(shortCode) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>密码保护</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      display:flex;justify-content:center;align-items:center;height:100vh;
      background:linear-gradient(135deg,#667eea 0%,#764ba2 100%)}
    .box{background:#fff;padding:40px;border-radius:16px;
      box-shadow:0 20px 60px rgba(0,0,0,0.3);text-align:center;max-width:400px;width:90%}
    h2{color:#333;margin-bottom:8px}
    p{color:#666;margin-bottom:24px;font-size:0.9rem}
    input{padding:14px 16px;border:2px solid #e0e0e0;border-radius:12px;
      width:100%;font-size:16px;margin-bottom:16px;transition:border-color 0.2s}
    input:focus{outline:none;border-color:#667eea}
    button{padding:14px 24px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);
      color:#fff;border:none;border-radius:12px;cursor:pointer;font-size:16px;width:100%;
      font-weight:600;transition:transform 0.2s}
    button:hover{transform:translateY(-2px)}
    .icon{font-size:3rem;margin-bottom:16px}
  </style>
</head>
<body>
  <div class="box">
    <div class="icon">🔒</div>
    <h2>该链接受密码保护</h2>
    <p>请输入访问密码以继续</p>
    <form method="get" action="/${shortCode}">
      <input type="password" name="pwd" placeholder="请输入访问密码" required autofocus>
      <button type="submit">进入链接</button>
    </form>
  </div>
</body>
</html>`;
}

// ====== API 处理器 ======

async function handleAPI(request, path, method) {
  const url = new URL(request.url);

  // 生成短链（公开接口）
  if (path === '/api/create' && method === 'POST') {
    try {
      const body = await request.json();
      const { url: targetUrl, customCode, expireDays, password } = body;
      
      if (!targetUrl || !/^https?:\/\/.+/.test(targetUrl)) {
        return jsonResponse({ error: '请输入有效的 URL' }, 400);
      }

      let shortCode = customCode;
      if (shortCode) {
        if (!/^[a-zA-Z0-9_-]{3,32}$/.test(shortCode)) {
          return jsonResponse({ error: '短码只能包含字母、数字、下划线和连字符，长度3-32位' }, 400);
        }
        const existing = await getLink(shortCode);
        if (existing) {
          return jsonResponse({ error: '该短码已被使用' }, 409);
        }
      } else {
        do {
          shortCode = generateShortCode();
        } while (await getLink(shortCode));
      }

      const linkData = {
        url: targetUrl,
        createdAt: Date.now(),
        active: true,
      };

      if (expireDays && expireDays > 0) {
        linkData.expireAt = Date.now() + expireDays * 24 * 60 * 60 * 1000;
      }
      if (password) {
        linkData.password = password;
      }

      await setLink(shortCode, linkData);
      await addToIndex(shortCode);

      const shortUrl = `https://${url.host}/${shortCode}`;
      return jsonResponse({
        success: true,
        shortCode,
        shortUrl,
        targetUrl,
        expireAt: linkData.expireAt || null,
        hasPassword: !!password,
      });
    } catch (err) {
      console.error('Create error:', err);
      return jsonResponse({ error: '创建失败: ' + err.message }, 500);
    }
  }

  // 管理员登录
  if (path === '/api/login' && method === 'POST') {
    try {
      const body = await request.json();
      const { username, password, totpCode } = body;

      // 检查环境变量是否配置
      if (!ADMIN_USERNAME || !ADMIN_PASSWORD_HASH || !ADMIN_TOTP_SECRET) {
        return jsonResponse({ error: '服务器配置不完整' }, 500);
      }

      const passwordHash = await sha256(password);
      if (username !== ADMIN_USERNAME || passwordHash !== ADMIN_PASSWORD_HASH) {
        return jsonResponse({ error: '账号或密码错误' }, 401);
      }

      const totpValid = await verifyTOTP(ADMIN_TOTP_SECRET, totpCode);
      if (!totpValid) {
        return jsonResponse({ error: 'TOTP 验证码错误' }, 401);
      }

      const token = await signJWT({
        sub: username,
        role: 'admin',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 86400,
      });

      return jsonResponse({ success: true, token });
    } catch (err) {
      console.error('Login error:', err);
      return jsonResponse({ error: '登录失败: ' + err.message }, 500);
    }
  }

  // 验证 Token
  if (path === '/api/verify' && method === 'GET') {
    const auth = request.headers.get('Authorization');
    if (!auth || !auth.startsWith('Bearer ')) {
      return jsonResponse({ valid: false }, 401);
    }
    const token = auth.slice(7);
    const payload = await verifyJWT(token);
    return jsonResponse({ valid: !!payload, user: payload });
  }

  // 以下接口需要管理员权限
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) {
    return jsonResponse({ error: '未授权' }, 401);
  }
  const token = auth.slice(7);
  const payload = await verifyJWT(token);
  if (!payload || payload.role !== 'admin') {
    return jsonResponse({ error: '权限不足' }, 403);
  }

  // 获取所有短链列表
  if (path === '/api/links' && method === 'GET') {
    const links = await getAllLinks();
    for (const link of links) {
      const clicks = await KV.get(`clicks:${link.shortCode}`);
      link.clicks = clicks ? parseInt(clicks) : 0;
    }
    return jsonResponse({ success: true, links });
  }

  // 获取单条短链详情
  if (path.startsWith('/api/links/') && method === 'GET') {
    const shortCode = path.split('/')[3];
    const link = await getLink(shortCode);
    if (!link) return jsonResponse({ error: '短链不存在' }, 404);
    const clicks = await KV.get(`clicks:${shortCode}`);
    return jsonResponse({ 
      success: true, 
      link: { ...link, shortCode, clicks: clicks ? parseInt(clicks) : 0 } 
    });
  }

  // 更新短链
  if (path.startsWith('/api/links/') && method === 'PUT') {
    const shortCode = path.split('/')[3];
    const link = await getLink(shortCode);
    if (!link) return jsonResponse({ error: '短链不存在' }, 404);
    
    const body = await request.json();
    if (body.url) link.url = body.url;
    if (body.active !== undefined) link.active = body.active;
    if (body.password !== undefined) link.password = body.password || undefined;
    if (body.expireDays !== undefined) {
      if (body.expireDays > 0) {
        link.expireAt = Date.now() + body.expireDays * 24 * 60 * 60 * 1000;
      } else {
        delete link.expireAt;
      }
    }
    
    await setLink(shortCode, link);
    return jsonResponse({ success: true });
  }

  // 删除短链
  if (path.startsWith('/api/links/') && method === 'DELETE') {
    const shortCode = path.split('/')[3];
    await deleteLink(shortCode);
    await removeFromIndex(shortCode);
    await KV.delete(`clicks:${shortCode}`);
    return jsonResponse({ success: true });
  }

  // 获取统计数据
  if (path === '/api/stats' && method === 'GET') {
    const links = await getAllLinks();
    let totalClicks = 0;
    const stats = [];
    for (const link of links) {
      const clicks = await KV.get(`clicks:${link.shortCode}`);
      const count = clicks ? parseInt(clicks) : 0;
      totalClicks += count;
      stats.push({ shortCode: link.shortCode, url: link.url, clicks: count });
    }
    return jsonResponse({
      success: true,
      totalLinks: links.length,
      totalClicks,
      stats,
    });
  }

  return jsonResponse({ error: '接口不存在' }, 404);
}

// ====== 主入口 ======

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // OPTIONS 预检
  if (method === 'OPTIONS') {
    return new Response(null, { 
      status: 204, 
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }
    });
  }

  try {
    // API 路由
    if (path.startsWith('/api/')) {
      return await handleAPI(request, path, method);
    }

    // 短链跳转（排除静态资源路径）
    if (path !== '/' && 
        !path.startsWith('/admin') && 
        !path.startsWith('/login') && 
        !path.startsWith('/assets/') &&
        !path.startsWith('/404') &&
        !path.endsWith('.html') &&
        !path.endsWith('.css') &&
        !path.endsWith('.js') &&
        !path.endsWith('.ico') &&
        !path.endsWith('.png') &&
        !path.endsWith('.jpg')) {
      
      const shortCode = path.slice(1);
      if (shortCode && !shortCode.includes('/')) {
        const link = await getLink(shortCode);
        if (link && link.active !== false) {
          // 检查是否过期
          if (link.expireAt && Date.now() > link.expireAt) {
            return Response.redirect('/404.html', 302);
          }
          // 检查密码保护
          if (link.password && !url.searchParams.get('pwd')) {
            return htmlResponse(passwordPage(shortCode));
          }
          if (link.password && url.searchParams.get('pwd') !== link.password) {
            return htmlResponse(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>密码错误</title>
              <style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5;}
              .box{background:#fff;padding:40px;border-radius:12px;text-align:center;}
              h2{color:#dc3545;}a{color:#007bff;}</style></head>
              <body><div class="box"><h2>❌ 密码错误</h2><p><a href="/${shortCode}">重新输入</a> | <a href="/">返回首页</a></p></div></body></html>`);
          }
          // 记录点击并跳转
          await incrementClicks(shortCode);
          return Response.redirect(link.url, 302);
        }
        return Response.redirect('/404.html', 302);
      }
    }

    // 静态页面路由 - 交给 Pages 静态托管
    return context.next();

  } catch (err) {
    console.error('Request error:', err);
    return jsonResponse({ error: 'Internal Server Error', message: err.message }, 500);
  }
}
