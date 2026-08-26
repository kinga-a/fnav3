// ============================================
// EdgeOne Pages 短链接服务 - 主入口
// 路由: 所有路径
// ============================================

// 环境变量
const KV = shortlink_kv;  // KV 命名空间绑定变量
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const ADMIN_TOTP_SECRET = process.env.ADMIN_TOTP_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;
const DOMAIN = process.env.EO_PAGES_DOMAIN || 'your-domain.edgeone.app';

// ====== 工具函数 ======

// SHA-256 哈希
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
  base32 = base32.toUpperCase().replace(/=+$/, '');
  for (let char of base32) {
    const val = alphabet.indexOf(char);
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
  view.setBigUint64(0, BigInt(counter), false);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, counterBuffer);
  const hash = new Uint8Array(signature);
  
  const offset = hash[hash.length - 1] & 0x0f;
  const code = ((hash[offset] & 0x7f) << 24 |
                (hash[offset + 1] & 0xff) << 16 |
                (hash[offset + 2] & 0xff) << 8 |
                (hash[offset + 3] & 0xff)) % Math.pow(10, digits);
  
  return code.toString().padStart(digits, '0');
}

async function verifyTOTP(secret, code, window = 1) {
  const key = base32Decode(secret);
  const now = Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / 30);
  
  for (let i = -window; i <= window; i++) {
    const expected = await hotp(key, counter + i);
    if (expected === code) return true;
  }
  return false;
}

// JWT 签名/验证
async function signJWT(payload) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const sig = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '');
  return `${data}.${sig}`;
}

async function verifyJWT(token) {
  try {
    const [header, body, signature] = token.split('.');
    const data = `${header}.${body}`;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBytes = Uint8Array.from(atob(signature.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(data));
    if (!valid) return null;
    return JSON.parse(atob(body));
  } catch {
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

// CORS 头
function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
  };
}

// JSON 响应
function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

// ====== KV 数据操作 ======

async function getLink(shortCode) {
  const data = await KV.get(`link:${shortCode}`);
  return data ? JSON.parse(data) : null;
}

async function setLink(shortCode, data) {
  await KV.put(`link:${shortCode}`, JSON.stringify(data));
}

async function deleteLink(shortCode) {
  await KV.delete(`link:${shortCode}`);
}

async function incrementClicks(shortCode) {
  const key = `clicks:${shortCode}`;
  const current = await KV.get(key);
  const count = current ? parseInt(current) + 1 : 1;
  await KV.put(key, count.toString());
  return count;
}

async function getAllLinks() {
  const links = [];
  // 注意：KV list 在 EdgeOne 中可能有限制，这里简化处理
  // 实际生产环境建议维护一个索引 key
  const listKey = 'link_index';
  const indexData = await KV.get(listKey);
  const index = indexData ? JSON.parse(indexData) : [];
  for (const code of index) {
    const link = await getLink(code);
    if (link) links.push({ ...link, shortCode: code });
  }
  return links;
}

async function addToIndex(shortCode) {
  const listKey = 'link_index';
  const indexData = await KV.get(listKey);
  const index = indexData ? JSON.parse(indexData) : [];
  if (!index.includes(shortCode)) {
    index.push(shortCode);
    await KV.put(listKey, JSON.stringify(index));
  }
}

async function removeFromIndex(shortCode) {
  const listKey = 'link_index';
  const indexData = await KV.get(listKey);
  const index = indexData ? JSON.parse(indexData) : [];
  const filtered = index.filter(c => c !== shortCode);
  await KV.put(listKey, JSON.stringify(filtered));
}

// ====== 路由处理 ======

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // OPTIONS 预检
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(url.origin) });
  }

  // API 路由
  if (path.startsWith('/api/')) {
    return handleAPI(request, path, method);
  }

  // 短链跳转
  if (path !== '/' && !path.startsWith('/admin') && !path.startsWith('/login') && !path.startsWith('/assets/')) {
    const shortCode = path.slice(1); // 去掉开头的 /
    const link = await getLink(shortCode);
    if (link && link.active !== false) {
      // 检查是否过期
      if (link.expireAt && Date.now() > link.expireAt) {
        return Response.redirect('/404.html', 302);
      }
      // 检查密码保护
      if (link.password && !url.searchParams.get('pwd')) {
        return new Response(`
          <!DOCTYPE html>
          <html>
          <head><meta charset="utf-8"><title>密码保护</title>
          <style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5;}
          .box{background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.1);text-align:center;}
          input{padding:12px 16px;border:1px solid #ddd;border-radius:8px;width:250px;font-size:16px;margin:10px 0;}
          button{padding:12px 24px;background:#007bff;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:16px;}
          button:hover{background:#0056b3;}</style></head>
          <body><div class="box">
            <h2>🔒 该链接受密码保护</h2>
            <form method="get"><input type="password" name="pwd" placeholder="请输入访问密码" required autofocus><br>
            <button type="submit">进入</button></form>
          </div></body></html>`, { headers: { 'Content-Type': 'text/html' } });
      }
      if (link.password && url.searchParams.get('pwd') !== link.password) {
        return new Response('密码错误', { status: 403 });
      }
      // 记录点击
      await incrementClicks(shortCode);
      return Response.redirect(link.url, 302);
    }
    return Response.redirect('/404.html', 302);
  }

  // 静态页面路由
  return context.next();
}

// ====== API 处理器 ======

async function handleAPI(request, path, method) {
  const url = new URL(request.url);

  // 生成短链（公开接口，无需登录）
  if (path === '/api/create' && method === 'POST') {
    try {
      const body = await request.json();
      const { url: targetUrl, customCode, expireDays, password } = body;
      
      if (!targetUrl || !/^https?:\/\/.+/.test(targetUrl)) {
        return jsonResponse({ error: '请输入有效的 URL' }, 400);
      }

      let shortCode = customCode;
      if (shortCode) {
        // 检查自定义短码是否已存在
        const existing = await getLink(shortCode);
        if (existing) {
          return jsonResponse({ error: '该短码已被使用' }, 409);
        }
        // 验证自定义短码格式
        if (!/^[a-zA-Z0-9_-]{3,32}$/.test(shortCode)) {
          return jsonResponse({ error: '短码只能包含字母、数字、下划线和连字符，长度3-32位' }, 400);
        }
      } else {
        // 生成随机短码，确保不重复
        do {
          shortCode = generateShortCode();
        } while (await getLink(shortCode));
      }

      const linkData = {
        url: targetUrl,
        createdAt: Date.now(),
        active: true,
        clicks: 0,
      };

      if (expireDays && expireDays > 0) {
        linkData.expireAt = Date.now() + expireDays * 24 * 60 * 60 * 1000;
      }
      if (password) {
        linkData.password = password;
      }

      await setLink(shortCode, linkData);
      await addToIndex(shortCode);

      const shortUrl = `https://${DOMAIN}/${shortCode}`;
      return jsonResponse({
        success: true,
        shortCode,
        shortUrl,
        targetUrl,
        expireAt: linkData.expireAt || null,
        hasPassword: !!password,
      });
    } catch (err) {
      return jsonResponse({ error: '创建失败: ' + err.message }, 500);
    }
  }

  // 管理员登录
  if (path === '/api/login' && method === 'POST') {
    try {
      const body = await request.json();
      const { username, password, totpCode } = body;

      const passwordHash = await sha256(password);
      if (username !== ADMIN_USERNAME || passwordHash !== ADMIN_PASSWORD_HASH) {
        return jsonResponse({ error: '账号或密码错误' }, 401);
      }

      if (!await verifyTOTP(ADMIN_TOTP_SECRET, totpCode)) {
        return jsonResponse({ error: 'TOTP 验证码错误' }, 401);
      }

      const token = await signJWT({
        sub: username,
        role: 'admin',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 86400, // 24小时
      });

      return jsonResponse({ success: true, token });
    } catch (err) {
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
    // 补充点击数
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
