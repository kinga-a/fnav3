// ============================================
// EdgeOne Pages 短链接服务 - 使用全局变量绑定 KV
// ============================================

// KV 直接作为全局变量使用（控制台绑定的 Variable Name）
// 注意：控制台绑定时 Variable Name 必须填 shortlink_kv

// 环境变量从 context.env 读取
// ADMIN_USERNAME, ADMIN_PASSWORD_HASH, ADMIN_TOTP_SECRET, JWT_SECRET

// ====== 工具函数 ======

async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(base32) {
  let bits = '';
  const result = [];
  const cleaned = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
  
  for (let i = 0; i < cleaned.length; i++) {
    const val = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    result.push(parseInt(bits.substring(i, i + 8), 2));
  }
  
  return new Uint8Array(result);
}

function writeUInt64BE(buffer, offset, value) {
  const high = Math.floor(value / 0x100000000);
  const low = value >>> 0;
  const view = new DataView(buffer);
  view.setUint32(offset, high, false);
  view.setUint32(offset + 4, low, false);
}

async function hotp(key, counter, digits) {
  digits = digits || 6;
  
  const counterBuffer = new ArrayBuffer(8);
  writeUInt64BE(counterBuffer, 0, counter);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, counterBuffer);
  const hash = new Uint8Array(signature);
  
  const offset = hash[hash.length - 1] & 0x0f;
  const code = ((hash[offset] & 0x7f) << 24 |
                (hash[offset + 1] & 0xff) << 16 |
                (hash[offset + 2] & 0xff) << 8 |
                (hash[offset + 3] & 0xff)) >>> 0;
  
  const mod = Math.pow(10, digits);
  return (code % mod).toString().padStart(digits, '0');
}

async function verifyTOTP(secret, code, window) {
  window = window || 1;
  try {
    const key = base32Decode(secret);
    const now = Math.floor(Date.now() / 1000);
    const counter = Math.floor(now / 30);
    
    for (let i = -window; i <= window; i++) {
      const expected = await hotp(key, counter + i);
      if (expected === code) return true;
    }
  } catch (e) {
    console.error('TOTP error:', e);
  }
  return false;
}

function base64UrlEncode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlDecode(str) {
  let padding = '';
  const padLen = 4 - (str.length % 4);
  if (padLen !== 4) {
    padding = new Array(padLen + 1).join('=');
  }
  return atob(str.replace(/-/g, '+').replace(/_/g, '/') + padding);
}

async function signJWT(payload, secret) {
  const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64UrlEncode(JSON.stringify(payload));
  const data = header + '.' + body;
  
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const sigArray = new Uint8Array(signature);
  let sigStr = '';
  for (let i = 0; i < sigArray.length; i++) {
    sigStr += String.fromCharCode(sigArray[i]);
  }
  const sig = base64UrlEncode(sigStr);
  
  return data + '.' + sig;
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const data = parts[0] + '.' + parts[1];
    
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    let padding = '';
    const padLen = 4 - (parts[2].length % 4);
    if (padLen !== 4) {
      padding = new Array(padLen + 1).join('=');
    }
    const sigBase64 = parts[2].replace(/-/g, '+').replace(/_/g, '/') + padding;
    const sigBinary = atob(sigBase64);
    const sigBytes = new Uint8Array(sigBinary.length);
    for (let i = 0; i < sigBinary.length; i++) {
      sigBytes[i] = sigBinary.charCodeAt(i);
    }
    
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(data));
    if (!valid) return null;
    
    return JSON.parse(base64UrlDecode(parts[1]));
  } catch (e) {
    console.error('JWT verify error:', e);
    return null;
  }
}

function generateShortCode(length) {
  length = length || 6;
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  return result;
}

function jsonResponse(data, status, extraHeaders) {
  status = status || 200;
  extraHeaders = extraHeaders || {};
  return new Response(JSON.stringify(data), {
    status: status,
    headers: Object.assign({ 'Content-Type': 'application/json' }, extraHeaders),
  });
}

function htmlResponse(html, status) {
  status = status || 200;
  return new Response(html, {
    status: status,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function passwordPage(shortCode) {
  return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>密码保护</title>' +
    '<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:linear-gradient(135deg,#667eea,#764ba2)}' +
    '.box{background:#fff;padding:40px;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.3);text-align:center;max-width:400px;width:90%}h2{color:#333;margin-bottom:8px}p{color:#666;margin-bottom:24px;font-size:.9rem}' +
    'input{padding:14px 16px;border:2px solid #e0e0e0;border-radius:12px;width:100%;font-size:16px;margin-bottom:16px}input:focus{outline:none;border-color:#667eea}' +
    'button{padding:14px 24px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:12px;cursor:pointer;font-size:16px;width:100%;font-weight:600}' +
    '.icon{font-size:3rem;margin-bottom:16px}</style></head><body><div class="box"><div class="icon">🔒</div><h2>该链接受密码保护</h2><p>请输入访问密码以继续</p>' +
    '<form method="get" action="/' + shortCode + '"><input type="password" name="pwd" placeholder="请输入访问密码" required autofocus><button type="submit">进入链接</button></form></div></body></html>';
}

// ====== 主入口 ======

export async function onRequest(context) {
  const request = context.request;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // 环境变量从 context.env 读取
  const env = context.env || {};
  const ADMIN_USERNAME = env.ADMIN_USERNAME || '';
  const ADMIN_PASSWORD_HASH = env.ADMIN_PASSWORD_HASH || '';
  const ADMIN_TOTP_SECRET = env.ADMIN_TOTP_SECRET || '';
  const JWT_SECRET = env.JWT_SECRET || '';

  // KV 直接作为全局变量使用（控制台绑定的 Variable Name = shortlink_kv）
  // 注意：不需要从 env 读取，直接像全局变量一样使用

  // ====== KV 操作函数 ======
  
  async function getLink(shortCode) {
    try {
      const data = await shortlink_kv.get('link:' + shortCode);
      return data ? JSON.parse(data) : null;
    } catch (e) {
      return null;
    }
  }

  async function setLink(shortCode, data) {
    await shortlink_kv.put('link:' + shortCode, JSON.stringify(data));
  }

  async function deleteLink(shortCode) {
    await shortlink_kv.delete('link:' + shortCode);
  }

  async function incrementClicks(shortCode) {
    try {
      const key = 'clicks:' + shortCode;
      const current = await shortlink_kv.get(key);
      const count = current ? parseInt(current) + 1 : 1;
      await shortlink_kv.put(key, count.toString());
      return count;
    } catch (e) {
      return 0;
    }
  }

  async function getAllLinks() {
    const links = [];
    try {
      const indexData = await shortlink_kv.get('link_index');
      const index = indexData ? JSON.parse(indexData) : [];
      for (let i = 0; i < index.length; i++) {
        const link = await getLink(index[i]);
        if (link) {
          link.shortCode = index[i];
          links.push(link);
        }
      }
    } catch (e) {
      console.error('getAllLinks error:', e);
    }
    return links;
  }

  async function addToIndex(shortCode) {
    try {
      const indexData = await shortlink_kv.get('link_index');
      const index = indexData ? JSON.parse(indexData) : [];
      if (index.indexOf(shortCode) === -1) {
        index.push(shortCode);
        await shortlink_kv.put('link_index', JSON.stringify(index));
      }
    } catch (e) {
      console.error('addToIndex error:', e);
    }
  }

  async function removeFromIndex(shortCode) {
    try {
      const indexData = await shortlink_kv.get('link_index');
      const index = indexData ? JSON.parse(indexData) : [];
      const filtered = [];
      for (let i = 0; i < index.length; i++) {
        if (index[i] !== shortCode) {
          filtered.push(index[i]);
        }
      }
      await shortlink_kv.put('link_index', JSON.stringify(filtered));
    } catch (e) {
      console.error('removeFromIndex error:', e);
    }
  }

  // ====== API 路由 ======

  async function handleAPI(request, path, method) {
    if (path === '/api/create' && method === 'POST') {
      try {
        const body = await request.json();
        const targetUrl = body.url;
        const customCode = body.customCode;
        const expireDays = body.expireDays;
        const password = body.password;
        
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

        const shortUrl = 'https://' + url.host + '/' + shortCode;
        return jsonResponse({
          success: true,
          shortCode: shortCode,
          shortUrl: shortUrl,
          targetUrl: targetUrl,
          expireAt: linkData.expireAt || null,
          hasPassword: !!password,
        });
      } catch (err) {
        console.error('Create error:', err);
        return jsonResponse({ error: '创建失败: ' + err.message }, 500);
      }
    }

    if (path === '/api/login' && method === 'POST') {
      try {
        const body = await request.json();
        const username = body.username;
        const password = body.password;
        const totpCode = body.totpCode;

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
        }, JWT_SECRET);

        return jsonResponse({ success: true, token: token });
      } catch (err) {
        console.error('Login error:', err);
        return jsonResponse({ error: '登录失败: ' + err.message }, 500);
      }
    }

    if (path === '/api/verify' && method === 'GET') {
      const auth = request.headers.get('Authorization');
      if (!auth || auth.indexOf('Bearer ') !== 0) {
        return jsonResponse({ valid: false }, 401);
      }
      const token = auth.substring(7);
      const payload = await verifyJWT(token, JWT_SECRET);
      return jsonResponse({ valid: !!payload, user: payload });
    }

    const auth = request.headers.get('Authorization');
    if (!auth || auth.indexOf('Bearer ') !== 0) {
      return jsonResponse({ error: '未授权' }, 401);
    }
    const token = auth.substring(7);
    const payload = await verifyJWT(token, JWT_SECRET);
    if (!payload || payload.role !== 'admin') {
      return jsonResponse({ error: '权限不足' }, 403);
    }

    if (path === '/api/links' && method === 'GET') {
      const links = await getAllLinks();
      for (let i = 0; i < links.length; i++) {
        const clicks = await shortlink_kv.get('clicks:' + links[i].shortCode);
        links[i].clicks = clicks ? parseInt(clicks) : 0;
      }
      return jsonResponse({ success: true, links: links });
    }

    if (path.indexOf('/api/links/') === 0 && method === 'GET') {
      const shortCode = path.split('/')[3];
      const link = await getLink(shortCode);
      if (!link) return jsonResponse({ error: '短链不存在' }, 404);
      const clicks = await shortlink_kv.get('clicks:' + shortCode);
      return jsonResponse({
        success: true,
        link: Object.assign({}, link, { shortCode: shortCode, clicks: clicks ? parseInt(clicks) : 0 })
      });
    }

    if (path.indexOf('/api/links/') === 0 && method === 'PUT') {
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

    if (path.indexOf('/api/links/') === 0 && method === 'DELETE') {
      const shortCode = path.split('/')[3];
      await deleteLink(shortCode);
      await removeFromIndex(shortCode);
      await shortlink_kv.delete('clicks:' + shortCode);
      return jsonResponse({ success: true });
    }

    if (path === '/api/stats' && method === 'GET') {
      const links = await getAllLinks();
      let totalClicks = 0;
      const stats = [];
      for (let i = 0; i < links.length; i++) {
        const clicks = await shortlink_kv.get('clicks:' + links[i].shortCode);
        const count = clicks ? parseInt(clicks) : 0;
        totalClicks += count;
        stats.push({ shortCode: links[i].shortCode, url: links[i].url, clicks: count });
      }
      return jsonResponse({
        success: true,
        totalLinks: links.length,
        totalClicks: totalClicks,
        stats: stats,
      });
    }

    return jsonResponse({ error: '接口不存在' }, 404);
  }

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
    if (path.indexOf('/api/') === 0) {
      return await handleAPI(request, path, method);
    }

    // 短链跳转
    if (path !== '/' &&
        path.indexOf('/admin') !== 0 &&
        path.indexOf('/login') !== 0 &&
        path.indexOf('/assets/') !== 0 &&
        path.indexOf('/404') !== 0 &&
        !/\.(html|css|js|ico|png|jpg|svg|woff|woff2|ttf)$/.test(path)) {
      
      const shortCode = path.substring(1);
      if (shortCode && shortCode.indexOf('/') === -1) {
        const link = await getLink(shortCode);
        if (link && link.active !== false) {
          if (link.expireAt && Date.now() > link.expireAt) {
            return Response.redirect('/404.html', 302);
          }
          if (link.password && !url.searchParams.get('pwd')) {
            return htmlResponse(passwordPage(shortCode));
          }
          if (link.password && url.searchParams.get('pwd') !== link.password) {
            return htmlResponse('<!DOCTYPE html><html><head><meta charset="utf-8"><title>密码错误</title>' +
              '<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}' +
              '.box{background:#fff;padding:40px;border-radius:12px;text-align:center}h2{color:#dc3545}a{color:#007bff}</style></head>' +
              '<body><div class="box"><h2>❌ 密码错误</h2><p><a href="/' + shortCode + '">重新输入</a> | <a href="/">返回首页</a></p></div></body></html>');
          }
          await incrementClicks(shortCode);
          return Response.redirect(link.url, 302);
        }
        return Response.redirect('/404.html', 302);
      }
    }

    // 静态页面
    return context.next();

  } catch (err) {
    console.error('Request error:', err);
    return jsonResponse({ error: 'Internal Server Error', message: err.message }, 500);
  }
}
