// ============================================
// EdgeOne Pages Edge Functions - API 路由
// 路径: /api/*
// ============================================

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
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, counterBuffer);
  const hash = new Uint8Array(signature);
  const offset = hash[hash.length - 1] & 0x0f;
  const code = ((hash[offset] & 0x7f) << 24 | (hash[offset + 1] & 0xff) << 16 | (hash[offset + 2] & 0xff) << 8 | (hash[offset + 3] & 0xff)) >>> 0;
  return (code % Math.pow(10, digits)).toString().padStart(digits, '0');
}

async function verifyTOTP(secret, code, window) {
  window = window || 1;
  try {
    const key = base32Decode(secret);
    const now = Math.floor(Date.now() / 1000);
    const counter = Math.floor(now / 30);
    for (let i = -window; i <= window; i++) {
      if (await hotp(key, counter + i) === code) return true;
    }
  } catch (e) {}
  return false;
}

function base64UrlEncode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlDecode(str) {
  let padding = '';
  const padLen = 4 - (str.length % 4);
  if (padLen !== 4) padding = new Array(padLen + 1).join('=');
  return atob(str.replace(/-/g, '+').replace(/_/g, '/') + padding);
}

async function signJWT(payload, secret) {
  const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64UrlEncode(JSON.stringify(payload));
  const data = header + '.' + body;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const sigArray = new Uint8Array(signature);
  let sigStr = '';
  for (let i = 0; i < sigArray.length; i++) sigStr += String.fromCharCode(sigArray[i]);
  return data + '.' + base64UrlEncode(sigStr);
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const data = parts[0] + '.' + parts[1];
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    let padding = '';
    const padLen = 4 - (parts[2].length % 4);
    if (padLen !== 4) padding = new Array(padLen + 1).join('=');
    const sigBase64 = parts[2].replace(/-/g, '+').replace(/_/g, '/') + padding;
    const sigBinary = atob(sigBase64);
    const sigBytes = new Uint8Array(sigBinary.length);
    for (let i = 0; i < sigBinary.length; i++) sigBytes[i] = sigBinary.charCodeAt(i);
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(data));
    return valid ? JSON.parse(base64UrlDecode(parts[1])) : null;
  } catch (e) { return null; }
}

function generateShortCode(length) {
  length = length || 6;
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) result += chars[randomValues[i] % chars.length];
  return result;
}

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function getLink(shortCode) {
  try {
    const data = await shortlink_kv.get('link:' + shortCode);
    return data ? JSON.parse(data) : null;
  } catch (e) { return null; }
}

async function setLink(shortCode, data) {
  await shortlink_kv.put('link:' + shortCode, JSON.stringify(data));
}

async function addToIndex(shortCode) {
  try {
    const indexData = await shortlink_kv.get('link_index');
    const index = indexData ? JSON.parse(indexData) : [];
    if (index.indexOf(shortCode) === -1) {
      index.push(shortCode);
      await shortlink_kv.put('link_index', JSON.stringify(index));
    }
  } catch (e) {}
}

export async function onRequest(context) {
  const request = context.request;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  const env = context.env || {};
  const ADMIN_USERNAME = env.ADMIN_USERNAME || '';
  const ADMIN_PASSWORD_HASH = env.ADMIN_PASSWORD_HASH || '';
  const ADMIN_TOTP_SECRET = env.ADMIN_TOTP_SECRET || '';
  const JWT_SECRET = env.JWT_SECRET || '';

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
          return jsonResponse({ error: '短码格式错误' }, 400);
        }
        if (await getLink(shortCode)) {
          return jsonResponse({ error: '该短码已被使用' }, 409);
        }
      } else {
        do { shortCode = generateShortCode(); } while (await getLink(shortCode));
      }

      const linkData = { url: targetUrl, createdAt: Date.now(), active: true };
      if (expireDays && expireDays > 0) linkData.expireAt = Date.now() + expireDays * 24 * 60 * 60 * 1000;
      if (password) linkData.password = password;

      await setLink(shortCode, linkData);
      await addToIndex(shortCode);

      return jsonResponse({
        success: true,
        shortCode: shortCode,
        shortUrl: 'https://' + url.host + '/s/' + shortCode,
        targetUrl: targetUrl,
        expireAt: linkData.expireAt || null,
        hasPassword: !!password,
      });
    } catch (err) {
      return jsonResponse({ error: '创建失败: ' + err.message }, 500);
    }
  }

  if (path === '/api/login' && method === 'POST') {
    try {
      const body = await request.json();
      if (!ADMIN_USERNAME || !ADMIN_PASSWORD_HASH || !ADMIN_TOTP_SECRET) {
        return jsonResponse({ error: '服务器配置不完整' }, 500);
      }
      const passwordHash = await sha256(body.password);
      if (body.username !== ADMIN_USERNAME || passwordHash !== ADMIN_PASSWORD_HASH) {
        return jsonResponse({ error: '账号或密码错误' }, 401);
      }
      if (!await verifyTOTP(ADMIN_TOTP_SECRET, body.totpCode)) {
        return jsonResponse({ error: 'TOTP 验证码错误' }, 401);
      }
      const token = await signJWT({
        sub: body.username,
        role: 'admin',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 86400,
      }, JWT_SECRET);
      return jsonResponse({ success: true, token: token });
    } catch (err) {
      return jsonResponse({ error: '登录失败' }, 500);
    }
  }

  if (path === '/api/verify' && method === 'GET') {
    const auth = request.headers.get('Authorization');
    if (!auth || auth.indexOf('Bearer ') !== 0) return jsonResponse({ valid: false }, 401);
    const payload = await verifyJWT(auth.substring(7), JWT_SECRET);
    return jsonResponse({ valid: !!payload, user: payload });
  }

  const auth = request.headers.get('Authorization');
  if (!auth || auth.indexOf('Bearer ') !== 0) return jsonResponse({ error: '未授权' }, 401);
  const token = auth.substring(7);
  const payload = await verifyJWT(token, JWT_SECRET);
  if (!payload || payload.role !== 'admin') return jsonResponse({ error: '权限不足' }, 403);

  if (path === '/api/links' && method === 'GET') {
    const links = [];
    try {
      const indexData = await shortlink_kv.get('link_index');
      const index = indexData ? JSON.parse(indexData) : [];
      for (let i = 0; i < index.length; i++) {
        const link = await getLink(index[i]);
        if (link) {
          const clicks = await shortlink_kv.get('clicks:' + index[i]);
          links.push(Object.assign({}, link, { shortCode: index[i], clicks: clicks ? parseInt(clicks) : 0 }));
        }
      }
    } catch (e) {}
    return jsonResponse({ success: true, links: links });
  }

  if (path.indexOf('/api/links/') === 0 && method === 'GET') {
    const shortCode = path.split('/')[3];
    const link = await getLink(shortCode);
    if (!link) return jsonResponse({ error: '短链不存在' }, 404);
    const clicks = await shortlink_kv.get('clicks:' + shortCode);
    return jsonResponse({ success: true, link: Object.assign({}, link, { shortCode: shortCode, clicks: clicks ? parseInt(clicks) : 0 }) });
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
      if (body.expireDays > 0) link.expireAt = Date.now() + body.expireDays * 24 * 60 * 60 * 1000;
      else delete link.expireAt;
    }
    await setLink(shortCode, link);
    return jsonResponse({ success: true });
  }

  if (path.indexOf('/api/links/') === 0 && method === 'DELETE') {
    const shortCode = path.split('/')[3];
    await shortlink_kv.delete('link:' + shortCode);
    const indexData = await shortlink_kv.get('link_index');
    const index = indexData ? JSON.parse(indexData) : [];
    const filtered = [];
    for (let i = 0; i < index.length; i++) if (index[i] !== shortCode) filtered.push(index[i]);
    await shortlink_kv.put('link_index', JSON.stringify(filtered));
    await shortlink_kv.delete('clicks:' + shortCode);
    return jsonResponse({ success: true });
  }

  if (path === '/api/stats' && method === 'GET') {
    let totalLinks = 0, totalClicks = 0;
    const stats = [];
    try {
      const indexData = await shortlink_kv.get('link_index');
      const index = indexData ? JSON.parse(indexData) : [];
      totalLinks = index.length;
      for (let i = 0; i < index.length; i++) {
        const link = await getLink(index[i]);
        const clicks = await shortlink_kv.get('clicks:' + index[i]);
        const count = clicks ? parseInt(clicks) : 0;
        totalClicks += count;
        if (link) stats.push({ shortCode: index[i], url: link.url, clicks: count });
      }
    } catch (e) {}
    return jsonResponse({ success: true, totalLinks, totalClicks, stats });
  }

  return jsonResponse({ error: '接口不存在' }, 404);
}
