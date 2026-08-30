/**
 * 初始化脚本：生成密码哈希和 TOTP Secret
 * 用法：node setup.js
 */

async function setup() {
  const encoder = new TextEncoder();

  // 生成密码哈希
  console.log('=== 密码哈希生成 ===');
  const password = 'your-strong-password'; // 修改为你的密码

  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');

  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: encoder.encode(saltHex), iterations: 100000, hash: 'SHA-256' },
    key, 256
  );
  const hashHex = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  const passwordHash = `${saltHex}$100000$${hashHex}`;
  console.log('ADMIN_PASSWORD_HASH:', passwordHash);

  // 生成 TOTP Secret
  console.log('');
  console.log('=== TOTP Secret 生成 ===');
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const secretBytes = new Uint8Array(32);
  crypto.getRandomValues(secretBytes);
  const secret = Array.from(secretBytes).map(b => chars[b % 32]).join('');
  console.log('TOTP_SECRET:', secret);

  const uri = `otpauth://totp/EdgeOne-KV-App:${encodeURIComponent('admin')}?secret=${secret}&issuer=EdgeOne-KV-App`;
  console.log('TOTP URI:', uri);

  console.log('');
  console.log('=== 环境变量配置 ===');
  console.log('ADMIN_USERNAME=admin');
  console.log(`ADMIN_PASSWORD_HASH=${passwordHash}`);
  console.log(`TOTP_SECRET=${secret}`);
  console.log('JWT_SECRET=' + Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2,'0')).join(''));
  console.log('MY_KV=my_kv');
}

setup().catch(console.error);
