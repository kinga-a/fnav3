// ============================================
// EdgeOne Pages Edge Functions - 短链跳转
// 路径: /s/*
// ============================================

export async function onRequest(context) {
  const request = context.request;
  const url = new URL(request.url);
  const path = url.pathname;

  // 获取短码 /s/xxx → xxx
  const shortCode = path.replace(/^\/s\//, '').replace(/\/$/, '');

  if (!shortCode || !/^[a-zA-Z0-9_-]+$/.test(shortCode)) {
    return Response.redirect('/404.html', 302);
  }

  try {
    const data = await shortlink_kv.get('link:' + shortCode);
    if (!data) {
      return Response.redirect('/404.html', 302);
    }

    const link = JSON.parse(data);

    // 检查过期
    if (link.expireAt && Date.now() > link.expireAt) {
      return Response.redirect('/404.html', 302);
    }

    // 密码保护
    if (link.password && !url.searchParams.get('pwd')) {
      return new Response('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>密码保护</title>' +
        '<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:linear-gradient(135deg,#667eea,#764ba2)}' +
        '.box{background:#fff;padding:40px;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.3);text-align:center;max-width:400px;width:90%}h2{color:#333;margin-bottom:8px}p{color:#666;margin-bottom:24px;font-size:.9rem}' +
        'input{padding:14px 16px;border:2px solid #e0e0e0;border-radius:12px;width:100%;font-size:16px;margin-bottom:16px}input:focus{outline:none;border-color:#667eea}' +
        'button{padding:14px 24px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:12px;cursor:pointer;font-size:16px;width:100%;font-weight:600}' +
        '.icon{font-size:3rem;margin-bottom:16px}</style></head><body><div class="box"><div class="icon">🔒</div><h2>该链接受密码保护</h2><p>请输入访问密码以继续</p>' +
        '<form method="get" action="/s/' + shortCode + '"><input type="password" name="pwd" placeholder="请输入访问密码" required autofocus><button type="submit">进入链接</button></form></div></body></html>', {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (link.password && url.searchParams.get('pwd') !== link.password) {
      return new Response('<!DOCTYPE html><html><head><meta charset="utf-8"><title>密码错误</title>' +
        '<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}' +
        '.box{background:#fff;padding:40px;border-radius:12px;text-align:center}h2{color:#dc3545}a{color:#007bff}</style></head>' +
        '<body><div class="box"><h2>❌ 密码错误</h2><p><a href="/s/' + shortCode + '">重新输入</a> | <a href="/">返回首页</a></p></div></body></html>', {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // 记录点击
    const clickKey = 'clicks:' + shortCode;
    const current = await shortlink_kv.get(clickKey);
    const count = current ? parseInt(current) + 1 : 1;
    await shortlink_kv.put(clickKey, count.toString());

    // 跳转
    return Response.redirect(link.url, 302);

  } catch (e) {
    return Response.redirect('/404.html', 302);
  }
}
