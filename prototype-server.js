const express = require('express');
const path = require('path');
const app = express();
const WORKER = 'https://school-board-api.dajianweixi.workers.dev'; // 同じワーカーURLを使用

// 静的ファイル配信（public フォルダー）
app.use(express.static(path.join(__dirname, 'public')));

// API プロキシー（/api 以下をワーカーに転送）
app.use('/api', async (req, res) => {
  try {
    const target = new URL('/api' + req.url, WORKER);
    let body;
    if (!['GET', 'HEAD'].includes(req.method)) {
      body = await new Promise(r => {
        const chunks = [];
        req.on('data', d => chunks.push(d));
        req.on('end', () => r(Buffer.concat(chunks)));
      });
    }
    const headers = { ...req.headers, host: target.hostname };
    delete headers['transfer-encoding'];
    const fetchRes = await fetch(target, { method: req.method, headers, body });
    const resHeaders = {};
    fetchRes.headers.forEach((v, k) => {
      if (k !== 'transfer-encoding') resHeaders[k] = v;
    });
    res.writeHead(fetchRes.status, resHeaders);
    res.end(await fetchRes.text());
  } catch (e) {
    console.error('Proxy error:', e.message);
    res.status(502).json({ error: 'Bad Gateway' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Prototype server running on port ${PORT}`));