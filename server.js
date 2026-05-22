const express = require('express');
const path = require('path');
const app = express();

app.use('/api', async (req, res) => {
  try {
    const target = new URL('/api' + req.url, 'https://school-board-api.dajianweixi.workers.dev');
    let body;
    if (!['GET', 'HEAD'].includes(req.method)) {
      body = await new Promise(r => { const c = []; req.on('data', d => c.push(d)); req.on('end', () => r(Buffer.concat(c))); });
    }
    const h = { ...req.headers, host: target.hostname };
    delete h['transfer-encoding'];
    const pr = await fetch(target, { method: req.method, headers: h, body });
    const rh = {};
    pr.headers.forEach((v, k) => { if (k !== 'transfer-encoding') rh[k] = v; });
    res.writeHead(pr.status, rh);
    res.end(await pr.text());
  } catch (e) {
    console.error('Proxy error:', e.message);
    try { res.status(502).json({ error: 'Bad Gateway' }) } catch (_) {}
  }
});

app.use(express.static(path.join(__dirname, 'public')));
const port = process.env.PORT || 10000;
app.listen(port, () => console.log('Server running on port ' + port));
