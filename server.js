const express = require('express');
const path = require('path');
const https = require('https');
const app = express();

app.use('/api', (req, res) => {
  const u = new URL('/api' + req.url, 'https://school-board-api.dajianweixi.workers.dev');
  const opts = {
    hostname: u.hostname, port: 443, path: u.pathname + u.search,
    method: req.method,
    headers: { ...req.headers, host: u.hostname }
  };
  const pr = https.request(opts, (prs) => {
    const h = { ...prs.headers };
    delete h['transfer-encoding'];
    res.writeHead(prs.statusCode, h);
    prs.pipe(res);
  });
  pr.on('error', (e) => { console.error('Proxy error:', e.message); res.status(502).json({ error: 'Bad Gateway' }) });
  req.pipe(pr);
});

app.use(express.static(path.join(__dirname, 'public')));
const port = process.env.PORT || 10000;
app.listen(port, () => console.log('Server running on port ' + port));
