const express = require('express');
const path = require('path');
const fs = require('fs');
const webPush = require('web-push');
const app = express();
const DATA_FILE = path.join(__dirname, 'push_subs.json');

let VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY;
if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webPush.setVapidDetails('mailto:admin@school.example.com', VAPID_PUBLIC, VAPID_PRIVATE);
  console.log('VAPID keys loaded from env');
} else {
  const keys = webPush.generateVAPIDKeys();
  VAPID_PUBLIC = keys.publicKey;
  webPush.setVapidDetails('mailto:admin@school.example.com', keys.publicKey, keys.privateKey);
  console.log('Generated temporary VAPID keys. Set env vars VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY for persistence.');
}

const WORKER = 'https://school-board-api.dajianweixi.workers.dev';
let pushSubs = [];
try { pushSubs = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8')); console.log('Loaded ' + pushSubs.length + ' push subscriptions'); } catch(e) {}
function saveSubs() { try { fs.writeFileSync(DATA_FILE, JSON.stringify(pushSubs)); } catch(e) { console.error('Failed to save subscriptions:', e.message); } }

async function verifyToken(token) {
  if (!token) return null;
  try {
    const r = await fetch(WORKER + '/api/me', { headers: { 'Authorization': token } });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

app.get('/api/push/vapid-key', (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC });
});

app.post('/api/push/subscribe', express.json(), async (req, res) => {
  try {
    const user = await verifyToken(req.headers.authorization);
    if (!user) return res.status(401).json({ error: '認証が必要です' });
    const { topics } = req.body;
    pushSubs = pushSubs.filter(s => s.username !== user.username);
    pushSubs.push({ ...req.body, username: user.username, topics: topics || [], createdAt: new Date().toISOString() });
    saveSubs();
    res.json({ ok: true, topics: topics || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/push/unsubscribe', express.json(), async (req, res) => {
  try {
    const user = await verifyToken(req.headers.authorization);
    if (!user) return res.status(401).json({ error: '認証が必要です' });
    pushSubs = pushSubs.filter(s => s.username !== user.username);
    saveSubs();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/push/subscriptions', async (req, res) => {
  try {
    const user = await verifyToken(req.headers.authorization);
    if (!user || !['admin', 'teacher'].some(r => (user.role || '').split(',').map(x => x.trim()).includes(r)))
      return res.status(403).json({ error: '権限がありません' });
    res.json(pushSubs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Send notification to subscribers of a specific category
app.post('/api/push/notify', express.json(), async (req, res) => {
  try {
    const { category, title, body, url, excludeUser } = req.body;
    if (!category || !title) return res.status(400).json({ error: 'カテゴリとタイトルは必須です' });
    const user = await verifyToken(req.headers.authorization);
    if (!user) return res.status(401).json({ error: '認証が必要です' });
    const targets = pushSubs.filter(s => s.topics && (s.topics.includes(category) || s.topics.includes('all')) && s.username !== excludeUser);
    const results = { sent: 0, failed: 0 };
    await Promise.all(targets.map(async sub => {
      try {
        await webPush.sendNotification(sub, JSON.stringify({ title, body: body || '', icon: '/icon.svg', data: { url: url || '/' } }));
        results.sent++;
      } catch (e) {
        results.failed++;
        if (e.statusCode === 410 || e.statusCode === 404) { pushSubs = pushSubs.filter(s => s.endpoint !== sub.endpoint); saveSubs(); }
      }
    }));
    res.json(results);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Admin broadcast to all subscribers
app.post('/api/push/send', express.json(), async (req, res) => {
  try {
    const { title, body, url } = req.body;
    if (!title) return res.status(400).json({ error: 'タイトルは必須です' });
    const user = await verifyToken(req.headers.authorization);
    if (!user || !['admin', 'teacher'].some(r => (user.role || '').split(',').map(x => x.trim()).includes(r)))
      return res.status(403).json({ error: '権限がありません' });
    const results = { sent: 0, failed: 0 };
    await Promise.all(pushSubs.map(async sub => {
      try {
        await webPush.sendNotification(sub, JSON.stringify({ title, body: body || '', icon: '/icon.svg', data: { url: url || '/' } }));
        results.sent++;
      } catch (e) {
        results.failed++;
        if (e.statusCode === 410 || e.statusCode === 404) { pushSubs = pushSubs.filter(s => s.endpoint !== sub.endpoint); saveSubs(); }
      }
    }));
    res.json(results);
  } catch (e) {
    console.error('Push send error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.use('/api/gemini/ask', express.json({limit:'10mb'}), async (req, res) => {
  try {
    const { question, image } = req.body;
    if ((!question || !question.trim()) && !image) return res.status(400).json({ error: '質問または画像を入力してください' });
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: '認証が必要です' });
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) return res.status(503).json({ error: 'Gemini API キーが設定されていません' });
    const yearlyResp = await fetch('https://school-board-api.dajianweixi.workers.dev/api/yearly-schedule', { headers: { 'Authorization': token } });
    const yearlyData = yearlyResp.ok ? await yearlyResp.json() : [];
    const now = new Date();
    const near = yearlyData.filter(e => new Date(e.date + 'T00:00:00') >= new Date(now.getFullYear() - 1, 3, 1));
    const limited = near.slice(0, 50);
    const months = ['','1月','2月','3月','4月','5月','6月','7月','8月','9月','10月','11月','12月'];
    const context = limited.map(e => `${e.date} ${months[parseInt(e.month)]||''} ${e.category||''} ${e.title} ${e.description||''}`).join('\n');
    const prompt = `あなたは学校の年間予定表アシスタントです。以下の年間予定データに基づいて質問に簡潔に答えてください。データにない情報は「データに見つかりませんでした」と答えてください。\n\n【年間予定データ】\n${context||'（データなし）'}\n\n【質問】\n${question||'画像について説明してください'}`;
    const parts = [{ text: prompt }];
    if (image) {
      const m = image.match(/^data:([^;]+);base64,(.+)$/);
      if (m) parts.push({ inlineData: { mimeType: m[1], data: m[2] } });
    }
    const geminiResp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts }] })
    });
    const result = await geminiResp.json();
    if (!geminiResp.ok) return res.status(500).json({ error: result.error?.message || 'Gemini API エラー' });
    const answer = result.candidates?.[0]?.content?.parts?.[0]?.text || '回答を生成できませんでした';
    res.json({ answer });
  } catch (e) {
    console.error('Gemini error:', e.message);
    res.status(500).json({ error: e.message || 'Geminiエラーが発生しました' });
  }
});

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
