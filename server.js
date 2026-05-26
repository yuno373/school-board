const express = require('express');
const path = require('path');
const fs = require('fs');
const webPush = require('web-push');
const app = express();
const DATA_FILE = path.join(__dirname, 'push_subs.json');
const WORKER = 'https://school-board-api.dajianweixi.workers.dev';
const MIGRATE_KEY = process.env.MIGRATE_KEY || 'migrate2026';

let VAPID_PUBLIC, VAPID_PRIVATE;
async function initVapid() {
  VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY;
  VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY;
  if (VAPID_PUBLIC && VAPID_PRIVATE) {
    webPush.setVapidDetails('mailto:admin@school.example.com', VAPID_PUBLIC, VAPID_PRIVATE);
    console.log('VAPID keys loaded from env');
    return;
  }
  // Try R2
  try {
    const r = await fetch(WORKER + '/api/vapid-keys');
    if (r.ok) { const saved = await r.json(); VAPID_PUBLIC = saved.publicKey; VAPID_PRIVATE = saved.privateKey; webPush.setVapidDetails('mailto:admin@school.example.com', VAPID_PUBLIC, VAPID_PRIVATE); console.log('VAPID keys loaded from R2'); return; }
  } catch(e) {}
  // Try local file
  const keyFile = path.join(__dirname, 'vapid_keys.json');
  try {
    const saved = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    VAPID_PUBLIC = saved.publicKey; VAPID_PRIVATE = saved.privateKey;
    webPush.setVapidDetails('mailto:admin@school.example.com', VAPID_PUBLIC, VAPID_PRIVATE);
    console.log('VAPID keys loaded from file');
    return;
  } catch(e) {}
  // Generate new
  const keys = webPush.generateVAPIDKeys();
  VAPID_PUBLIC = keys.publicKey; VAPID_PRIVATE = keys.privateKey;
  webPush.setVapidDetails('mailto:admin@school.example.com', VAPID_PUBLIC, VAPID_PRIVATE);
  try { fs.writeFileSync(keyFile, JSON.stringify(keys)); } catch(_) {}
  fetch(WORKER + '/api/vapid-keys', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Auth-Key': MIGRATE_KEY }, body: JSON.stringify(keys) }).catch(() => {});
  console.log('Generated new VAPID keys, saved to R2');
}

let pushSubs = [];
async function loadSubsFromR2() {
  try {
    const r = await fetch(WORKER + '/api/push/subs');
    if (r.ok) { pushSubs = await r.json(); console.log('Loaded ' + pushSubs.length + ' push subscriptions from R2'); return; }
  } catch(e) { console.log('R2 push subs fetch failed:', e.message); }
  try { pushSubs = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8')); console.log('Loaded ' + pushSubs.length + ' push subscriptions from local file'); } catch(e) { console.log('No local push subs file'); }
}
function syncSubsToR2() {
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(pushSubs)); } catch(e) {}
  fetch(WORKER + '/api/push/subs', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Auth-Key': MIGRATE_KEY }, body: JSON.stringify(pushSubs) }).catch(() => {});
}

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
    syncSubsToR2();
    res.json({ ok: true, topics: topics || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/push/unsubscribe', express.json(), async (req, res) => {
  try {
    const user = await verifyToken(req.headers.authorization);
    if (!user) return res.status(401).json({ error: '認証が必要です' });
    pushSubs = pushSubs.filter(s => s.username !== user.username);
    syncSubsToR2();
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
    const catLabels = { 'general': '📝 上中連絡', 'lost': '🔍 忘れ物', 'chat': '💬 部長チャット', 'dm': '✉️ DM', 'group-dm': '👥 グループDM', 'schedule': '📅 予定', 'disaster': '🚨 防災情報' };
    const prefix = catLabels[category] || ('🏷️ ' + category);
    const prefixedTitle = prefix + ': ' + title;
    const targets = pushSubs.filter(s => s.username !== excludeUser && (!s.topics || s.topics.length === 0 || s.topics.includes(category) || s.topics.includes('club_'+category) || s.topics.includes('committee_'+category) || s.topics.includes('all')));
    const results = { sent: 0, failed: 0, errors: [] };
    await Promise.all(targets.map(async sub => {
      try {
        await webPush.sendNotification(sub, JSON.stringify({ title: prefixedTitle, body: body || '', icon: '/icon.svg', data: { url: url || '/' } }));
        results.sent++;
      } catch (e) {
        results.failed++;
        results.errors.push({ username: sub.username, code: e.statusCode, message: e.message });
        if (e.statusCode === 410 || e.statusCode === 404) { pushSubs = pushSubs.filter(s => s.endpoint !== sub.endpoint); syncSubsToR2(); }
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
    const results = { sent: 0, failed: 0, errors: [] };
    await Promise.all(pushSubs.map(async sub => {
      try {
        await webPush.sendNotification(sub, JSON.stringify({ title, body: body || '', icon: '/icon.svg', data: { url: url || '/' } }));
        results.sent++;
      } catch (e) {
        results.failed++;
        results.errors.push({ username: sub.username, code: e.statusCode, message: e.message });
        if (e.statusCode === 410 || e.statusCode === 404) { pushSubs = pushSubs.filter(s => s.endpoint !== sub.endpoint); syncSubsToR2(); }
      }
    }));
    res.json(results);
  } catch (e) {
    console.error('Push send error:', e.message);
    res.status(500).json({ error: e.message });
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

const port = process.env.PORT || 3000;

Promise.all([initVapid(), loadSubsFromR2()]).then(() => {
  app.listen(port, () => console.log('Server running on port ' + port));
}).catch(() => {
  app.listen(port, () => console.log('Server running on port ' + port));
});
