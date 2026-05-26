// Cloudflare Worker — New School Board API
// ============================================================
// Features: JWT auth, AES-256-GCM, rate-limit, login-lock,
//           audit-log, reactions, club-questions, notifications,
//           tab-config, CSRF protection

// ---- Constants ----
const VALID_ROLES = ['admin','teacher','president','vice-president','chairperson','student'];
const ROLE_HIERARCHY = ['admin','teacher','chairperson','president','vice-president','student'];
const REACTION_TYPES = ['like','heart','ok','question','thanks'];
const CATEGORIES = ['吹奏楽部','茶道部','美術部','卓球部','テニス部女子','テニス部男子','サッカー部','野球部','陸上部','バスケ部女子','バスケ部男子','バレー部'];
const COMM_CATS = ['整備委員会','生活委員会','選挙管理委員会','図書委員会','給食委員会','合唱委員会','体育委員会','保健委員会','放送委員会','1学年委員会','2学年委員会','3学年委員会','中央委員会','部活動委員会'];
const BAD_WORDS = ['死ね','殺す','馬鹿','バカ','あほ','アホ','くそ','クソ','消えろ','うざい','きもい','キモい','むかつく','ふざけんな','ざまあ','しね','ころす','ばか','あほ','くそ','うざ','きも','むかつ'];
const LOCK_ATTEMPTS = { warn: 5, hard: 10 };
const LOCK_DURATIONS = { warn: 10 * 60 * 1000, hard: 60 * 60 * 1000 };

// ---- Rate limiter (in-memory) ----
const rateMap = new Map();
let rateLimitRemaining = 300;
let rateLimitLimit = 300;
function checkRate(ip) {
  const now = Date.now();
  let entry = rateMap.get(ip);
  if (!entry || now > entry.reset) { entry = { count: 0, reset: now + 60000 }; }
  entry.count++;
  rateMap.set(ip, entry);
  rateLimitRemaining = Math.max(0, 300 - entry.count);
  rateLimitLimit = 300;
  if (entry.count > 300) return json({ error: 'リクエストが多すぎます' }, 429);
  return null;
}

// ---- Utilities ----
const enc = s => new TextEncoder().encode(s);
const dec = b => new TextDecoder().decode(b);
const uuid = () => crypto.randomUUID();

async function hashPwd(pwd, salt) {
  const d = enc(salt + pwd);
  const h = await crypto.subtle.digest('SHA-256', d);
  return Array.from(new Uint8Array(h)).map(x => x.toString(16).padStart(2, '0')).join('');
}

async function hmacSign(data, secret) {
  const json = JSON.stringify(data);
  const b64 = btoa(unescape(encodeURIComponent(json)));
  const key = await crypto.subtle.importKey('raw', enc(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc(b64));
  return b64 + '.' + Array.from(new Uint8Array(sig)).map(x => x.toString(16).padStart(2, '0')).join('');
}

async function hmacVerify(token, secret) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [b64, sigHex] = parts;
  try {
    const key = await crypto.subtle.importKey('raw', enc(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sig = new Uint8Array(sigHex.match(/.{2}/g).map(x => parseInt(x, 16)));
    if (!await crypto.subtle.verify('HMAC', key, sig, enc(b64))) return null;
    const data = JSON.parse(decodeURIComponent(escape(atob(b64))));
    if (data.exp && Date.now() > data.exp) return null;
    return data;
  } catch(e) { return null; }
}

// ---- AES-256-GCM Encryption ----
async function aesEncrypt(plaintext, keyHex) {
  const key = await crypto.subtle.importKey('raw', new Uint8Array(keyHex.match(/.{2}/g).map(x => parseInt(x, 16))), { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc(plaintext));
  const combined = new Uint8Array(iv.length + ct.byteLength);
  combined.set(iv); combined.set(new Uint8Array(ct), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function aesDecrypt(cipherB64, keyHex) {
  const combined = Uint8Array.from(atob(cipherB64), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ct = combined.slice(12);
  const key = await crypto.subtle.importKey('raw', new Uint8Array(keyHex.match(/.{2}/g).map(x => parseInt(x, 16))), { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return dec(pt);
}

function deriveAesKey(userSecret, salt) {
  // Derive a 256-bit key from a known secret + salt using SHA-256
  // In production use a proper KDF; here we stretch with SHA-256
  return hashPwd(userSecret, salt);
}

// ---- R2 helpers ----
async function r2Get(bucket, key) {
  try {
    const obj = await bucket.get(key);
    if (!obj) return null;
    return JSON.parse(await obj.text());
  } catch(e) { return null; }
}

async function r2Put(bucket, key, data) {
  await bucket.put(key, JSON.stringify(data));
}

// ---- Response helpers ----
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-CSRF-Token',
      'X-Content-Type-Options': 'nosniff',
      'X-RateLimit-Remaining': String(rateLimitRemaining),
      'X-RateLimit-Limit': String(rateLimitLimit)
    }
  });
}

// ---- Auth ----
async function getUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/);
  if (m) {
    const u = await hmacVerify(m[1], env.COOKIE_SECRET);
    if (u) return u;
  }
  const cookie = request.headers.get('Cookie') || '';
  const cm = cookie.match(/session=([^;]+)/);
  if (!cm) return null;
  return await hmacVerify(cm[1], env.COOKIE_SECRET);
}

function hasOneOf(userRole, roles) {
  if (!roles) return true;
  const parts = userRole.split(',').map(r => r.trim());
  return roles.some(r => parts.includes(r));
}

function requireAuth(user, roles = null) {
  if (!user) return json({ error: '認証が必要です' }, 401);
  if (roles && !hasOneOf(user.role, roles)) return json({ error: '権限がありません' }, 403);
  return null;
}

function sanitize(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}

function randomPassword() {
  const b = new Uint8Array(4);
  crypto.getRandomValues(b);
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function hasAbuse(text) {
  const t = text.replace(/\s/g, '');
  return BAD_WORDS.some(w => t.includes(w));
}

// ---- Audit log ----
async function auditLog(env, action, username, details = {}, ip = 'unknown') {
  const log = await r2Get(env.DATA, 'audit.json') || [];
  log.unshift({ id: uuid(), action, username, details, ip, timestamp: new Date().toISOString() });
  if (log.length > 1000) log.length = 1000;
  await r2Put(env.DATA, 'audit.json', log);
}

// ---- Notifications ----
async function addNotification(env, type, message, link = '') {
  const notifs = await r2Get(env.DATA, 'notifications.json') || [];
  notifs.unshift({ id: uuid(), type, message, link, read: false, dismissed: false, created_at: new Date().toISOString() });
  if (notifs.length > 200) notifs.length = 200;
  await r2Put(env.DATA, 'notifications.json', notifs);
}

// ---- Login lock check ----
async function checkLock(env, username) {
  const locks = await r2Get(env.DATA, 'login_locks.json') || {};
  const lock = locks[username];
  if (!lock) return null;
  if (Date.now() < lock.until) {
    const remaining = Math.ceil((lock.until - Date.now()) / 60000);
    return { locked: true, remaining, level: lock.level };
  }
  delete locks[username];
  await r2Put(env.DATA, 'login_locks.json', locks);
  return null;
}

async function recordFailedAttempt(env, username) {
  const locks = await r2Get(env.DATA, 'login_locks.json') || {};
  if (!locks[username]) locks[username] = { count: 0, until: 0, level: 0 };
  locks[username].count++;
  const cnt = locks[username].count;
  if (cnt >= LOCK_ATTEMPTS.hard) {
    locks[username].until = Date.now() + LOCK_DURATIONS.hard;
    locks[username].level = 2;
    await r2Put(env.DATA, 'login_locks.json', locks);
    await addNotification(env, 'lock', `ユーザー「${sanitize(username)}」が${LOCK_ATTEMPTS.hard}回ログイン失敗でロックされました（1時間）`, '/admin');
    return { locked: true, duration: 60, level: 2 };
  }
  if (cnt >= LOCK_ATTEMPTS.warn) {
    locks[username].until = Date.now() + LOCK_DURATIONS.warn;
    locks[username].level = 1;
    await r2Put(env.DATA, 'login_locks.json', locks);
    await addNotification(env, 'lock', `ユーザー「${sanitize(username)}」が${LOCK_ATTEMPTS.warn}回ログイン失敗でロックされました（10分）`, '/admin');
    return { locked: true, duration: 10, level: 1 };
  }
  await r2Put(env.DATA, 'login_locks.json', locks);
  return { locked: false, attempts: cnt };
}

// ---- Default tab config ----
const DEFAULT_TABS = [
  { l: '上中連絡', n: '上中連絡' },
  { l: '忘れ物', n: '忘れ物' },
  { l: '生徒会', n: '生徒会' },
  { l: '3学年委員会', n: '3学年委員会' }, { l: '2学年委員会', n: '2学年委員会' }, { l: '1学年委員会', n: '1学年委員会' },
  { l: '中央委員会', n: '中央委員会', roles: ['admin','teacher','president','vice-president','chairperson'] },
  { l: '部活動委員会', n: '部活動委員会', roles: ['admin','teacher','president','vice-president','chairperson'] },
  { l: '— 部活動 —', g: true },
  { l: '吹奏楽部', n: '吹奏楽部' }, { l: '茶道部', n: '茶道部' }, { l: '美術部', n: '美術部' }, { l: '卓球部', n: '卓球部' },
  { l: 'テニス部女子', n: 'テニス部女子' }, { l: 'テニス部男子', n: 'テニス部男子' }, { l: 'サッカー部', n: 'サッカー部' },
  { l: '野球部', n: '野球部' }, { l: '陸上部', n: '陸上部' }, { l: 'バスケ部女子', n: 'バスケ部女子' }, { l: 'バスケ部男子', n: 'バスケ部男子' }, { l: 'バレー部', n: 'バレー部' },
  { l: '— 委員会 —', g: true },
  { l: '整備委員会', n: '整備委員会' }, { l: '生活委員会', n: '生活委員会' }, { l: '選挙管理委員会', n: '選挙管理委員会' }, { l: '図書委員会', n: '図書委員会' },
  { l: '給食委員会', n: '給食委員会' }, { l: '合唱委員会', n: '合唱委員会' }, { l: '体育委員会', n: '体育委員会' },
  { l: '保健委員会', n: '保健委員会' }, { l: '放送委員会', n: '放送委員会' }
];

// ============================================================
// ---- HANDLER ----
// ============================================================
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const pwdSalt = env.PWD_SALT || 'school-board-salt-2026';
  const hp = (pwd) => hashPwd(pwd, pwdSalt);

  // CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-CSRF-Token',
        'X-RateLimit-Remaining': String(rateLimitRemaining),
        'X-RateLimit-Limit': String(rateLimitLimit)
      }
    });
  }

  // Rate limit
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rlErr = checkRate(ip);
  if (rlErr) return rlErr;

  try {
    // ============================================================
    // 1. AUTH ENDPOINTS
    // ============================================================
    if (path === '/api/setup' && method === 'POST') {
      const { username, password, role } = await request.json();
      if (!username || !password) return json({ error: '入力してください' }, 400);
      const users = await r2Get(env.DATA, 'users.json') || [];
      const existing = users.find(u => u.username === username);
      if (existing) return json({ error: '既に存在します' }, 409);
      const newUser = {
        id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2),
        username, password, password_plain: '',
        role: role || 'student', role_subtype: '',
        grade: '', class_num: '', seat_num: '',
        club: '', committee: '',
        display_name: username, created_at: new Date().toISOString()
      };
      users.push(newUser);
      await r2Put(env.DATA, 'users.json', users);
      await auditLog(env, 'setup', username, { action: 'create_first_admin' });
      return json({ message: '作成しました', username });
    }
    if (path === '/api/login' && method === 'POST') {
      const { username, password } = await request.json();
      if (!username || !password) return json({ error: '入力してください' }, 400);

      // Check lock
      const lock = await checkLock(env, username);
      if (lock) return json({ error: `ログインがロックされました。あと${lock.remaining}分お待ちください`, locked: true, remaining: lock.remaining }, 423);

      const users = await r2Get(env.DATA, 'users.json') || [];
      const hashedInput = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', enc(password)))).map(x => x.toString(16).padStart(2, '0')).join('');
      const pwdHash = await hp(password);
      const pwdHash2 = await hp(hashedInput);
      const validUser = users.find(u =>
        (u.username === username || u.display_name === username) &&
        (u.password === pwdHash || u.password === pwdHash2 || u.password === password || u.password === hashedInput)
      );

      if (!validUser) {
        const fail = await recordFailedAttempt(env, username);
        await notifyHomeroomOnFail(env, username);
        return json({ error: 'ユーザー名またはパスワードが違います', attempts: fail.attempts || 0 }, 401);
      }

      // Reset lock on success
      const locks = await r2Get(env.DATA, 'login_locks.json') || {};
      delete locks[username];
      await r2Put(env.DATA, 'login_locks.json', locks);

      const exp = Date.now() + 3600000; // 1 hour JWT
      const sessionData = {
        id: validUser.id, username: validUser.username, role: validUser.role,
        display_name: validUser.display_name || validUser.username, grade: validUser.grade || '',
        club: validUser.club || '', committee: validUser.committee || '',
        teacher_setup_done: validUser.teacher_setup_done || false, exp
      };
      const token = await hmacSign(sessionData, env.COOKIE_SECRET);
      await auditLog(env, 'login', validUser.username, {}, ip);
      return new Response(JSON.stringify({
        token, username: validUser.username, role: validUser.role,
        display_name: validUser.display_name || validUser.username,
        grade: validUser.grade || '', club: validUser.club || '', committee: validUser.committee || '',
        teacher_setup_done: validUser.teacher_setup_done || false
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Set-Cookie': `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600`,
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type,Authorization'
        }
      });
    }

    // POST /api/logout
    if (path === '/api/logout' && method === 'POST') {
      return json({ ok: true });
    }

    // ============================================================
    // Auth middleware (everything below requires authentication)
    // ============================================================
    const user = await getUser(request, env);
    let authErr;

    // GET /api/me
    if (path === '/api/me' && method === 'GET') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const users = await r2Get(env.DATA, 'users.json') || [];
      const u = users.find(x => x.id === user.id);
      return json({
        username: user.username, role: user.role,
        display_name: user.display_name || user.username,
        grade: u?.grade || '', class_num: u?.class_num || '', seat_num: u?.seat_num || '',
        club: u?.club || '', committee: u?.committee || '',
        teacher_grade: u?.teacher_grade || '', teacher_subject: u?.teacher_subject || '', teacher_homeroom: u?.teacher_homeroom || '',
        teacher_setup_done: u?.teacher_setup_done || false,
        icon: u?.icon || '', created_at: u?.created_at || ''
      });
    }

    // PUT /api/me
    if (path === '/api/me' && method === 'PUT') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const { display_name, icon, club, committee, grade, class_num, seat_num, teacher_grade, teacher_subject, teacher_homeroom, teacher_setup_done } = await request.json();
      const users = await r2Get(env.DATA, 'users.json') || [];
      const u = users.find(x => x.id === user.id);
      if (!u) return json({ error: '見つかりません' }, 404);
      if (display_name !== undefined) u.display_name = sanitize(display_name.trim());
      if (icon !== undefined) u.icon = icon;
      if (club !== undefined) u.club = club;
      if (committee !== undefined) u.committee = committee;
      if (grade !== undefined) u.grade = String(grade);
      if (class_num !== undefined) u.class_num = String(class_num);
      if (seat_num !== undefined) u.seat_num = String(seat_num);
      if (teacher_grade !== undefined) u.teacher_grade = String(teacher_grade);
      if (teacher_subject !== undefined) u.teacher_subject = sanitize(teacher_subject.trim());
      if (teacher_homeroom !== undefined) u.teacher_homeroom = String(teacher_homeroom);
      if (teacher_setup_done !== undefined) u.teacher_setup_done = !!teacher_setup_done;
      await r2Put(env.DATA, 'users.json', users);
      await auditLog(env, 'update_profile', user.username, { fields: Object.keys({ display_name, icon, club, committee }).filter(k => arguments[1][k] !== undefined) });
      // Issue new token with updated data
      const exp = Date.now() + 3600000;
      const newSession = { id: u.id, username: u.username, role: u.role, display_name: u.display_name || u.username, grade: u.grade || '', club: u.club || '', committee: u.committee || '', teacher_setup_done: u.teacher_setup_done || false, exp };
      const newToken = await hmacSign(newSession, env.COOKIE_SECRET);
      return json({ success: true, token: newToken, display_name: u.display_name || u.username, club: u.club || '', committee: u.committee || '' });
    }

    // POST /api/me/password
    if (path === '/api/me/password' && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const { currentPassword, newPassword } = await request.json();
      if (!currentPassword || !newPassword) return json({ error: '入力してください' }, 400);
      if (newPassword.length < 6) return json({ error: '6文字以上' }, 400);
      const users = await r2Get(env.DATA, 'users.json') || [];
      const u = users.find(x => x.id === user.id);
      if (!u) return json({ error: '見つかりません' }, 404);
      const curHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', enc(currentPassword)))).map(x => x.toString(16).padStart(2, '0')).join('');
      if (u.password !== (await hp(curHash))) return json({ error: '現在のパスワードが違います' }, 403);
      const newHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', enc(newPassword)))).map(x => x.toString(16).padStart(2, '0')).join('');
      u.password = await hp(newHash);
      u.password_plain = newPassword;
      await r2Put(env.DATA, 'users.json', users);
      return json({ success: true });
    }

    // POST /api/me/verify
    if (path === '/api/me/verify' && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const { password } = await request.json();
      if (!password) return json({ error: '入力してください' }, 400);
      const users = await r2Get(env.DATA, 'users.json') || [];
      const u = users.find(x => x.id === user.id);
      const pwdHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', enc(password)))).map(x => x.toString(16).padStart(2, '0')).join('');
      if (!u || u.password !== (await hp(pwdHash))) return json({ error: 'パスワードが違います' }, 403);
      return json({ success: true });
    }

    // ============================================================
    // 2. POSTS
    // ============================================================
    if (path === '/api/posts/counts' && method === 'GET') {
      const posts = await r2Get(env.DATA, 'posts.json') || [];
      const counts = {};
      posts.forEach(p => { const cat = p.category || 'その他'; counts[cat] = (counts[cat] || 0) + 1; });
      return json(counts);
    }

    if (path === '/api/posts' && method === 'GET') {
      const category = url.searchParams.get('category');
      let posts = await r2Get(env.DATA, 'posts.json') || [];
      if (category) posts = posts.filter(p => p.category === category);
      posts.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      // Strip private content for non-authors
      posts = posts.map(p => {
        if (!p.private_password) return p;
        const isAuthor = user && user.username === p.username;
        const resp = { ...p };
        if (!isAuthor) { resp.has_private = true; delete resp.content; }
        delete resp.private_password; delete resp.private_wrong; delete resp.private_notified;
        return resp;
      });
      return json(posts);
    }

    if (path === '/api/posts' && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher', 'president', 'vice-president', 'chairperson']);
      if (authErr) return authErr;
      const { title, content, category, files, expiresIn, private_password, link } = await request.json();
      if (!title || !category) return json({ error: 'タイトルとカテゴリは必須です' }, 400);
      const privateCats = ['1学年委員会','2学年委員会','3学年委員会'];
      const isPrivate = privateCats.includes(category) && private_password;
      const posts = await r2Get(env.DATA, 'posts.json') || [];
      const expires_at = expiresIn ? new Date(Date.now() + parseInt(expiresIn) * 86400000).toISOString() : null;
      const post = {
        id: uuid(), title: sanitize(title.trim()), content: sanitize(content?.trim() || ''), category,
        username: user.username, display_name: user.display_name || user.username,
        created_at: new Date().toISOString(), expires_at, claims: [], files: files || [],
        link: link?.trim() || ''
      };
      if (isPrivate) {
        post.private_password = await hp(private_password);
        post.private_wrong = {};
        post.private_notified = {};
      }
      posts.push(post);
      if (posts.length > 200) posts.splice(0, posts.length - 200);
      await r2Put(env.DATA, 'posts.json', posts);
      // Strip private content from response
      const resp = { ...post };
      if (resp.private_password) { resp.has_private = true; delete resp.content; delete resp.private_password; delete resp.private_wrong; delete resp.private_notified; }
      return json(resp, 201);
    }

    // POST /api/posts/:id/verify-password
    const verifyPwd = path.match(/^\/api\/posts\/([^/]+)\/verify-password$/);
    if (verifyPwd && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const { password } = await request.json();
      if (!password) return json({ error: 'パスワードが必要です' }, 400);
      const posts = await r2Get(env.DATA, 'posts.json') || [];
      const p = posts.find(x => x.id === verifyPwd[1]);
      if (!p) return json({ error: '見つかりません' }, 404);
      if (!p.private_password) return json(p);
      const inputHash = await hp(password);
      if (p.private_password !== inputHash) {
        if (!p.private_wrong) p.private_wrong = {};
        if (!p.private_notified) p.private_notified = {};
        p.private_wrong[user.username] = (p.private_wrong[user.username] || 0) + 1;
        if (p.private_wrong[user.username] >= 5 && !p.private_notified[user.username]) {
          p.private_notified[user.username] = true;
          await addNotification(env, 'private_password_fail', `${user.display_name||user.username}さんが「${p.title}」のパスワードを5回間違えました`, `/01index.html?cat=${encodeURIComponent(p.category)}`);
          await auditLog(env, 'private_password_fail', user.username, { postId: p.id, title: p.title });
        }
        await r2Put(env.DATA, 'posts.json', posts);
        return json({ error: 'パスワードが違います', attempts: p.private_wrong[user.username] }, 403);
      }
      // Reset attempts on success
      if (p.private_wrong) delete p.private_wrong[user.username];
      await r2Put(env.DATA, 'posts.json', posts);
      const resp = { ...p };
      delete resp.private_password; delete resp.private_wrong; delete resp.private_notified;
      return json(resp);
    }

    // POST /api/posts/:id/set-password
    const setPwd = path.match(/^\/api\/posts\/([^/]+)\/set-password$/);
    if (setPwd && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const { password } = await request.json();
      const posts = await r2Get(env.DATA, 'posts.json') || [];
      const p = posts.find(x => x.id === setPwd[1]);
      if (!p) return json({ error: '見つかりません' }, 404);
      if (password) {
        p.private_password = await hp(password);
        if (!p.private_wrong) p.private_wrong = {};
        if (!p.private_notified) p.private_notified = {};
      } else {
        delete p.private_password; delete p.private_wrong; delete p.private_notified;
      }
      await r2Put(env.DATA, 'posts.json', posts);
      return json({ ok: true });
    }

    const postDel = path.match(/^\/api\/posts\/([^/]+)$/);
    if (postDel && method === 'DELETE') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const posts = await r2Get(env.DATA, 'posts.json') || [];
      const idx = posts.findIndex(p => p.id === postDel[1]);
      if (idx === -1) return json({ error: '見つかりません' }, 404);
      const p = posts[idx];
      if (!hasOneOf(user.role, ['admin','teacher']) && p.username !== user.username) return json({ error: '権限がありません' }, 403);
      posts.splice(idx, 1);
      await r2Put(env.DATA, 'posts.json', posts);
      await auditLog(env, 'delete_post', user.username, { postId: postDel[1], category: p.category });
      return json({ ok: true });
    }

    // Claim
    const claim = path.match(/^\/api\/posts\/([^/]+)\/claim$/);
    if (claim && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const posts = await r2Get(env.DATA, 'posts.json') || [];
      const p = posts.find(x => x.id === claim[1]);
      if (!p) return json({ error: '見つかりません' }, 404);
      if (!p.claims) p.claims = [];
      if (p.claims.find(c => c.username === user.username)) return json({ error: '既に申請済みです' }, 400);
      p.claims.push({ username: user.username, display_name: user.display_name || user.username, claimed_at: new Date().toISOString() });
      await r2Put(env.DATA, 'posts.json', posts);
      return json({ claims: p.claims });
    }

    if (claim && method === 'DELETE') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const posts = await r2Get(env.DATA, 'posts.json') || [];
      const p = posts.find(x => x.id === claim[1]);
      if (!p) return json({ error: '見つかりません' }, 404);
      if (!p.claims) p.claims = [];
      p.claims = p.claims.filter(c => c.username !== user.username);
      await r2Put(env.DATA, 'posts.json', posts);
      return json({ claims: p.claims });
    }

    // GET /api/admin/posts
    if (path === '/api/admin/posts' && method === 'GET') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const posts = await r2Get(env.DATA, 'posts.json') || [];
      posts.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      return json(posts);
    }

    // GET /api/admin/login-locks
    if (path === '/api/admin/login-locks' && method === 'GET') {
      authErr = requireAuth(user, ['admin']);
      if (authErr) return authErr;
      const locks = await r2Get(env.DATA, 'login_locks.json') || {};
      return json(Object.entries(locks).map(([username, data]) => ({ username, ...data })));
    }

    // ============================================================
    // 3. USERS
    // ============================================================
    // GET /api/users/public (no auth, just teacher names for password reset)
if (path === '/api/users/public' && method === 'GET') {
  const users = await r2Get(env.DATA, 'users.json') || [];
  return json(users.map(u => ({
    username: u.username, display_name: u.display_name || u.username,
    role: u.role
  })));
}

if (path === '/api/users' && method === 'GET') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const users = await r2Get(env.DATA, 'users.json') || [];
      return json(users.map(u => ({
        id: u.id, username: u.username, password_plain: u.password_plain || '',
        role: u.role, grade: u.grade || '', class_num: u.class_num || '',
        seat_num: u.seat_num || '', club: u.club || '', committee: u.committee || '',
        display_name: u.display_name || u.username, icon: u.icon || '',
        created_at: u.created_at || '', locked: false
      })));
    }

    if (path === '/api/users' && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const { username, password, role, grade, class_num, seat_num, club, committee, display_name, teacher_grades, teacher_subject, teacher_homeroom } = await request.json();
      if (!username || !password || !role) return json({ error: '必須項目不足' }, 400);
      if (password.length < 6) return json({ error: '6文字以上' }, 400);
      const newRoles = role.split(',').map(r => r.trim());
      if (!newRoles.every(r => VALID_ROLES.includes(r))) return json({ error: '権限が不正です' }, 400);
      const isSelfAdmin = newRoles.includes('admin');
      if (isSelfAdmin && !user.role.split(',').map(r => r.trim()).includes('admin')) return json({ error: '管理者の作成は管理者のみ可能です' }, 403);
      const users = await r2Get(env.DATA, 'users.json') || [];
      if (users.find(u => u.username === username)) return json({ error: '既に存在します' }, 409);
      const newUser = {
        id: uuid(), username, password: await hp(password), password_plain: password,
        role, grade: grade || '', class_num: class_num || '', seat_num: seat_num || '',
        club: club || '', committee: committee || '', display_name: display_name || username,
        icon: '', created_at: new Date().toISOString()
      };
      if (newRoles.includes('teacher')) {
        newUser.teacher_grades = teacher_grades || '';
        newUser.teacher_subject = teacher_subject || '';
        newUser.teacher_homeroom = !!teacher_homeroom;
        newUser.teacher_setup_done = false;
      }
      users.push(newUser);
      await r2Put(env.DATA, 'users.json', users);
      await auditLog(env, 'create_user', user.username, { target: username, role });
      return json({ id: newUser.id, username: newUser.username, role: newUser.role }, 201);
    }

    const userUpd = path.match(/^\/api\/users\/([^/]+)$/);
    if (userUpd && method === 'PUT') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const updates = await request.json();
      const users = await r2Get(env.DATA, 'users.json') || [];
      const u = users.find(x => x.id === userUpd[1]);
      if (!u) return json({ error: '見つかりません' }, 404);
      if ((u.role || '').includes('admin') && !(user.role || '').includes('admin')) return json({ error: '管理者は変更できません' }, 403);
      if (updates.role) {
        const newRoles = updates.role.split(',').map(r => r.trim());
        if (!newRoles.every(r => VALID_ROLES.includes(r))) return json({ error: '権限が不正です' }, 400);
        if (newRoles.includes('admin') && user.username !== u.username) return json({ error: '管理者権限は付与できません' }, 403);
        u.role = updates.role;
      }
      if (updates.password) {
        const pwdHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', enc(updates.password)))).map(x => x.toString(16).padStart(2, '0')).join('');
        u.password = await hp(pwdHash);
        u.password_plain = updates.password;
      }
      if (updates.grade !== undefined) u.grade = updates.grade;
      if (updates.class_num !== undefined) u.class_num = updates.class_num;
      if (updates.seat_num !== undefined) u.seat_num = updates.seat_num;
      if (updates.club !== undefined) u.club = updates.club;
      if (updates.committee !== undefined) u.committee = updates.committee;
      if (updates.display_name !== undefined) u.display_name = updates.display_name;
      if (updates.teacher_grade !== undefined) u.teacher_grade = updates.teacher_grade;
      if (updates.teacher_subject !== undefined) u.teacher_subject = updates.teacher_subject;
      if (updates.teacher_homeroom !== undefined) u.teacher_homeroom = updates.teacher_homeroom;
      if (updates.teacher_setup_done !== undefined) u.teacher_setup_done = !!updates.teacher_setup_done;
      // Auto-add teachers/admin to chat
      if (updates.role && (updates.role.includes('admin') || updates.role.includes('teacher'))) {
        const parts = await r2Get(env.DATA, 'chat_participants.json') || [];
        if (!parts.includes(u.username)) { parts.push(u.username); await r2Put(env.DATA, 'chat_participants.json', parts); }
      }
      await r2Put(env.DATA, 'users.json', users);
      await auditLog(env, 'update_user', user.username, { target: u.username, fields: Object.keys(updates) });
      return json({ id: u.id, username: u.username, role: u.role });
    }

    // Reset password
    const pwdReset = path.match(/^\/api\/users\/([^/]+)\/reset-password$/);
    if (pwdReset && method === 'PUT') {
      authErr = requireAuth(user, ['admin']);
      if (authErr) return authErr;
      const users = await r2Get(env.DATA, 'users.json') || [];
      const u = users.find(x => x.id === pwdReset[1]);
      if (!u) return json({ error: '見つかりません' }, 404);
      const newPwd = randomPassword();
      const newPwdHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', enc(newPwd)))).map(x => x.toString(16).padStart(2, '0')).join('');
      u.password = await hp(newPwdHash);
      u.password_plain = newPwd;
      await r2Put(env.DATA, 'users.json', users);
      await auditLog(env, 'reset_password', user.username, { target: u.username });
      return json({ message: 'パスワードを再発行しました', newPassword: newPwd });
    }

    // Unlock user
    const unlock = path.match(/^\/api\/users\/([^/]+)\/unlock$/);
    if (unlock && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const users = await r2Get(env.DATA, 'users.json') || [];
      const u = users.find(x => x.id === unlock[1]);
      if (!u) return json({ error: '見つかりません' }, 404);
      const locks = await r2Get(env.DATA, 'login_locks.json') || {};
      if (locks[u.username]) {
        delete locks[u.username];
        await r2Put(env.DATA, 'login_locks.json', locks);
        await addNotification(env, 'unlock', `ユーザー「${sanitize(u.username)}」のログインロックが${sanitize(user.display_name || user.username)}により解除されました`, '/admin');
        await auditLog(env, 'unlock_user', user.username, { target: u.username });
      }
      return json({ ok: true });
    }

    // DELETE /api/users/:id
    if (userUpd && method === 'DELETE') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const users = await r2Get(env.DATA, 'users.json') || [];
      const idx = users.findIndex(x => x.id === userUpd[1]);
      if (idx === -1) return json({ error: '見つかりません' }, 404);
      if (users[idx].id === user.id) return json({ error: '自分自身は削除できません' }, 400);
      if ((users[idx].role || '').includes('admin')) return json({ error: '管理者は削除できません' }, 403);
      await auditLog(env, 'delete_user', user.username, { target: users[idx].username });
      users.splice(idx, 1);
      await r2Put(env.DATA, 'users.json', users);
      return json({ ok: true });
    }

    // POST /api/users/batch
    if (path === '/api/users/batch' && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const body = await request.json();
      const rawPassword = body.password || '111111';
      const password = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', enc(rawPassword)))).map(x => x.toString(16).padStart(2, '0')).join('');
      const users = await r2Get(env.DATA, 'users.json') || [];
      const created = [];
      let seq = 1;

      // Teacher batch generation
      if (body.teachers) {
        const prefix = body.prefix || 'T';
        let nextNum = body.startNum || 1;
        const count = parseInt(body.teachers) || 1;
        for (let i = 0; i < count; i++) {
          while (users.find(u => u.username === prefix + String(nextNum).padStart(3, '0'))) nextNum++;
          const tid = prefix + String(nextNum).padStart(3, '0');
          const disp = body.displayPrefix ? body.displayPrefix + String(nextNum) : tid;
          if (users.find(u => u.username === tid)) continue;
          users.push({
            id: uuid(), username: tid, password: await hp(password), password_plain: rawPassword,
            role: 'teacher', grade: '', class_num: '', seat_num: '',
            club: '', committee: '', display_name: disp, icon: '',
            teacher_grades: '', teacher_subject: '', teacher_homeroom: false,
            teacher_setup_done: false,
            created_at: new Date().toISOString()
          });
          created.push(tid);
          nextNum++;
        }
        await r2Put(env.DATA, 'users.json', users);
        await auditLog(env, 'batch_create_teacher', user.username, { count: created.length, body: JSON.stringify(body) });
        return json({ created: created.length, password: rawPassword, users: created });
      }

      // New format: { years: [{ year, classes: [{ perClass }] }] }
      // Old format: { year, classes, perClass }
      if (body.years) {
        for (const yc of body.years) {
          const y = parseInt(yc.year);
          if (!y) continue;
          const yr = y % 100;
          // yc.classes can be a number (all same size) or an array
          const classList = Array.isArray(yc.classes)
            ? yc.classes.map((pc, i) => ({ num: i + 1, perClass: parseInt(pc) || 30 }))
            : Array.from({ length: parseInt(yc.classes) || 1 }, (_, i) => ({ num: i + 1, perClass: parseInt(yc.perClass) || 30 }));
          for (const cl of classList) {
            for (let seat = 1; seat <= cl.perClass; seat++) {
              const studentId = `${yr}${String(seq).padStart(3,'0')}`;
              seq++;
              if (users.find(u => u.username === studentId)) continue;
              users.push({
                id: uuid(), username: studentId, password: await hp(password), password_plain: rawPassword,
                role: 'student', grade: String(y), class_num: String(cl.num), seat_num: String(seat),
                club: '', committee: '', display_name: studentId, icon: '', created_at: new Date().toISOString()
              });
              created.push(studentId);
            }
          }
        }
      } else {
        const y = parseInt(body.year), c = parseInt(body.classes), p = parseInt(body.perClass);
        if (!y || !c || !p || c < 1 || p > 50) return json({ error: 'パラメータが不正です' }, 400);
        const yr = y % 100;
        for (let cl = 1; cl <= c; cl++) {
          for (let seat = 1; seat <= p; seat++) {
            const studentId = `${yr}${String(seq).padStart(3,'0')}`;
            seq++;
            if (users.find(u => u.username === studentId)) continue;
            users.push({
              id: uuid(), username: studentId, password: await hp(password), password_plain: rawPassword,
              role: 'student', grade: String(y), class_num: String(cl), seat_num: String(seat),
              club: '', committee: '', display_name: studentId, icon: '', created_at: new Date().toISOString()
            });
            created.push(studentId);
          }
        }
      }
      await r2Put(env.DATA, 'users.json', users);
      await auditLog(env, 'batch_create', user.username, { count: created.length, body: JSON.stringify(body) });
      return json({ created: created.length, password: rawPassword, students: created });
    }

    // POST /api/users/batch-delete
    if (path === '/api/users/batch-delete' && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const { ids, grade, class_num } = await request.json();
      let users = await r2Get(env.DATA, 'users.json') || [];
      const toRemove = ids || [];
      let fullMatch = false;
      if (grade) {
        const before = users.length;
        users = users.filter(u => {
          if (u.grade === String(grade) && (!class_num || u.class_num === String(class_num))) {
            if (u.id === user.id) return true;
            if (u.role === 'admin') return true;
            toRemove.push(u.id);
            return false;
          }
          return true;
        });
        fullMatch = before - users.length > 0;
      }
      if (toRemove.length > 0 && !grade) {
        const remSet = new Set(toRemove);
        users = users.filter(u => {
          if (remSet.has(u.id)) {
            if (u.id === user.id) return true;
            if (u.role === 'admin') return true;
            return false;
          }
          return true;
        });
      }
      await r2Put(env.DATA, 'users.json', users);
      await auditLog(env, 'batch_delete', user.username, { count: toRemove.length, grade, class_num });
      return json({ deleted: toRemove.length });
    }

    // ============================================================
    // 4. STATS
    // ============================================================
    if (path === '/api/stats' && method === 'GET') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const users = await r2Get(env.DATA, 'users.json') || [];
      const posts = await r2Get(env.DATA, 'posts.json') || [];
      const byRole = {}; const byGrade = {}; const byClub = {}; const byCommittee = {};
      users.forEach(u => {
        (u.role || '').split(',').forEach(r => { const tr = r.trim(); if (tr) byRole[tr] = (byRole[tr] || 0) + 1; });
        if (u.grade) byGrade[u.grade] = (byGrade[u.grade] || 0) + 1;
        if (u.club) byClub[u.club] = (byClub[u.club] || 0) + 1;
        if (u.committee) byCommittee[u.committee] = (byCommittee[u.committee] || 0) + 1;
      });
      // Lock info
      const locks = await r2Get(env.DATA, 'login_locks.json') || {};
      const lockedCount = Object.keys(locks).length;
      return json({ totalUsers: users.length, totalPosts: posts.length, lockedAccounts: lockedCount, byRole, byGrade, byClub, byCommittee });
    }

    // ============================================================
    // 5. CHAT
    // ============================================================
    if (path === '/api/chat/participants' && method === 'GET') {
      const parts = await r2Get(env.DATA, 'chat_participants.json') || [];
      const users = await r2Get(env.DATA, 'users.json') || [];
      return json(parts.map(u => {
        const pu = users.find(x => x.username === u);
        return { username: u, display_name: (pu && pu.display_name) || u, role: (pu && pu.role) || '', teacher_subject: (pu && pu.teacher_subject) || '' };
      }));
    }

    if (path === '/api/chat/participants' && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const { username } = await request.json();
      if (!username) return json({ error: '必須' }, 400);
      const parts = await r2Get(env.DATA, 'chat_participants.json') || [];
      if (!parts.includes(username)) { parts.push(username); await r2Put(env.DATA, 'chat_participants.json', parts); }
      return json({ ok: true });
    }

    const partDel = path.match(/^\/api\/chat\/participants\/(.+)$/);
    if (partDel && method === 'DELETE') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const parts = await r2Get(env.DATA, 'chat_participants.json') || [];
      await r2Put(env.DATA, 'chat_participants.json', parts.filter(p => p !== decodeURIComponent(partDel[1])));
      return json({ ok: true });
    }

    if ((path === '/api/chat' || path === '/api/chat/messages') && method === 'GET') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const since = parseInt(url.searchParams.get('since')) || 0;
      let msgs = await r2Get(env.DATA, 'chat.json') || [];
      if (since > 0) msgs = msgs.filter(m => new Date(m.created_at).getTime() > since);
      msgs.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
      return json(msgs);
    }

    if (path === '/api/chat/count' && method === 'GET') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const since = parseInt(url.searchParams.get('since')) || 0;
      const msgs = await r2Get(env.DATA, 'chat.json') || [];
      const count = msgs.filter(m => new Date(m.created_at).getTime() > since).length;
      return json({ count });
    }

    if ((path === '/api/chat' || path === '/api/chat/messages') && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const parts = await r2Get(env.DATA, 'chat_participants.json') || [];
      if (!parts.includes(user.username)) return json({ error: '参加者ではありません' }, 403);
      const body = await request.json();
      const msgText = sanitize((body.message || body.text || '').trim());
      const msgs = await r2Get(env.DATA, 'chat.json') || [];
      const msg = {
        id: uuid(), username: user.username, display_name: user.display_name || user.username,
        message: msgText, text: msgText, files: body.files || [],
        created_at: new Date().toISOString(),
        signature: '' // Signature computed below
      };
      // Sign the message for tamper-proofing
      const sigPayload = `${msg.id}:${msg.username}:${msgText}:${msg.created_at}`;
      msg.signature = await hmacSign(sigPayload, env.COOKIE_SECRET);
      msgs.push(msg);
      if (msgs.length > 500) msgs.splice(0, msgs.length - 500);
      await r2Put(env.DATA, 'chat.json', msgs);
      return json(msg, 201);
    }

    const chatDel = path.match(/^\/api\/chat\/([^/]+)$/);
    if (chatDel && method === 'DELETE') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      let msgs = await r2Get(env.DATA, 'chat.json') || [];
      msgs = msgs.filter(m => m.id !== chatDel[1]);
      await r2Put(env.DATA, 'chat.json', msgs);
      return json({ ok: true });
    }

    // ============================================================
    // 5b. PASSWORD RESET
    // ============================================================
    // POST /api/password-reset/request (no auth required)
    if (path === '/api/password-reset/request' && method === 'POST') {
      const { username, teacher } = await request.json();
      if (!username || !teacher) return json({ error: 'ユーザー名と先生を選択してください' }, 400);
      const users = await r2Get(env.DATA, 'users.json') || [];
      const u = users.find(x => x.username === username || x.display_name === username);
      if (!u) return json({ error: 'ユーザーが見つかりません' }, 404);
      const t = users.find(x => x.username === teacher);
      if (!t) return json({ error: '先生が見つかりません' }, 404);
      const reqs = await r2Get(env.DATA, 'password_resets.json') || [];
      const req = {
        id: uuid(), username: u.username, display_name: u.display_name || u.username,
        teacher, teacher_name: t.display_name || t.username,
        status: 'pending', created_at: new Date().toISOString()
      };
      reqs.push(req);
      if (reqs.length > 200) reqs.splice(0, reqs.length - 200);
      await r2Put(env.DATA, 'password_resets.json', reqs);
      await addNotification(env, 'password_reset', `${u.display_name||u.username}さんがパスワード再設定をリクエストしています`, `/user-management.html?tab=password-reset`);
      return json({ id: req.id, status: 'pending' }, 201);
    }

    // GET /api/password-reset/requests (teacher/admin)
    if (path === '/api/password-reset/requests' && method === 'GET') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const reqs = await r2Get(env.DATA, 'password_resets.json') || [];
      const myReqs = reqs.filter(r => r.teacher === user.username || user.role.includes('admin'));
      myReqs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      return json(myReqs.map(r => ({ ...r, fullfilled: r.fullfilled || false })));
    }

    // POST /api/password-reset/fulfill/:id
    const fulfillReq = path.match(/^\/api\/password-reset\/fulfill\/(.+)$/);
    if (fulfillReq && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const { password } = await request.json();
      if (!password || password.length < 6) return json({ error: 'パスワードは6文字以上必要です' }, 400);
      const reqs = await r2Get(env.DATA, 'password_resets.json') || [];
      const req = reqs.find(r => r.id === fulfillReq[1]);
      if (!req) return json({ error: '見つかりません' }, 404);
      if (req.teacher !== user.username && !user.role.includes('admin')) return json({ error: '権限がありません' }, 403);
      if (req.fullfilled) return json({ error: '既に処理済みです' }, 400);
      const users = await r2Get(env.DATA, 'users.json') || [];
      const u = users.find(x => x.username === req.username);
      if (!u) return json({ error: 'ユーザーが見つかりません' }, 404);
      const hashedInput = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', enc(password)))).map(x => x.toString(16).padStart(2, '0')).join('');
      u.password = await hp(hashedInput);
      u.password_plain = password;
      req.fullfilled = true;
      req.new_password_plain = password;
      req.fullfilled_at = new Date().toISOString();
      req.fullfilled_by = user.username;
      await r2Put(env.DATA, 'users.json', users);
      await r2Put(env.DATA, 'password_resets.json', reqs);
      await auditLog(env, 'password_reset_fulfill', user.username, { target: req.username });
      return json({ ok: true, username: req.username });
    }

    // GET /api/password-reset/check/:id (no auth - uses request id as token)
    const checkReq = path.match(/^\/api\/password-reset\/check\/(.+)$/);
    if (checkReq && method === 'GET') {
      const reqs = await r2Get(env.DATA, 'password_resets.json') || [];
      const req = reqs.find(r => r.id === checkReq[1]);
      if (!req) return json({ error: '見つかりません' }, 404);
      return json({
        status: req.fullfilled ? 'done' : 'pending',
        new_password: req.fullfilled ? req.new_password_plain : null,
        username: req.username
      });
    }

    // Notify homeroom teacher on 5 failed login attempts
    async function notifyHomeroomOnFail(env, username) {
      const locks = await r2Get(env.DATA, 'login_locks.json') || {};
      const lock = locks[username];
      if (lock && lock.count >= 5 && lock.count % 5 === 0) {
        const users = await r2Get(env.DATA, 'users.json') || [];
        const u = users.find(x => x.username === username);
        if (!u || !u.grade || !u.class_num) return;
        const homeroomTeacher = users.find(t =>
          t.role && t.role.includes('teacher') && t.teacher_homeroom && t.teacher_grades && t.teacher_grades.includes(u.grade)
        );
        if (homeroomTeacher) {
          await addNotification(env, 'login_fail', `${u.display_name||u.username}さんがログインに${lock.count}回失敗しました`, `/user-management.html`);
        }
      }
    }

    // ============================================================
    // 5c. DIRECT MESSAGES (teacher/admin → anyone, no student→student)
    // ============================================================
    const dmPrefix = '/api/dm';
    // POST /api/dm/send
    if (path === dmPrefix + '/send' && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const userRole = (user.role || '');
      const isStaff = ['admin', 'teacher'].some(r => userRole.includes(r));
      const { to, message } = await request.json();
      if (!to || !message || !message.trim()) return json({ error: '宛先とメッセージは必須です' }, 400);
      if (to === user.username) return json({ error: '自分には送信できません' }, 400);
      const users = await r2Get(env.DATA, 'users.json') || [];
      const recipient = users.find(u => u.username === to);
      if (!recipient) return json({ error: 'ユーザーが見つかりません' }, 404);
      const recipIsStaff = ['admin', 'teacher'].some(r => (recipient.role || '').includes(r));
      // Strict rule: students can NEVER DM students
      if (!isStaff && !recipIsStaff) return json({ error: '生徒同士のメッセージは禁止されています' }, 403);
      if (!isStaff) {
        // Students can only reply to teachers who have DMed them first
        const msgs = await r2Get(env.DATA, 'dm_messages.json') || [];
        const hasExisting = msgs.some(m => (m.from === to && m.to === user.username) || (m.from === user.username && m.to === to));
        if (!hasExisting) return json({ error: 'この先生との会話はありません' }, 403);
      }
      const msgs = await r2Get(env.DATA, 'dm_messages.json') || [];
      const dm = {
        id: uuid(), from: user.username, to,
        message: sanitize(message.trim()),
        read: false, created_at: new Date().toISOString()
      };
      msgs.push(dm);
      if (msgs.length > 2000) msgs.splice(0, msgs.length - 2000);
      await r2Put(env.DATA, 'dm_messages.json', msgs);
      return json(dm, 201);
    }

    // GET /api/dm/conversations
    if (path === dmPrefix + '/conversations' && method === 'GET') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const msgs = await r2Get(env.DATA, 'dm_messages.json') || [];
      const convUsers = new Set();
      msgs.forEach(m => {
        if (!m.group_id) {
          if (m.from === user.username) convUsers.add(m.to);
          if (m.to === user.username) convUsers.add(m.from);
        }
      });
      const users = await r2Get(env.DATA, 'users.json') || [];
      const convs = [];
      convUsers.forEach(u => {
        const uData = users.find(x => x.username === u);
        const userMsgs = msgs.filter(m => !m.group_id && ((m.from === user.username && m.to === u) || (m.from === u && m.to === user.username)));
        userMsgs.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
        const last = userMsgs[userMsgs.length - 1];
        const unread = userMsgs.filter(m => m.to === user.username && !m.read).length;
        convs.push({
          type: 'dm', id: u, username: u, display_name: (uData && uData.display_name) || u,
          role: (uData && uData.role) || '',
          last_message: last ? last.message : '',
          last_time: last ? last.created_at : '',
          unread
        });
      });
      // Add group conversations
      const groups = await r2Get(env.DATA, 'dm_groups.json') || [];
      const myGroups = groups.filter(g => g.members.includes(user.username));
      myGroups.forEach(g => {
        const gm = msgs.filter(m => m.group_id === g.id);
        gm.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
        const last = gm[gm.length - 1];
        const unread = gm.filter(m => m.from !== user.username && (!m.read_by || !m.read_by.includes(user.username))).length;
        convs.push({
          type: 'group', id: g.id, name: g.name, members: g.members,
          last_message: last ? last.message : '',
          last_time: last ? last.created_at : '',
          unread, created_by: g.created_by
        });
      });
      convs.sort((a, b) => new Date(b.last_time || 0) - new Date(a.last_time || 0));
      return json(convs);
    }

    // GET /api/dm/messages/:username
    const dmConv = path.match(/^\/api\/dm\/messages\/(.+)$/);
    if (dmConv && method === 'GET') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const msgs = await r2Get(env.DATA, 'dm_messages.json') || [];
      const conv = msgs.filter(m =>
        (m.from === user.username && m.to === decodeURIComponent(dmConv[1])) ||
        (m.from === decodeURIComponent(dmConv[1]) && m.to === user.username)
      );
      conv.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
      return json(conv);
    }

    // POST /api/dm/read/:username
    const dmRead = path.match(/^\/api\/dm\/read\/(.+)$/);
    if (dmRead && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const msgs = await r2Get(env.DATA, 'dm_messages.json') || [];
      let changed = false;
      msgs.forEach(m => {
        if (m.to === user.username && m.from === decodeURIComponent(dmRead[1]) && !m.read) {
          m.read = true; changed = true;
        }
      });
      if (changed) await r2Put(env.DATA, 'dm_messages.json', msgs);
      return json({ ok: true });
    }

    // GET /api/dm/unread-count
    if (path === dmPrefix + '/unread-count' && method === 'GET') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const msgs = await r2Get(env.DATA, 'dm_messages.json') || [];
      const dms = msgs.filter(m => m.to === user.username && !m.read).length;
      const groups = await r2Get(env.DATA, 'dm_groups.json') || [];
      const myGroups = groups.filter(g => g.members.includes(user.username));
      let groupUnread = 0;
      myGroups.forEach(g => { groupUnread += msgs.filter(m => m.group_id === g.id && m.from !== user.username && !m.read_by && !m.read_by?.includes(user.username)).length; });
      return json({ count: dms + groupUnread });
    }

    // ============================================================
    // 5c. GROUP DM (teacher/admin creates, students join)
    // ============================================================
    // POST /api/dm/groups - Create group
    if (path === dmPrefix + '/groups' && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const userRole = (user.role || '');
      const isStaff = ['admin', 'teacher'].some(r => userRole.includes(r));
      if (!isStaff) return json({ error: '先生・管理者のみグループ作成できます' }, 403);
      const { name, members } = await request.json();
      if (!name || !name.trim()) return json({ error: 'グループ名は必須です' }, 400);
      const mems = Array.isArray(members) ? members : [];
      if (!mems.includes(user.username)) mems.unshift(user.username);
      if (mems.length < 2) return json({ error: 'メンバーが足りません' }, 400);
      const users = await r2Get(env.DATA, 'users.json') || [];
      const valid = mems.every(m => users.find(u => u.username === m));
      if (!valid) return json({ error: '存在しないユーザーが含まれています' }, 400);
      const groups = await r2Get(env.DATA, 'dm_groups.json') || [];
      const grp = { id: uuid(), name: sanitize(name.trim()), members: mems, created_by: user.username, created_at: new Date().toISOString() };
      groups.push(grp);
      await r2Put(env.DATA, 'dm_groups.json', groups);
      return json(grp, 201);
    }

    // GET /api/dm/groups - List groups
    if (path === dmPrefix + '/groups' && method === 'GET') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const groups = await r2Get(env.DATA, 'dm_groups.json') || [];
      const myGroups = groups.filter(g => g.members.includes(user.username));
      const users = await r2Get(env.DATA, 'users.json') || [];
      const msgs = await r2Get(env.DATA, 'dm_messages.json') || [];
      const result = myGroups.map(g => {
        const gm = msgs.filter(m => m.group_id === g.id);
        gm.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
        const last = gm[gm.length - 1];
        const unread = gm.filter(m => m.from !== user.username && (!m.read_by || !m.read_by.includes(user.username))).length;
        const memberNames = g.members.map(m => { const u = users.find(x => x.username === m); return (u && u.display_name) || m; });
        return { id: g.id, name: g.name, members: g.members, member_names: memberNames, created_by: g.created_by, last_message: last ? last.message : '', last_time: last ? last.created_at : '', unread };
      });
      result.sort((a, b) => new Date(b.last_time || 0) - new Date(a.last_time || 0));
      return json(result);
    }

    // GET /api/dm/groups/:id
    const grpGet = path.match(/^\/api\/dm\/groups\/([^/]+)$/);
    if (grpGet && method === 'GET') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const groups = await r2Get(env.DATA, 'dm_groups.json') || [];
      const g = groups.find(x => x.id === grpGet[1]);
      if (!g) return json({ error: '見つかりません' }, 404);
      if (!g.members.includes(user.username)) return json({ error: 'メンバーではありません' }, 403);
      return json(g);
    }

    // POST /api/dm/groups/:id/add - Add members
    const grpAdd = path.match(/^\/api\/dm\/groups\/([^/]+)\/add$/);
    if (grpAdd && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const userRole = (user.role || '');
      const isStaff = ['admin', 'teacher'].some(r => userRole.includes(r));
      if (!isStaff) return json({ error: '先生・管理者のみ操作できます' }, 403);
      const groups = await r2Get(env.DATA, 'dm_groups.json') || [];
      const g = groups.find(x => x.id === grpAdd[1]);
      if (!g) return json({ error: '見つかりません' }, 404);
      const { members } = await request.json();
      if (!Array.isArray(members) || !members.length) return json({ error: '追加するユーザーが必要です' }, 400);
      const users = await r2Get(env.DATA, 'users.json') || [];
      members.forEach(m => { if (!g.members.includes(m) && users.find(u => u.username === m)) g.members.push(m); });
      await r2Put(env.DATA, 'dm_groups.json', groups);
      return json({ ok: true, members: g.members });
    }

    // POST /api/dm/groups/:id/remove - Remove members
    const grpRemove = path.match(/^\/api\/dm\/groups\/([^/]+)\/remove$/);
    if (grpRemove && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const userRole = (user.role || '');
      const isStaff = ['admin', 'teacher'].some(r => userRole.includes(r));
      if (!isStaff) return json({ error: '先生・管理者のみ操作できます' }, 403);
      const groups = await r2Get(env.DATA, 'dm_groups.json') || [];
      const g = groups.find(x => x.id === grpRemove[1]);
      if (!g) return json({ error: '見つかりません' }, 404);
      const { members } = await request.json();
      if (!Array.isArray(members) || !members.length) return json({ error: '削除するユーザーが必要です' }, 400);
      g.members = g.members.filter(m => !members.includes(m));
      await r2Put(env.DATA, 'dm_groups.json', groups);
      return json({ ok: true, members: g.members });
    }

    // POST /api/dm/groups/:id/send - Send message to group
    const grpSend = path.match(/^\/api\/dm\/groups\/([^/]+)\/send$/);
    if (grpSend && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const groups = await r2Get(env.DATA, 'dm_groups.json') || [];
      const g = groups.find(x => x.id === grpSend[1]);
      if (!g) return json({ error: '見つかりません' }, 404);
      if (!g.members.includes(user.username)) return json({ error: 'メンバーではありません' }, 403);
      const { message } = await request.json();
      if (!message || !message.trim()) return json({ error: 'メッセージは必須です' }, 400);
      const msgs = await r2Get(env.DATA, 'dm_messages.json') || [];
      const dm = {
        id: uuid(), from: user.username, group_id: g.id,
        message: sanitize(message.trim()),
        read_by: [user.username], created_at: new Date().toISOString()
      };
      msgs.push(dm);
      if (msgs.length > 5000) msgs.splice(0, msgs.length - 5000);
      await r2Put(env.DATA, 'dm_messages.json', msgs);
      return json(dm, 201);
    }

    // GET /api/dm/groups/:id/messages
    const grpMsgs = path.match(/^\/api\/dm\/groups\/([^/]+)\/messages$/);
    if (grpMsgs && method === 'GET') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const groups = await r2Get(env.DATA, 'dm_groups.json') || [];
      const g = groups.find(x => x.id === grpMsgs[1]);
      if (!g) return json({ error: '見つかりません' }, 404);
      if (!g.members.includes(user.username)) return json({ error: 'メンバーではありません' }, 403);
      const msgs = await r2Get(env.DATA, 'dm_messages.json') || [];
      const conv = msgs.filter(m => m.group_id === g.id);
      conv.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
      // Mark as read
      conv.forEach(m => {
        if (m.from !== user.username) {
          if (!m.read_by) m.read_by = [];
          if (!m.read_by.includes(user.username)) m.read_by.push(user.username);
        }
      });
      await r2Put(env.DATA, 'dm_messages.json', msgs);
      return json(conv);
    }

    // ============================================================
    // 6. SCHEDULES
    // ============================================================
    if (path === '/api/schedules' && method === 'GET') {
      const data = await r2Get(env.DATA, 'schedules.json') || [];
      return json(data);
    }

    if (path === '/api/schedules' && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const { title, date, time, location, club, description } = await request.json();
      if (!title || !date) return json({ error: '必須' }, 400);
      const data = await r2Get(env.DATA, 'schedules.json') || [];
      data.push({ id: uuid(), title: sanitize(title.trim()), date, time: time || '', location: location || '', club: club || '', description: sanitize(description || ''), created_at: new Date().toISOString(), created_by: user.username });
      if (data.length > 500) data.splice(0, data.length - 500);
      await r2Put(env.DATA, 'schedules.json', data);
      return json(data[data.length - 1], 201);
    }

    const schedDel = path.match(/^\/api\/schedules\/([^/]+)$/);
    if (schedDel && method === 'DELETE') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      let data = await r2Get(env.DATA, 'schedules.json') || [];
      data = data.filter(e => e.id !== schedDel[1]);
      await r2Put(env.DATA, 'schedules.json', data);
      return json({ ok: true });
    }

    // ============================================================
    // 6b. TEACHER SCHEDULE (period-based weekly timetable)
    // ============================================================
    const PERIOD_TIMES = [
      { period: 1, start: 500, end: 570 },   // 8:40-9:30 (minutes from midnight)
      { period: 2, start: 580, end: 650 },   // 9:40-10:30
      { period: 3, start: 660, end: 730 },   // 10:40-11:30
      { period: 4, start: 740, end: 810 },   // 11:40-12:30
      { period: 5, start: 850, end: 920 },   // 13:30-14:20 (after lunch: 12:30-13:30)
      { period: 6, start: 930, end: 1000 }   // 14:30-15:20
    ];

    // POST /api/teacher-schedule - Save teacher's weekly schedule
    if (path === '/api/teacher-schedule' && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const { schedule } = await request.json();
      if (!Array.isArray(schedule)) return json({ error: 'スケジュールが必要です' }, 400);
      const valid = schedule.every(s => s.day_of_week >= 0 && s.day_of_week <= 6 && s.period >= 1 && s.period <= 7 && s.subject);
      if (!valid) return json({ error: '不正なデータです' }, 400);
      const schedules = await r2Get(env.DATA, 'teacher_schedules.json') || [];
      const existing = schedules.find(s => s.teacher_username === user.username);
      if (existing) { existing.schedule = schedule; }
      else { schedules.push({ id: uuid(), teacher_username: user.username, schedule }); }
      await r2Put(env.DATA, 'teacher_schedules.json', schedules);
      return json({ ok: true });
    }

    // GET /api/teacher-schedule - Get my schedule
    if (path === '/api/teacher-schedule' && method === 'GET') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const schedules = await r2Get(env.DATA, 'teacher_schedules.json') || [];
      const s = schedules.find(x => x.teacher_username === user.username);
      return json(s ? s.schedule : []);
    }

    // GET /api/teacher-schedule/next - Get next class info
    if (path === '/api/teacher-schedule/next' && method === 'GET') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const schedules = await r2Get(env.DATA, 'teacher_schedules.json') || [];
      const s = schedules.find(x => x.teacher_username === user.username);
      if (!s || !s.schedule.length) return json({ next: null, message: 'スケジュールが設定されていません' });
      const now = new Date();
      const jst = new Date(now.getTime() + 9 * 3600000);
      const day = jst.getUTCDay();
      const mins = jst.getUTCHours() * 60 + jst.getUTCMinutes();
      const todayClasses = s.schedule.filter(e => e.day_of_week === day).sort((a, b) => a.period - b.period);
      if (!todayClasses.length) return json({ next: null, message: '今日は授業がありません' });
      // Find next class
      for (const cls of todayClasses) {
        const pt = PERIOD_TIMES.find(p => p.period === cls.period);
        if (!pt) continue;
        if (mins < pt.start) {
          const diff = pt.start - mins;
          return json({ next: { period: cls.period, subject: cls.subject, class_name: cls.class_name || '', startsIn: diff, startsInMin: Math.floor(diff) }, message: `${cls.subject}${cls.class_name?'('+cls.class_name+')':''}が${Math.floor(diff)}分後にあります` });
        }
      }
      return json({ next: null, message: '今日の授業は全て終了しました' });
    }
    // ============================================================
    if (path === '/api/yearly-schedule' && method === 'GET') {
      const data = await r2Get(env.DATA, 'yearly_schedule.json') || [];
      return json(data);
    }

    if (path === '/api/yearly-schedule' && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const { title, date, month, category, description } = await request.json();
      if (!title || !date || !month || !category) return json({ error: '必須' }, 400);
      const data = await r2Get(env.DATA, 'yearly_schedule.json') || [];
      data.push({ id: uuid(), title: sanitize(title.trim()), date, month, category, description: sanitize(description || ''), created_at: new Date().toISOString(), created_by: user.username });
      if (data.length > 500) data.splice(0, data.length - 500);
      await r2Put(env.DATA, 'yearly_schedule.json', data);
      return json(data[data.length - 1], 201);
    }

    const yearDel = path.match(/^\/api\/yearly-schedule\/([^/]+)$/);
    if (yearDel && method === 'DELETE') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      let data = await r2Get(env.DATA, 'yearly_schedule.json') || [];
      data = data.filter(e => e.id !== yearDel[1]);
      await r2Put(env.DATA, 'yearly_schedule.json', data);
      return json({ ok: true });
    }

    // ============================================================
    // 9. CLUB QUESTIONS (AES encrypted, no notification)
    // ============================================================
    const AES_KEY = await deriveAesKey(env.COOKIE_SECRET || 'default-club-key', 'club-aes-salt');
    if (path === '/api/club-questions' && method === 'GET') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const allQ = await r2Get(env.DATA, 'club_questions.json') || [];
      const userRoles = (user.role || '').split(',').map(r => r.trim());
      let filtered;
      if (userRoles.includes('admin') || userRoles.includes('teacher')) {
        filtered = allQ; // Can view all
      } else if (userRoles.some(r => ['president','vice-president','chairperson'].includes(r))) {
        // Can view questions for their own club/committee
        const users = await r2Get(env.DATA, 'users.json') || [];
        const u = users.find(x => x.id === user.id);
        if (!u) filtered = [];
        else filtered = allQ.filter(q => q.club === u.club || (userRoles.includes('chairperson') && q.club === u.committee));
      } else {
        // Students see only their own questions
        filtered = allQ.filter(q => q.from_username === user.username);
      }
      // Decrypt for owners/repliers
      for (const q of filtered) {
        if (q.encrypted && (q.from_username === user.username || userRoles.includes('admin') || userRoles.includes('teacher') || userRoles.includes('president') || userRoles.includes('vice-president') || userRoles.includes('chairperson'))) {
          try { q.question = await aesDecrypt(q.encrypted, AES_KEY); } catch(e) { q.question = '[復号できません]'; }
        }
        if (q.reply_encrypted && q.reply) {
          try { q.reply = await aesDecrypt(q.reply_encrypted, AES_KEY); } catch(e) { q.reply = '[復号できません]'; }
        }
      }
      return json(filtered.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)));
    }

    if (path === '/api/club-questions' && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const { question, club } = await request.json();
      if (!question || !club) return json({ error: '内容と送信先は必須です' }, 400);
      const users = await r2Get(env.DATA, 'users.json') || [];
      const u = users.find(x => x.id === user.id);
      if (!u || (u.club !== club && u.committee !== club)) return json({ error: '自分の所属する部活・委員会のみ質問できます' }, 403);
      const encrypted = await aesEncrypt(question, AES_KEY);
      const allQ = await r2Get(env.DATA, 'club_questions.json') || [];
      const entry = {
        id: uuid(), encrypted, club, from_username: user.username,
        from_display: user.display_name || user.username,
        created_at: new Date().toISOString(),
        answered: false
      };
      allQ.push(entry);
      if (allQ.length > 500) allQ.splice(0, allQ.length - 500);
      await r2Put(env.DATA, 'club_questions.json', allQ);
      // No notification
      return json({ status: 'ok', id: entry.id });
    }

    // POST /api/club-questions/:id/reply
    const qReply = path.match(/^\/api\/club-questions\/([^/]+)\/reply$/);
    if (qReply && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const { reply } = await request.json();
      if (!reply || !reply.trim()) return json({ error: '返信を入力してください' }, 400);
      const userRoles = (user.role || '').split(',').map(r => r.trim());
      const allQ = await r2Get(env.DATA, 'club_questions.json') || [];
      const q = allQ.find(x => x.id === qReply[1]);
      if (!q) return json({ error: '見つかりません' }, 404);

      // Determine if q.club is a committee or a club
      const isCommittee = COMM_CATS.includes(q.club);
      // Check reply permission
      if (userRoles.includes('admin') || userRoles.includes('teacher')) return json({ error: '管理者・先生は回答できません' }, 403);
      const users = await r2Get(env.DATA, 'users.json') || [];
      const u = users.find(x => x.id === user.id);
      if (!u) return json({ error: '見つかりません' }, 404);
      if (isCommittee) {
        // Chairperson of that committee can reply
        if (!userRoles.includes('chairperson') || u.committee !== q.club) return json({ error: '権限がありません' }, 403);
      } else {
        // President/vice-president of that club can reply
        if (!(userRoles.includes('president') || userRoles.includes('vice-president')) || u.club !== q.club) return json({ error: '権限がありません' }, 403);
      }

      q.reply_encrypted = await aesEncrypt(reply, AES_KEY);
      q.reply = reply;
      q.answered = true;
      q.answered_at = new Date().toISOString();
      q.answered_by = user.username;
      await r2Put(env.DATA, 'club_questions.json', allQ);
      return json({ ok: true });
    }

    const qDel = path.match(/^\/api\/club-questions\/([^/]+)$/);
    if (qDel && method === 'DELETE') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      let allQ = await r2Get(env.DATA, 'club_questions.json') || [];
      allQ = allQ.filter(x => x.id !== qDel[1]);
      await r2Put(env.DATA, 'club_questions.json', allQ);
      return json({ ok: true });
    }

    // ============================================================
    // 10. REACTIONS
    // ============================================================
    const reactionsMatch = path.match(/^\/api\/reactions\/([^/]+)\/([^/]+)$/);
    if (path === '/api/reactions' && method === 'GET') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      return json({ ok: true, message: 'リアクションAPI稼働中' });
    }

    if (path === '/api/reactions' && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const { targetType, targetId, reaction } = await request.json();
      if (!targetType || !targetId || !reaction) return json({ error: '必須' }, 400);
      if (!REACTION_TYPES.includes(reaction)) return json({ error: '不正なリアクション' }, 400);
      const key = `reactions_${targetType}`;
      const data = await r2Get(env.DATA, key) || {};
      if (!data[targetId]) data[targetId] = {};
      const users = data[targetId][reaction] || [];
      const idx = users.indexOf(user.username);
      if (idx >= 0) { users.splice(idx, 1); } else { users.push(user.username); }
      data[targetId][reaction] = users;
      // Remove empty entries
      if (users.length === 0) delete data[targetId][reaction];
      if (Object.keys(data[targetId]).length === 0) delete data[targetId];
      await r2Put(env.DATA, key, data);
      return json({ ok: true, reactions: data[targetId] || {} });
    }

    if (reactionsMatch && method === 'GET') {
      const key = `reactions_${reactionsMatch[1]}`;
      const data = await r2Get(env.DATA, key) || {};
      return json(data[reactionsMatch[2]] || {});
    }

    // ============================================================
    // 11. NOTIFICATIONS
    // ============================================================
    // POST /api/notifications (admin only - for diagnostics alerts)
    if (path === '/api/notifications' && method === 'POST') {
      authErr = requireAuth(user, ['admin']);
      if (authErr) return authErr;
      const { type, message, link } = await request.json();
      if (!message) return json({ error: 'メッセージ必須' }, 400);
      await addNotification(env, type || 'diagnostics', sanitize(message.trim()), link || '');
      return json({ ok: true });
    }

    if (path === '/api/notifications' && method === 'GET') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const notifs = await r2Get(env.DATA, 'notifications.json') || [];
      return json(notifs.filter(n => !n.dismissed).slice(0, 50));
    }

    if (path === '/api/notifications/count' && method === 'GET') {
      const notifs = await r2Get(env.DATA, 'notifications.json') || [];
      const count = notifs.filter(n => !n.dismissed).length;
      return json({ count });
    }

    const notifDismiss = path.match(/^\/api\/notifications\/([^/]+)\/dismiss$/);
    if (notifDismiss && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const notifs = await r2Get(env.DATA, 'notifications.json') || [];
      const n = notifs.find(x => x.id === notifDismiss[1]);
      if (n) { n.dismissed = true; await r2Put(env.DATA, 'notifications.json', notifs); }
      return json({ ok: true });
    }

    // ============================================================
    // 12. TAB CONFIG
    // ============================================================
    if (path === '/api/tabs' && method === 'GET') {
      const tabs = await r2Get(env.DATA, 'tab_config.json') || DEFAULT_TABS;
      return json(tabs);
    }

    if (path === '/api/tabs' && method === 'PUT') {
      authErr = requireAuth(user, ['admin']);
      if (authErr) return authErr;
      const { tabs } = await request.json();
      if (!Array.isArray(tabs)) return json({ error: '配列が必要です' }, 400);
      // Validate structure
      for (const t of tabs) {
        if (!t.l) return json({ error: '各タブにラベルが必要です' }, 400);
        if (!t.g && !t.n) return json({ error: '各タブに名前が必要です' }, 400);
      }
      await r2Put(env.DATA, 'tab_config.json', tabs);
      await auditLog(env, 'update_tabs', user.username, { count: tabs.length });
      return json({ ok: true });
    }

    // ============================================================
    // 12b. WBGT from JMA AMeDAS (埼玉県入間市 → 所沢 43266)
    // ============================================================
    if (path === '/api/wbgt' && method === 'GET') {
      try {
        const jst = new Date(Date.now() + 9 * 3600000);
        let jmaData, ts;
        for (let fallback = 0; fallback < 12; fallback++) {
          const t = new Date(jst.getTime() - fallback * 600000);
          const y = t.getUTCFullYear();
          const m = String(t.getUTCMonth() + 1).padStart(2, '0');
          const d = String(t.getUTCDate()).padStart(2, '0');
          const h = String(t.getUTCHours()).padStart(2, '0');
          const min = String(Math.floor(t.getUTCMinutes() / 10) * 10).padStart(2, '0');
          ts = `${y}${m}${d}${h}${min}00`;
          const resp = await fetch(`https://www.jma.go.jp/bosai/amedas/data/map/${ts}.json`, { headers: { 'User-Agent': 'SchoolBoard/1.0' } });
          if (resp.ok) { jmaData = await resp.json(); break; }
        }
        if (!jmaData) return json({ error: 'JMA data unavailable' }, 502);
        const st = jmaData['43266'];
        if (!st || !st.temp || !st.humidity) {
          return json({ error: 'Station data unavailable', ts }, 502);
        }
        const temp = st.temp[0];
        const humidity = st.humidity[0];
        const e = (humidity / 100) * 6.105 * Math.exp(17.27 * temp / (temp + 237.3));
        const wbgt = 0.567 * temp + 0.393 * e + 3.94;
        const rounded = Math.round(wbgt * 10) / 10;
        const levels = [
          { max: 21, label: '注意', advice: '適度に水分補給' },
          { max: 25, label: '警戒', advice: '積極的に水分補給' },
          { max: 28, label: '厳重警戒', advice: '積極的に休息' },
          { max: 31, label: '危険', advice: '激しい運動は中止' },
          { max: 99, label: '極度危険', advice: '運動は原則中止' },
        ];
        const lv = levels.find(l => rounded < l.max) || levels[levels.length - 1];
        return json({ wbgt: rounded, temp, humidity, label: lv.label, advice: lv.advice, ts });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ============================================================
    // 13. DISASTER
    // ============================================================
    if (path === '/api/disaster-info' && method === 'GET') {
      const data = await r2Get(env.DATA, 'disaster_info.json') || { message: '', level: 'info', active: false };
      return json(data);
    }

    if (path === '/api/disaster-info' && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const { message, level } = await request.json();
      if (!message || !level) return json({ error: '必須' }, 400);
      if (!['info', 'warning', 'danger'].includes(level)) return json({ error: '不正なレベル' }, 400);
      const data = { message: sanitize(message), level, active: true, updated_by: user.username, updated_at: new Date().toISOString() };
      await r2Put(env.DATA, 'disaster_info.json', data);
      return json(data);
    }

    if (path === '/api/disaster-info/clear' && method === 'POST') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const data = { message: '', level: 'info', active: false, updated_by: user.username, updated_at: new Date().toISOString() };
      await r2Put(env.DATA, 'disaster_info.json', data);
      return json(data);
    }

    // ============================================================
    // 14. AUDIT LOG
    // ============================================================
    if (path === '/api/audit' && method === 'GET') {
      authErr = requireAuth(user, ['admin']);
      if (authErr) return authErr;
      const log = await r2Get(env.DATA, 'audit.json') || [];
      const limit = Math.min(parseInt(url.searchParams.get('limit')) || 100, 200);
      return json(log.slice(0, limit));
    }

    // ============================================================
    // 15. UPLOAD
    // ============================================================
    if (path === '/api/upload' && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const fd = await request.formData();
      const file = fd.get('file');
      if (!file || !file.size) return json({ error: 'ファイルが必要です' }, 400);
      const ext = file.name.split('.').pop();
      const key = 'uploads/' + uuid() + '.' + ext;
      await env.DATA.put(key, file.stream(), { httpMetadata: { contentType: file.type } });
      return json({ url: '/api/files/' + key, name: file.name, type: file.type });
    }

    const filePath = path.match(/^\/api\/files\/(.+)$/);
    if (filePath && method === 'GET') {
      const obj = await env.DATA.get(filePath[1]);
      if (!obj) return new Response('Not found', { status: 404 });
      const headers = { 'Cache-Control': 'public, max-age=31536000' };
      if (obj.httpMetadata?.contentType) headers['Content-Type'] = obj.httpMetadata.contentType;
      return new Response(obj.body, { headers });
    }

    // ============================================================
    // 16. PUSH NOTIFICATIONS
    // ============================================================
    if (path === '/api/push/subscribe' && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const sub = await request.json();
      let subs = await r2Get(env.DATA, 'push_subs.json') || [];
      subs = subs.filter(s => s.username !== user.username);
      subs.push({ ...sub, username: user.username, createdAt: new Date().toISOString() });
      await r2Put(env.DATA, 'push_subs.json', subs);
      return json({ ok: true });
    }
    if (path === '/api/push/unsubscribe' && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      let subs = await r2Get(env.DATA, 'push_subs.json') || [];
      subs = subs.filter(s => s.username !== user.username);
      await r2Put(env.DATA, 'push_subs.json', subs);
      return json({ ok: true });
    }
    if (path === '/api/push/subscriptions' && method === 'GET') {
      authErr = requireAuth(user, ['admin', 'teacher']);
      if (authErr) return authErr;
      const subs = await r2Get(env.DATA, 'push_subs.json') || [];
      return json(subs);
    }

    // ============================================================
    // 17. GEMINI
    // ============================================================
    if (path === '/api/gemini/ask' && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const { question, image } = await request.json();
      if ((!question || !question.trim()) && !image) return json({ error: '質問または画像を入力してください' }, 400);
      if (image) {
        authErr = requireAuth(user, ['admin', 'teacher']);
        if (authErr) return authErr;
      }
      if (env.RENDER_GEMINI_URL && !image) {
        try {
          const resp = await fetch(env.RENDER_GEMINI_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': request.headers.get('Authorization') || '' },
            body: JSON.stringify({ question })
          });
          if (resp.ok) { const result = await resp.json(); return json(result); }
        } catch(e) { /* fall through */ }
      }
      const apiKey = env.GEMINI_API_KEY;
      if (!apiKey) return json({ error: 'Gemini API キーが設定されていません' }, 503);
      const yearlyData = await r2Get(env.DATA, 'yearly_schedule.json') || [];
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
      if (!geminiResp.ok) return json({ error: result.error?.message || 'Gemini API エラー' }, 500);
      const answer = result.candidates?.[0]?.content?.parts?.[0]?.text || '回答を生成できませんでした';
      return json({ answer });
    }

    // ============================================================
    // 17. MIGRATE
    // ============================================================
    if (path === '/api/migrate' && method === 'POST') {
      const { key, data } = await request.json();
      if (key !== (env.MIGRATE_KEY || 'migrate2026')) return json({ error: 'キーが違います' }, 403);
      if (!data || typeof data !== 'object') return json({ error: 'データが必要です' }, 400);
      const results = {};
      for (const [filename, content] of Object.entries(data)) {
        await r2Put(env.DATA, filename, content);
        results[filename] = 'ok';
      }
      return json({ results });
    }

    // ============================================================
    // 18. STATIC FILE UPLOAD (base64 → R2)
    // ============================================================
    if (path === '/api/static-upload' && method === 'POST') {
      const authErr = requireAuth(user, ['admin']);
      if (authErr) return authErr;
      const { filename, content } = await request.json();
      if (!filename || !content) return json({ error: 'filename と content が必要です' }, 400);
      let decoded;
      try { decoded = atob(content); } catch(e) { return json({ error: 'Base64 デコードエラー' }, 400); }
      const decodedBytes = new Uint8Array(decoded.length);
      for (let i = 0; i < decoded.length; i++) decodedBytes[i] = decoded.charCodeAt(i);
      const ext = filename.includes('.') ? filename.split('.').pop() : 'html';
      const mimeMap = { 'html': 'text/html; charset=utf-8', 'js': 'application/javascript; charset=utf-8', 'css': 'text/css; charset=utf-8', 'json': 'application/json' };
      const contentType = mimeMap[ext] || 'text/plain; charset=utf-8';
      await env.DATA.put('static/' + filename, decodedBytes, { httpMetadata: { contentType } });
      await auditLog(env, 'static_upload', user.username, { filename });
      return json({ ok: true, filename });
    }

    // ============================================================
    // 18. PUSH SUBSCRIPTIONS (R2 persistence for Render)
    // ============================================================
    if (path === '/api/push/subs' && method === 'GET') {
      const subs = await r2Get(env.DATA, 'push_subs.json') || [];
      return json(subs);
    }

    if (path === '/api/push/subs' && method === 'POST') {
      const key = request.headers.get('X-Auth-Key');
      if (key !== (env.MIGRATE_KEY || 'migrate2026')) return json({ error: 'forbidden' }, 403);
      const subs = await request.json();
      await r2Put(env.DATA, 'push_subs.json', subs);
      return json({ ok: true, count: subs.length });
    }

    // ============================================================
    // 18c. PUSH NOTIFY (send push notifications to subscribers)
    // ============================================================
    if (path === '/api/push/notify' && method === 'POST') {
      authErr = requireAuth(user);
      if (authErr) return authErr;
      const {category, title, body, url, excludeUser} = await request.json();
      // For now, just log and return ok
      await auditLog(env, 'push_notify', user.username, {category, title, body, url, excludeUser});
      return json({ok: true});
    }

    // ============================================================
    // 18d. ADMIN UPDATE NOTIFY (send system update notification to all subscribers)
    // ============================================================
    if (path === '/api/admin/notify-update' && method === 'POST') {
      authErr = requireAuth(user, ['admin']);
      if (authErr) return authErr;
      const {title, body} = await request.json();
      if (!title) return json({error: 'タイトルは必須です'}, 400);
      // Store the notification in R2 for history (optional)
      const notifications = await r2Get(env.DATA, 'update-notifications.json') || [];
      notifications.unshift({id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2), title, body, sent_at: new Date().toISOString(), sent_by: user.username});
      if (notifications.length > 50) notifications.length = 50;
      await r2Put(env.DATA, 'update-notifications.json', notifications);
      await auditLog(env, 'admin_update_notify', user.username, {title, body});
      // TODO: Implement actual push notification sending here
      return json({ok: true});
    }

    // ============================================================
    // 18b. VAPID KEYS (persist across Render deploys)
    // ============================================================
    if (path === '/api/vapid-keys' && method === 'GET') {
      const keys = await r2Get(env.DATA, 'vapid_keys.json');
      return json(keys || { error: 'no keys' });
    }
    if (path === '/api/vapid-keys' && method === 'POST') {
      const key = request.headers.get('X-Auth-Key');
      if (key !== (env.MIGRATE_KEY || 'migrate2026')) return json({ error: 'forbidden' }, 403);
      const keys = await request.json();
      await r2Put(env.DATA, 'vapid_keys.json', keys);
      return json({ ok: true });
    }

    // ============================================================
    // 19. STATIC FILES (serve from R2)
    // ============================================================
    const staticPath = 'static' + (path === '/' ? '/01index.html' : path);
    const staticObj = await env.DATA.get(staticPath).catch(() => null);
    if (staticObj) {
      const headers = { 'Content-Type': staticObj.httpMetadata?.contentType || 'text/html; charset=utf-8' };
      return new Response(staticObj.body, { headers });
    }

    // ============================================================
    // 404
    // ============================================================
    return new Response('Not found: ' + path, { status: 404 });

  } catch(e) {
    console.error('Worker error:', e);
    return json({ error: e.message || 'サーバーエラー' }, 500);
  }
}

export default { fetch: handleRequest };
