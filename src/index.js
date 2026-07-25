import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const dataDir = path.join(root, 'data');
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'velora-online.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  avatar_url TEXT,
  bio TEXT NOT NULL DEFAULT '',
  status_text TEXT NOT NULL DEFAULT '',
  presence TEXT NOT NULL DEFAULT 'offline',
  last_seen INTEGER NOT NULL,
  profile_complete INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  last_active INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS verification_codes (
  id TEXT PRIMARY KEY,
  phone TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  purpose TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sms_rate (
  phone TEXT PRIMARY KEY,
  last_sent INTEGER NOT NULL,
  hour_count INTEGER NOT NULL DEFAULT 0,
  hour_start INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chats (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  username TEXT,
  avatar_url TEXT,
  description TEXT NOT NULL DEFAULT '',
  owner_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_message_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS chat_members (
  id TEXT PRIMARY KEY,
  chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member',
  joined_at INTEGER NOT NULL,
  UNIQUE(chat_id, account_id)
);
CREATE TABLE IF NOT EXISTS chat_prefs (
  id TEXT PRIMARY KEY,
  chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  is_pinned INTEGER NOT NULL DEFAULT 0,
  is_archived INTEGER NOT NULL DEFAULT 0,
  is_muted INTEGER NOT NULL DEFAULT 0,
  unread_count INTEGER NOT NULL DEFAULT 0,
  UNIQUE(chat_id, account_id)
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  sender_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  type TEXT NOT NULL DEFAULT 'text',
  content TEXT NOT NULL DEFAULT '',
  reply_to_id TEXT,
  media_url TEXT,
  media_name TEXT,
  media_size INTEGER,
  media_duration INTEGER,
  is_edited INTEGER NOT NULL DEFAULT 0,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_msg_chat ON messages(chat_id, created_at);
CREATE TABLE IF NOT EXISTS reactions (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  emoji TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(message_id, account_id, emoji)
);
`);

db.exec(`
CREATE TABLE IF NOT EXISTS blocks (
  id TEXT PRIMARY KEY,
  blocker_id TEXT NOT NULL,
  blocked_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(blocker_id, blocked_id)
);
CREATE TABLE IF NOT EXISTS calls (
  id TEXT PRIMARY KEY,
  chat_id TEXT NOT NULL,
  caller_id TEXT NOT NULL,
  callee_id TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'audio',
  status TEXT NOT NULL DEFAULT 'ringing',
  offer_sdp TEXT,
  answer_sdp TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS call_signals (
  id TEXT PRIMARY KEY,
  call_id TEXT NOT NULL,
  from_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
`);

// wipe legacy demo accounts if somehow present
db.prepare(`DELETE FROM accounts WHERE username IN ('alice','bob','cara')`).run();

const app = express();
app.use(cors());
app.use(express.json({ limit: '40mb' }));

const now = () => Date.now();
const DAY_MS = 24 * 60 * 60 * 1000;
const ONLINE_STALE_MS = 90_000;

function normalizePhone(input) {
  const digits = String(input || '').replace(/[^\d+]/g, '');
  if (digits.startsWith('+')) return `+${digits.slice(1).replace(/\D/g, '')}`;
  const only = digits.replace(/\D/g, '');
  if (only.length === 11 && only.startsWith('8')) return `+7${only.slice(1)}`;
  if (only.length === 11 && only.startsWith('7')) return `+${only}`;
  if (only.length === 10) return `+7${only}`;
  return only.startsWith('+') ? only : `+${only}`;
}

function isHiddenUsername(u) {
  return String(u || '').startsWith('__h_');
}

function effectivePresence(presence, lastSeen) {
  if (presence === 'online' && lastSeen && now() - Number(lastSeen) > ONLINE_STALE_MS) return 'offline';
  return presence;
}

function mapAccount(row) {
  const username = isHiddenUsername(row.username) ? '' : row.username;
  return {
    id: row.id,
    username,
    displayName: row.display_name,
    phone: row.phone,
    avatarPath: row.avatar_url || null,
    bio: row.bio,
    statusText: row.status_text,
    presence: effectivePresence(row.presence, row.last_seen),
    lastSeen: row.last_seen,
    profileComplete: !!row.profile_complete,
    createdAt: row.created_at,
  };
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const session = db.prepare(`SELECT * FROM sessions WHERE token = ? AND is_active = 1`).get(token);
  if (!session) return res.status(401).json({ error: 'Unauthorized' });
  const account = db.prepare(`SELECT * FROM accounts WHERE id = ?`).get(session.account_id);
  if (!account) return res.status(401).json({ error: 'Unauthorized' });
  db.prepare(`UPDATE sessions SET last_active = ? WHERE id = ?`).run(now(), session.id);
  req.account = account;
  req.token = token;
  next();
}

async function sendSms(phone, code) {
  const apiId = process.env.SMSRU_API_ID || '';
  const twilioSid = process.env.TWILIO_ACCOUNT_SID || '';
  const twilioToken = process.env.TWILIO_AUTH_TOKEN || '';
  const twilioFrom = process.env.TWILIO_FROM || '';
  const text = `Velora: ваш код ${code}. Никому не сообщайте.`;

  if (apiId) {
    const url = new URL('https://sms.ru/sms/send');
    url.searchParams.set('api_id', apiId);
    url.searchParams.set('to', phone.replace(/\D/g, ''));
    url.searchParams.set('msg', text);
    url.searchParams.set('json', '1');
    const r = await fetch(url);
    const j = await r.json();
    if (j.status !== 'OK' && j.status_code !== 100) {
      throw new Error(j.status_text || 'SMS.ru error');
    }
    return { provider: 'smsru' };
  }

  if (twilioSid && twilioToken && twilioFrom) {
    const body = new URLSearchParams({ To: phone, From: twilioFrom, Body: text });
    const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${twilioSid}/Messages.json`, {
      method: 'POST',
      headers: {
        Authorization: 'Basic ' + Buffer.from(`${twilioSid}:${twilioToken}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    });
    if (!r.ok) throw new Error('Twilio SMS error');
    return { provider: 'twilio' };
  }

  // Dev fallback — only if explicitly allowed
  if (process.env.SMS_DEV_MODE === '1') {
    console.log(`[DEV SMS] ${phone} → ${code}`);
    return { provider: 'dev', previewCode: code };
  }

  throw new Error('SMS-провайдер не настроен. Добавьте SMSRU_API_ID в server/.env');
}

function ensureSaved(accountId) {
  const exists = db
    .prepare(
      `SELECT c.id FROM chats c INNER JOIN chat_members m ON m.chat_id = c.id WHERE c.type = 'saved' AND m.account_id = ?`
    )
    .get(accountId);
  if (exists) return;
  const t = now();
  const chatId = uuid();
  db.prepare(
    `INSERT INTO chats (id, type, title, username, avatar_url, description, owner_id, created_at, updated_at, last_message_at)
     VALUES (?, 'saved', 'Избранное', NULL, NULL, '', ?, ?, ?, ?)`
  ).run(chatId, accountId, t, t, t);
  db.prepare(`INSERT INTO chat_members (id, chat_id, account_id, role, joined_at) VALUES (?, ?, ?, 'owner', ?)`).run(
    uuid(),
    chatId,
    accountId,
    t
  );
  db.prepare(
    `INSERT INTO chat_prefs (id, chat_id, account_id, is_pinned, is_archived, is_muted, unread_count) VALUES (?, ?, ?, 1, 0, 0, 0)`
  ).run(uuid(), chatId, accountId);
}

app.get('/health', (_req, res) => res.json({ ok: true, service: 'velora-online', version: '1.3.0' }));

app.post('/auth/request-code', async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    if (!/^\+\d{10,15}$/.test(phone)) return res.status(400).json({ error: 'Неверный номер телефона' });

    const rate = db.prepare(`SELECT * FROM sms_rate WHERE phone = ?`).get(phone);
    const t = now();
    if (rate) {
      if (t - rate.last_sent < 60_000) {
        return res.status(429).json({ error: 'Подождите минуту перед повторной отправкой' });
      }
      let hourCount = rate.hour_count;
      let hourStart = rate.hour_start;
      if (t - hourStart > 3600_000) {
        hourCount = 0;
        hourStart = t;
      }
      if (hourCount >= 5) return res.status(429).json({ error: 'Слишком много SMS. Попробуйте позже' });
      db.prepare(`UPDATE sms_rate SET last_sent = ?, hour_count = ?, hour_start = ? WHERE phone = ?`).run(
        t,
        hourCount + 1,
        hourStart,
        phone
      );
    } else {
      db.prepare(`INSERT INTO sms_rate (phone, last_sent, hour_count, hour_start) VALUES (?, ?, 1, ?)`).run(phone, t, t);
    }

    const code = String(Math.floor(1000 + Math.random() * 9000));
    const codeHash = bcrypt.hashSync(code, 8);
    db.prepare(`UPDATE verification_codes SET consumed = 1 WHERE phone = ? AND consumed = 0`).run(phone);
    db.prepare(
      `INSERT INTO verification_codes (id, phone, code_hash, purpose, attempts, expires_at, consumed, created_at)
       VALUES (?, ?, ?, 'login', 0, ?, 0, ?)`
    ).run(uuid(), phone, codeHash, t + 5 * 60_000, t);

    const sms = await sendSms(phone, code);
    const existing = db.prepare(`SELECT id FROM accounts WHERE phone = ?`).get(phone);
    res.json({
      phone,
      purpose: existing ? 'login' : 'register',
      expiresIn: 300,
      previewCode: sms.previewCode || undefined,
    });
  } catch (err) {
    res.status(500).json({ error: err.message || String(err) });
  }
});

app.post('/auth/verify-code', (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const code = String(req.body.code || '').trim();
    if (!/^\d{4}$/.test(code)) return res.status(400).json({ error: 'Код из 4 цифр' });

    const row = db
      .prepare(`SELECT * FROM verification_codes WHERE phone = ? AND consumed = 0 ORDER BY created_at DESC LIMIT 1`)
      .get(phone);
    if (!row) return res.status(400).json({ error: 'Сначала запросите код' });
    if (row.expires_at < now()) return res.status(400).json({ error: 'Код истёк' });
    if (row.attempts >= 5) return res.status(429).json({ error: 'Слишком много попыток' });

    if (!bcrypt.compareSync(code, row.code_hash)) {
      db.prepare(`UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?`).run(row.id);
      return res.status(400).json({ error: 'Неверный код' });
    }
    db.prepare(`UPDATE verification_codes SET consumed = 1 WHERE id = ?`).run(row.id);

    let account = db.prepare(`SELECT * FROM accounts WHERE phone = ?`).get(phone);
    let isNew = false;
    const t = now();
    if (!account) {
      isNew = true;
      const id = uuid();
      const tempUser = `user${phone.replace(/\D/g, '').slice(-8)}`;
      db.prepare(
        `INSERT INTO accounts (id, username, display_name, password_hash, phone, avatar_url, bio, status_text, presence, last_seen, profile_complete, created_at, updated_at)
         VALUES (?, ?, 'Новый пользователь', ?, ?, NULL, '', '', 'online', ?, 0, ?, ?)`
      ).run(id, tempUser, bcrypt.hashSync(uuid(), 8), phone, t, t, t);
      ensureSaved(id);
      account = db.prepare(`SELECT * FROM accounts WHERE id = ?`).get(id);
    } else {
      db.prepare(`UPDATE accounts SET presence = 'online', last_seen = ?, updated_at = ? WHERE id = ?`).run(t, t, account.id);
      ensureSaved(account.id);
    }

    const token = uuid();
    db.prepare(
      `INSERT INTO sessions (id, account_id, token, is_active, created_at, last_active) VALUES (?, ?, ?, 1, ?, ?)`
    ).run(uuid(), account.id, token, t, t);

    res.json({ account: mapAccount(account), token, isNew });
  } catch (err) {
    res.status(500).json({ error: err.message || String(err) });
  }
});

app.post('/auth/logout', auth, (req, res) => {
  db.prepare(`UPDATE sessions SET is_active = 0 WHERE token = ?`).run(req.token);
  db.prepare(`UPDATE accounts SET presence = 'offline', last_seen = ? WHERE id = ?`).run(now(), req.account.id);
  res.json({ ok: true });
});

app.get('/me', auth, (req, res) => res.json(mapAccount(req.account)));

app.patch('/me', auth, (req, res) => {
  try {
    const patch = req.body || {};
    const within24h = now() - Number(req.account.created_at) < DAY_MS;
    let username = req.account.username;
    let displayName = patch.displayName !== undefined ? String(patch.displayName).trim() : req.account.display_name;

    if (patch.username !== undefined) {
      const raw = String(patch.username).trim().replace(/^@/, '').toLowerCase();
      if (!raw) {
        if (within24h) return res.status(400).json({ error: 'Первые 24 часа username обязателен' });
        username = `__h_${req.account.id.replace(/-/g, '').slice(0, 16)}`;
      } else {
        if (!/^[a-z0-9_]{3,32}$/.test(raw)) return res.status(400).json({ error: 'Неверный username' });
        const clash = db.prepare(`SELECT id FROM accounts WHERE username = ? AND id != ?`).get(raw, req.account.id);
        if (clash) return res.status(400).json({ error: 'Username уже занят' });
        username = raw;
      }
    }

    if (patch.displayName !== undefined) {
      if (!displayName) {
        if (within24h) return res.status(400).json({ error: 'Первые 24 часа имя обязательно' });
        displayName = '';
      }
    }

    let passwordHash = req.account.password_hash;
    if (patch.password !== undefined) {
      const pwd = String(patch.password);
      if (pwd.length < 6 || !/[A-ZА-Я]/.test(pwd)) {
        return res.status(400).json({ error: 'Пароль: минимум 6 символов и хотя бы одна заглавная буква' });
      }
      passwordHash = bcrypt.hashSync(pwd, 10);
    }

    // presence меняется только через /presence (автоматика клиента)
    db.prepare(
      `UPDATE accounts SET username = ?, display_name = ?, bio = ?, status_text = ?, avatar_url = ?,
       password_hash = ?, profile_complete = ?, updated_at = ?, last_seen = ? WHERE id = ?`
    ).run(
      username,
      displayName,
      patch.bio ?? req.account.bio,
      patch.statusText ?? req.account.status_text,
      patch.avatarPath !== undefined ? patch.avatarPath : req.account.avatar_url,
      passwordHash,
      patch.profileComplete === false ? 0 : patch.profileComplete === true ? 1 : req.account.profile_complete,
      now(),
      now(),
      req.account.id
    );
    const updated = db.prepare(`SELECT * FROM accounts WHERE id = ?`).get(req.account.id);
    res.json(mapAccount(updated));
  } catch (err) {
    res.status(500).json({ error: err.message || String(err) });
  }
});

app.post('/auth/login-password', (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || '');
    const account = db.prepare(`SELECT * FROM accounts WHERE phone = ?`).get(phone);
    if (!account) return res.status(400).json({ error: 'Аккаунт с этим номером не найден' });
    if (!account.profile_complete) return res.status(400).json({ error: 'Сначала завершите регистрацию по SMS' });
    if (!bcrypt.compareSync(password, account.password_hash)) {
      return res.status(400).json({ error: 'Неверный пароль' });
    }
    const t = now();
    db.prepare(`UPDATE accounts SET presence = 'online', last_seen = ?, updated_at = ? WHERE id = ?`).run(t, t, account.id);
    const token = uuid();
    db.prepare(
      'INSERT INTO sessions (id, account_id, token, is_active, created_at, last_active) VALUES (?, ?, ?, 1, ?, ?)'
    ).run(uuid(), account.id, token, t, t);
    res.json({ account: mapAccount(account), token, isNew: false });
  } catch (err) {
    res.status(500).json({ error: err.message || String(err) });
  }
});

app.post('/presence', auth, (req, res) => {
  try {
    const status = String(req.body?.status || 'online');
    if (!['online', 'away', 'offline'].includes(status)) {
      return res.status(400).json({ error: 'Неверный статус' });
    }
    const t = now();
    db.prepare(`UPDATE accounts SET presence = ?, last_seen = ?, updated_at = ? WHERE id = ?`).run(
      status,
      t,
      t,
      req.account.id
    );
    res.json({ ok: true, presence: status, lastSeen: t });
  } catch (err) {
    res.status(500).json({ error: err.message || String(err) });
  }
});

app.get('/accounts/:id', auth, (req, res) => {
  const row = db.prepare(`SELECT * FROM accounts WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Не найден' });
  res.json(mapAccount(row));
});

app.get('/search/username/:username', auth, (req, res) => {
  const username = String(req.params.username || '').replace(/^@/, '').trim().toLowerCase();
  if (!username || username.length < 2 || username.startsWith('__h_')) {
    return res.json({ users: [], channels: [], chats: [], messages: [] });
  }
  const like = `${username}%`;
  const rows = db
    .prepare(
      `SELECT id, username, display_name as displayName, avatar_url as avatarPath, presence, last_seen as lastSeen, status_text as statusText
       FROM accounts
       WHERE id != ?
         AND username NOT LIKE '__h_%'
         AND (
           lower(username) = ? OR lower(username) LIKE ?
         )
       ORDER BY CASE WHEN lower(username) = ? THEN 0 ELSE 1 END, username
       LIMIT 20`
    )
    .all(req.account.id, username, like, username)
    .map((r) => ({
      ...r,
      presence: effectivePresence(r.presence, r.lastSeen),
    }));
  res.json({ users: rows, channels: [], chats: [], messages: [] });
});

app.get('/chats', auth, (req, res) => {
  const archived = req.query.archived === '1' ? 1 : 0;
  const rows = db
    .prepare(
      `SELECT c.*, p.is_pinned, p.is_archived, p.is_muted, p.unread_count,
        (SELECT m.content FROM messages m WHERE m.chat_id = c.id AND m.is_deleted = 0 ORDER BY m.created_at DESC LIMIT 1) as last_message,
        (SELECT m.type FROM messages m WHERE m.chat_id = c.id AND m.is_deleted = 0 ORDER BY m.created_at DESC LIMIT 1) as last_message_type
       FROM chats c
       INNER JOIN chat_members cm ON cm.chat_id = c.id AND cm.account_id = ?
       INNER JOIN chat_prefs p ON p.chat_id = c.id AND p.account_id = ?
       WHERE p.is_archived = ?
       ORDER BY p.is_pinned DESC, c.last_message_at DESC`
    )
    .all(req.account.id, req.account.id, archived);

  const mapped = rows.map((row) => {
    let title = row.title;
    let username = row.username;
    let avatarPath = row.avatar_url;
    let peerPresence = null;
    let peerLastSeen = null;
    let peerId = null;
    if (row.type === 'private') {
      const peer = db
        .prepare(
          `SELECT a.* FROM accounts a INNER JOIN chat_members cm ON cm.account_id = a.id
           WHERE cm.chat_id = ? AND a.id != ? LIMIT 1`
        )
        .get(row.id, req.account.id);
      if (peer) {
        title = peer.display_name || 'Без имени';
        username = isHiddenUsername(peer.username) ? null : peer.username;
        avatarPath = peer.avatar_url;
        peerPresence = effectivePresence(peer.presence, peer.last_seen);
        peerLastSeen = peer.last_seen;
        peerId = peer.id;
      }
    }
    return {
      id: row.id,
      type: row.type,
      title,
      username,
      avatarPath,
      description: row.description,
      ownerId: row.owner_id,
      isPinned: row.is_pinned,
      isArchived: row.is_archived,
      isMuted: row.is_muted,
      folderId: null,
      lastMessageAt: row.last_message_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      unreadCount: row.unread_count,
      lastMessage: row.last_message,
      lastMessageType: row.last_message_type,
      peerPresence,
      peerLastSeen: peerLastSeen ?? null,
      peerId,
    };
  });
  res.json(mapped);
});

app.post('/chats/private', auth, (req, res) => {
  const peerId = req.body.peerId;
  if (!peerId || peerId === req.account.id) return res.status(400).json({ error: 'Неверный пользователь' });
  if (isBlockedEither(req.account.id, peerId)) return res.status(403).json({ error: 'Пользователь в чёрном списке' });
  const peer = db.prepare(`SELECT * FROM accounts WHERE id = ?`).get(peerId);
  if (!peer) return res.status(404).json({ error: 'Пользователь не найден' });

  const existing = db
    .prepare(
      `SELECT c.id FROM chats c
       INNER JOIN chat_members m1 ON m1.chat_id = c.id AND m1.account_id = ?
       INNER JOIN chat_members m2 ON m2.chat_id = c.id AND m2.account_id = ?
       WHERE c.type = 'private' LIMIT 1`
    )
    .get(req.account.id, peerId);
  if (existing) {
    const chat = db.prepare(`SELECT * FROM chats WHERE id = ?`).get(existing.id);
    return res.json({
      id: chat.id,
      type: chat.type,
      title: peer.display_name,
      username: peer.username,
      avatarPath: peer.avatar_url,
      unreadCount: 0,
    });
  }

  const t = now();
  const chatId = uuid();
  db.prepare(
    `INSERT INTO chats (id, type, title, username, avatar_url, description, owner_id, created_at, updated_at, last_message_at)
     VALUES (?, 'private', ?, ?, ?, '', NULL, ?, ?, ?)`
  ).run(chatId, peer.display_name, peer.username, peer.avatar_url, t, t, t);
  for (const uid of [req.account.id, peerId]) {
    db.prepare(`INSERT INTO chat_members (id, chat_id, account_id, role, joined_at) VALUES (?, ?, ?, 'member', ?)`).run(
      uuid(),
      chatId,
      uid,
      t
    );
    db.prepare(
      `INSERT INTO chat_prefs (id, chat_id, account_id, is_pinned, is_archived, is_muted, unread_count) VALUES (?, ?, ?, 0, 0, 0, 0)`
    ).run(uuid(), chatId, uid);
  }
  res.json({
    id: chatId,
    type: 'private',
    title: peer.display_name,
    username: peer.username,
    avatarPath: peer.avatar_url,
    unreadCount: 0,
  });
});

app.post('/chats', auth, (req, res) => {
  const type = req.body.type === 'channel' ? 'channel' : 'group';
  const title = String(req.body.title || '').trim();
  if (!title) return res.status(400).json({ error: 'Название обязательно' });
  const username = req.body.username ? String(req.body.username).replace(/^@/, '').toLowerCase() : null;
  const t = now();
  const chatId = uuid();
  db.prepare(
    `INSERT INTO chats (id, type, title, username, avatar_url, description, owner_id, created_at, updated_at, last_message_at)
     VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)`
  ).run(chatId, type, title, username, req.body.description || '', req.account.id, t, t, t);
  db.prepare(`INSERT INTO chat_members (id, chat_id, account_id, role, joined_at) VALUES (?, ?, ?, 'owner', ?)`).run(
    uuid(),
    chatId,
    req.account.id,
    t
  );
  db.prepare(
    `INSERT INTO chat_prefs (id, chat_id, account_id, is_pinned, is_archived, is_muted, unread_count) VALUES (?, ?, ?, 0, 0, 0, 0)`
  ).run(uuid(), chatId, req.account.id);
  res.json({ id: chatId, type, title, username });
});

app.post('/chats/:id/read', auth, (req, res) => {
  db.prepare(`UPDATE chat_prefs SET unread_count = 0 WHERE chat_id = ? AND account_id = ?`).run(req.params.id, req.account.id);
  res.json({ ok: true });
});

app.patch('/chats/:id/prefs', auth, (req, res) => {
  const cur = db
    .prepare(`SELECT * FROM chat_prefs WHERE chat_id = ? AND account_id = ?`)
    .get(req.params.id, req.account.id);
  if (!cur) return res.status(404).json({ error: 'Chat not found' });
  const p = req.body || {};
  let nextPinned = p.isPinned !== undefined ? (p.isPinned ? 1 : 0) : cur.is_pinned;
  if (nextPinned === 1 && !cur.is_pinned) {
    const pinnedCount = db
      .prepare(`SELECT COUNT(*) as c FROM chat_prefs WHERE account_id = ? AND is_pinned = 1`)
      .get(req.account.id).c;
    if (pinnedCount >= 5) return res.status(400).json({ error: 'Можно закрепить максимум 5 чатов' });
  }
  db.prepare(
    `UPDATE chat_prefs SET is_pinned = ?, is_archived = ?, is_muted = ? WHERE chat_id = ? AND account_id = ?`
  ).run(
    nextPinned,
    p.isArchived !== undefined ? (p.isArchived ? 1 : 0) : cur.is_archived,
    p.isMuted !== undefined ? (p.isMuted ? 1 : 0) : cur.is_muted,
    req.params.id,
    req.account.id
  );
  res.json({ ok: true });
});

app.post('/chats/:id/leave', auth, (req, res) => {
  const chatId = req.params.id;
  const member = db
    .prepare(`SELECT id FROM chat_members WHERE chat_id = ? AND account_id = ?`)
    .get(chatId, req.account.id);
  if (!member) return res.status(404).json({ error: 'Не в чате' });
  db.prepare(`DELETE FROM chat_members WHERE chat_id = ? AND account_id = ?`).run(chatId, req.account.id);
  db.prepare(`DELETE FROM chat_prefs WHERE chat_id = ? AND account_id = ?`).run(chatId, req.account.id);
  res.json({ ok: true });
});

app.post('/blocks', auth, (req, res) => {
  const blockedId = String(req.body?.accountId || '');
  if (!blockedId || blockedId === req.account.id) return res.status(400).json({ error: 'Неверный пользователь' });
  const t = now();
  try {
    db.prepare(`INSERT INTO blocks (id, blocker_id, blocked_id, created_at) VALUES (?, ?, ?, ?)`).run(
      uuid(),
      req.account.id,
      blockedId,
      t
    );
  } catch {
    /* already blocked */
  }
  res.json({ ok: true });
});

app.delete('/blocks/:id', auth, (req, res) => {
  db.prepare(`DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?`).run(req.account.id, req.params.id);
  res.json({ ok: true });
});

app.get('/blocks', auth, (req, res) => {
  const rows = db
    .prepare(
      `SELECT b.blocked_id as id, a.username, a.display_name as displayName, a.avatar_url as avatarPath
       FROM blocks b INNER JOIN accounts a ON a.id = b.blocked_id WHERE b.blocker_id = ?`
    )
    .all(req.account.id);
  res.json(rows);
});

function isBlockedEither(a, b) {
  return !!db
    .prepare(
      `SELECT id FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?) LIMIT 1`
    )
    .get(a, b, b, a);
}

app.get('/chats/:id/messages', auth, (req, res) => {
  const member = db
    .prepare(`SELECT id FROM chat_members WHERE chat_id = ? AND account_id = ?`)
    .get(req.params.id, req.account.id);
  if (!member) return res.status(403).json({ error: 'Access denied' });
  const rows = db
    .prepare(
      `SELECT * FROM messages WHERE chat_id = ? AND is_deleted = 0 ORDER BY created_at DESC LIMIT ?`
    )
    .all(req.params.id, Number(req.query.limit || 100))
    .reverse();

  const mapped = rows.map((row) => {
    const sender = db.prepare(`SELECT display_name, avatar_url FROM accounts WHERE id = ?`).get(row.sender_id);
    const reactionsRaw = db
      .prepare(
        `SELECT emoji, COUNT(*) as count, SUM(CASE WHEN account_id = ? THEN 1 ELSE 0 END) as reacted
         FROM reactions WHERE message_id = ? GROUP BY emoji`
      )
      .all(req.account.id, row.id);
    let replyPreview = null;
    if (row.reply_to_id) {
      const reply = db
        .prepare(
          `SELECT m.id, m.content, a.display_name as senderName FROM messages m
           LEFT JOIN accounts a ON a.id = m.sender_id WHERE m.id = ?`
        )
        .get(row.reply_to_id);
      if (reply) replyPreview = reply;
    }
    return {
      id: row.id,
      chatId: row.chat_id,
      senderId: row.sender_id,
      type: row.type,
      content: row.content,
      replyToId: row.reply_to_id,
      mediaPath: row.media_url,
      mediaName: row.media_name,
      mediaSize: row.media_size,
      mediaDuration: row.media_duration,
      isEdited: row.is_edited,
      isDeleted: row.is_deleted,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      senderName: sender?.display_name,
      senderAvatar: sender?.avatar_url || null,
      reactions: reactionsRaw.map((r) => ({ emoji: r.emoji, count: r.count, reacted: !!r.reacted })),
      replyPreview,
    };
  });
  res.json(mapped);
});

app.post('/chats/:id/messages', auth, (req, res) => {
  const member = db
    .prepare(`SELECT id FROM chat_members WHERE chat_id = ? AND account_id = ?`)
    .get(req.params.id, req.account.id);
  if (!member) return res.status(403).json({ error: 'Access denied' });
  const chatRow = db.prepare(`SELECT type FROM chats WHERE id = ?`).get(req.params.id);
  if (chatRow?.type === 'private') {
    const peer = db
      .prepare(`SELECT account_id FROM chat_members WHERE chat_id = ? AND account_id != ? LIMIT 1`)
      .get(req.params.id, req.account.id);
    if (peer && isBlockedEither(req.account.id, peer.account_id)) {
      return res.status(403).json({ error: 'Нельзя писать: пользователь в чёрном списке' });
    }
  }
  const type = req.body.type || 'text';
  const content = String(req.body.content || '').trim();
  if (type === 'text' && !content && !req.body.mediaPath) return res.status(400).json({ error: 'Пустое сообщение' });
  const t = now();
  const id = uuid();
  db.prepare(
    `INSERT INTO messages (id, chat_id, sender_id, type, content, reply_to_id, media_url, media_name, media_size, media_duration, is_edited, is_deleted, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)`
  ).run(
    id,
    req.params.id,
    req.account.id,
    type,
    content,
    req.body.replyToId || null,
    req.body.mediaPath || null,
    req.body.mediaName || null,
    req.body.mediaSize ?? null,
    req.body.mediaDuration ?? null,
    t,
    t
  );
  db.prepare(`UPDATE chats SET last_message_at = ?, updated_at = ? WHERE id = ?`).run(t, t, req.params.id);
  db.prepare(`UPDATE chat_prefs SET unread_count = unread_count + 1 WHERE chat_id = ? AND account_id != ?`).run(
    req.params.id,
    req.account.id
  );
  const message = {
    id,
    chatId: req.params.id,
    senderId: req.account.id,
    type,
    content,
    replyToId: req.body.replyToId || null,
    mediaPath: req.body.mediaPath || null,
    mediaName: req.body.mediaName || null,
    mediaSize: req.body.mediaSize ?? null,
    mediaDuration: req.body.mediaDuration ?? null,
    isEdited: 0,
    isDeleted: 0,
    createdAt: t,
    updatedAt: t,
    senderName: req.account.display_name,
    senderAvatar: req.account.avatar_url,
    reactions: [],
    replyPreview: null,
  };
  res.json(message);
});

app.post('/messages/:id/react', auth, (req, res) => {
  const emoji = String(req.body.emoji || '👍');
  const msg = db.prepare(`SELECT * FROM messages WHERE id = ?`).get(req.params.id);
  if (!msg) return res.status(404).json({ error: 'Not found' });
  const existing = db
    .prepare(`SELECT id FROM reactions WHERE message_id = ? AND account_id = ? AND emoji = ?`)
    .get(req.params.id, req.account.id, emoji);
  if (existing) db.prepare(`DELETE FROM reactions WHERE id = ?`).run(existing.id);
  else
    db.prepare(`INSERT INTO reactions (id, message_id, account_id, emoji, created_at) VALUES (?, ?, ?, ?, ?)`).run(
      uuid(),
      req.params.id,
      req.account.id,
      emoji,
      now()
    );
  res.json({ ok: true });
});

app.delete('/messages/:id', auth, (req, res) => {
  const msg = db.prepare(`SELECT * FROM messages WHERE id = ?`).get(req.params.id);
  if (!msg) return res.status(404).json({ error: 'Not found' });
  if (msg.sender_id !== req.account.id) return res.status(403).json({ error: 'Forbidden' });
  db.prepare(`UPDATE messages SET is_deleted = 1, content = '', media_url = NULL, updated_at = ? WHERE id = ?`).run(
    now(),
    req.params.id
  );
  res.json({ ok: true });
});

app.patch('/messages/:id', auth, (req, res) => {
  const msg = db.prepare(`SELECT * FROM messages WHERE id = ?`).get(req.params.id);
  if (!msg) return res.status(404).json({ error: 'Not found' });
  if (msg.sender_id !== req.account.id) return res.status(403).json({ error: 'Forbidden' });
  if (msg.type !== 'text') return res.status(400).json({ error: 'Only text' });
  db.prepare(`UPDATE messages SET content = ?, is_edited = 1, updated_at = ? WHERE id = ?`).run(
    String(req.body.content || '').trim(),
    now(),
    req.params.id
  );
  res.json({ ok: true });
});

app.post('/calls/start', auth, (req, res) => {
  try {
    const peerId = String(req.body?.peerId || '');
    const chatId = String(req.body?.chatId || '');
    const mode = req.body?.mode === 'video' ? 'video' : 'audio';
    const offer = String(req.body?.offerSdp || '');
    if (!peerId || !chatId || !offer) return res.status(400).json({ error: 'Нужны peerId, chatId, offerSdp' });
    if (isBlockedEither(req.account.id, peerId)) return res.status(403).json({ error: 'Пользователь в чёрном списке' });
    db.prepare(`UPDATE calls SET status = 'ended', updated_at = ? WHERE caller_id = ? AND status IN ('ringing','active')`).run(
      now(),
      req.account.id
    );
    const id = uuid();
    const t = now();
    db.prepare(
      `INSERT INTO calls (id, chat_id, caller_id, callee_id, mode, status, offer_sdp, answer_sdp, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'ringing', ?, NULL, ?, ?)`
    ).run(id, chatId, req.account.id, peerId, mode, offer, t, t);
    res.json({ id, status: 'ringing', mode, chatId, peerId });
  } catch (err) {
    res.status(500).json({ error: err.message || String(err) });
  }
});

app.get('/calls/incoming', auth, (req, res) => {
  const row = db
    .prepare(
      `SELECT c.*, a.display_name as callerName, a.avatar_url as callerAvatar, a.username as callerUsername
       FROM calls c INNER JOIN accounts a ON a.id = c.caller_id
       WHERE c.callee_id = ? AND c.status = 'ringing' ORDER BY c.created_at DESC LIMIT 1`
    )
    .get(req.account.id);
  if (!row) return res.json(null);
  res.json({
    id: row.id,
    chatId: row.chat_id,
    mode: row.mode,
    status: row.status,
    offerSdp: row.offer_sdp,
    callerId: row.caller_id,
    callerName: row.callerName,
    callerAvatar: row.callerAvatar,
    callerUsername: isHiddenUsername(row.callerUsername) ? '' : row.callerUsername,
    createdAt: row.created_at,
  });
});

app.get('/calls/:id', auth, (req, res) => {
  const row = db.prepare(`SELECT * FROM calls WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  if (row.caller_id !== req.account.id && row.callee_id !== req.account.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json({
    id: row.id,
    chatId: row.chat_id,
    mode: row.mode,
    status: row.status,
    offerSdp: row.offer_sdp,
    answerSdp: row.answer_sdp,
    callerId: row.caller_id,
    calleeId: row.callee_id,
    updatedAt: row.updated_at,
  });
});

app.post('/calls/:id/answer', auth, (req, res) => {
  const row = db.prepare(`SELECT * FROM calls WHERE id = ?`).get(req.params.id);
  if (!row || row.callee_id !== req.account.id) return res.status(404).json({ error: 'Not found' });
  if (row.status !== 'ringing') return res.status(400).json({ error: 'Звонок уже не активен' });
  const answer = String(req.body?.answerSdp || '');
  if (!answer) return res.status(400).json({ error: 'Нужен answerSdp' });
  db.prepare(`UPDATE calls SET status = 'active', answer_sdp = ?, updated_at = ? WHERE id = ?`).run(answer, now(), row.id);
  res.json({ ok: true, status: 'active' });
});

app.post('/calls/:id/reject', auth, (req, res) => {
  const row = db.prepare(`SELECT * FROM calls WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  if (row.caller_id !== req.account.id && row.callee_id !== req.account.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  db.prepare(`UPDATE calls SET status = 'rejected', updated_at = ? WHERE id = ?`).run(now(), row.id);
  res.json({ ok: true });
});

app.post('/calls/:id/hangup', auth, (req, res) => {
  const row = db.prepare(`SELECT * FROM calls WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  if (row.caller_id !== req.account.id && row.callee_id !== req.account.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  db.prepare(`UPDATE calls SET status = 'ended', updated_at = ? WHERE id = ?`).run(now(), row.id);
  res.json({ ok: true });
});

app.post('/calls/:id/signal', auth, (req, res) => {
  const row = db.prepare(`SELECT * FROM calls WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  if (row.caller_id !== req.account.id && row.callee_id !== req.account.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const kind = String(req.body?.kind || 'ice');
  const payload = JSON.stringify(req.body?.payload ?? {});
  db.prepare(
    `INSERT INTO call_signals (id, call_id, from_id, kind, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)`
  ).run(uuid(), row.id, req.account.id, kind, payload, now());
  res.json({ ok: true });
});

app.get('/calls/:id/signals', auth, (req, res) => {
  const row = db.prepare(`SELECT * FROM calls WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  if (row.caller_id !== req.account.id && row.callee_id !== req.account.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const after = Number(req.query.after || 0);
  const rows = db
    .prepare(
      `SELECT id, from_id as fromId, kind, payload, created_at as createdAt FROM call_signals
       WHERE call_id = ? AND from_id != ? AND created_at > ? ORDER BY created_at ASC LIMIT 100`
    )
    .all(row.id, req.account.id, after)
    .map((r) => ({ ...r, payload: JSON.parse(r.payload) }));
  res.json(rows);
});

const port = Number(process.env.PORT || 8788);
app.listen(port, '0.0.0.0', () => {
  console.log(`Velora online API → http://0.0.0.0:${port}`);
  console.log(`Health: http://127.0.0.1:${port}/health`);
  if (!process.env.SMSRU_API_ID && process.env.SMS_DEV_MODE !== '1') {
    console.warn('⚠ SMS не настроен. Для теста: SMS_DEV_MODE=1 в .env');
    console.warn('  Для реальных SMS: SMSRU_API_ID=... в server/.env (sms.ru)');
  }
});
