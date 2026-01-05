// server.js (production-minded MVP) — fixed version
// Required env:
// - JWT_SECRET (required)
// - MONGO_URL (recommended; but your ./db module may handle it)
// - MEDIA_BASE_URL (optional, default http://localhost:5000)
// - PERSISTENT_MEDIA_ROOT (optional, default path.join(__dirname, 'media'))
// - REDIS_URL (optional)

// NOTE: This file updates three important areas:
// 1) lru-cache usage (new API: LRUCache)
// 2) /posts/reels: fixed liked bug (p._1 -> p._id)
// 3) /posts/:id/view: view counter now uses viewedBy and atomically increments + records viewer
// 4) Cache invalidation is now user-scoped by default; global invalidation kept for admin operations

const { LRUCache } = require('lru-cache');

const postsCache = new LRUCache({
  max: 500,
  ttl: 1000 * 20 // 20 seconds
});

require('dotenv').config();

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');
const mime = require('mime-types');
const FileType = require('file-type');
const mongoose = require('mongoose');

const app = express();
const connectDB = require("./config/connectDB");
if (!global.onlineUsers) global.onlineUsers = new Set();

// -----------------
// Env + basic checks
// -----------------
if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET missing');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;
const MEDIA_BASE_URL = process.env.MEDIA_BASE_URL || `http://localhost:${process.env.PORT || 5000}`;
const PERSISTENT_MEDIA_ROOT = process.env.PERSISTENT_MEDIA_ROOT || path.join(__dirname, 'media');
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',').map(s => s.trim()).filter(Boolean);
connectDB();

// -----------------
// Models (expect these files to exist)
// -----------------
const User = require('./models/User');
const Post = require('./models/Post');
const Like = require('./models/Like');
const Follow = require('./models/Follow');
const Message = require('./models/Message');
const Comment = require('./models/Comment');

// -----------------
// Security middlewares
// -----------------
app.use(helmet({
  contentSecurityPolicy: false // leave more control to frontend for video embeds; tune CSP in production
}));

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);

    const allowed = ALLOWED_ORIGINS.some(o =>
      origin === o || origin.startsWith(o)
    );

    if (allowed) return callback(null, true);

    console.log("CORS BLOCKED:", origin);
    return callback(null, false);
  },
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'Range'],
  exposedHeaders: ['Content-Length', 'Content-Range', 'Accept-Ranges'],
};


app.use(cors(corsOptions));
app.use(express.json({ limit: '1mb' })); // limit JSON size

// -----------------
// Rate limiting
// -----------------
const globalLimiter = rateLimit({ windowMs: 60 * 1000, max: 300 });
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { msg: 'Too many auth attempts, try again later' }
});

// -----------------
// Ensure media dirs
// -----------------
function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

ensureDir(path.join(PERSISTENT_MEDIA_ROOT, 'videos'));
ensureDir(path.join(PERSISTENT_MEDIA_ROOT, 'images'));

const AVATAR_ROOT = path.join(__dirname, 'avatars');
ensureDir(AVATAR_ROOT);

// serve avatars WITH PROPER HEADERS (fix broken images)
app.use('/avatars', (req, res, next) => {
  const origin =
    req.headers.origin && ALLOWED_ORIGINS.includes(req.headers.origin)
      ? req.headers.origin
      : ALLOWED_ORIGINS[0];

  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Expose-Headers', 'Content-Length');
  res.setHeader('Vary', 'Origin');

  res.setHeader('Cross-Origin-Embedder-Policy', 'unsafe-none');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

  next();
}, express.static(AVATAR_ROOT));
const cloudinary = require('cloudinary').v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// -----------------
// Redis optional
// -----------------
let redisClient = null;
let redisPub = null;
let redisSub = null;
let redisAvailable = false;

async function initRedis() {
  if (!process.env.REDIS_URL) return;
  try {
    const IORedis = require('ioredis');
    redisClient = new IORedis(process.env.REDIS_URL);
    redisPub = redisClient.duplicate();
    redisSub = redisClient.duplicate();
    await redisClient.connect?.();
    await redisPub.connect?.();
    await redisSub.connect?.();
    redisAvailable = true;
    console.log('Redis connected');
  } catch (e) {
    console.warn('Redis init failed, continuing without Redis:', e.message || e);
    redisAvailable = false;
  }
}
initRedis().catch(e => console.warn('initRedis error', e.message || e));

// -----------------
// Lightweight LRU for in-memory caches (bounded to avoid memory growth)
// -----------------
function createLRU(maxSize = 50000) {
  const map = new Map();
  return {
    get(k) {
      const v = map.get(k);
      if (!v) return undefined;
      map.delete(k);
      map.set(k, v);
      return v;
    },
    set(k, v) {
      if (map.has(k)) map.delete(k);
      map.set(k, v);
      if (map.size > maxSize) {
        const firstKey = map.keys().next().value;
        map.delete(firstKey);
      }
    },
    delete(k) { map.delete(k); },
    has(k) { return map.has(k); },
    keys() { return Array.from(map.keys()); }
  };
}

const followCache = createLRU(10000);
const userRateCache = createLRU(20000);

// -----------------
// Helpers
// -----------------
function generateFilename(originalname) {
  const ext = path.extname(originalname) || '';
  const uuid = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
  return `${Date.now()}-${uuid}${ext}`;
}

async function validateFileMagic(filePath, allowedPrefixes = []) {
  try {
    const ft = await FileType.fromFile(filePath);
    if (!ft) return false;
    if (!allowedPrefixes || allowedPrefixes.length === 0) return !!ft.mime;
    return allowedPrefixes.some(pref => ft.mime.startsWith(pref));
  } catch {
    return false;
  }
}


function safeResolveWithin(base, file) {
  const baseResolved = path.resolve(base);
  const full = path.resolve(path.join(base, file));
  if (!full.startsWith(baseResolved)) return null;
  return full;
}

// -----------------
// Multer storages + filters (use persistent root)
// -----------------
const mediaStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const mimetype = file.mimetype || '';
    if (mimetype.startsWith('video/')) {
      const dir = path.join(PERSISTENT_MEDIA_ROOT, 'videos'); ensureDir(dir); return cb(null, dir);
    }
    if (mimetype.startsWith('image/')) {
      const dir = path.join(PERSISTENT_MEDIA_ROOT, 'images'); ensureDir(dir); return cb(null, dir);
    }
    return cb(new Error('Unsupported media type'));
  },
  filename: (req, file, cb) => cb(null, generateFilename(file.originalname))
});

function mediaFileFilter(req, file, cb) {
  if (!file.mimetype) return cb(new Error('Missing mimetype'), false);
  if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) return cb(null, true);
  return cb(new Error('Unsupported media type'), false);
}

const mediaUpload = multer({
  storage: mediaStorage,
  fileFilter: mediaFileFilter,
  limits: { files: 5, fileSize: 150 * 1024 * 1024 } // 150MB per file
});

const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => { const dir = path.join(__dirname, 'avatars'); ensureDir(dir); cb(null, dir); },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.png';
    const uid = (req.user && req.user.id) ? String(req.user.id) : 'anon';
    cb(null, `${uid}-${Date.now()}${ext}`);
  }
});
function avatarFileFilter(req, file, cb) {
  if (!file.mimetype) return cb(new Error('Missing mimetype'), false);
  if (file.mimetype.startsWith('image/')) return cb(null, true);
  return cb(new Error('Unsupported avatar type'), false);
}
const avatarUpload = multer({ storage: avatarStorage, fileFilter: avatarFileFilter, limits: { fileSize: 5 * 1024 * 1024 } });

// -----------------
// Auth helpers (JWT includes tokenVersion for revocation)
// -----------------
async function signTokenForUser(user) {
  const payload = {
    id: String(user._id),
    username: user.username,
    role: user.role || 'user',
    tv: (user.tokenVersion || 0)
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ msg: 'Token topilmadi' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // fetch current tokenVersion
    try {
      const user = await User.findById(payload.id).select('+tokenVersion');
      if (!user) return res.status(401).json({ msg: 'Token noto‘g‘ri' });
      if ((user.tokenVersion || 0) !== (payload.tv || 0)) {
        return res.status(401).json({ msg: 'Token bekor qilingan' });
      }
      req.user = { id: String(user._id), username: user.username, role: user.role };
    } catch (e) {
      // if DB fails, proceed cautiously
      req.user = { id: payload.id, username: payload.username, role: payload.role };
    }

    // user-level rate limiter (lightweight)
    try {
      const uid = String(req.user.id);
      let meta = userRateCache.get(uid) || { count: 0, resetAt: Date.now() + 60 * 1000 };
      if (Date.now() > meta.resetAt) meta = { count: 0, resetAt: Date.now() + 60 * 1000 };
      meta.count = (meta.count || 0) + 1;
      userRateCache.set(uid, meta);
      if (meta.count > 120) return res.status(429).json({ msg: 'Too many requests (user rate limit)' });
    } catch (e) { console.warn('user rate limiter failed', e.message || e); }

    return next();
  } catch (e) {
    return res.status(401).json({ msg: 'Token noto‘g‘ri' });
  }
}

async function adminMiddleware(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ msg: 'Token topilmadi' });
    if (req.user.role === 'admin') return next();
    const u = await User.findById(req.user.id).select('role');
    if (u && u.role === 'admin') return next();
    return res.status(403).json({ msg: 'Admin emassiz' });
  } catch (e) {
    return res.status(500).json({ msg: 'Server xatosi' });
  }
}

// -----------------
// Follow caching functions (keyed by userId)
// -----------------
async function getCachedFollowing(userId) {
  if (!userId) return null;
  try {
    if (redisAvailable && redisClient) {
      const raw = await redisClient.get(`follows:${userId}`);
      if (raw) return new Set(JSON.parse(raw));
    }
  } catch (e) { console.warn('redis getCachedFollowing failed', e.message || e); }
  const v = followCache.get(userId);
  return v ? new Set(Array.from(v)) : null;
}

async function setCachedFollowing(userId, list) {
  if (!userId) return;
  const arr = Array.isArray(list) ? list : Array.from(list || []);
  try {
    if (redisAvailable && redisClient) {
      await redisClient.set(`follows:${userId}`, JSON.stringify(arr), 'EX', 60);
    }
  } catch (e) { console.warn('redis setCachedFollowing failed', e.message || e); }
  followCache.set(userId, new Set(arr));
}

// -----------------
// Startup indexes (best-effort non-blocking)
// -----------------
(async function ensureIndexes() {
  try {
    if (Follow && Follow.collection) {
      await Follow.collection.createIndex({ followerId: 1, followingId: 1 }, { unique: true, background: true });
    }
    if (Like && Like.collection) {
      await Like.collection.createIndex({ postId: 1, userId: 1 }, { unique: true, background: true });
    }
    if (Message && Message.collection) {
      await Message.collection.createIndex({ from: 1, to: 1, createdAt: -1 }, { background: true });
    }
    if (Comment && Comment.collection) {
      await Comment.collection.createIndex({ postId: 1, createdAt: -1 }, { background: true });
    }
    if (Post && Post.collection) {
      await Post.collection.createIndex({ status: 1, createdAt: -1 }, { background: true });
      await Post.collection.createIndex({ likesCount: -1, views: -1 }, { background: true });
      await Post.collection.createIndex({ userId: 1, createdAt: -1 }, { background: true });
    }
    console.log('Indexes ensured (best-effort)');
  } catch (e) {
    console.warn('Index ensure warning:', e.message || e);
  }
})().catch(() => {});

// -----------------
// Cache invalidation helpers
// -----------------
function invalidateAllPostsCache() {
  try {
    const keys = typeof postsCache.keys === 'function' ? postsCache.keys() : [];
    for (const key of keys) {
      if (typeof key === 'string' && key.startsWith('posts:')) postsCache.delete(key);
    }
  } catch (e) {
    console.warn('invalidateAllPostsCache failed', e && e.message ? e.message : e);
  }
}

function invalidateUserPostsCache(userId) {
  try {
    const keys = typeof postsCache.keys === 'function' ? postsCache.keys() : [];
    for (const key of keys) {
      if (typeof key !== 'string') continue;
      if (userId && key.startsWith(`posts:${userId}:`)) {
        postsCache.delete(key);
        continue;
      }
      // also clear guest cache so the user sees updated content when logged out
      if (key.startsWith('posts:guest:')) postsCache.delete(key);
    }
  } catch (e) {
    console.warn('invalidateUserPostsCache failed', e && e.message ? e.message : e);
  }
}

// -----------------
// Routes: Auth
// -----------------
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ msg: 'Username va password majburiy' });
    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ msg: 'Username band' });
    const user = await User.create({
      username,
      password   // plain password
    });

    const token = await signTokenForUser(user);
    res.json({ msg: 'Ro‘yxatdan o‘tildi', user: { id: user._id, username: user.username }, token });
  } catch (e) {
    console.error('REGISTER ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ msg: 'Username va password majburiy' });
    const user = await User.findOne({ username }).select('+password +tokenVersion +role');
    if (!user) return res.status(400).json({ msg: 'User topilmadi' });
    const match = await user.comparePassword(password);
    if (!match) return res.status(400).json({ msg: 'Parol noto‘g‘ri' });
    const token = await signTokenForUser(user);
    res.json({ msg: 'Login muvaffaqiyatli', token });
  } catch (e) {
    console.error('LOGIN ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

// logout / revoke tokens for user by incrementing tokenVersion
app.post('/auth/logout', authMiddleware, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { $inc: { tokenVersion: 1 } });
    // selectively invalidate this user's caches
    invalidateUserPostsCache(req.user.id);
    return res.json({ msg: 'Chiqish amalga oshirildi' });
  } catch (e) {
    console.error('LOGOUT ERROR:', e);
    return res.status(500).json({ msg: 'Server xatosi' });
  }
});

// -----------------
// Uploads
// -----------------
app.post('/upload/avatar', authMiddleware, avatarUpload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ msg: 'Avatar yuklanmadi' });
  try {
    const ok = await validateFileMagic(req.file.path, ['image/']);
    if (!ok) { fs.unlinkSync(req.file.path); return res.status(400).json({ msg: 'Avatar fayli yaroqsiz yoki manipulyatsiya qilingan' }); }

    const user = await User.findById(req.user.id);
    if (!user) { fs.unlinkSync(req.file.path); return res.status(404).json({ msg: 'Foydalanuvchi topilmadi' }); }

    // remove previous avatar if stored locally and inside avatars dir
    if (user.avatar && user.avatar.startsWith(MEDIA_BASE_URL)) {
      try {
        const rel = user.avatar.replace(MEDIA_BASE_URL, '');
        const disk = path.join(__dirname, rel);
        if (fs.existsSync(disk)) fs.unlinkSync(disk);
      } catch (e) { /* ignore */ }
    }

    user.avatar = `${MEDIA_BASE_URL}/avatars/${req.file.filename}`;
    await user.save();
    // avatar change may affect profile caches; invalidate only this user's feeds
    invalidateUserPostsCache(req.user.id);
    res.json({ msg: 'Avatar yangilandi', avatar: user.avatar });
  } catch (e) {
    console.error('AVATAR ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});
app.post('/upload', authMiddleware, mediaUpload.array('media', 5), async (req, res) => {
  try {
    const files = req.files || [];
    if (!files.length) return res.status(400).json({ msg: "Media yuklanmadi" });

    const hasVideo = files.some(f => (f.mimetype || "").startsWith("video/"));
    const hasImage = files.some(f => (f.mimetype || "").startsWith("image/"));

    if (hasVideo && hasImage) {
      files.forEach(f => fs.unlinkSync(f.path));
      return res.status(400).json({ msg: "Video va rasm aralashtirib bo‘lmaydi" });
    }

    if (hasVideo && files.length > 1) {
      files.forEach(f => fs.unlinkSync(f.path));
      return res.status(400).json({ msg: "Faqat bitta video mumkin" });
    }

    const uploads = [];

    for (const file of files) {
      const result = await cloudinary.uploader.upload(file.path, {
        resource_type: file.mimetype.startsWith("video") ? "video" : "image",
        folder: "intizom"
      });

      fs.unlinkSync(file.path); // remove local copy

      uploads.push({
        type: file.mimetype.startsWith("video") ? "video" : "image",
        url: result.secure_url
      });
    }

    const postDoc = await Post.create({
      userId: req.user.id,
      username: req.user.username,
      title: String(req.body.title || "").slice(0, 200),
      description: String(req.body.description || "").slice(0, 2000),
      type: hasVideo ? "video" : "carousel",
      media: uploads,
      status: "approved",
      likesCount: 0,
      views: 0,
      commentsCount: 0,
      createdAt: new Date()
    });

    // new post should invalidate caches for this user and guest caches
    invalidateUserPostsCache(req.user.id);

    res.json({ msg: "Post yaratildi", post: postDoc });
  } catch (e) {
    console.error("UPLOAD ERROR:", e);
    res.status(500).json({ msg: "Server xatosi" });
  }
});


// -----------------
// Media streaming (single implementation)
// -----------------
app.get('/media/:folder/:file', (req, res) => {
  res.setHeader("Cache-Control", "public, max-age=31536000, immutable");

  try {
    // FIXED: avoid wildcard origin when credentials are true — select origin from request if allowed
    const originToAllow = req.headers.origin && ALLOWED_ORIGINS.includes(req.headers.origin)
      ? req.headers.origin
      : ALLOWED_ORIGINS[0];
      
    res.setHeader('Access-Control-Allow-Origin', originToAllow);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Range, Content-Type, Authorization');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Range, Accept-Ranges, Content-Length');
    res.setHeader('Vary', 'Origin');

    // FIXED: explicitly override COEP/COOP/RO headers so autoplay and cross-origin embedding work in browsers
    res.setHeader('Cross-Origin-Embedder-Policy', 'unsafe-none');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

    const { folder, file } = req.params;
    const baseDir = path.join(PERSISTENT_MEDIA_ROOT, folder);
    const safePath = safeResolveWithin(baseDir, file);
    if (!safePath) return res.sendStatus(403);
    if (!fs.existsSync(safePath)) return res.sendStatus(404);

    const stat = fs.statSync(safePath);
    const fileSize = stat.size;
    const range = req.headers.range;
    const contentType = mime.lookup(safePath) || 'application/octet-stream';

    if (contentType.startsWith('video/')) {
      if (!range) {
        res.writeHead(200, {
          'Content-Length': fileSize,
          'Content-Type': contentType,
          'Accept-Ranges': 'bytes'
        });
        fs.createReadStream(safePath).pipe(res);
        return;
      }
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10) || 0;
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      const chunkSize = (end - start) + 1;
      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunkSize,
        'Content-Type': contentType
      });
      fs.createReadStream(safePath, { start, end }).pipe(res);
      return;
    }

    // image or other
    res.writeHead(200, {
      'Content-Length': fileSize,
      'Content-Type': contentType
    });
    fs.createReadStream(safePath).pipe(res);

  } catch (e) {
    console.error('MEDIA STREAM ERROR:', e);
    res.sendStatus(500);
  }
});

// -----------------
// Posts listing optimized for scale
// - uses Post stored counters (likesCount/commentsCount/views)
// - avoids aggregation per-request
// -----------------
app.get('/posts', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.max(1, Math.min(50, parseInt(req.query.limit || '10')));

    let currentUserId = null;
    let currentUsername = null;
    let followingSet = new Set();

    const auth = req.headers.authorization;
    if (auth) {
      try {
        const token = auth.split(' ')[1];
        const payload = jwt.verify(token, JWT_SECRET);
        currentUserId = payload.id;
        currentUsername = payload.username;
        const cached = await getCachedFollowing(currentUserId);
        if (cached) followingSet = cached;
        else {
          // support both followerId and follower fields for compatibility
          const follows = await Follow.find({ $or: [{ followerId: currentUserId }, { follower: currentUsername }] }).select('followingId following');
          const followingList = follows.map(f => (f.followingId ? String(f.followingId) : (f.following || '')));
          followingSet = new Set(followingList);
          await setCachedFollowing(currentUserId, followingList);
        }
      } catch (e) { /* ignore auth parse errors */ }
    }

    // CACHE CHECK (user-scoped)
    const userPart = currentUserId || 'guest';
    const cacheKey = `posts:${userPart}:${page}:${limit}:${req.query.feed || 'all'}`;
    const cached = postsCache.get(cacheKey);
    if (cached) {
      return res.json(cached);
    }

    const query = { status: 'approved' };
    // optionally allow filter by following
    if (req.query.feed === 'following' && currentUserId) {
      // if followingSet empty return empty results quickly
      if (!followingSet || followingSet.size === 0) {
        const emptyResponse = { page, limit, posts: [] };
        postsCache.set(cacheKey, emptyResponse);
        return res.json(emptyResponse);
      }
      // if followingSet contains userIds, match by userId; otherwise by username
      const userIdList = Array.from(followingSet).filter(s => mongoose.Types.ObjectId.isValid(s));
      if (userIdList.length > 0) query.userId = { $in: userIdList };
      else query.username = { $in: Array.from(followingSet) };
    }

    const posts = await Post.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    const postIds = posts.map(p => p._id);
    // liked set for user
    const likedSet = new Set();
    if (currentUserId && postIds.length) {
      const likes = await Like.find({ postId: { $in: postIds }, userId: currentUserId }).select('postId').lean();
      likes.forEach(l => likedSet.add(String(l.postId)));
    }

    const results = posts.map(p => {
      const pid = String(p._id);
      const postUser = p.username || (p.userId ? String(p.userId) : '');
      return {
        id: pid,
        user: postUser,
        title: p.title,
        description: p.description,
        type: p.type,
        media: p.media,
        createdAt: p.createdAt,
        views: p.views || 0,
        commentsCount: p.commentsCount || 0,
        likesCount: p.likesCount || 0,
        liked: currentUserId ? likedSet.has(pid) : false,
        isFollowing: postUser ? followingSet.has(postUser) : false
      };
    });

    // CACHE SAVE (user-scoped)
    const response = { page, limit, posts: results };
    postsCache.set(cacheKey, response);
    res.json(response);
  } catch (e) {
    console.error('GET POSTS ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

app.delete('/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const userId = req.params.id;

    await Post.deleteMany({ userId });
    await Follow.deleteMany({ $or: [{ followerId: userId }, { followingId: userId }] });
    await Like.deleteMany({ userId });
    await Message.deleteMany({ $or: [{ from: userId }, { to: userId }] });

    await User.findByIdAndDelete(userId);

    // admin deleted a user — invalidate everything for safety
    invalidateAllPostsCache();

    res.json({ msg: 'User to‘liq o‘chirildi' });
  } catch (e) {
    console.error('DELETE USER ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

// -----------------
// Like / Comment endpoints (atomic counters)
// -----------------
app.post('/posts/:id/like', authMiddleware, async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.user.id;

    try {
      await Like.create({ postId, userId, createdAt: new Date() });
      await Post.updateOne({ _id: postId }, { $inc: { likesCount: 1 } });
      // selective invalidation (only this user's posts + guest)
      invalidateUserPostsCache(userId);
    } catch (e) {
      if (e.code !== 11000) throw e;
    }

    const post = await Post.findById(postId).select('likesCount');
    res.json({ likesCount: post.likesCount });
  } catch (e) {
    console.error("LIKE ERROR:", e);
    res.status(500).json({ msg: "Server xatosi" });
  }
});


app.post('/posts/:id/unlike', authMiddleware, async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.user.id;

    const removed = await Like.findOneAndDelete({ postId, userId });
    if (removed) {
      await Post.updateOne({ _id: postId, likesCount: { $gt: 0 } }, { $inc: { likesCount: -1 } });
      invalidateUserPostsCache(userId);
    }

    const post = await Post.findById(postId).select('likesCount');
    res.json({ likesCount: post.likesCount });
  } catch (e) {
    console.error("UNLIKE ERROR:", e);
    res.status(500).json({ msg: "Server xatosi" });
  }
});


app.post('/posts/:id/comment', authMiddleware, async (req, res) => {
  try {
    const postId = req.params.id;
    const text = String(req.body.text || '').trim().slice(0, 2000);
    if (!text) return res.status(400).json({ msg: 'Comment bo‘sh bo‘lishi mumkin emas' });
    const c = await Comment.create({
      postId,
      user: req.user.username,   // MUHIM
      userId: req.user.id,
      text,
      createdAt: new Date()
    });
    await Post.updateOne({ _id: postId }, { $inc: { commentsCount: 1 } });
    // selective invalidation
    invalidateUserPostsCache(req.user.id);
    res.json({ msg: 'Comment qo‘shildi', comment: c });
  } catch (e) {
    console.error('COMMENT ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

// -----------------
// Follow / Unfollow
app.post('/follow/:username', authMiddleware, async (req, res) => {
  try {
    const followerId = req.user.id;
    const username = req.params.username;

    const targetUser = await User.findOne({ username }).select('_id');
    if (!targetUser) return res.status(404).json({ msg: 'User not found' });

    const followingId = targetUser._id;

    if (String(followerId) === String(followingId))
      return res.status(400).json({ msg: 'O‘zingizni follow qila olmaysiz' });

    await Follow.create({ followerId, followingId });

    // following affects "following" feed — invalidate only follower's posts cache + guest
    invalidateUserPostsCache(followerId);

    res.json({ msg: 'Follow qo‘shildi' });
  } catch (e) {
    if (e.code === 11000) return res.json({ msg: 'Already following' });
    console.error('FOLLOW ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

app.post('/unfollow/:username', authMiddleware, async (req, res) => {
  try {
    const followerId = req.user.id;
    const username = req.params.username;

    const targetUser = await User.findOne({ username }).select('_id');
    if (!targetUser) return res.status(404).json({ msg: 'User not found' });

    await Follow.deleteOne({
      followerId,
      followingId: targetUser._id
    });

    invalidateUserPostsCache(followerId);

    res.json({ msg: 'Unfollow qilindi' });
  } catch (e) {
    console.error('UNFOLLOW ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

// -----------------
// Simple admin approve endpoint to mark posts approved
// -----------------
app.post('/admin/posts/:id/approve', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    await Post.updateOne({ _id: id }, { $set: { status: 'approved' } });
    // approved posts can affect feeds; invalidate all to be safe
    invalidateAllPostsCache();
    res.json({ msg: 'Post approved' });
  } catch (e) {
    console.error('ADMIN APPROVE ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

// -----------------
// Socket.IO (with Redis adapter if available)
// -----------------
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);

      const allowed = ALLOWED_ORIGINS.some(o =>
        origin === o || origin.startsWith(o)
      );

      if (allowed) return callback(null, true);

      console.log("SOCKET CORS BLOCKED:", origin);
      return callback(null, false);
    },
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Redis adapter (ixtiyoriy)
(async function attachRedisAdapter() {
  if (!redisAvailable || !redisClient) return;
  try {
    const { createAdapter } = require('@socket.io/redis-adapter');
    io.adapter(createAdapter(redisClient, redisClient.duplicate()));
    console.log('Socket.IO Redis adapter attached');
  } catch (e) {
    console.warn('Socket.IO adapter error', e.message || e);
  }
})();

// Socket auth middleware
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;
    if (!token) return next(new Error('Token topilmadi'));

    const payload = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(payload.id).select('+tokenVersion +username +role');
    if (!user) return next(new Error('Token noto‘g‘ri'));

    if ((user.tokenVersion || 0) !== (payload.tv || 0))
      return next(new Error('Token bekor qilingan'));

    socket.user = {
      id: String(user._id),
      username: user.username,
      role: user.role
    };

    return next();
  } catch (e) {
    return next(new Error('Token noto‘g‘ri'));
  }
});

// Socket connection
io.on('connection', socket => {
  const username = socket.user.username;

  socket.join(username);
  global.onlineUsers.add(username);
io.emit('online_users', Array.from(global.onlineUsers));

  socket.emit('connected', { msg: 'connected', username });

  console.log("Socket connected:", username);


  // manage online set (Redis-backed if available)
  (async () => {
    try {
      if (redisAvailable && redisClient) {
        await redisClient.sadd('online_users', username);
        const members = await redisClient.smembers('online_users');
        io.emit('online_users', members);
      } else {
        if (!global.onlineUsers) global.onlineUsers = new Set();
        global.onlineUsers.add(username);
        io.emit('online_users', Array.from(global.onlineUsers));
      }
    } catch (e) { console.warn('online update failed', e.message || e); }
  })();

  socket.on('disconnect', async () => {
    
    try {
      if (redisAvailable && redisClient) {
        await redisClient.srem('online_users', username);
        const members = await redisClient.smembers('online_users');
        io.emit('online_users', members);
      } else {
        global.onlineUsers.delete(username);
        io.emit('online_users', Array.from(global.onlineUsers));
      }
    } catch (e) { console.warn('online remove failed', e.message || e); }
  });
global.onlineUsers.delete(username);
io.emit('online_users', Array.from(global.onlineUsers));

  socket.on('typing', (data) => {
    const { to } = data || {};
    if (to) io.to(to).emit('typing', { from: username });
  });

  socket.on('private_message', async (data) => {
    try {
      const { to, text } = data || {};
      if (!to || !text || !String(text).trim()) return;
      const msg = await Message.create({ from: username, to, text: String(text).trim(), createdAt: new Date() });
      io.to(to).emit('private_message', msg);
      io.to(username).emit('private_message', msg);
    } catch (e) { console.error('SOCKET PRIVATE_MESSAGE ERROR:', e); }
  });
});

// -----------------
// Graceful shutdown
// -----------------
async function shutdown() {
  try {
    console.log('Shutting down...');
    await mongoose.disconnect();
    server.close(() => {
      console.log('HTTP server closed');
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000);
  } catch (e) {
    console.error('Shutdown error', e);
    process.exit(1);
  }
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
app.get('/follow/check/:identifier', authMiddleware, async (req, res) => {
  try {
    const id = req.user.id;
    const target = req.params.identifier;

    let targetUserId = null;
    if (mongoose.Types.ObjectId.isValid(target)) {
      targetUserId = target;
    } else {
      const u = await User.findOne({ username: target }).select('_id');
      if (u) targetUserId = String(u._id);
    }
    if (!targetUserId) return res.json({ isFollowing: false });

    const exists = await Follow.findOne({ followerId: id, followingId: targetUserId });
    res.json({ isFollowing: !!exists });
  } catch (e) {
    console.error('FOLLOW CHECK ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});
app.get('/posts/reels', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.max(1, Math.min(20, parseInt(req.query.limit || '5')));

    let userId = null;
    if (req.headers.authorization) {
      try {
        const token = req.headers.authorization.split(' ')[1];
        const payload = jwt.verify(token, JWT_SECRET);
        userId = payload.id;
      } catch {}
    }

    const query = { status: 'approved', type: 'video' };

    const docs = await Post.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    const ids = docs.map(p => p._id);

    let likedSet = new Set();
    if (userId && ids.length) {
      const likes = await Like.find({ postId: { $in: ids }, userId })
        .select('postId')
        .lean();
      likes.forEach(l => likedSet.add(String(l.postId)));
    }

    const total = await Post.countDocuments(query);

    res.json({
      posts: docs.map(p => ({
        ...p,
        id: String(p._id),
        userId: String(p.userId),
        // FIX: use _id (not _1)
        liked: userId ? likedSet.has(String(p._id)) : false
      })),
      hasMore: page * limit < total
    });
  } catch (e) {
    console.error('GET /posts/reels ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});
app.post('/posts/:id/view', async (req, res) => {
  try {
    let viewer = req.ip;
    if (req.headers.authorization) {
      try {
        const token = req.headers.authorization.split(' ')[1];
        const payload = jwt.verify(token, JWT_SECRET);
        viewer = payload.id;
      } catch {}
    }

    // Atomically increment views only if this viewer hasn't been recorded yet
    const result = await Post.updateOne(
      { _id: req.params.id, viewedBy: { $ne: viewer } },
      { $inc: { views: 1 }, $push: { viewedBy: viewer } }
    );

    res.json({ viewed: result.modifiedCount === 1 });
  } catch (e) {
    console.error('VIEW ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

app.get('/posts/:id/comments', authMiddleware, async (req, res) => {
  try {
    const postId = req.params.id;

    const comments = await Comment.find({ postId })
      .sort({ createdAt: 1 })
      .limit(200)
      .lean();

    res.json({
      comments: comments.map(c => ({
        id: String(c._id),
        user: c.user,        // MUHIM
        text: c.text,
        createdAt: c.createdAt
      }))
    });

  } catch (e) {
    console.error('GET COMMENTS ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});
app.get('/profile/:username', async (req, res) => {
  try {
    const u = await User.findOne({ username: req.params.username }).lean();
    if (!u) return res.status(404).json({ msg: 'User not found' });

    const postsCount = await Post.countDocuments({ userId: u._id, status: 'approved' });
    const followers = await Follow.countDocuments({ followingId: u._id });
    const following = await Follow.countDocuments({ followerId: u._id });

    res.json({
      username: u.username,
      avatar: u.avatar || null,
      bio: u.bio || '',
      website: u.website || '',
      posts: postsCount,
      followers,
      following
    });
  } catch (e) {
    console.error('GET PROFILE ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});
app.get('/posts/user/:username', async (req, res) => {
  try {
    const u = await User.findOne({ username: req.params.username }).select('_id username');
    if (!u) return res.json({ posts: [] });

    const posts = await Post.find({ userId: u._id, status: 'approved' })
      .sort({ createdAt: -1 })
      .lean();

    res.json({
      posts: posts.map(p => ({
        ...p,
        id: String(p._id),
        user: u.username,
        username: u.username,
        userId: String(p.userId)
      }))
    });
  } catch (e) {
    console.error('GET USER POSTS ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

app.get('/profile/:username/followers', async (req, res) => {
  try {
    const u = await User.findOne({ username: req.params.username }).select('_id username');
    if (!u) return res.json([]);

    const followers = await Follow.find({ followingId: u._id })
      .populate('followerId', 'username avatar')
      .lean();

    res.json(followers.map(f => ({
      username: f.followerId.username,
      avatar: f.followerId.avatar || null
    })));
  } catch (e) {
    console.error('GET FOLLOWERS ERROR:', e);
    res.status(500).json([]);
  }
});
app.get('/profile/:username/following', async (req, res) => {
  try {
    const u = await User.findOne({ username: req.params.username }).select('_id username');
    if (!u) return res.json([]);

    const following = await Follow.find({ followerId: u._id })
      .populate('followingId', 'username avatar')
      .lean();

    res.json(following.map(f => ({
      username: f.followingId.username,
      avatar: f.followingId.avatar || null
    })));
  } catch (e) {
    console.error('GET FOLLOWING ERROR:', e);
    res.status(500).json([]);
  }
});
app.put('/profile', authMiddleware, async (req, res) => {
  try {
    const { bio = "", website = "" } = req.body;

    await User.findByIdAndUpdate(req.user.id, {
      $set: {
        bio: String(bio).slice(0, 160),
        website: String(website).slice(0, 200)
      }
    });

    // profile update may affect feeds for this user
    invalidateUserPostsCache(req.user.id);

    res.json({ msg: 'Profile updated' });
  } catch (e) {
    console.error('PROFILE UPDATE ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});
// =======================
// MESSAGES API
// =======================

// Chat list
app.get('/chats', authMiddleware, async (req, res) => {
  try {
    const me = req.user.username;

    const sent = await Message.find({ from: me }).select('to text createdAt').lean();
    const received = await Message.find({ to: me }).select('from text createdAt').lean();

    const map = {};

    sent.forEach(m => {
      if (!map[m.to] || map[m.to].createdAt < m.createdAt) {
        map[m.to] = { username: m.to, lastMessage: m.text, createdAt: m.createdAt };
      }
    });

    received.forEach(m => {
      if (!map[m.from] || map[m.from].createdAt < m.createdAt) {
        map[m.from] = { username: m.from, lastMessage: m.text, createdAt: m.createdAt };
      }
    });

    const chats = Object.values(map).sort((a, b) => b.createdAt - a.createdAt);

    res.json(chats);
  } catch (e) {
    console.error('GET /chats ERROR', e);
    res.status(500).json([]);
  }
});

// Load messages
app.get('/messages/:username', authMiddleware, async (req, res) => {
  try {
    const me = req.user.username;
    const other = req.params.username;

    const msgs = await Message.find({
      $or: [
        { from: me, to: other },
        { from: other, to: me }
      ]
    }).sort({ createdAt: 1 });

    res.json(msgs);
  } catch (e) {
    console.error('GET /messages ERROR', e);
    res.status(500).json([]);
  }
});

// Send message
app.post('/messages', authMiddleware, async (req, res) => {
  try {
    const { to, text } = req.body;
    const from = req.user.username;

    const msg = await Message.create({
      from,
      to,
      text,
      createdAt: new Date()
    });

    res.json({ message: msg });
  } catch (e) {
    console.error('POST /messages ERROR', e);
    res.status(500).json({ msg: 'Server error' });
  }
});
app.get('/users/search', authMiddleware, async (req, res) => {
  try {
    const q = String(req.query.q || '').trim().toLowerCase();
    if (!q) return res.json([]);

    const users = await User.find({
      username: { $regex: q, $options: 'i' }
    })
      .select('username avatar')
      .limit(20)
      .lean();

    res.json(users.map(u => ({
      id: String(u._id),
      username: u.username,
      avatar: u.avatar || null
    })));
  } catch (e) {
    console.error('USER SEARCH ERROR:', e);
    res.status(500).json([]);
  }
});
app.put('/auth/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ msg: 'Barcha maydonlar majburiy' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ msg: 'Yangi parol kamida 6 belgidan iborat bo‘lishi kerak' });
    }

    // foydalanuvchini eski paroli bilan yuklaymiz
    const user = await User.findById(req.user.id).select('+password +tokenVersion');
    if (!user) return res.status(404).json({ msg: 'Foydalanuvchi topilmadi' });

    const ok = await user.comparePassword(currentPassword);
    if (!ok) {
      return res.status(400).json({ msg: 'Joriy parol noto‘g‘ri' });
    }

    // yangi parolni qo‘yamiz (pre("save") hash qiladi)
    user.password = newPassword;
    user.tokenVersion = (user.tokenVersion || 0) + 1; // eski tokenlarni bekor qilamiz
    await user.save();

    res.json({ msg: 'Parol muvaffaqiyatli yangilandi' });
  } catch (e) {
    console.error('CHANGE PASSWORD ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});
app.get('/admin/posts', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.min(50, parseInt(req.query.limit || '20'));

    const posts = await Post.find({})
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    res.json(posts);
  } catch (e) {
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

app.delete('/admin/posts/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ msg: 'Post topilmadi' });

    for (const m of post.media || []) {
      // try/catch per file
      try {
        const rel = m.url.replace(MEDIA_BASE_URL + '/media/', '');
        const disk = path.join(PERSISTENT_MEDIA_ROOT, rel);
        if (fs.existsSync(disk)) fs.unlinkSync(disk);
      } catch (e) { /* ignore file removal errors */ }
    }

    await Post.deleteOne({ _id: post._id });

    invalidateAllPostsCache();

    res.json({ msg: 'Post va media to‘liq o‘chirildi' });
  } catch (e) {
    res.status(500).json({ msg: 'Server xatosi' });
  }
});
app.get('/posts/:id', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id).lean();
    if (!post) return res.status(404).json({ msg: 'Post topilmadi' });
    res.json({
      ...post,
      id: String(post._id),
      user: post.username,
      userId: String(post.userId)
    });
  } catch (e) {
    res.status(500).json({ msg: 'Server xatosi' });
  }
});
app.get('/admin/media', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const files = [];

    const walk = dir => {
      fs.readdirSync(dir).forEach(f => {
        const full = path.join(dir, f);
        if (fs.statSync(full).isDirectory()) walk(full);
        else files.push(full.replace(PERSISTENT_MEDIA_ROOT, ''));
      });
    };

    walk(PERSISTENT_MEDIA_ROOT);

    res.json(files);
  } catch (e) {
    res.status(500).json({ msg: 'Server xatosi' });
  }
});
app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('username role');
    res.json(user);
  } catch {
    res.status(401).json({ msg: 'Unauthorized' });
  }
});
app.get('/users/online', authMiddleware, (req, res) => {
  res.json(Array.from(global.onlineUsers));
});

app.get('/users/all', authMiddleware, async (req, res) => {
  const users = await User.find().select('username avatar').lean();
  res.json(users);
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    memory: process.memoryUsage().rss
  });
});

// -----------------
// Start server
// -----------------
const PORT = process.env.PORT || 10000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server listening on ${PORT}`);
});
