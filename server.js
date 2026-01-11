// server.js (production-minded MVP) — fixed & consolidated version
// Required env:
// - JWT_SECRET (required)
// - MONGO_URL (recommended; but your ./db module may handle it)
// - MEDIA_BASE_URL (optional, default http://localhost:5000)
// - PERSISTENT_MEDIA_ROOT (optional, default path.join(__dirname, 'media'))
// - REDIS_URL (optional)

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
const { Server } = require('socket.io');
const mime = require('mime-types');
const FileType = require('file-type');
const mongoose = require('mongoose');
const cookieParser = require("cookie-parser");

const adminDomainOnly = require('./middlewares/adminDomainOnly');
const adminIpOnly = require('./middlewares/adminIpOnly');
const adminLoginLimiter = require('./middlewares/adminLoginLimiter');

const app = express();
const connectDB = require("./config/connectDB");
if (!global.onlineUsers) global.onlineUsers = new Set();
app.set('trust proxy', true);
app.use(cookieParser());

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
const RefreshToken = require('./models/RefreshToken');

// -----------------
// Security middlewares
// -----------------
app.use(helmet({
  contentSecurityPolicy: false // tune CSP in production as needed
}));

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    const allowed = ALLOWED_ORIGINS.includes(origin);
    callback(null, allowed);
  },
  credentials: true
}));

app.use(express.json({ limit: '1mb' }));

// -----------------
// Rate limiting
// -----------------
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { msg: 'Too many auth attempts, try again later' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/auth', authLimiter);

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 150,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/posts', apiLimiter);
app.use('/follow', apiLimiter);
app.use('/messages', apiLimiter);

const viewLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
});

// -----------------
// Ensure media dirs
// -----------------
function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

ensureDir(path.join(PERSISTENT_MEDIA_ROOT, 'videos'));
ensureDir(path.join(PERSISTENT_MEDIA_ROOT, 'images'));

// Note: AVATAR_ROOT and serving avatars statically removed — avatars will be uploaded to Cloudinary via memory upload.

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
// Lightweight LRU for in-memory caches
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
// Multer storages + filters
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

// Avatar upload — switched to memory storage (no local avatars dir)
const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

// -----------------
// Auth helpers (JWT includes tokenVersion for revocation)
// -----------------
function signAccessToken(user) {
  return jwt.sign(
    {
      id: String(user._id),
      username: user.username,
      role: user.role,
      tv: user.tokenVersion || 0
    },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
}

function signRefreshToken() {
  return crypto.randomBytes(40).toString('hex');
}

async function createRefreshToken(user) {
  const rawToken = signRefreshToken();
  const hash = crypto.createHash('sha256').update(rawToken).digest('hex');

  await RefreshToken.create({
    userId: user._id,
    tokenHash: hash,
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
  });

  return rawToken;
}

// Centralized cookie setter/clearer
function setAuthCookies(res, accessToken, refreshToken) {
  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    domain: ".intizom.org",
    path: "/",
    maxAge: 15 * 60 * 1000
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    domain: ".intizom.org",
    path: "/auth/refresh",
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
}



// Clear auth cookies on logout
function clearAuthCookies(res) {
  res.clearCookie("accessToken", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    domain: ".intizom.org",
    path: "/"
  });

  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    domain: ".intizom.org",
    path: "/auth/refresh"
  });
}



// -----------------
// REPLACED: authMiddleware (uses accessToken cookie)
// -----------------
async function authMiddleware(req, res, next) {
  const token = req.cookies?.accessToken;
  if (!token) return res.status(401).json({ msg: 'Unauthorized' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.id).select('+tokenVersion +username +role');
    if (!user) return res.status(401).json({ msg: 'Unauthorized' });
    if ((user.tokenVersion || 0) !== (payload.tv || 0)) return res.status(401).json({ msg: 'Token revoked' });

    req.user = { id: String(user._id), username: user.username, role: user.role };

    return next();
  } catch (e) {
    return res.status(401).json({ msg: 'Unauthorized' });
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
      if (key.startsWith('posts:guest:')) postsCache.delete(key);
    }
  } catch (e) {
    console.warn('invalidateUserPostsCache failed', e && e.message ? e.message : e);
  }
}

// -----------------
// Routes: Auth
// -----------------
app.post("/auth/register", authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ msg: "Username va password majburiy" });

    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ msg: "Username band" });

    const user = await User.create({ username, password });

    const accessToken = signAccessToken(user);
    const refreshToken = await createRefreshToken(user);

    setAuthCookies(res, accessToken, refreshToken);

    res.json({ msg: "Ro‘yxatdan o‘tildi" });
  } catch (e) {
    console.error("REGISTER ERROR:", e);
    res.status(500).json({ msg: "Server xatosi" });
  }
});

app.post("/auth/login", authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ msg: "Username va password majburiy" });

    const user = await User.findOne({ username }).select("+password +tokenVersion +role");
    if (!user) return res.status(400).json({ msg: "User topilmadi" });

    const ok = await user.comparePassword(password);
    if (!ok) return res.status(400).json({ msg: "Parol noto‘g‘ri" });

    const accessToken = signAccessToken(user);
    const refreshToken = await createRefreshToken(user);

    setAuthCookies(res, accessToken, refreshToken);

    res.json({ msg: "Login muvaffaqiyatli" });
  } catch (e) {
    console.error("LOGIN ERROR:", e);
    res.status(500).json({ msg: "Server xatosi" });
  }
});

// Refresh endpoint: rotate refresh token and return new access token
app.post('/auth/refresh', async (req, res) => {
  try {
    const raw = req.cookies?.refreshToken;
    if (!raw) return res.status(401).json({ msg: 'Refresh token topilmadi' });

    const hash = crypto.createHash('sha256').update(String(raw)).digest('hex');

    const tokenDoc = await RefreshToken.findOne({ tokenHash: hash });
    if (!tokenDoc) return res.status(401).json({ msg: 'Refresh token noto‘g‘ri' });
    if (tokenDoc.expiresAt && tokenDoc.expiresAt < new Date()) {
      await RefreshToken.deleteOne({ _id: tokenDoc._id });
      return res.status(401).json({ msg: 'Refresh token muddati o‘tgan' });
    }

    const user = await User.findById(tokenDoc.userId).select('+tokenVersion +username +role');
    if (!user) return res.status(401).json({ msg: 'Foydalanuvchi topilmadi' });

    // rotate: remove used token and create a new one
    await RefreshToken.deleteOne({ _id: tokenDoc._id });

    const newRefresh = await createRefreshToken(user);
    const newAccess = signAccessToken(user);

    setAuthCookies(res, newAccess, newRefresh);

    res.json({ msg: 'Tokens refreshed' });
  } catch (e) {
    console.error('REFRESH ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

// logout / revoke tokens for user by incrementing tokenVersion
app.post('/auth/logout', authMiddleware, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { $inc: { tokenVersion: 1 } });
    try { await RefreshToken.deleteMany({ userId: req.user.id }); } catch (e) { console.warn('Failed to remove refresh tokens', e.message || e); }
    invalidateUserPostsCache(req.user.id);

    clearAuthCookies(res);

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
  try {
    if (!req.file) return res.status(400).json({ msg: 'Avatar yuklanmadi' });

    const result = await cloudinary.uploader.upload_stream({
      folder: 'intizom/avatars',
      resource_type: 'image'
    }, async (err, uploaded) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ msg: 'Cloudinary xatosi' });
      }

      const user = await User.findById(req.user.id);
      user.avatar = uploaded.secure_url;
      await user.save();

      res.json({ msg: 'Avatar yangilandi', avatar: uploaded.secure_url });
    });

    result.end(req.file.buffer);
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
    const originToAllow = req.headers.origin && ALLOWED_ORIGINS.includes(req.headers.origin)
      ? req.headers.origin
      : ALLOWED_ORIGINS[0];

    res.setHeader('Access-Control-Allow-Origin', originToAllow);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Range, Content-Type, Authorization');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Range, Accept-Ranges, Content-Length');
    res.setHeader('Vary', 'Origin');

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
// -----------------
app.get('/posts', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.max(1, Math.min(50, parseInt(req.query.limit || '10')));

    let currentUserId = null;
    let currentUsername = null;
    let followingSet = new Set();

    if (req.cookies?.accessToken) {
      try {
        const payload = jwt.verify(req.cookies.accessToken, JWT_SECRET);
        currentUserId = payload.id;
        currentUsername = payload.username;
        const cached = await getCachedFollowing(currentUserId);
        if (cached) followingSet = cached;
        else {
          const follows = await Follow.find({ $or: [{ followerId: currentUserId }, { follower: currentUsername }] }).select('followingId following');
          const followingList = follows.map(f => (f.followingId ? String(f.followingId) : (f.following || '')));
          followingSet = new Set(followingList);
          await setCachedFollowing(currentUserId, followingList);
        }
      } catch (e) { /* ignore auth parse errors */ }
    }

    const userPart = currentUserId || 'guest';
    const cacheKey = `posts:${userPart}:${page}:${limit}:${req.query.feed || 'all'}`;
    const cached = postsCache.get(cacheKey);
    if (cached) {
      return res.json(cached);
    }

    const query = { status: 'approved' };
    if (req.query.feed === 'following' && currentUserId) {
      if (!followingSet || followingSet.size === 0) {
        const emptyResponse = { page, limit, posts: [] };
        postsCache.set(cacheKey, emptyResponse);
        return res.json(emptyResponse);
      }
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

    const response = { page, limit, posts: results };
    postsCache.set(cacheKey, response);
    res.json(response);
  } catch (e) {
    console.error('GET POSTS ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

// -----------------
// Specific endpoints (kept singular / deduped)
// -----------------
app.get('/posts/reels', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.max(1, Math.min(20, parseInt(req.query.limit || '5')));

    let userId = null;
    if (req.cookies?.accessToken) {
      try {
        const payload = jwt.verify(req.cookies.accessToken, JWT_SECRET);
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
      const likes = await Like.find({ postId: { $in: ids }, userId }).select('postId').lean();
      likes.forEach(l => likedSet.add(String(l.postId)));
    }

    const total = await Post.countDocuments(query);

    res.json({
      posts: docs.map(p => ({
        ...p,
        id: String(p._id),
        userId: String(p.userId),
        liked: userId ? likedSet.has(String(p._id)) : false
      })),
      hasMore: page * limit < total
    });
  } catch (e) {
    console.error('GET /posts/reels ERROR:', e);
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

// Like / Unlike / Comment endpoints
app.post('/posts/:id/like', authMiddleware, async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.user.id;

    try {
      await Like.create({ postId, userId, createdAt: new Date() });
      await Post.updateOne({ _id: postId }, { $inc: { likesCount: 1 } });
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
      user: req.user.username,
      userId: req.user.id,
      text,
      createdAt: new Date()
    });
    await Post.updateOne({ _id: postId }, { $inc: { commentsCount: 1 } });
    invalidateUserPostsCache(req.user.id);
    res.json({ msg: 'Comment qo‘shildi', comment: c });
  } catch (e) {
    console.error('COMMENT ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

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

// Admin endpoints (delete user / posts)
app.delete('/admin/users/:id',
  adminDomainOnly,
  authMiddleware,
  adminMiddleware,
  adminIpOnly,
  async (req, res) => {
    try {
      const userId = req.params.id;

      await Post.deleteMany({ userId });
      await Follow.deleteMany({ $or: [{ followerId: userId }, { followingId: userId }] });
      await Like.deleteMany({ userId });
      await Message.deleteMany({ $or: [{ from: userId }, { to: userId }] });

      await User.findByIdAndDelete(userId);

      invalidateAllPostsCache();

      res.json({ msg: 'User to‘liq o‘chirildi' });
    } catch (e) {
      console.error('DELETE USER ERROR:', e);
      res.status(500).json({ msg: 'Server xatosi' });
    }
  }
);

app.post('/admin/posts/:id/approve',
  adminDomainOnly,
  authMiddleware,
  adminMiddleware,
  adminIpOnly,
  async (req, res) => {
    try {
      const id = req.params.id;
      await Post.updateOne({ _id: id }, { $set: { status: 'approved' } });
      invalidateAllPostsCache();
      res.json({ msg: 'Post approved' });
    } catch (e) {
      console.error('ADMIN APPROVE ERROR:', e);
      res.status(500).json({ msg: 'Server xatosi' });
    }
  }
);

app.delete('/admin/posts/:id',
  adminDomainOnly,
  authMiddleware,
  adminMiddleware,
  adminIpOnly,
  async (req, res) => {
    try {
      const post = await Post.findById(req.params.id);
      if (!post) return res.status(404).json({ msg: 'Post topilmadi' });

      for (const m of post.media || []) {
        try {
          // If media stored as local file under PERSISTENT_MEDIA_ROOT/media/... remove safely
          const rel = (m.url || '').replace(MEDIA_BASE_URL + '/media/', '');
          const disk = safeResolveWithin(PERSISTENT_MEDIA_ROOT, rel);
          if (disk && fs.existsSync(disk)) fs.unlinkSync(disk);
        } catch (e) { /* ignore file removal errors */ }
      }

      await Post.deleteOne({ _id: post._id });

      invalidateAllPostsCache();

      res.json({ msg: 'Post va media to‘liq o‘chirildi' });
    } catch (e) {
      console.error('ADMIN DELETE POST ERROR:', e);
      res.status(500).json({ msg: 'Server xatosi' });
    }
  }
);
app.get(
  "/admin/posts",
  adminDomainOnly,
  authMiddleware,
  adminMiddleware,
  adminIpOnly,
  async (req, res) => {
    try {
      const posts = await Post.find({})
        .sort({ createdAt: -1 })
        .limit(200)
        .lean();

      res.json(posts);
    } catch (e) {
      res.status(500).json({ msg: "Postlarni olishda xatolik" });
    }
  }
);


// -----------------
// View endpoint (atomic views + viewer dedupe)
// -----------------
app.post('/posts/:id/view', viewLimiter, async (req, res) => {
  try {
    let viewer = req.ip;
    if (req.cookies?.accessToken) {
      try {
        const payload = jwt.verify(req.cookies.accessToken, JWT_SECRET);
        viewer = payload.id;
      } catch {}
    }

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

// Comments, profile, search, messages (kept as before)
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
        user: c.user,
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

    invalidateUserPostsCache(req.user.id);

    res.json({ msg: 'Profile updated' });
  } catch (e) {
    console.error('PROFILE UPDATE ERROR:', e);
    res.status(500).json({ msg: 'Server xatosi' });
  }
});

// Messages API
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
    console.error('GET /messages ERROR:', e);
    res.status(500).json([]);
  }
});

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
    console.error('POST /messages ERROR:', e);
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

    const user = await User.findById(req.user.id).select('+password +tokenVersion');
    if (!user) return res.status(404).json({ msg: 'Foydalanuvchi topilmadi' });

    const ok = await user.comparePassword(currentPassword);
    if (!ok) {
      return res.status(400).json({ msg: 'Joriy parol noto‘g‘ri' });
    }

    user.password = newPassword;
    user.tokenVersion = (user.tokenVersion || 0) + 1; // revoke old tokens
    await user.save();

    clearAuthCookies(res); // tokens invalidated; require re-login or refresh via cookie route

    res.json({ msg: 'Parol muvaffaqiyatli yangilandi' });
  } catch (e) {
    console.error('CHANGE PASSWORD ERROR:', e);
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
      const allowed = ALLOWED_ORIGINS.includes(origin);
      if (allowed) return callback(null, true);
      console.log("SOCKET CORS BLOCKED:", origin);
      callback(null, false);
    },
    methods: ['GET', 'POST'],
    credentials: true
  }
});


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

// robust cookie parser for socket requests
function parseCookieHeader(cookieHeader) {
  const map = {};
  if (!cookieHeader) return map;
  cookieHeader.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx < 0) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    try { map[k] = decodeURIComponent(v); } catch { map[k] = v; }
  });
  return map;
}

// Socket auth middleware: require accessToken cookie only
io.use(async (socket, next) => {
  try {
    const cookieHeader = socket.request.headers.cookie || "";
    const cookies = parseCookieHeader(cookieHeader);
    const token = cookies.accessToken;
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

// manage online count
let onlineCount = 0;

io.on('connection', socket => {
  onlineCount++;

  const username = socket.user.username;

  socket.join(username);
  global.onlineUsers.add(username);
  io.emit('online_users', Array.from(global.onlineUsers));

  socket.emit('connected', { msg: 'connected', username });

  console.log("Socket connected:", username);

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
    onlineCount--;
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
// Follow check, stats, misc
// -----------------
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

app.get('/stats', async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    res.json({
      totalUsers: usersCount,
      onlineUsers: onlineCount
    });
  } catch (e) {
    res.status(500).json({ totalUsers: 0, onlineUsers: 0 });
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
