import express from "express";
import path from "path";
import cors from "cors";
import morgan from "morgan";
import favicon from 'serve-favicon';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import multer from 'multer';
import bodyParser from 'body-parser';
import mime from 'mime';
import dotenv from 'dotenv';
import { dirname } from 'path';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import { body, validationResult } from 'express-validator';
import crypto from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));

dotenv.config();

const getPositiveIntegerEnv = (name, fallback) => {
    const value = Number.parseInt(process.env[name], 10);
    return Number.isSafeInteger(value) && value > 0 ? value : fallback;
};

const allowedOrigins = new Set(
    (process.env.CORS_ORIGINS || '')
        .split(',')
        .map(origin => origin.trim())
        .filter(Boolean)
);

// Validate required environment variables
const requiredEnvVars = ['JWT', 'RKEY'];
for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        console.error(`Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
}

const app = express();

// Trust proxy for rate limiting behind Cloudflare/reverse proxy
app.set('trust proxy', 1);

// Simple JSON-based database
class SimpleDB {
    constructor() {
        this.dbPath = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
        this.usersPath = path.join(this.dbPath, 'users.json');
        this.filesPath = path.join(this.dbPath, 'files.json');
        this.sessionsPath = path.join(this.dbPath, 'sessions.json');

        // Create data directory
        if (!fs.existsSync(this.dbPath)) {
            fs.mkdirSync(this.dbPath, { recursive: true, mode: 0o700 });
        } else {
            fs.chmodSync(this.dbPath, 0o700);
        }

        // Initialize database files
        this.initDB();
    }

    initDB() {
        for (const dbFile of [this.usersPath, this.filesPath, this.sessionsPath]) {
            if (!fs.existsSync(dbFile)) {
                fs.writeFileSync(dbFile, JSON.stringify([], null, 2), { mode: 0o600 });
            } else {
                fs.chmodSync(dbFile, 0o600);
            }
        }
    }

    readData(filePath) {
        try {
            const data = fs.readFileSync(filePath, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            return [];
        }
    }

    writeData(filePath, data) {
        const temporaryPath = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
        fs.writeFileSync(temporaryPath, JSON.stringify(data, null, 2), { mode: 0o600 });
        fs.renameSync(temporaryPath, filePath);
    }

    // User operations
    async getUser(username) {
        const users = this.readData(this.usersPath);
        return users.find(user => user.username === username);
    }

    async createUser(username, password) {
        const users = this.readData(this.usersPath);
        const newUser = {
            id: users.length + 1,
            username,
            password,
            created_at: new Date().toISOString()
        };
        users.push(newUser);
        this.writeData(this.usersPath, users);
        return newUser;
    }

    async deleteUser(username) {
        const users = this.readData(this.usersPath);
        const filteredUsers = users.filter(user => user.username !== username);
        this.writeData(this.usersPath, filteredUsers);
        return users.length !== filteredUsers.length;
    }

    // File operations
    async getFile(fileID) {
        const files = this.readData(this.filesPath);
        return files.find(file => file.fileID === fileID);
    }

    async getFilesByOwner(owner) {
        const files = this.readData(this.filesPath);
        return files.filter(file => file.owner === owner);
    }

    async createFile(fileData) {
        const files = this.readData(this.filesPath);
        const newFile = {
            id: files.length + 1,
            ...fileData,
            created_at: new Date().toISOString()
        };
        files.push(newFile);
        this.writeData(this.filesPath, files);
        return newFile;
    }

    async deleteFile(fileID) {
        const files = this.readData(this.filesPath);
        const filteredFiles = files.filter(file => file.fileID !== fileID);
        this.writeData(this.filesPath, filteredFiles);
        return files.length !== filteredFiles.length;
    }

    async deleteFilesByOwner(owner) {
        const files = this.readData(this.filesPath);
        const deletedFiles = files.filter(file => file.owner === owner);
        this.writeData(this.filesPath, files.filter(file => file.owner !== owner));
        return deletedFiles;
    }

    // Session operations
    async getSession(sessionID) {
        const sessions = this.readData(this.sessionsPath);
        return sessions.find(session => session.session_id === sessionID);
    }

    async createSession(sessionData) {
        const sessions = this.readData(this.sessionsPath);
        const newSession = {
            id: sessions.length + 1,
            ...sessionData,
            created_at: new Date().toISOString()
        };
        sessions.push(newSession);
        this.writeData(this.sessionsPath, sessions);
        return newSession;
    }

    async deleteSession(sessionID) {
        const sessions = this.readData(this.sessionsPath);
        const filteredSessions = sessions.filter(session => session.session_id !== sessionID);
        this.writeData(this.sessionsPath, filteredSessions);
        return sessions.length !== filteredSessions.length;
    }

    async updateSession(sessionID, changes) {
        const sessions = this.readData(this.sessionsPath);
        const session = sessions.find(item => item.session_id === sessionID);
        if (!session) {
            return null;
        }
        Object.assign(session, changes);
        this.writeData(this.sessionsPath, sessions);
        return session;
    }

    async cleanupExpiredSessions() {
        const sessions = this.readData(this.sessionsPath);
        const now = new Date();
        const activeSessions = sessions.filter(session => new Date(session.expires_at) > now);
        for (const session of sessions) {
            if (new Date(session.expires_at) <= now) {
                cleanupSessionDirectory(session.session_id);
            }
        }
        this.writeData(this.sessionsPath, activeSessions);
        return sessions.length - activeSessions.length;
    }

    // Statistics
    async getStats() {
        const users = this.readData(this.usersPath);
        const files = this.readData(this.filesPath);
        const sessions = this.readData(this.sessionsPath);

        const now = new Date();
        const activeSessions = sessions.filter(session => new Date(session.expires_at) > now && !session.completed_file_id);

        return {
            totalUsers: users.length,
            totalFiles: files.length,
            totalSize: files.reduce((sum, file) => sum + (file.size || 0), 0),
            activeSessions: activeSessions.length
        };
    }
}

const db = new SimpleDB();

// Create files directory if it doesn't exist
const filesDir = path.resolve(process.env.FILES_DIR || path.join(__dirname, 'files'));
if (!fs.existsSync(filesDir)) {
    fs.mkdirSync(filesDir, { recursive: true, mode: 0o700 });
}

// Create temp directory for chunked uploads
const tempDir = path.resolve(process.env.TEMP_DIR || path.join(__dirname, 'temp'));
if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true, mode: 0o700 });
}

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    crossOriginEmbedderPolicy: false, // Allow file downloads
}));

// Middleware
app.use(compression());
morgan.token('safe-url', req => {
    const url = new URL(req.originalUrl, 'http://localhost');
    for (const key of ['key', 'accessKey', 'token']) {
        if (url.searchParams.has(key)) {
            url.searchParams.set(key, '[redacted]');
        }
    }
    return `${url.pathname}${url.search}`;
});
app.use(morgan(':remote-addr - :remote-user [:date[clf]] ":method :safe-url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent"'));
app.use(favicon(path.join(__dirname, 'favicon.ico')));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: false, limit: '10mb' }));

// Serve static files from public directory
app.use('/public', express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag: true,
    lastModified: true
}));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(cors({
    // Native clients do not send Origin. Browser clients must be explicitly
    // allow-listed instead of reflecting every Origin with credentials.
    origin(origin, callback) {
        callback(null, !origin || allowedOrigins.has(origin));
    },
    credentials: process.env.CORS_ALLOW_CREDENTIALS === 'true',
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Chunk-Index', 'X-Total-Chunks', 'X-Private', 'X-Access-Key']
}));

const requestLimiter = rateLimit({
    windowMs: getPositiveIntegerEnv('RATE_LIMIT_WINDOW', 15 * 60 * 1000),
    limit: getPositiveIntegerEnv('RATE_LIMIT_MAX', 500),
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    skip: req => req.path.startsWith('/api/file/upload/chunk/') || req.path === '/health'
});
const authLimiter = rateLimit({
    windowMs: getPositiveIntegerEnv('AUTH_RATE_LIMIT_WINDOW', 15 * 60 * 1000),
    limit: getPositiveIntegerEnv('AUTH_RATE_LIMIT_MAX', 10),
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { errors: ['Too many authentication attempts, try again later'], success: false, data: null }
});
const uploadLimiter = rateLimit({
    windowMs: getPositiveIntegerEnv('UPLOAD_RATE_LIMIT_WINDOW', 60 * 60 * 1000),
    limit: getPositiveIntegerEnv('UPLOAD_RATE_LIMIT_MAX', 30),
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { errors: ['Too many upload requests, try again later'], success: false, data: null }
});
const chunkLimiter = rateLimit({
    windowMs: getPositiveIntegerEnv('CHUNK_RATE_LIMIT_WINDOW', 60 * 60 * 1000),
    limit: getPositiveIntegerEnv('CHUNK_RATE_LIMIT_MAX', 1000),
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { errors: ['Too many chunk upload requests, try again later'], success: false, data: null }
});
app.use(requestLimiter);

// Cloudflare compatibility headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Cloudflare specific headers - now handled by trust proxy
    next();
});

// Authentication middleware
const authenticateUser = (req, res, next) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ errors: ["Authorization token required"], success: false, data: null });
    }

    let processedToken = '';
    if (token?.startsWith('Bearer ')) {
        processedToken = token.slice(7);
    } else {
        processedToken = token;
    }

    try {
        const decoded = jwt.verify(processedToken, process.env.JWT, { algorithms: ['HS256'] });
        if (!decoded?.username || typeof decoded.username !== 'string') {
            throw new Error('Invalid token payload');
        }
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ errors: ["Invalid token"], success: false, data: null });
    }
};

const verifyToken = (token) => {
    try {
        const processedToken = token?.startsWith('Bearer ') ? token.slice(7) : token;
        const decoded = jwt.verify(processedToken, process.env.JWT, { algorithms: ['HS256'] });
        if (!decoded?.username || typeof decoded.username !== 'string') {
            return null;
        }
        return decoded;
    } catch (error) {
        return null;
    }
};

// Utility functions
const generateFileID = () => {
    return crypto.randomBytes(12).toString('hex');
};

const generateAccessKey = () => {
    return crypto.randomBytes(18).toString('hex');
};

const generateSessionID = () => {
    return crypto.randomBytes(16).toString('hex');
};

const isValidFileType = (mimeType) => {
    if(!process.env.FILTER_MIME) {
        return true;
    }
    // Handle null/undefined mimeType
    if (!mimeType || typeof mimeType !== 'string') {
        return false;
    }

    const allowedTypes = [
        'image/', 'video/', 'audio/', 'text/', 'application/pdf', 'application/x-iso9660-image', 'application/octet-stream',
        'application/vnd.android.package-archive',
        'application/zip', 'application/x-zip-compressed',
        'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    ];

    return allowedTypes.some(type => mimeType.startsWith(type));
};

const getFileLocation = (file) => path.join(filesDir, `${file.fileID}${file.ext}`);

const getFileMimeType = (file) => {
    // Android's package installer depends on the APK media type being explicit.
    if (file.ext?.toLowerCase() === '.apk') {
        return 'application/vnd.android.package-archive';
    }
    return file.mime_type || mime.getType(file.filename) || 'application/octet-stream';
};

const safeDownloadFilename = (filename) => {
    const safeName = path.basename(filename || 'download')
        .replace(/[\r\n"]/g, '_')
        .trim();
    return safeName || 'download';
};

const isMatchingAccessKey = (providedKey, accessKey) => {
    if (typeof providedKey !== 'string' || typeof accessKey !== 'string') {
        return false;
    }
    const provided = Buffer.from(providedKey);
    const expected = Buffer.from(accessKey);
    return provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
};

const canAccessFile = (req, file) => {
    if (file.private) {
        const token = verifyToken(req.headers.authorization);
        if (!token || token.username !== file.owner) {
            return false;
        }
    }
    return !file.accessKey || isMatchingAccessKey(req.query.key, file.accessKey);
};

const applyFileCacheHeaders = (res, file) => {
    if (file.private || file.accessKey) {
        res.setHeader('Cache-Control', 'private, no-store');
    } else {
        res.setHeader('Cache-Control', 'public, max-age=259200, no-transform');
    }
};

const getSessionDirectory = (sessionID) => path.join(tempDir, sessionID);

const getUploadedChunkIndexes = (session) => {
    const sessionDir = getSessionDirectory(session.session_id);
    if (!fs.existsSync(sessionDir)) {
        return [];
    }

    return fs.readdirSync(sessionDir)
        .map(name => {
            const match = /^chunk_(\d+)$/.exec(name);
            return match ? Number.parseInt(match[1], 10) : null;
        })
        .filter(index => Number.isInteger(index) && index >= 0 && index < session.total_chunks)
        .sort((a, b) => a - b);
};

const getMissingChunkIndexes = (session) => {
    const uploaded = new Set(getUploadedChunkIndexes(session));
    return Array.from({ length: session.total_chunks }, (_, index) => index)
        .filter(index => !uploaded.has(index));
};

const getAssemblyPath = (sessionID) => path.join(filesDir, `.${sessionID}.${process.pid}.assembling`);

const cleanupAssemblyFiles = (sessionID) => {
    const prefix = `.${sessionID}.`;
    for (const name of fs.readdirSync(filesDir)) {
        if (name.startsWith(prefix) && name.endsWith('.assembling')) {
            fs.rmSync(path.join(filesDir, name), { force: true });
        }
    }
};

const cleanupSessionDirectory = (sessionID) => {
    fs.rmSync(getSessionDirectory(sessionID), { recursive: true, force: true });
    cleanupAssemblyFiles(sessionID);
};

const getOwnedActiveSession = async (sessionID, username) => {
    const session = await db.getSession(sessionID);
    if (!session || session.owner !== username || new Date(session.expires_at) <= new Date()) {
        return null;
    }
    return session;
};

// An interrupted process can leave an assembly lock behind. Assembly names are
// internal (dot-prefixed, generated session IDs), so removing them at boot is safe.
for (const name of fs.readdirSync(filesDir)) {
    if (/^\.[a-f0-9]{32}\.\d+\.assembling$/.test(name)) {
        fs.rmSync(path.join(filesDir, name), { force: true });
    }
}



// Main route
app.get('/', (req, res) => {
    res.json({
        message: "PrintedWaste Grid Service",
        status: true,
        errors: []
    });
});

// File viewing routes
app.get('/view/:id', async (req, res) => {
    try {
        const id = req.params.id.replace(/\.[^/.]+$/, "");
        const file = await db.getFile(id);

        if (!file) {
            return res.status(404).json({ errors: ["File not found"], success: false, data: null });
        }

        if (!canAccessFile(req, file)) {
            return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
        }

        const fileLocation = getFileLocation(file);

        if (!fs.existsSync(fileLocation)) {
            return res.status(404).json({ errors: ["File not found on disk"], success: false, data: null });
        }

        res.type(getFileMimeType(file));
        res.setHeader('Content-Disposition', `inline; filename="${safeDownloadFilename(file.filename)}"`);
        applyFileCacheHeaders(res, file);
        res.sendFile(fileLocation, { acceptRanges: true }, error => {
            if (error && !res.headersSent) {
                console.error('View file stream error:', error);
                res.status(error.statusCode || 500).json({ errors: ['Unable to read file'], success: false, data: null });
            }
        });
    } catch (error) {
        console.error('View file error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

app.get('/download/:id', async (req, res) => {
    try {
        const file = await db.getFile(req.params.id);

        if (!file) {
            return res.status(404).json({ errors: ["File not found"], success: false, data: null });
        }

        if (!canAccessFile(req, file)) {
            return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
        }

        const fileLocation = getFileLocation(file);

        if (!fs.existsSync(fileLocation)) {
            return res.status(404).json({ errors: ["File not found on disk"], success: false, data: null });
        }

        // Explicitly set the APK type and enable range requests so Android's
        // DownloadManager can resume and hand the completed file to the installer.
        res.type(getFileMimeType(file));
        res.setHeader('Accept-Ranges', 'bytes');
        applyFileCacheHeaders(res, file);
        res.download(fileLocation, safeDownloadFilename(file.filename), error => {
            if (error && !res.headersSent) {
                console.error('Download file stream error:', error);
                res.status(error.statusCode || 500).json({ errors: ['Unable to download file'], success: false, data: null });
            }
        });
    } catch (error) {
        console.error('Download file error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

// API Routes
app.get('/api/file/:id', async (req, res) => {
    try {
        const file = await db.getFile(req.params.id);

        if (!file) {
            return res.status(404).json({ errors: ["File not found"], success: false, data: null });
        }

        if (!canAccessFile(req, file)) {
            return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
        }

        const fileLocation = getFileLocation(file);

        if (!fs.existsSync(fileLocation)) {
            return res.status(404).json({ errors: ["File not found on disk"], success: false, data: null });
        }

        const stats = fs.statSync(fileLocation);
        file.size = stats.size;
        file.type = getFileMimeType(file);

        res.status(200).json({ success: true, data: { file }, errors: [] });
    } catch (error) {
        console.error('Get file info error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

// Chunked upload initialization
app.post('/api/file/upload/init', uploadLimiter, authenticateUser, [
    body('filename').isString().isLength({ min: 1, max: 255 }),
    body('size').isInt({ min: 1, max: 1073741824 }), // Max 1GB
    body('chunkSize').optional().isInt({ min: 1024 * 1024, max: 10 * 1024 * 1024 }), // 1MB to 10MB chunks
    body('private').optional().isBoolean(),
    body('accessKey').optional().isBoolean(),
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array().map(e => e.msg), success: false, data: null });
        }

        const { filename, size, chunkSize = 5 * 1024 * 1024, private: isPrivate = false, accessKey: needsAccessKey = false } = req.body; // Default 5MB chunks
        const safeFilename = path.basename(filename).replace(/[\r\n]/g, '').trim();
        if (!safeFilename) {
            return res.status(400).json({ errors: ['Invalid filename'], success: false, data: null });
        }
        const totalChunks = Math.ceil(size / chunkSize);
        const sessionID = generateSessionID();
        const ext = path.extname(safeFilename).toLowerCase();
        const mimeType = getFileMimeType({ filename: safeFilename, ext });

        if (!isValidFileType(mimeType)) {
            return res.status(400).json({ errors: ["File type not allowed"], success: false, data: null });
        }

        // Clean up old sessions (older than 24 hours)
        await db.cleanupExpiredSessions();

        // Create upload session
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        await db.createSession({
            session_id: sessionID,
            filename: safeFilename,
            owner: req.user.username,
            total_chunks: totalChunks,
            chunk_size: chunkSize,
            total_size: size,
            mime_type: mimeType,
            ext,
            private: isPrivate,
            needs_access_key: needsAccessKey,
            expires_at: expiresAt
        });

        res.status(201).json({
            success: true,
            data: {
                sessionID,
                totalChunks,
                chunkSize,
                uploadUrl: `/api/file/upload/chunk/${sessionID}`,
                completeUrl: `/api/file/upload/complete/${sessionID}`
            },
            errors: []
        });
    } catch (error) {
        console.error('Upload init error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

// Chunk uploads only persist a chunk. Completion is deliberately explicit: a
// concurrent final chunk must not race a server-side merge on mobile networks.
app.post('/api/file/upload/chunk/:sessionID', chunkLimiter, authenticateUser, multer({
    dest: tempDir,
    limits: { fileSize: 10 * 1024 * 1024, files: 1 }
}).single('chunk'), async (req, res) => {
    let temporaryChunkPath;
    try {
        const { sessionID } = req.params;
        temporaryChunkPath = req.file?.path;
        const chunkIndexHeader = req.headers['x-chunk-index'];
        const totalChunksHeader = req.headers['x-total-chunks'];
        const chunkIndex = Number.parseInt(chunkIndexHeader, 10);
        const totalChunks = Number.parseInt(totalChunksHeader, 10);

        if (!req.file) {
            return res.status(400).json({ errors: ['Chunk file required'], success: false, data: null });
        }
        if (!/^\d+$/.test(String(chunkIndexHeader)) || !/^\d+$/.test(String(totalChunksHeader))) {
            return res.status(400).json({ errors: ['Invalid chunk headers'], success: false, data: null });
        }

        const session = await getOwnedActiveSession(sessionID, req.user.username);
        if (!session) {
            return res.status(404).json({ errors: ['Upload session not found or expired'], success: false, data: null });
        }
        if (session.completed_file_id) {
            return res.status(409).json({ errors: ['Upload has already been finalized'], success: false, data: null });
        }
        if (totalChunks !== session.total_chunks || chunkIndex < 0 || chunkIndex >= session.total_chunks) {
            return res.status(400).json({ errors: ['Chunk index does not match upload session'], success: false, data: null });
        }

        const isLastChunk = chunkIndex === session.total_chunks - 1;
        const expectedChunkSize = isLastChunk
            ? session.total_size - (session.chunk_size * chunkIndex)
            : session.chunk_size;
        if (req.file.size !== expectedChunkSize) {
            return res.status(400).json({
                errors: [`Invalid chunk size. Expected ${expectedChunkSize} bytes`],
                success: false,
                data: null
            });
        }

        const sessionDir = getSessionDirectory(sessionID);
        if (!fs.existsSync(sessionDir)) {
            fs.mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
        }

        const chunkPath = path.join(sessionDir, `chunk_${chunkIndex}`);
        fs.renameSync(req.file.path, chunkPath);
        temporaryChunkPath = null;

        const uploadedChunks = getUploadedChunkIndexes(session).length;
        res.status(200).json({
            success: true,
            data: {
                uploadedChunks,
                totalChunks: session.total_chunks,
                readyToComplete: uploadedChunks === session.total_chunks,
                message: `Chunk ${chunkIndex + 1}/${session.total_chunks} uploaded`
            },
            errors: []
        });
    } catch (error) {
        console.error('Chunk upload error:', error);
        res.status(500).json({ errors: ['Internal server error'], success: false, data: null });
    } finally {
        if (temporaryChunkPath && fs.existsSync(temporaryChunkPath)) {
            fs.unlinkSync(temporaryChunkPath);
        }
    }
});

app.get('/api/file/upload/session/:sessionID', authenticateUser, async (req, res) => {
    try {
        const session = await getOwnedActiveSession(req.params.sessionID, req.user.username);
        if (!session) {
            return res.status(404).json({ errors: ['Upload session not found or expired'], success: false, data: null });
        }

        const uploadedChunkIndexes = session.completed_file_id
            ? Array.from({ length: session.total_chunks }, (_, index) => index)
            : getUploadedChunkIndexes(session);
        res.status(200).json({
            success: true,
            data: {
                sessionID: session.session_id,
                filename: session.filename,
                completed: Boolean(session.completed_file_id),
                result: session.completed_file_id ? {
                    fileID: session.completed_file_id,
                    privateKey: session.completed_access_key,
                    size: session.total_size,
                    sha256: session.completed_sha256,
                    message: 'File uploaded successfully'
                } : null,
                totalChunks: session.total_chunks,
                chunkSize: session.chunk_size,
                totalSize: session.total_size,
                uploadedChunkIndexes,
                missingChunkIndexes: session.completed_file_id ? [] : getMissingChunkIndexes(session),
                readyToComplete: uploadedChunkIndexes.length === session.total_chunks,
                expiresAt: session.expires_at
            },
            errors: []
        });
    } catch (error) {
        console.error('Upload session status error:', error);
        res.status(500).json({ errors: ['Internal server error'], success: false, data: null });
    }
});

app.post('/api/file/upload/complete/:sessionID', authenticateUser, async (req, res) => {
    let assemblingPath;
    let ownsAssemblingFile = false;
    try {
        const session = await getOwnedActiveSession(req.params.sessionID, req.user.username);
        if (!session) {
            return res.status(404).json({ errors: ['Upload session not found or expired'], success: false, data: null });
        }
        if (session.completed_file_id) {
            return res.status(200).json({
                success: true,
                data: {
                    fileID: session.completed_file_id,
                    privateKey: session.completed_access_key,
                    size: session.total_size,
                    sha256: session.completed_sha256,
                    message: 'File uploaded successfully'
                },
                errors: []
            });
        }

        const missingChunkIndexes = getMissingChunkIndexes(session);
        if (missingChunkIndexes.length > 0) {
            return res.status(409).json({
                errors: ['Upload is incomplete'],
                success: false,
                data: { missingChunkIndexes }
            });
        }

        assemblingPath = getAssemblyPath(session.session_id);
        let descriptor;
        try {
            descriptor = fs.openSync(assemblingPath, 'wx', 0o600);
            ownsAssemblingFile = true;
        } catch (error) {
            if (error.code === 'EEXIST') {
                return res.status(409).json({ errors: ['Upload is already being finalized'], success: false, data: null });
            }
            throw error;
        }

        let totalBytesWritten = 0;
        const hash = crypto.createHash('sha256');
        try {
            for (let index = 0; index < session.total_chunks; index++) {
                const chunk = fs.readFileSync(path.join(getSessionDirectory(session.session_id), `chunk_${index}`));
                totalBytesWritten += chunk.length;
                hash.update(chunk);
                fs.writeSync(descriptor, chunk);
            }
        } finally {
            fs.closeSync(descriptor);
        }

        if (totalBytesWritten !== session.total_size) {
            fs.unlinkSync(assemblingPath);
            return res.status(400).json({
                errors: [`File size mismatch. Expected: ${session.total_size}, Got: ${totalBytesWritten}`],
                success: false,
                data: null
            });
        }

        let fileID;
        do {
            fileID = generateFileID();
        } while (await db.getFile(fileID));

        const finalFilePath = path.join(filesDir, `${fileID}${session.ext}`);
        const accessKey = session.needs_access_key ? generateAccessKey() : null;
        const sha256 = hash.digest('hex');
        fs.renameSync(assemblingPath, finalFilePath);
        ownsAssemblingFile = false;

        try {
            await db.createFile({
                filename: session.filename,
                owner: req.user.username,
                fileID,
                private: session.private,
                accessKey,
                ext: session.ext,
                size: session.total_size,
                mime_type: session.mime_type,
                sha256
            });
        } catch (error) {
            fs.rmSync(finalFilePath, { force: true });
            throw error;
        }

        cleanupSessionDirectory(session.session_id);
        await db.updateSession(session.session_id, {
            completed_file_id: fileID,
            completed_access_key: accessKey,
            completed_sha256: sha256,
            completed_at: new Date().toISOString()
        });

        res.status(201).json({
            success: true,
            data: {
                fileID,
                privateKey: accessKey,
                size: session.total_size,
                sha256,
                message: 'File uploaded successfully'
            },
            errors: []
        });
    } catch (error) {
        if (ownsAssemblingFile && assemblingPath) {
            fs.rmSync(assemblingPath, { force: true });
        }
        console.error('Complete upload error:', error);
        res.status(500).json({ errors: ['Internal server error'], success: false, data: null });
    }
});

app.delete('/api/file/upload/session/:sessionID', authenticateUser, async (req, res) => {
    try {
        const session = await getOwnedActiveSession(req.params.sessionID, req.user.username);
        if (!session) {
            return res.status(404).json({ errors: ['Upload session not found or expired'], success: false, data: null });
        }
        if (session.completed_file_id) {
            return res.status(409).json({ errors: ['Completed uploads cannot be cancelled'], success: false, data: null });
        }
        cleanupSessionDirectory(session.session_id);
        await db.deleteSession(session.session_id);
        res.status(200).json({ success: true, data: null, errors: [] });
    } catch (error) {
        console.error('Cancel upload error:', error);
        res.status(500).json({ errors: ['Internal server error'], success: false, data: null });
    }
});

// Single file upload (for files under 100MB)
app.post('/api/file/upload', uploadLimiter, authenticateUser, multer({
    dest: filesDir,
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit for single upload
}).single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ errors: ["File required"], success: false, data: null });
        }

        const filename = path.basename(req.file.originalname).replace(/[\r\n]/g, '').trim();
        if (!filename) {
            fs.rmSync(req.file.path, { force: true });
            return res.status(400).json({ errors: ['Invalid filename'], success: false, data: null });
        }
        const ext = path.extname(filename).toLowerCase();
        const mimeType = getFileMimeType({ filename, ext });
        const isPrivate = req.headers['x-private'] === 'true';
        const accessKey = req.headers['x-access-key'] === 'true' ? generateAccessKey() : null;

        if (!isValidFileType(mimeType)) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ errors: ["File type not allowed"], success: false, data: null });
        }

        const stats = fs.statSync(req.file.path);
        let fileID;
        do {
            fileID = generateFileID();
        } while (await db.getFile(fileID));
        const finalFilePath = path.join(filesDir, `${fileID}${ext}`);
        const sha256 = crypto.createHash('sha256').update(fs.readFileSync(req.file.path)).digest('hex');
        fs.renameSync(req.file.path, finalFilePath);
        try {
            await db.createFile({
                filename,
                owner: req.user.username,
                fileID,
                private: isPrivate,
                accessKey,
                ext,
                size: stats.size,
                mime_type: mimeType,
                sha256
            });
        } catch (error) {
            fs.rmSync(finalFilePath, { force: true });
            throw error;
        }

        res.status(201).json({
            success: true,
            data: {
                fileID,
                privateKey: accessKey,
                size: stats.size,
                sha256
            },
            errors: []
        });
    } catch (error) {
        console.error('Single upload error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

app.delete('/api/file/:id', authenticateUser, async (req, res) => {
    try {
        const file = await db.getFile(req.params.id);

        if (!file) {
            return res.status(404).json({ errors: ["File not found"], success: false, data: null });
        }

        if (file.owner !== req.user.username) {
            return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
        }

        await db.deleteFile(req.params.id);

        const fileLocation = getFileLocation(file);
        if (fs.existsSync(fileLocation)) {
            fs.unlinkSync(fileLocation);
        }

        res.status(200).json({ success: true, data: null, errors: [] });
    } catch (error) {
        console.error('Delete file error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

// User management routes
app.post('/api/user/register', authLimiter, [
    body('username').isString().isLength({ min: 3, max: 50 }).matches(/^[a-zA-Z0-9_]+$/),
    body('password').isString().isLength({ min: 8, max: 128 }),
    body('registerKey').isString()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array().map(e => e.msg), success: false, data: null });
        }

        const { username, password, registerKey } = req.body;

        if (!isMatchingAccessKey(registerKey, process.env.RKEY)) {
            return res.status(401).json({ errors: ["Invalid register key"], success: false, data: null });
        }

        const existingUser = await db.getUser(username);
        if (existingUser) {
            return res.status(400).json({ errors: ["Username already exists"], success: false, data: null });
        }

        const hashedPassword = bcrypt.hashSync(password, 12);

        const newUser = await db.createUser(username, hashedPassword);

        res.status(201).json({ success: true, data: { id: newUser.id }, errors: [] });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

app.post('/api/user/login', authLimiter, [
    body('username').isString().isLength({ min: 1 }),
    body('password').isString().isLength({ min: 1 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array().map(e => e.msg), success: false, data: null });
        }

        const { username, password } = req.body;

        const user = await db.getUser(username);

        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ errors: ["Invalid username or password"], success: false, data: null });
        }

        const token = jwt.sign({ username: user.username }, process.env.JWT, { expiresIn: "1w" });

        res.status(200).json({ success: true, data: { token }, errors: [] });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

app.delete('/api/user/:username', authenticateUser, async (req, res) => {
    try {
        const { username } = req.params;

        if (req.user.username !== username) {
            return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
        }

        const deleted = await db.deleteUser(username);

        if (!deleted) {
            return res.status(404).json({ errors: ["User not found"], success: false, data: null });
        }

        const deletedFiles = await db.deleteFilesByOwner(username);
        for (const file of deletedFiles) {
            fs.rmSync(getFileLocation(file), { force: true });
        }

        res.status(200).json({ success: true, data: { deletedFiles: deletedFiles.length }, errors: [] });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

app.get('/api/user/files', authenticateUser, async (req, res) => {
    try {
        const files = await db.getFilesByOwner(req.user.username);

        files.forEach((file) => {
            const fileLocation = getFileLocation(file);
            if (fs.existsSync(fileLocation)) {
                const stats = fs.statSync(fileLocation);
                file.size = stats.size;
                file.type = getFileMimeType(file);
            } else {
                file.size = 0;
                file.type = 'unknown';
            }
        });

        res.status(200).json({ success: true, data: { files }, errors: [] });
    } catch (error) {
        console.error('Get user files error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

// Share route
app.get('/share/:id', async (req, res) => {
    try {
        const file = await db.getFile(req.params.id);

        if (!file) {
            return res.status(404).json({ errors: ["File not found"], success: false, data: null });
        }

        if (!canAccessFile(req, file)) {
            return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
        }

        const fileLocation = getFileLocation(file);

        if (!fs.existsSync(fileLocation)) {
            return res.status(404).json({ errors: ["File not found on disk"], success: false, data: null });
        }

        const stats = fs.statSync(fileLocation);
        file.size = stats.size;
        file.type = getFileMimeType(file);
        const shareViewUrl = process.env.SHARE_VIEW_URL || 'https://printedwaste.com/grid/view/';
        const shareUrl = new URL(shareViewUrl);
        shareUrl.searchParams.set('id', file.fileID);
        if (file.accessKey) {
            shareUrl.searchParams.set('key', file.accessKey);
        }
        file.redirectUrl = shareUrl.toString();
        file.image = file.type?.startsWith('image') || false;

        res.render('share.ejs', { file });
    } catch (error) {
        console.error('Share file error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({
        status: "healthy",
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
    });
});

// Status endpoint
app.get('/status', authenticateUser, async (req, res) => {
    try {
        const stats = await db.getStats();

        // Get disk usage
        let diskUsage = 0;
        if (fs.existsSync(filesDir)) {
            const files = fs.readdirSync(filesDir);
            for (const file of files) {
                const filePath = path.join(filesDir, file);
                const stats = fs.statSync(filePath);
                diskUsage += stats.size;
            }
        }

        res.status(200).json({
            success: true,
            data: {
                status: "online",
                totalFiles: stats.totalFiles,
                totalUsers: stats.totalUsers,
                totalSize: stats.totalSize,
                diskUsage: diskUsage,
                activeSessions: stats.activeSessions,
                version: "2.1.0",
                uptime: process.uptime(),
                memory: process.memoryUsage()
            },
            errors: []
        });
    } catch (error) {
        console.error('Status error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

// Cleanup old upload sessions (run every hour)
setInterval(async () => {
    try {
        const cleanedCount = await db.cleanupExpiredSessions();
        const timestamp = new Date().toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
        if (cleanedCount > 0) {
            console.log(`[${timestamp}] Cleaned up ${cleanedCount} expired upload sessions`);
        }
    } catch (error) {
        console.error('Cleanup error:', error);
    }
}, 60 * 60 * 1000);

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    if (error instanceof multer.MulterError) {
        const status = error.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
        return res.status(status).json({ errors: ['Invalid upload payload'], success: false, data: null });
    }
    if (error instanceof SyntaxError && 'body' in error) {
        return res.status(400).json({ errors: ['Invalid JSON request body'], success: false, data: null });
    }
    res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ errors: ["Route not found"], success: false, data: null });
});

// Start server
const port = process.env.PORT || 3020;

// Start server
app.listen(port, () => {
    const timestamp = new Date().toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        day: '2-digit',
        month: '2-digit',
        year: 'numeric'
    });
    console.log(`[${timestamp}] Server Started on port ${port}`);
});
