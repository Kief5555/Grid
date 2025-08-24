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
        this.dbPath = path.join(__dirname, 'data');
        this.usersPath = path.join(this.dbPath, 'users.json');
        this.filesPath = path.join(this.dbPath, 'files.json');
        this.sessionsPath = path.join(this.dbPath, 'sessions.json');

        // Create data directory
        if (!fs.existsSync(this.dbPath)) {
            fs.mkdirSync(this.dbPath, { recursive: true });
        }

        // Initialize database files
        this.initDB();
    }

    initDB() {
        if (!fs.existsSync(this.usersPath)) {
            fs.writeFileSync(this.usersPath, JSON.stringify([], null, 2));
        }
        if (!fs.existsSync(this.filesPath)) {
            fs.writeFileSync(this.filesPath, JSON.stringify([], null, 2));
        }
        if (!fs.existsSync(this.sessionsPath)) {
            fs.writeFileSync(this.sessionsPath, JSON.stringify([], null, 2));
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
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
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

    async cleanupExpiredSessions() {
        const sessions = this.readData(this.sessionsPath);
        const now = new Date();
        const activeSessions = sessions.filter(session => new Date(session.expires_at) > now);
        this.writeData(this.sessionsPath, activeSessions);
        return sessions.length - activeSessions.length;
    }

    // Statistics
    async getStats() {
        const users = this.readData(this.usersPath);
        const files = this.readData(this.filesPath);
        const sessions = this.readData(this.sessionsPath);

        const now = new Date();
        const activeSessions = sessions.filter(session => new Date(session.expires_at) > now);

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
const filesDir = path.join(__dirname, 'files');
if (!fs.existsSync(filesDir)) {
    fs.mkdirSync(filesDir, { recursive: true });
}

// Create temp directory for chunked uploads
const tempDir = path.join(__dirname, 'temp');
if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
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

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { errors: ["Too many requests"], success: false, data: null },
    standardHeaders: true,
    legacyHeaders: false,
});

const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // limit each IP to 10 uploads per hour
    message: { errors: ["Upload limit exceeded"], success: false, data: null },
});

const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 50, // allow 50 requests per 15 minutes, then...
    delayMs: (used, req) => {
        const delayAfter = req.slowDown.limit;
        return (used - delayAfter) * 500;
    }
});

// Middleware
app.use(compression());
// app.use(speedLimiter);
// app.use(limiter);
app.use(morgan(':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent"'));
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
    credentials: true,
    origin: true,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    // allowedHeaders: ['Content-Type', 'Authorization', 'X-Chunk-Index', 'X-Total-Chunks', 'X-Session-ID', 'X-File-Size', 'X-File-Name', 'X-Private', 'X-Access-Key']
}));

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
        const decoded = jwt.verify(processedToken, process.env.JWT);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ errors: ["Invalid token"], success: false, data: null });
    }
};

const verifyToken = (token) => {
    try {
        const decoded = jwt.verify(token, process.env.JWT);
        return decoded;
    } catch (error) {
        return null;
    }
};

// Utility functions
const generateFileID = () => {
    return crypto.randomBytes(4).toString('hex');
};

const generateAccessKey = () => {
    return crypto.randomBytes(18).toString('hex');
};

const generateSessionID = () => {
    return crypto.randomBytes(16).toString('hex');
};

const isValidFileType = (mimeType) => {
    const allowedTypes = [
        'image/', 'video/', 'audio/', 'text/', 'application/pdf', 'application/x-iso9660-image', 'application/octet-stream',
        'application/zip', 'application/x-zip-compressed',
        'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    ];

    return allowedTypes.some(type => mimeType.startsWith(type));
};



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

        if (file.private) {
            const tokenRes = verifyToken(req.headers.authorization);
            if (!tokenRes) {
                return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
            }
        }

        if (file.accessKey && req.query.key !== file.accessKey) {
            return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
        }

        const fileLocation = path.join(__dirname, 'files', `${file.fileID}${file.ext}`);

        if (!fs.existsSync(fileLocation)) {
            return res.status(404).json({ errors: ["File not found on disk"], success: false, data: null });
        }

        const fileBuffer = fs.readFileSync(fileLocation);
        res.contentType(file.mime_type || mime.getType(fileLocation));
        res.setHeader('Content-Disposition', `inline; filename="${file.filename}"`);
        res.setHeader('Cache-Control', 'public, max-age=259200'); // 3 days
        res.setHeader('ETag', `"${crypto.createHash('md5').update(fileBuffer).digest('hex')}"`);

        // Check if file hasn't changed
        if (req.headers['if-none-match'] === res.getHeader('ETag')) {
            return res.status(304).end();
        }

        res.send(fileBuffer);
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

        if (file.private) {
            const tokenRes = verifyToken(req.headers.authorization);
            if (!tokenRes) {
                return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
            }
        }

        if (file.accessKey && req.query.key !== file.accessKey) {
            return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
        }

        const fileLocation = path.join(__dirname, 'files', `${file.fileID}${file.ext}`);

        if (!fs.existsSync(fileLocation)) {
            return res.status(404).json({ errors: ["File not found on disk"], success: false, data: null });
        }

        res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);
        res.setHeader('Cache-Control', 'public, max-age=259200'); // 3 days
        res.download(fileLocation, file.filename);
    } catch (error) {
        console.error('Download file error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

// API Routes
app.get('/api/file/:id', async (req, res) => {
    try {
        const file = await dbGet("SELECT fileID, filename, private, accessKey, ext, owner, size, mime_type FROM files WHERE fileID = ?", [req.params.id]);

        if (!file) {
            return res.status(404).json({ errors: ["File not found"], success: false, data: null });
        }

        if (file.private) {
            const tokenRes = verifyToken(req.headers.authorization);
            if (!tokenRes) {
                return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
            }
        }

        if (file.accessKey && req.query.key !== file.accessKey) {
            return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
        }

        const fileLocation = path.join(__dirname, 'files', `${file.fileID}${file.ext}`);

        if (!fs.existsSync(fileLocation)) {
            return res.status(404).json({ errors: ["File not found on disk"], success: false, data: null });
        }

        const stats = fs.statSync(fileLocation);
        file.size = stats.size;
        file.type = file.mime_type || mime.getType(fileLocation);

        res.status(200).json({ success: true, data: { file }, errors: [] });
    } catch (error) {
        console.error('Get file info error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

// Chunked upload initialization
app.post('/api/file/upload/init', authenticateUser, [
    body('filename').isString().isLength({ min: 1, max: 255 }),
    body('size').isInt({ min: 1, max: 1073741824 }), // Max 1GB
    body('chunkSize').optional().isInt({ min: 1024 * 1024, max: 10 * 1024 * 1024 }), // 1MB to 10MB chunks
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array().map(e => e.msg), success: false, data: null });
        }

        const { filename, size, chunkSize = 5 * 1024 * 1024 } = req.body; // Default 5MB chunks
        const totalChunks = Math.ceil(size / chunkSize);
        const sessionID = generateSessionID();
        const ext = path.extname(filename);
        const mimeType = mime.getType(filename);

        if (!isValidFileType(mimeType)) {
            return res.status(400).json({ errors: ["File type not allowed"], success: false, data: null });
        }

        // Clean up old sessions (older than 24 hours)
        await db.cleanupExpiredSessions();

        // Create upload session
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        await db.createSession({
            session_id: sessionID,
            filename,
            owner: req.user.username,
            total_chunks: totalChunks,
            chunk_size: chunkSize,
            total_size: size,
            mime_type: mimeType,
            ext,
            expires_at: expiresAt
        });

        res.status(201).json({
            success: true,
            data: {
                sessionID,
                totalChunks,
                chunkSize,
                uploadUrl: `/api/file/upload/chunk/${sessionID}`
            },
            errors: []
        });
    } catch (error) {
        console.error('Upload init error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

// Chunked upload endpoint
app.post('/api/file/upload/chunk/:sessionID', uploadLimiter, authenticateUser, multer({
    dest: tempDir,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB max per chunk
}).single('chunk'), async (req, res) => {
    try {
        const { sessionID } = req.params;
        const chunkIndex = parseInt(req.headers['x-chunk-index']);
        const totalChunks = parseInt(req.headers['x-total-chunks']);

        if (!req.file) {
            return res.status(400).json({ errors: ["Chunk file required"], success: false, data: null });
        }

        // Validate session
        const session = await db.getSession(sessionID);
        if (!session || session.owner !== req.user.username || new Date(session.expires_at) <= new Date()) {
            return res.status(404).json({ errors: ["Upload session not found or expired"], success: false, data: null });
        }



        if (chunkIndex >= session.total_chunks || chunkIndex < 0) {
            return res.status(400).json({ errors: ["Invalid chunk index"], success: false, data: null });
        }

        // Move chunk to session-specific directory
        const sessionDir = path.join(tempDir, sessionID);
        if (!fs.existsSync(sessionDir)) {
            fs.mkdirSync(sessionDir, { recursive: true });
        }

        const chunkPath = path.join(sessionDir, `chunk_${chunkIndex}`);
        fs.renameSync(req.file.path, chunkPath);

        // Check if all chunks are uploaded
        const uploadedChunks = fs.readdirSync(sessionDir).length;

        if (uploadedChunks === session.total_chunks) {
            // Combine all chunks
            const finalFilePath = path.join(__dirname, 'files', `${sessionID}${session.ext}`);
            const writeStream = fs.createWriteStream(finalFilePath);

            for (let i = 0; i < session.total_chunks; i++) {
                const chunkPath = path.join(sessionDir, `chunk_${i}`);
                const chunkBuffer = fs.readFileSync(chunkPath);
                writeStream.write(chunkBuffer);
                fs.unlinkSync(chunkPath); // Delete chunk after writing
            }

            writeStream.end();

            // Wait for file to be fully written
            await new Promise((resolve, reject) => {
                writeStream.on('finish', resolve);
                writeStream.on('error', reject);
            });

            // Verify file size
            const finalStats = fs.statSync(finalFilePath);
            if (finalStats.size !== session.total_size) {
                fs.unlinkSync(finalFilePath);
                return res.status(400).json({ errors: ["File size mismatch"], success: false, data: null });
            }

            // Create file record
            const fileID = generateFileID();
            const accessKey = req.headers['x-access-key'] === 'true' ? generateAccessKey() : null;
            const isPrivate = req.headers['x-private'] === 'true';

            await db.createFile({
                filename: session.filename,
                owner: req.user.username,
                fileID,
                private: isPrivate,
                accessKey,
                ext: session.ext,
                size: session.total_size,
                mime_type: session.mime_type
            });

            // Clean up session
            await db.deleteSession(sessionID);
            fs.rmdirSync(sessionDir);

            res.status(201).json({
                success: true,
                data: {
                    fileID,
                    privateKey: accessKey,
                    size: session.total_size,
                    message: "File uploaded successfully"
                },
                errors: []
            });
        } else {
            res.status(200).json({
                success: true,
                data: {
                    uploadedChunks,
                    totalChunks: session.total_chunks,
                    message: `Chunk ${chunkIndex + 1}/${session.total_chunks} uploaded`
                },
                errors: []
            });
        }
    } catch (error) {
        console.error('Chunk upload error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

// Legacy single file upload (for files under 100MB)
app.post('/api/file/upload', uploadLimiter, authenticateUser, multer({
    dest: 'files/',
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit for single upload
}).single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ errors: ["File required"], success: false, data: null });
        }

        const fileID = generateFileID();
        const filename = req.file.originalname;
        const ext = path.extname(filename);
        const mimeType = mime.getType(filename);
        const isPrivate = req.headers['x-private'] === 'true';
        const accessKey = req.headers['x-access-key'] === 'true' ? generateAccessKey() : null;

        if (!isValidFileType(mimeType)) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ errors: ["File type not allowed"], success: false, data: null });
        }

        const stats = fs.statSync(req.file.path);

        await db.createFile({
            filename,
            owner: req.user.username,
            fileID,
            private: isPrivate,
            accessKey,
            ext,
            size: stats.size,
            mime_type: mimeType
        });

        fs.renameSync(req.file.path, path.join(__dirname, 'files', `${fileID}${ext}`));

        res.status(201).json({
            success: true,
            data: {
                fileID,
                privateKey: accessKey,
                size: stats.size
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

        const fileLocation = path.join(__dirname, 'files', `${file.fileID}${file.ext}`);
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
app.post('/api/user/register', [
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

        if (registerKey !== process.env.RKEY) {
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

app.post('/api/user/login', [
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

        res.status(200).json({ success: true, data: null, errors: [] });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ errors: ["Internal server error"], success: false, data: null });
    }
});

app.get('/api/user/files', authenticateUser, async (req, res) => {
    try {
        const files = await db.getFilesByOwner(req.user.username);

        files.forEach((file) => {
            const fileLocation = path.join(__dirname, 'files', `${file.fileID}${file.ext}`);
            if (fs.existsSync(fileLocation)) {
                const stats = fs.statSync(fileLocation);
                file.size = stats.size;
                file.type = file.mime_type || mime.getType(fileLocation);
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

        if (file.private) {
            const tokenRes = verifyToken(req.headers.authorization);
            if (!tokenRes) {
                return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
            }
        }

        if (file.accessKey && req.query.key !== file.accessKey) {
            return res.status(401).json({ errors: ["Unauthorized"], success: false, data: null });
        }

        const fileLocation = path.join(__dirname, 'files', `${file.fileID}${file.ext}`);

        if (!fs.existsSync(fileLocation)) {
            return res.status(404).json({ errors: ["File not found on disk"], success: false, data: null });
        }

        const stats = fs.statSync(fileLocation);
        file.size = stats.size;
        file.type = file.mime_type || mime.getType(fileLocation);
        file.redirectUrl = `https://printedwaste.com/grid/view/?id=${file.fileID}${file.accessKey ? `?key=${file.accessKey}` : ''}`;
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
app.get('/status', async (req, res) => {
    try {
        const stats = await db.getStats();

        // Get disk usage
        const filesDir = path.join(__dirname, 'files');
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
                version: "2.0.0",
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
