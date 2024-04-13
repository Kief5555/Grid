import express from "express";
import db from 'better-sqlite3';
import path from "path";
import cors from "cors";
import morgan from "morgan";
import favicon from 'serve-favicon';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import formData from 'express-form-data';
import fs from 'fs';
import multer from 'multer';
import bodyParser from 'body-parser';
import mime from 'mime';
import dotenv from 'dotenv';
import { dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

dotenv.config();

const app = express();
const dbConnection = db('main.db');

// Create tables
dbConnection.prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)").run();
dbConnection.prepare("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, owner TEXT, fileID TEXT, private BOOLEAN, accessKey TEXT, ext TEXT)").run();

// Middleware
morgan.token('formattedMeta', (req, res) => {
    const formattedTimestamp = `[${new Date().toLocaleString()}]`.padEnd(25);
    return `${formattedTimestamp} ${req.method} ${req.originalUrl}`;
});
app.use(morgan(':formattedMeta :response-time ms'));
app.use(favicon(path.join(__dirname, 'favicon.ico')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cors());
app.use(formData.parse());

// Authentication
const authenticateUser = (req, res, next) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).send({ errors: ["Authorization token required"], success: false, data: null });
    }

    let processedToken = '';
    if (token.startsWith('Bearer ')) {
        processedToken = token.slice(7, token.length);
    } else {
        processedToken = token;
    }

    try {
        const decoded = jwt.verify(processedToken, process.env.JWT);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).send({ errors: ["Invalid token"], success: false, data: null });
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

// Main route
app.get('/', (req, res) => {
    res.send("PrintedWaste Grid Service");
});

// Generate File ID
const generateFileID = () => {
    //8 characters
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 8; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    return result;
};

const generateAccessKey = () => {
    //36 characters
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 36; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    return result;
}



//File routes
app.get('/view/:id', async (req, res) => {
    //Only files that can be rendered in the browser can be viewed, otherwise, download the file
    const file = await dbConnection.prepare("SELECT fileID, filename, private, ext FROM files WHERE fileID = ?").get(req.params.id);
    if (!file) return res.status(404).send({ errors: ["File not found"], status: false, data: null });

    if (file.private == true) {
        const tokenRes = verifyToken(req.headers.authorization);
        if (!tokenRes) return res.status(401).send({ errors: ["Unauthorized"], status: false, data: null });
    }

    if (file.accessKey && req.query.key !== file.accessKey) {
        return res.status(401).send({ errors: ["Unauthorized"], status: false, data: null });
    }

    const fileLocation = path.join(__dirname, 'files', `${file.fileID + file.ext}`);

    const file1 = fs.readFileSync(fileLocation);
    res.contentType(mime.getType(fileLocation));
    res.setHeader('Content-Disposition', `inline; filename=${file.filename}`);
    res.send(file1);
});

app.get('/download/:id', async (req, res) => {
    const file = await dbConnection.prepare("SELECT fileID, filename, private, ext FROM files WHERE fileID = ?").get(req.params.id);
    if (!file) return res.status(404).send({ errors: ["File not found"], status: false, data: null });

    if (file.private == true) {
        const tokenRes = verifyToken(req.headers.authorization);
        if (!tokenRes) return res.status(401).send({ errors: ["Unauthorized"], status: false, data: null });
    }

    if (file.accessKey && req.query.key !== file.accessKey) {
        return res.status(401).send({ errors: ["Unauthorized"], status: false, data: null });
    }

    const fileLocation = path.join(__dirname, 'files', `${file.fileID + file.ext}`);
    res.setHeader('Content-Disposition', `attachment; filename=${file.filename}`);
    res.download(fileLocation, file.filename);
});



// API Routes
app.get('/api/file/:id', async (req, res) => {
    const file = await dbConnection.prepare("SELECT fileID, filename, private, ext FROM files WHERE fileID = ?").get(req.params.id);
    if (!file) return res.status(404).send({ errors: ["File not found"], status: false, data: null });

    if (file.private == true) {
        const tokenRes = verifyToken(req.headers.authorization);
        if (!tokenRes) return res.status(401).send({ errors: ["Unauthorized"], status: false, data: null });
    }

    if (file.accessKey && req.query.key !== file.accessKey) {
        return res.status(401).send({ errors: ["Unauthorized"], status: false, data: null });
    }

    const fileLocation = path.join(__dirname, 'files', `${file.fileID + file.ext}`);
    fs.stat(fileLocation, (err, stats) => {
        if (err) return res.status(500).send({ errors: ["Internal server err"], status: false, data: null });
        file.size = stats.size;
        file.type = mime.getType(fileLocation);
        return res.status(200).send({ status: true, data: { file }, errors: [] });
    });
});

app.post('/api/file/upload', authenticateUser, multer({ dest: 'files/', limits: { fileSize: 100000000 } }).single('file'), (req, res) => {
    const file = req.files.file;
    const { self = false, accessKey = false } = req.body;
    if (!file) return res.status(400).send({ errors: ["File required"], success: false, data: null });
    const fileID = generateFileID()
    const filename = file.name;
    const owner = req.user.username;

    const insertFile = dbConnection.prepare("INSERT INTO files (filename, owner, fileID, private, accessKey, ext) VALUES (?, ?, ?, ?, ?, ?)");
    const result = insertFile.run(filename, owner, fileID, `${self}`, accessKey ? generateAccessKey() : null, `${path.extname(file.name)}`);
    if (result.changes === 0) return res.status(500).send({ errors: ["Internal Server Error"], success: false, data: null });

    fs.renameSync(file.path, path.join(__dirname, 'files', `${fileID + path.extname(file.name)}`));

    res.status(201).send({ success: true, data: { fileID: fileID }, errors: [] });
});

app.post('/api/user/register', async (req, res) => {
    const { username = "", password = "", registerKey = "" } = req.body;
    if (registerKey !== process.env.RKEY) {
        return res.status(401).send({ errors: ["Invalid register key"], success: false, data: null });
    }

    const existingUser = await dbConnection.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (existingUser) {
        return res.status(400).send({ errors: ["Username already exists"], success: false, data: null });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    const insertUser = dbConnection.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    const result = insertUser.run(username, hashedPassword);

    res.status(201).send({ success: true, data: { id: result.lastInsertRowid }, errors: [] });
});

app.post('/api/user/login', (req, res) => {
    const { username = "", password = "" } = req.body;

    const user = dbConnection.prepare("SELECT * FROM users WHERE username = ?").get(username);

    if (!user) {
        return res.status(401).send({ errors: ["Invalid username or password"], success: false, data: null });
    }
    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).send({ errors: ["Invalid username or password"], success: false, data: null });
    }

    const token = jwt.sign({ username: user.username }, process.env.JWT, { expiresIn: "1w" });

    res.status(200).send({ success: true, data: { token }, errors: [] });
});

app.delete('/api/user/delete/:username', (req, res) => {
    const { username } = req.params;

    const result = dbConnection.prepare("DELETE FROM users WHERE username = ?").run(username);

    if (result.changes === 0) {
        return res.status(404).send({ errors: ["User not found"], success: false, data: null });
    }

    res.status(200).send({ success: true, data: null, errors: [] });
});

//Get all files that the user has uploaded
app.get('/api/user/files', authenticateUser, (req, res) => {
    const files = dbConnection.prepare("SELECT * FROM files WHERE owner = ?").all(req.user.username);
    res.status(200).send({ success: true, data: { files }, errors: [] });
});

// Start server
const port = process.env.PORT || 3020;
app.listen(port, () => {
    console.log(`[${new Date().toLocaleString()}]   Server Started on port ${process.env.port || 3020}`.padEnd(25));
});
