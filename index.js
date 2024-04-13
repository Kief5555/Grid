console.clear();
/**********************************************************************
 * File grid by printedwaste
 * Host files that are accessible by authenticated users
 *********************************************************************/



/*******************Packages******************/
const express = require("express");
const app = express();
const db = require('better-sqlite3')('main.db');
const path = require("path");
const cors = require("cors");
const morgan = require("morgan");
const favicon = require('serve-favicon');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const formData = require('express-form-data');
const fs = require('fs');
const multer = require('multer');
require('dotenv').config();


//Create 2 tables, one for users and one for files
db.prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)").run();
db.prepare("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, owner TEXT, fileID TEXT, private BOOLEAN, accessKey TEXT)").run();


/*******************Middleware******************/
morgan.token('formattedMeta', function (req, res) {
    const formattedTimestamp = `[${new Date().toLocaleString()}]`.padEnd(25);

    return `${formattedTimestamp} ${req.method} ${req.originalUrl}`;
});
app.use(morgan(':formattedMeta :response-time ms'));
app.use(favicon(path.join(__dirname, 'favicon.ico')));
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(formData.parse());



/*******************Auth******************/
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


/*******************Main******************/
app.get('/', (req, res) => {
    res.send("Hello World");
})

const generateFileID = () => {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}




/*******************API******************/
app.get('/api/file/:id', (req, res) => {
    const file = db.prepare("SELECT fileID, private, accessKey, mimetype, size FROM files WHERE id = ?").get(req.params.id);
    if (!file) return res.status(404).send({ errors: ["File not found"], status: false, data: null });

    if (file.private) {
        verifyToken(req.headers.authorization);
        return res.status(401).send({ errors: ["Unauthorized"], status: false, data: null });
    }

    if (file.accessKey && req.query.key !== file.accessKey) {
        return res.status(401).send({ errors: ["Unauthorized"], status: false, data: null });
    }

    const fileLocation = path.join(__dirname, 'files', file.fileID);
    fs.stat(fileLocation, (err, stats) => {
        if (err) {
            return res.status(500).send({ errors: ["Internal Server Error"], status: false, data: null });
        }
        const fileSizeInBytes = stats.size;
        return res.status(200).send({ status: true, data: { file, fileSizeInBytes }, errors: [] });
    });
});

// Upload file endpoint. For fileID, generate one. Save the file name to db then rename and save the file to the server with the fileID. Use multer and 100mb limit then return the fileID
app.post('/api/file/upload', authenticateUser, multer({ dest: 'files/', limits: { fileSize: 100000000 } }).single('file'), (req, res) => {
    const { file } = req;
    const { private = false, accessKey = "" } = req.body;
    if(!file) return res.status(400).send({ errors: ["File required"], success: false, data: null });
    const fileID = generateFileID();
    const filename = file.filename;
    const owner = req.user.username;

    const insertFile = db.prepare("INSERT INTO files (filename, owner, fileID, private, accessKey, mimetype, size) VALUES (?, ?, ?, ?, ?, ?, ?)");
    const result = insertFile.run(filename, owner, fileID, private, accessKey, file.mimetype, file.size);

    fs.renameSync(file.path, path.join(__dirname, 'files', fileID));

    res.status(201).send({ success: true, data: { fileID: result.lastInsertRowid }, errors: [] });
});

// Register endpoint
app.post('/api/user/register', (req, res) => {
    const { username = "", password = "", registerKey = "" } = req.body;
    if (registerKey !== process.env.RKEY) {
        return res.status(401).send({ errors: ["Invalid register key"], success: false, data: null });
    }

    const existingUser = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (existingUser) {
        return res.status(400).send({ errors: ["Username already exists"], success: false, data: null });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    const insertUser = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    const result = insertUser.run(username, hashedPassword);

    res.status(201).send({ success: true, data: { id: result.lastInsertRowid }, errors: [] });
});

// Login endpoint
app.post('/api/user/login', (req, res) => {
    const { username = "", password = "" } = req.body;

    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

    if (!user) {
        return res.status(401).send({ errors: ["Invalid username or password"], success: false, data: null });
    }
    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).send({ errors: ["Invalid username or password"], success: false, data: null });
    }

    const token = jwt.sign({ username: user.username }, process.env.JWT, { expiresIn: "1w" });

    res.status(200).send({ success: true, data: { token }, errors: [] });
});

// Delete user endpoint
app.delete('/api/user/delete/:username', (req, res) => {
    const { username } = req.params;

    const result = db.prepare("DELETE FROM users WHERE username = ?").run(username);

    if (result.changes === 0) {
        return res.status(404).send({ errors: ["User not found"], success: false, data: null });
    }

    res.status(200).send({ success: true, data: null, errors: [] });
});


//Start server
const port = process.env.PORT || 3020;
app.listen(port, () => {
    console.log(`[${new Date().toLocaleString()}]   Server Started on port ${process.env.port || 3020}`.padEnd(25))
});