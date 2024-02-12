const express = require("express");
const app = express();
const db = require('better-sqlite3')('auth.db', options);
require("dotenv").config();


app.get('/', (req, res) => {
    
})