//Packages

const express = require("express");
const app = express();
const db = require('better-sqlite3')('auth.db', options);
const path = require("path");
const cors = require("cors");
const winston = require("winston");


//Authentication Functions


//Main
app.get('/', (req, res) => {
    
})