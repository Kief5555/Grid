/***
 * File grid by printedwaste
 * Host files that are accessible by authenticated users
 */



//Packages

const express = require("express");
const app = express();
const db = require('better-sqlite3')('auth.db', options);
const path = require("path");
const cors = require("cors");
const winston = require("winston");


/**************Definitions
 * auth table:
 * id
 * username (optional, unique)
 * password (optional)
 * email (optional, unique)
 * profile (optional)
 * key (optional)
 * tempkey (optional)
 * tempkeyexpiry (optional)
 * 
 * 
 * Logic: Some users are admins, some are not. The ones that are not admin have a temp key that expires after a certain amount of time. 
 */

//Useful functions
async function createTableIfNotExists() {
    db.prepare('CREATE TABLE IF NOT EXISTS auth (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, profile TEXT, key TEXT, tempkey TEXT, tempkeyexpiry TEXT)').run();
}
//Authentication Functions
async function createUser(username, password, email, profile) {
    db.prepare('INSERT INTO auth (username, password, email, profile) VALUES (?, ?, ?, ?)').run(username, password, email, profile);
}

function createTempKey() {

}

function authorizeUser() {
    
}

function deleteUser() {
        
}

//Main
app.get('/', (req, res) => {
    
})