#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Get command line arguments
const args = process.argv.slice(2);
const username = args[0];
const password = args[1];

if (!username || !password) {
    console.log('Usage: node add-user.js <username> <password>');
    console.log('Example: node add-user.js admin mypassword123');
    process.exit(1);
}

// Read existing users
const usersPath = path.join(__dirname, 'data', 'users.json');
let users = [];

if (fs.existsSync(usersPath)) {
    const data = fs.readFileSync(usersPath, 'utf8');
    users = JSON.parse(data);
}

// Check if user already exists
const existingUser = users.find(user => user.username === username);
if (existingUser) {
    console.log(`User '${username}' already exists!`);
    process.exit(1);
}

// Create new user
const hashedPassword = bcrypt.hashSync(password, 12);
const newUser = {
    id: users.length + 1,
    username,
    password: hashedPassword,
    created_at: new Date().toISOString()
};

users.push(newUser);

// Write back to file
fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));

console.log(`User '${username}' created successfully!`);
console.log(`ID: ${newUser.id}`);
console.log(`Created: ${newUser.created_at}`);