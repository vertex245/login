const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public')); // Serve static files (e.g., script.js)

const users = {}; // In-memory storage (use a database in production)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const PORT = process.env.PORT || 3000;

// Root route
app.get('/', (req, res) => {
    res.json({ message: 'Welcome to the Login Backend API. Use /register, /login, or /logout.' });
});

// Register endpoint
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    if (users[username]) {
        return res.status(400).json({ message: 'Username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { password: hashedPassword };
    console.log(`Registered user: ${username}`);
    res.status(201).json({ message: 'Registration successful' });
});

// Login endpoint with debug logging
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(`Login attempt for: ${username}, password provided: ${password}`);
    const user = users[username];
    if (!user) {
        console.log(`User ${username} not found`);
        return res.status(401).json({ message: 'Invalid username or password' });
    }
    const match = await bcrypt.compare(password, user.password);
    console.log(`Password match: ${match}`);
    if (!match) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    console.log(`Login successful for ${username}, token issued: ${token}`);
    res.json({ message: 'Login successful', token });
});

// Logout endpoint
app.post('/logout', (req, res) => {
    res.json({ message: 'Logout successful' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
