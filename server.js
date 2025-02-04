require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;
app.use(bodyParser.json());

const SECRET_KEY = process.env.SECRET_KEY;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

let refreshTokens = []; 
let posts = ["Early bird catches the worm."];

const users = [
    { username: 'admin', password: '123456', role: 'admin' },
    { username: 'user', password: '123568', role: 'user' }
];

// Middleware to authenticate JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Middleware for role-based access
function authorizeRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ message: 'You are not an admin' });
        }
        next();
    };
}

// Route to sign in 
app.post('/signin', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const accessToken = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ username: user.username }, REFRESH_SECRET, { expiresIn: '7d' });
    refreshTokens.push(refreshToken);
    res.json({ accessToken, refreshToken });
});

// Route to get posts (available for all authenticated users)
app.get('/posts', authenticateToken, (req, res) => {
    res.json(posts);
});

// Route to add posts (only admin can access)
app.post('/posts', authenticateToken, authorizeRole('admin'), (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ message: 'Message is required' });
    posts.push(message);
    res.status(201).json({ message: 'Post added successfully' });
});

// Route to refresh access token
app.post('/token', (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken || !refreshTokens.includes(refreshToken)) {
        return res.status(403).json({ message: 'Forbidden: Invalid refresh token' });
    }

    jwt.verify(refreshToken, REFRESH_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const newAccessToken = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '15m' });
        res.json({ accessToken: newAccessToken });
    });
});

// Route to logout and invalidate refresh token
app.post('/logout', (req, res) => {
    const { refreshToken } = req.body;
    refreshTokens = refreshTokens.filter(token => token !== refreshToken);
    res.json({ message: 'Logged out successfully' });
});


app.listen(PORT, () => {
  console.log(`listening on port ${PORT}`)
})
      