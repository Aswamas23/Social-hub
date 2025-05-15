require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.urlencoded({ extended: true }));

// --- Session Store (MemoryStore is NOT for production!) ---
const sessionConfig = {
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // true if behind HTTPS
    maxAge: 1000 * 60 * 60 * 2 // 2 hours
  }
};
app.use(session(sessionConfig));

// --- Serve static files ---
app.use(express.static(path.join(__dirname, 'public')));

// --- In-memory or file-based user store for demo (replace with DB in production) ---
const USERS_FILE = path.join(__dirname, 'users.json');
function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {
    return [];
  }
}
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// --- Routes ---

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Signup
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Missing fields');
  const users = loadUsers();
  if (users.find(u => u.username === username)) return res.status(400).send('User exists');
  const hash = await bcrypt.hash(password, 12);
  users.push({ username, password: hash });
  saveUsers(users);
  res.send('Signup successful!');
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Missing fields');
  const users = loadUsers();
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).send('User not found');
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).send('Invalid credentials');
  req.session.user = username;
  res.send('Login successful!');
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.send('Logged out!'));
});

// Protected route example
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.status(401).send('Unauthorized');
  res.send(`Welcome, ${req.session.user}!`);
});

// --- Error handling ---
app.use((err, req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    res.status(500).send('Server error');
  } else {
    res.status(500).send(err.stack);
  }
});

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
