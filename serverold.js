const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// In-memory user storage (replace with DB in production)
const users = [];

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve static files from public folder
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_secure_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Routes to serve pages (optional since static middleware serves them)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));

// Registration handler
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!name || !email || !password) {
      return res.redirect('/signup.html?error=All%20fields%20are%20required');
    }
    if (!emailRegex.test(email)) {
      return res.redirect('/signup.html?error=Invalid%20email%20format');
    }
    if (password.length < 8) {
      return res.redirect('/signup.html?error=Password%20must%20be%20at%20least%208%20characters');
    }
    if (users.some(u => u.email === email)) {
      return res.redirect('/signup.html?error=Email%20already%20registered');
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    users.push({
      id: Date.now().toString(),
      name,
      email,
      password: hashedPassword,
      joined: new Date().toISOString()
    });

    res.redirect('/login.html?success=Registration%20successful.%20Please%20login');

  } catch (err) {
    console.error('Signup error:', err);
    res.redirect('/signup.html?error=Server%20error');
  }
});

// Login handler
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);

    if (!user) {
      // Delay to mitigate brute force
      await new Promise(r => setTimeout(r, 2000));
      return res.redirect('/login.html?error=Invalid%20credentials');
    }

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) {
      await new Promise(r => setTimeout(r, 2000));
      return res.redirect('/login.html?error=Invalid%20credentials');
    }

    // Regenerate session to prevent fixation
    req.session.regenerate(err => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.redirect('/login.html?error=Server%20error');
      }

      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email
      };

      req.session.save(err => {
        if (err) {
          console.error('Session save error:', err);
          return res.redirect('/login.html?error=Server%20error');
        }
        res.redirect('/?success=Login%20successful');
      });
    });

  } catch (err) {
    console.error('Login error:', err);
    res.redirect('/login.html?error=Server%20error');
  }
});

// Logout endpoint
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.redirect('/?error=Logout%20failed');
    }
    res.clearCookie('connect.sid');
    res.redirect('/login.html?success=Logged%20out%20successfully');
  });
});
app.get('/support.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'support.html'));
});
// Support form handler
app.post('/support', (req, res) => {
  const { name, email, message } = req.body;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!name || !email || !message) {
    return res.redirect('/support.html?error=All%20fields%20are%20required');
  }
  if (!emailRegex.test(email)) {
    return res.redirect('/support.html?error=Invalid%20email%20format');
  }

  // Here you would typically send the message to your support system
  console.log('Support request:', { name, email, message });

  res.redirect('/support.html?success=Message%20sent%20successfully');
});
// Removed duplicate declaration of PORT
// Middleware to check if user is logged in
const isLoggedIn = (req, res, next) => {
  if (req.session.user) {
    return next();
  }
  res.redirect('/login.html?error=Please%20login%20to%20access%20this%20page');
};
// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
