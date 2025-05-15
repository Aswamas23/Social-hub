const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Temporary database (replace with real DB in production)
const users = [];

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'secure_random_key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        httpOnly: true
    }
}));

// Security headers middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    next();
});

// Route handlers
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));

// Enhanced registration handler
app.post('/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        // Validation
        if (!name || !email || !password) {
            return res.redirect('/signup.html?error=All fields are required');
        }
        if (!emailRegex.test(email)) {
            return res.redirect('/signup.html?error=Invalid email format');
        }
        if (password.length < 8) {
            return res.redirect('/signup.html?error=Password must be at least 8 characters');
        }
        if (users.some(user => user.email === email)) {
            return res.redirect('/signup.html?error=Email already registered');
        }

        // Secure password handling
        const hashedPassword = await bcrypt.hash(password, 12);
        users.push({
            id: Date.now().toString(),
            name,
            email,
            password: hashedPassword,
            joined: new Date().toISOString()
        });

        // Redirect with success message
        res.redirect('/login.html?success=Registration successful. Please login');

    } catch (error) {
        console.error('Signup Error:', error);
        res.redirect('/signup.html?error=Server error');
    }
});

// Enhanced login handler
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = users.find(user => user.email === email);

        // Rate limiting simulation (add proper rate limiting in production)
        if (!user) {
            await new Promise(resolve => setTimeout(resolve, 2000)); // Delay for brute-force protection
            return res.redirect('/login.html?error=Invalid credentials');
        }

        const passwordValid = await bcrypt.compare(password, user.password);
        if (!passwordValid) {
            await new Promise(resolve => setTimeout(resolve, 2000));
            return res.redirect('/login.html?error=Invalid credentials');
        }

        // Session management
        req.session.regenerate(err => {
            if (err) throw err;
            
            req.session.user = {
                id: user.id,
                name: user.name,
                email: user.email
            };
            
            req.session.save(err => {
                if (err) throw err;
                res.redirect('/?login=success');
            });
        });

    } catch (error) {
        console.error('Login Error:', error);
        res.redirect('/login.html?error=Server error');
    }
});

// Logout handler
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/?error=Logout failed');
        }
        res.clearCookie('connect.sid');
        res.redirect('/login.html?success=Logged out successfully');
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).redirect('/?error=Internal server error');
});

app.listen(PORT, () => {
    console.log(`Server running securely on port ${PORT}`);
});
