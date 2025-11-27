const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const redis = require('redis');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
    origin: process.env.CORS_ORIGINS || ['http://localhost:3000'],
    credentials: true
}));
app.use(express.json());

// Redis client for token blacklisting
const redisClient = redis.createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});
redisClient.connect();

// Rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: 'Too many authentication attempts, please try again later.'
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100 // 100 requests per minute
});

// JWT configuration
const JWT_CONFIG = {
    accessToken: {
        expiresIn: '15m',
        secret: process.env.JWT_ACCESS_SECRET || 'access-secret'
    },
    refreshToken: {
        expiresIn: '7d',
        secret: process.env.JWT_REFRESH_SECRET || 'refresh-secret'
    }
};

class JWTManager {
    static generateAccessToken(payload) {
        return jwt.sign(
            { 
                ...payload, 
                type: 'access',
                jti: this.generateTokenId() 
            },
            JWT_CONFIG.accessToken.secret,
            { expiresIn: JWT_CONFIG.accessToken.expiresIn }
        );
    }

    static generateRefreshToken(payload) {
        return jwt.sign(
            { 
                ...payload, 
                type: 'refresh',
                jti: this.generateTokenId() 
            },
            JWT_CONFIG.refreshToken.secret,
            { expiresIn: JWT_CONFIG.refreshToken.expiresIn }
        );
    }

    static generateTokenId() {
        return require('crypto').randomBytes(16).toString('hex');
    }

    static async verifyAccessToken(token) {
        try {
            // Check blacklist
            if (await redisClient.get(`blacklist:${token}`)) {
                throw new Error('Token revoked');
            }

            return jwt.verify(token, JWT_CONFIG.accessToken.secret);
        } catch (error) {
            throw new Error('Invalid token');
        }
    }

    static async verifyRefreshToken(token) {
        try {
            // Check blacklist
            if (await redisClient.get(`blacklist:${token}`)) {
                throw new Error('Token revoked');
            }

            return jwt.verify(token, JWT_CONFIG.refreshToken.secret);
        } catch (error) {
            throw new Error('Invalid refresh token');
        }
    }

    static async revokeToken(token, expiresIn) {
        await redisClient.setEx(
            `blacklist:${token}`,
            Math.floor(expiresIn / 1000), // Convert to seconds
            'revoked'
        );
    }
}

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        const payload = await JWTManager.verifyAccessToken(token);
        req.user = payload;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// Routes
app.post('/auth/login', authLimiter, async (req, res) => {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    // In production, get user from database
    const user = { id: 1, username: 'test', password: '$2a$12$hashedpassword' };

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate tokens
    const accessToken = JWTManager.generateAccessToken({ userId: user.id, username: user.username });
    const refreshToken = JWTManager.generateRefreshToken({ userId: user.id });

    res.json({
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: 'bearer',
        expires_in: 15 * 60 // 15 minutes in seconds
    });
});

app.post('/auth/refresh', async (req, res) => {
    const { refresh_token } = req.body;

    if (!refresh_token) {
        return res.status(400).json({ error: 'Refresh token required' });
    }

    try {
        const payload = await JWTManager.verifyRefreshToken(refresh_token);
        
        // Revoke old refresh token
        const decoded = jwt.decode(refresh_token);
        await JWTManager.revokeToken(refresh_token, decoded.exp * 1000 - Date.now());

        // Generate new tokens
        const accessToken = JWTManager.generateAccessToken({ userId: payload.userId, username: payload.username });
        const newRefreshToken = JWTManager.generateRefreshToken({ userId: payload.userId });

        res.json({
            access_token: accessToken,
            refresh_token: newRefreshToken,
            token_type: 'bearer',
            expires_in: 15 * 60
        });
    } catch (error) {
        return res.status(403).json({ error: 'Invalid refresh token' });
    }
});

app.post('/auth/logout', authenticateToken, async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        const decoded = jwt.decode(token);
        await JWTManager.revokeToken(token, decoded.exp * 1000 - Date.now());
    }

    res.json({ message: 'Successfully logged out' });
});

app.get('/protected', authenticateToken, apiLimiter, (req, res) => {
    res.json({ 
        message: 'This is a protected route',
        user: req.user 
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Secure API server running on port ${PORT}`);
});
