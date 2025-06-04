"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const prisma_1 = __importDefault(require("../lib/prisma"));
const crypto_1 = __importDefault(require("crypto"));
const auth_1 = require("../middleware/auth");
const router = express_1.default.Router();
// Generate refresh token
const generateRefreshToken = async (userId) => {
    const token = crypto_1.default.randomBytes(40).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 days expiry
    await prisma_1.default.refreshToken.create({
        data: {
            token,
            userId,
            expiresAt
        }
    });
    return token;
};
// Generate access token
const generateAccessToken = (userId) => {
    const signOptions = { expiresIn: Number(process.env.JWT_EXPIRES_IN) || '1h' };
    return jsonwebtoken_1.default.sign({ id: userId }, process.env.JWT_SECRET || 'your-super-secret-jwt-key', signOptions);
};
// Register new user
const registerHandler = async (req, res) => {
    try {
        const { email, password } = req.body;
        // Check if user already exists
        const existingUser = await prisma_1.default.user.findUnique({
            where: { email }
        });
        if (existingUser) {
            res.status(400).json({ error: 'Email already registered' });
            return;
        }
        // Hash password
        const salt = await bcryptjs_1.default.genSalt(10);
        const hashedPassword = await bcryptjs_1.default.hash(password, salt);
        // Create new user
        const user = await prisma_1.default.user.create({
            data: {
                email,
                password: hashedPassword
            }
        });
        // Generate tokens
        const accessToken = generateAccessToken(user.id);
        const refreshToken = await generateRefreshToken(user.id);
        res.status(201).json({
            user: { id: user.id, email: user.email },
            accessToken,
            refreshToken
        });
    }
    catch (error) {
        console.error('Registration error:', error);
        res.status(400).json({ error: 'Invalid registration data', details: error instanceof Error ? error.message : 'Unknown error' });
    }
};
// Login user
const loginHandler = async (req, res) => {
    try {
        const { email, password } = req.body;
        // Find user
        const user = await prisma_1.default.user.findUnique({
            where: { email }
        });
        if (!user) {
            res.status(401).json({ error: 'Invalid login credentials' });
            return;
        }
        // Check password
        const isMatch = await bcryptjs_1.default.compare(password, user.password);
        if (!isMatch) {
            res.status(401).json({ error: 'Invalid login credentials' });
            return;
        }
        // Generate tokens
        const accessToken = generateAccessToken(user.id);
        const refreshToken = await generateRefreshToken(user.id);
        res.json({
            user: { id: user.id, email: user.email },
            accessToken,
            refreshToken
        });
    }
    catch (error) {
        res.status(400).json({ error: 'Invalid login data' });
    }
};
// Refresh token
const refreshTokenHandler = async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) {
            res.status(400).json({ error: 'Refresh token is required' });
            return;
        }
        // Find refresh token in database
        const tokenRecord = await prisma_1.default.refreshToken.findUnique({
            where: { token: refreshToken },
            include: { user: true }
        });
        if (!tokenRecord) {
            res.status(401).json({ error: 'Invalid refresh token' });
            return;
        }
        // Check if token is expired
        if (tokenRecord.expiresAt < new Date()) {
            await prisma_1.default.refreshToken.delete({
                where: { id: tokenRecord.id }
            });
            res.status(401).json({ error: 'Refresh token expired' });
            return;
        }
        // Generate new access token
        const accessToken = generateAccessToken(tokenRecord.userId);
        res.json({ accessToken });
    }
    catch (error) {
        res.status(400).json({ error: 'Invalid refresh token data' });
    }
};
// Logout handler
const logoutHandler = async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) {
            res.status(400).json({ error: 'Refresh token is required' });
            return;
        }
        // Delete the refresh token from database
        await prisma_1.default.refreshToken.deleteMany({
            where: { token: refreshToken }
        });
        res.json({ message: 'Logged out successfully' });
    }
    catch (error) {
        res.status(400).json({ error: 'Logout failed' });
    }
};
// Change password handler
const changePasswordHandler = async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user?.id;
        // Assuming user ID is attached by auth middleware
        console.log("===============");
        console.log(currentPassword, newPassword);
        console.log("userId", userId);
        console.log("===============");
        if (!userId) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }
        // Get user
        const user = await prisma_1.default.user.findUnique({
            where: { id: userId }
        });
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
        // Verify current password
        const isMatch = await bcryptjs_1.default.compare(currentPassword, user.password);
        if (!isMatch) {
            res.status(401).json({ error: 'Current password is incorrect' });
            return;
        }
        // Hash new password
        const salt = await bcryptjs_1.default.genSalt(10);
        const hashedPassword = await bcryptjs_1.default.hash(newPassword, salt);
        // Update password
        await prisma_1.default.user.update({
            where: { id: userId },
            data: { password: hashedPassword }
        });
        // Delete all refresh tokens for this user
        await prisma_1.default.refreshToken.deleteMany({
            where: { userId }
        });
        res.json({ message: 'Password changed successfully' });
    }
    catch (error) {
        res.status(400).json({ error: 'Password change failed' });
    }
};
// Get current user handler
const meHandler = async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }
        const user = await prisma_1.default.user.findUnique({
            where: { id: userId },
            select: {
                id: true,
                email: true,
                createdAt: true,
                updatedAt: true
            }
        });
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
        res.json({ user });
    }
    catch (error) {
        res.status(400).json({ error: 'Failed to fetch user data' });
    }
};
router.post('/register', registerHandler);
router.post('/login', loginHandler);
router.post('/refresh', refreshTokenHandler);
router.post('/logout', logoutHandler);
router.post('/change-password', auth_1.auth, changePasswordHandler);
router.get('/me', auth_1.auth, meHandler);
exports.default = router;
