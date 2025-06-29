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
const nodemailer_1 = __importDefault(require("nodemailer"));
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
// Helper to send OTP email
const sendOtpEmail = async (email, otp) => {
    // Configure your transporter (update with your SMTP credentials)
    const transporter = nodemailer_1.default.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT),
        secure: false, // true for 465, false for other ports
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        },
    });
    await transporter.sendMail({
        from: process.env.SMTP_FROM || 'no-reply@example.com',
        to: email,
        subject: 'Your Email Verification Code',
        text: `Your verification code is: ${otp}`,
    });
};
// Register new user
const registerHandler = async (req, res) => {
    try {
        const { email, password, name, businessName, businessPhone, businessDescription, businessLocation } = req.body;
        // Check if user already exists
        const existingUser = await prisma_1.default.user.findUnique({
            where: { email }
        });
        if (existingUser) {
            res.status(400).json({ error: 'Email already registered' });
            return;
        }
        // Check if this is the first user (make them admin)
        const userCount = await prisma_1.default.user.count();
        const isFirstUser = userCount === 0;
        // Hash password
        const salt = await bcryptjs_1.default.genSalt(10);
        const hashedPassword = await bcryptjs_1.default.hash(password, salt);
        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        // Create business first
        const business = await prisma_1.default.business.create({
            data: {
                name: businessName || `${name}'s Business`,
                phone: businessPhone || '',
                description: businessDescription || '',
                location: businessLocation || ''
            }
        });
        // Create new user with business association
        const user = await prisma_1.default.user.create({
            data: {
                email,
                password: hashedPassword,
                name,
                authEmailOtp: otp,
                isEmailVerified: false,
                role: isFirstUser ? 'ADMIN' : 'USER', // First user becomes admin
                businessId: business.id
            },
            include: {
                business: true
            }
        });
        // Send OTP email
        await sendOtpEmail(email, otp);
        res.status(201).json({
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                business: user.business
            },
            message: isFirstUser
                ? 'Registration successful. You are the first user and have been assigned ADMIN role. Please check your email for the verification code.'
                : 'Registration successful. Please check your email for the verification code.'
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
        // Enforce email verification
        if (!user.isEmailVerified) {
            res.status(401).json({ error: 'Please verify your email before logging in.' });
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
            user: { id: user.id, email: user.email, verified: user.isEmailVerified, role: user.role },
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
                name: true,
                role: true,
                isEmailVerified: true,
                createdAt: true,
                updatedAt: true,
                business: {
                    select: {
                        id: true,
                        name: true,
                        phone: true,
                        description: true,
                        location: true,
                        createdAt: true,
                        updatedAt: true
                    }
                }
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
// Email verification handler
const verifyEmailHandler = async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) {
            res.status(400).json({ error: 'Email and OTP are required' });
            return;
        }
        const user = await prisma_1.default.user.findUnique({ where: { email } });
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
        if (user.isEmailVerified) {
            res.status(400).json({ error: 'Email already verified' });
            return;
        }
        if (user.authEmailOtp !== otp) {
            res.status(400).json({ error: 'Invalid OTP' });
            return;
        }
        await prisma_1.default.user.update({
            where: { email },
            data: {
                isEmailVerified: true,
                authEmailOtp: null
            }
        });
        res.json({ message: 'Email verified successfully' });
    }
    catch (error) {
        res.status(400).json({ error: 'Email verification failed' });
    }
};
const resendOtpHandler = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            res.status(400).json({ error: 'Email is required' });
            return;
        }
        const user = await prisma_1.default.user.findUnique({ where: { email } });
        if (!user) {
            // To prevent user enumeration, send a generic success response
            res.json({ message: 'If a matching account exists, a new OTP has been sent.' });
            return;
        }
        if (user.isEmailVerified) {
            res.status(400).json({ error: 'Email is already verified.' });
            return;
        }
        // Generate a new OTP and send it
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await prisma_1.default.user.update({
            where: { email },
            data: { authEmailOtp: otp },
        });
        await sendOtpEmail(email, otp);
        res.json({ message: 'A new OTP has been sent to your email.' });
    }
    catch (error) {
        res.status(500).json({ error: 'Failed to resend OTP.' });
    }
};
// Forgot password handler
const forgotPasswordHandler = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            res.status(400).json({ error: 'Email is required' });
            return;
        }
        const user = await prisma_1.default.user.findUnique({ where: { email } });
        if (!user) {
            // For security, do not reveal if user does not exist
            res.json({ message: 'If the email exists, a reset code has been sent.' });
            return;
        }
        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await prisma_1.default.user.update({
            where: { email },
            data: { authEmailOtp: otp }
        });
        await sendOtpEmail(email, otp);
        res.json({ message: 'If the email exists, a reset code has been sent.' });
    }
    catch (error) {
        res.status(400).json({ error: 'Failed to process forgot password request' });
    }
};
// Reset password handler
const resetPasswordHandler = async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        if (!email || !otp || !newPassword) {
            res.status(400).json({ error: 'Email, OTP, and new password are required' });
            return;
        }
        const user = await prisma_1.default.user.findUnique({ where: { email } });
        if (!user || user.authEmailOtp !== otp) {
            res.status(400).json({ error: 'Invalid OTP or email' });
            return;
        }
        // Hash new password
        const salt = await bcryptjs_1.default.genSalt(10);
        const hashedPassword = await bcryptjs_1.default.hash(newPassword, salt);
        await prisma_1.default.user.update({
            where: { email },
            data: {
                password: hashedPassword,
                authEmailOtp: null
            }
        });
        res.json({ message: 'Password reset successful' });
    }
    catch (error) {
        res.status(400).json({ error: 'Failed to reset password' });
    }
};
// Placeholder admin middleware (replace with real implementation)
const adminAuth = (req, res, next) => {
    if (req.user && req.user.role === 'ADMIN') {
        next();
    }
    else {
        res.status(403).json({ error: 'Admin access required' });
    }
};
// Get all users (admin only)
const getAllUsersHandler = async (req, res) => {
    try {
        const users = await prisma_1.default.user.findMany({
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                isEmailVerified: true,
                createdAt: true,
                updatedAt: true
            }
        });
        res.json({ users });
    }
    catch (error) {
        res.status(400).json({ error: 'Failed to fetch users' });
    }
};
// Update user (admin only)
const updateUserHandler = async (req, res) => {
    try {
        const { id } = req.params;
        const { email, name, role, isEmailVerified } = req.body;
        const user = await prisma_1.default.user.update({
            where: { id },
            data: {
                email,
                name,
                role,
                isEmailVerified
            }
        });
        res.json({ user });
    }
    catch (error) {
        res.status(400).json({ error: 'Failed to update user' });
    }
};
// Delete user (admin only)
const deleteUserHandler = async (req, res) => {
    try {
        const { id } = req.params;
        await prisma_1.default.user.delete({ where: { id } });
        res.json({ message: 'User deleted successfully' });
    }
    catch (error) {
        res.status(400).json({ error: 'Failed to delete user' });
    }
};
// Update profile handler
const updateProfileHandler = async (req, res) => {
    try {
        const userId = req.user?.id;
        const { name, businessName, businessPhone, businessDescription, businessLocation } = req.body;
        if (!userId) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }
        // Get user with business
        const user = await prisma_1.default.user.findUnique({
            where: { id: userId },
            include: { business: true }
        });
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
        // Update user and business information
        const updatedUser = await prisma_1.default.user.update({
            where: { id: userId },
            data: {
                name: name || user.name,
                business: {
                    update: {
                        name: businessName || user.business?.name,
                        phone: businessPhone || user.business?.phone,
                        description: businessDescription || user.business?.description,
                        location: businessLocation || user.business?.location
                    }
                }
            },
            include: {
                business: {
                    select: {
                        id: true,
                        name: true,
                        phone: true,
                        description: true,
                        location: true,
                        createdAt: true,
                        updatedAt: true
                    }
                }
            }
        });
        res.json({
            user: {
                id: updatedUser.id,
                email: updatedUser.email,
                name: updatedUser.name,
                role: updatedUser.role,
                isEmailVerified: updatedUser.isEmailVerified,
                createdAt: updatedUser.createdAt,
                updatedAt: updatedUser.updatedAt,
                business: updatedUser.business
            },
            message: 'Profile updated successfully'
        });
    }
    catch (error) {
        console.error('Profile update error:', error);
        res.status(400).json({ error: 'Failed to update profile', details: error instanceof Error ? error.message : 'Unknown error' });
    }
};
router.post('/register', registerHandler);
router.post('/login', loginHandler);
router.post('/refresh', refreshTokenHandler);
router.post('/logout', logoutHandler);
router.post('/change-password', auth_1.auth, changePasswordHandler);
router.get('/me', auth_1.auth, meHandler);
router.put('/profile', auth_1.auth, updateProfileHandler);
router.post('/verify-email', verifyEmailHandler);
router.post('/resend-otp', resendOtpHandler);
router.post('/forgot-password', forgotPasswordHandler);
router.post('/reset-password', resetPasswordHandler);
router.get('/users', auth_1.auth, adminAuth, getAllUsersHandler);
router.put('/users/:id', auth_1.auth, adminAuth, updateUserHandler);
router.delete('/users/:id', auth_1.auth, adminAuth, deleteUserHandler);
exports.default = router;
