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
const https_1 = __importDefault(require("https"));
const url_1 = require("url");
const router = express_1.default.Router();
// Test internet connectivity
const testInternetConnectivity = async () => {
    return new Promise((resolve) => {
        const testUrl = 'https://www.google.com';
        const url = new url_1.URL(testUrl);
        const req = https_1.default.request({
            hostname: url.hostname,
            port: 443,
            path: url.pathname,
            method: 'GET',
            timeout: 10000, // 10 seconds timeout
        }, (res) => {
            console.log(`Internet connectivity test: ${res.statusCode} - ${testUrl}`);
            resolve(true);
        });
        req.on('error', (error) => {
            console.error('Internet connectivity test failed:', error.message);
            resolve(false);
        });
        req.on('timeout', () => {
            console.error('Internet connectivity test timed out');
            req.destroy();
            resolve(false);
        });
        req.end();
    });
};
// Test SMTP connectivity
const testSMTPConnectivity = async () => {
    return new Promise((resolve) => {
        const transporter = nodemailer_1.default.createTransport({
            host: "live.smtp.mailtrap.io",
            port: 587,
            auth: {
                user: "api",
                pass: process.env.MAILTRAP_API_TOKEN || "7f85c4911d44ef254a48f62cbe27bd57"
            },
            connectionTimeout: 5000, // 5 seconds
            greetingTimeout: 5000,
            socketTimeout: 5000,
        });
        transporter.verify((error, success) => {
            if (error) {
                console.error('SMTP connectivity test failed:', error.message);
                resolve(false);
            }
            else {
                console.log('SMTP connectivity test: Success - Server is ready to take our messages');
                resolve(true);
            }
        });
    });
};
// Test network connectivity
const testNetworkConnectivity = async () => {
    console.log('=== Network Connectivity Test ===');
    // Test internet connectivity
    const internetOk = await testInternetConnectivity();
    console.log(`Internet connectivity: ${internetOk ? '✅ OK' : '❌ FAILED'}`);
    // Test SMTP connectivity
    const smtpOk = await testSMTPConnectivity();
    console.log(`SMTP connectivity: ${smtpOk ? '✅ OK' : '❌ FAILED'}`);
    // Log environment variables (without sensitive data)
    console.log('Mailtrap Configuration:');
    console.log(`- Host: live.smtp.mailtrap.io`);
    console.log(`- Port: 587`);
    console.log(`- User: api`);
    console.log(`- API Token: ${process.env.MAILTRAP_API_TOKEN ? 'SET' : 'NOT SET'}`);
    console.log(`- From: ${process.env.SMTP_FROM || 'NOT SET'}`);
    console.log('=== End Network Test ===');
};
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
    console.log("++++++++++++++++++++++++");
    console.log(email);
    console.log(otp);
    console.log("++++++++++++++++++++++++");
    // Run network connectivity tests first
    await testNetworkConnectivity();
    try {
        const transporter = nodemailer_1.default.createTransport({
            host: "live.smtp.mailtrap.io",
            port: 587,
            auth: {
                user: "api",
                pass: process.env.MAILTRAP_API_TOKEN || "7f85c4911d44ef254a48f62cbe27bd57"
            },
            // Add timeout configurations to prevent hanging connections
            connectionTimeout: 10000, // 10 seconds
            greetingTimeout: 10000, // 10 seconds
            socketTimeout: 10000, // 10 seconds
        });
        await transporter.sendMail({
            from: process.env.SMTP_FROM || 'noreply@yourdomain.com',
            to: email,
            subject: 'Your Email Verification Code',
            text: `Your verification code is: ${otp}`,
        });
    }
    catch (error) {
        console.error('Email sending error:', error);
        // Handle specific email errors
        if (error instanceof Error) {
            if (error.message.includes('getaddrinfo EAI_AGAIN')) {
                throw new Error('Email service temporarily unavailable due to network issues. Please try again later.');
            }
            else if (error.message.includes('Invalid login')) {
                throw new Error('Email service authentication failed. Please check SMTP credentials.');
            }
            else if (error.message.includes('ECONNREFUSED')) {
                throw new Error('Email service connection refused. Please check SMTP configuration.');
            }
            else if (error.message.includes('timeout') || error.message.includes('ETIMEDOUT') || error.message.includes('Connection timeout')) {
                throw new Error('Email service connection timed out. Please try again later.');
            }
            else if (error.message.includes('ENOTFOUND')) {
                throw new Error('Email service host not found. Please check SMTP configuration.');
            }
            else {
                throw new Error(`Email sending failed: ${error.message}`);
            }
        }
        else {
            throw new Error('Email sending failed due to an unknown error.');
        }
    }
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
        // Use transaction to ensure atomicity
        const result = await prisma_1.default.$transaction(async (tx) => {
            // Create business first
            const business = await tx.business.create({
                data: {
                    name: businessName || `${name}'s Business`,
                    phone: businessPhone || '',
                    description: businessDescription || '',
                    location: businessLocation || ''
                }
            });
            // Create new user with business association
            const user = await tx.user.create({
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
            return { user, business };
        });
        // Try to send OTP email, but don't fail registration if it fails
        let emailSent = false;
        let emailError = null;
        try {
            await sendOtpEmail(email, otp);
            emailSent = true;
        }
        catch (error) {
            console.error('Email sending failed but registration continued:', error);
            emailError = error instanceof Error ? error.message : 'Unknown email error';
        }
        res.status(201).json({
            user: {
                id: result.user.id,
                email: result.user.email,
                name: result.user.name,
                role: result.user.role,
                business: result.user.business
            },
            otp: emailSent ? undefined : otp, // Only return OTP if email failed
            emailSent,
            emailError,
            message: isFirstUser
                ? `Registration successful. You are the first user and have been assigned ADMIN role. ${emailSent ? 'Please check your email for the verification code.' : 'Email sending failed. Please use the OTP provided below.'}`
                : `Registration successful. ${emailSent ? 'Please check your email for the verification code.' : 'Email sending failed. Please use the OTP provided below.'}`
        });
    }
    catch (error) {
        console.error('Registration error:', error);
        res.status(400).json({
            error: 'Invalid registration data',
            details: error instanceof Error ? error.message : 'Unknown error'
        });
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
        // Try to send OTP email, but don't fail if it doesn't work
        let emailSent = false;
        let emailError = null;
        try {
            await sendOtpEmail(email, otp);
            emailSent = true;
        }
        catch (error) {
            console.error('Email sending failed for forgot password:', error);
            emailError = error instanceof Error ? error.message : 'Unknown email error';
        }
        res.json({
            message: emailSent
                ? 'If the email exists, a reset code has been sent.'
                : 'Password reset initiated. Email sending failed. Please use the OTP provided below.',
            otp: emailSent ? undefined : otp, // Only return OTP if email failed
            emailSent,
            emailError
        });
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
// Test endpoint for network connectivity (remove in production)
router.get('/test-network', async (req, res) => {
    try {
        await testNetworkConnectivity();
        res.json({ message: 'Network test completed. Check server logs for details.' });
    }
    catch (error) {
        res.status(500).json({ error: 'Network test failed', details: error instanceof Error ? error.message : 'Unknown error' });
    }
});
exports.default = router;
