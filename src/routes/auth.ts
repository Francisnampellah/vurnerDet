import express, { Request, Response, Router, RequestHandler } from 'express';
import jwt, { SignOptions } from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import prisma from '../lib/prisma';
import crypto from 'crypto';
import { auth } from '../middleware/auth';

const router: Router = express.Router();

// Generate refresh token
const generateRefreshToken = async (userId: string): Promise<string> => {
  const token = crypto.randomBytes(40).toString('hex');
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 30); // 30 days expiry

  await prisma.refreshToken.create({
    data: {
      token,
      userId,
      expiresAt
    }
  });

  return token;
};

// Generate access token
const generateAccessToken = (userId: string): string => {
  const signOptions: SignOptions = { expiresIn: Number(process.env.JWT_EXPIRES_IN) || '1h' };
  return jwt.sign(
    { id: userId },
    process.env.JWT_SECRET || 'your-super-secret-jwt-key',
    signOptions
  );
};

// Register new user
const registerHandler: RequestHandler = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      res.status(400).json({ error: 'Email already registered' });
      return;
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const user = await prisma.user.create({
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
  } catch (error) {
    console.error('Registration error:', error);
    res.status(400).json({ error: 'Invalid registration data', details: error instanceof Error ? error.message : 'Unknown error' });
  }
};

// Login user
const loginHandler: RequestHandler = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      res.status(401).json({ error: 'Invalid login credentials' });
      return;
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
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
  } catch (error) {
    res.status(400).json({ error: 'Invalid login data' });
  }
};

// Refresh token
const refreshTokenHandler: RequestHandler = async (req: Request, res: Response): Promise<void> => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({ error: 'Refresh token is required' });
      return;
    }

    // Find refresh token in database
    const tokenRecord = await prisma.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: true }
    });

    if (!tokenRecord) {
      res.status(401).json({ error: 'Invalid refresh token' });
      return;
    }

    // Check if token is expired
    if (tokenRecord.expiresAt < new Date()) {
      await prisma.refreshToken.delete({
        where: { id: tokenRecord.id }
      });
      res.status(401).json({ error: 'Refresh token expired' });
      return;
    }

    // Generate new access token
    const accessToken = generateAccessToken(tokenRecord.userId);

    res.json({ accessToken });
  } catch (error) {
    res.status(400).json({ error: 'Invalid refresh token data' });
  }
};

// Logout handler
const logoutHandler: RequestHandler = async (req: Request, res: Response): Promise<void> => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({ error: 'Refresh token is required' });
      return;
    }

    // Delete the refresh token from database
    await prisma.refreshToken.deleteMany({
      where: { token: refreshToken }
    });

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(400).json({ error: 'Logout failed' });
  }
};

// Change password handler
const changePasswordHandler: RequestHandler = async (req: Request, res: Response): Promise<void> => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user?.id;
    // Assuming user ID is attached by auth middleware

    console.log("===============")
    console.log(currentPassword, newPassword)
    console.log("userId",userId)
    console.log("===============")
    
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    // Get user
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      res.status(401).json({ error: 'Current password is incorrect' });
      return;
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update password
    await prisma.user.update({
      where: { id: userId },
      data: { password: hashedPassword }
    });

    // Delete all refresh tokens for this user
    await prisma.refreshToken.deleteMany({
      where: { userId }
    });

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    res.status(400).json({ error: 'Password change failed' });
  }
};

// Get current user handler
const meHandler: RequestHandler = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;

    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const user = await prisma.user.findUnique({
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
  } catch (error) {
    res.status(400).json({ error: 'Failed to fetch user data' });
  }
};

router.post('/register', registerHandler);
router.post('/login', loginHandler);
router.post('/refresh', refreshTokenHandler);
router.post('/logout', logoutHandler);
router.post('/change-password', auth, changePasswordHandler);
router.get('/me', auth, meHandler);

export default router; 