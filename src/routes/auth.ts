import express, { Request, Response, Router, RequestHandler } from 'express';
import jwt, { SignOptions } from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import prisma from '../lib/prisma';

const router: Router = express.Router();

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

    // Generate token
    const signOptions: SignOptions = { expiresIn: Number(process.env.JWT_EXPIRES_IN) || '24h' };
    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET || 'your-super-secret-jwt-key',
      signOptions
    );

    res.status(201).json({ user, token });
  } catch (error) {
    res.status(400).json({ error: 'Invalid registration data' });
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

    // Generate token
    const signOptions: SignOptions = { expiresIn: Number(process.env.JWT_EXPIRES_IN) || '24h' };
    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET || 'your-super-secret-jwt-key',
      signOptions
    );

    res.json({ user, token });
  } catch (error) {
    res.status(400).json({ error: 'Invalid login data' });
  }
};

router.post('/register', registerHandler);
router.post('/login', loginHandler);

export default router; 