import express, { Request, Response, Router, RequestHandler } from 'express';
import prisma from '../lib/prisma';
import { auth } from '../middleware/auth';

const router: Router = express.Router();

// Create business for current user
const createBusinessHandler: RequestHandler = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;
    const { name, phone, description, location } = req.body;

    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    // Check if user already has a business
    const existingUser = await prisma.user.findUnique({
      where: { id: userId },
      include: { business: true }
    });

    if (existingUser?.business) {
      res.status(400).json({ error: 'User already has a business' });
      return;
    }

    // Create business and associate with user
    const business = await prisma.business.create({
      data: {
        name,
        phone,
        description,
        location,
        user: {
          connect: { id: userId }
        }
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            name: true,
            role: true
          }
        }
      }
    });

    res.status(201).json({ business });
  } catch (error) {
    console.error('Create business error:', error);
    res.status(400).json({ error: 'Failed to create business' });
  }
};

// Update business for current user
const updateBusinessHandler: RequestHandler = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;
    const { name, phone, description, location } = req.body;

    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    // Get user with business
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { business: true }
    });

    if (!user?.business) {
      res.status(404).json({ error: 'Business not found' });
      return;
    }

    // Update business
    const business = await prisma.business.update({
      where: { id: user.business.id },
      data: {
        name,
        phone,
        description,
        location
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            name: true,
            role: true
          }
        }
      }
    });

    res.json({ business });
  } catch (error) {
    console.error('Update business error:', error);
    res.status(400).json({ error: 'Failed to update business' });
  }
};

// Get business for current user
const getBusinessHandler: RequestHandler = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;

    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { business: true }
    });

    if (!user?.business) {
      res.status(404).json({ error: 'Business not found' });
      return;
    }

    res.json({ business: user.business });
  } catch (error) {
    console.error('Get business error:', error);
    res.status(400).json({ error: 'Failed to get business' });
  }
};

// Check if user has business
const hasBusinessHandler: RequestHandler = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;

    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { business: true }
    });

    res.json({ hasBusiness: !!user?.business });
  } catch (error) {
    console.error('Check business error:', error);
    res.status(400).json({ error: 'Failed to check business status' });
  }
};

router.post('/', auth, createBusinessHandler);
router.put('/', auth, updateBusinessHandler);
router.get('/', auth, getBusinessHandler);
router.get('/check', auth, hasBusinessHandler);

export default router; 