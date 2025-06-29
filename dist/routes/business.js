"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const prisma_1 = __importDefault(require("../lib/prisma"));
const auth_1 = require("../middleware/auth");
const router = express_1.default.Router();
// Create business for current user
const createBusinessHandler = async (req, res) => {
    try {
        const userId = req.user?.id;
        const { name, phone, description, location } = req.body;
        if (!userId) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }
        // Check if user already has a business
        const existingUser = await prisma_1.default.user.findUnique({
            where: { id: userId },
            include: { business: true }
        });
        if (existingUser?.business) {
            res.status(400).json({ error: 'User already has a business' });
            return;
        }
        // Create business and associate with user
        const business = await prisma_1.default.business.create({
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
    }
    catch (error) {
        console.error('Create business error:', error);
        res.status(400).json({ error: 'Failed to create business' });
    }
};
// Update business for current user
const updateBusinessHandler = async (req, res) => {
    try {
        const userId = req.user?.id;
        const { name, phone, description, location } = req.body;
        if (!userId) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }
        // Get user with business
        const user = await prisma_1.default.user.findUnique({
            where: { id: userId },
            include: { business: true }
        });
        if (!user?.business) {
            res.status(404).json({ error: 'Business not found' });
            return;
        }
        // Update business
        const business = await prisma_1.default.business.update({
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
    }
    catch (error) {
        console.error('Update business error:', error);
        res.status(400).json({ error: 'Failed to update business' });
    }
};
// Get business for current user
const getBusinessHandler = async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }
        const user = await prisma_1.default.user.findUnique({
            where: { id: userId },
            include: { business: true }
        });
        if (!user?.business) {
            res.status(404).json({ error: 'Business not found' });
            return;
        }
        res.json({ business: user.business });
    }
    catch (error) {
        console.error('Get business error:', error);
        res.status(400).json({ error: 'Failed to get business' });
    }
};
// Check if user has business
const hasBusinessHandler = async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }
        const user = await prisma_1.default.user.findUnique({
            where: { id: userId },
            include: { business: true }
        });
        res.json({ hasBusiness: !!user?.business });
    }
    catch (error) {
        console.error('Check business error:', error);
        res.status(400).json({ error: 'Failed to check business status' });
    }
};
router.post('/', auth_1.auth, createBusinessHandler);
router.put('/', auth_1.auth, updateBusinessHandler);
router.get('/', auth_1.auth, getBusinessHandler);
router.get('/check', auth_1.auth, hasBusinessHandler);
exports.default = router;
