import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import authRoutes from './routes/auth';
import { auth } from './middleware/auth';
import scanRoutes from "./routes/zap"

// Load environment variables
dotenv.config();

// Initialize Prisma Client
const prisma = new PrismaClient();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors()); // Enable CORS for all routes
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/scan', scanRoutes);

// Protected route example
app.get('/api/protected', auth, (_req, res) => {
  res.json({ message: 'This is a protected route' });
});

app.get('/', (_req, res) => {
  res.send('Hello, TypeScript!');
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
