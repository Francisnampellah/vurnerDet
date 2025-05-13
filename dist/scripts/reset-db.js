"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const prisma = new client_1.PrismaClient();
async function resetDatabase() {
    try {
        // Drop all tables
        await prisma.$executeRaw `DROP SCHEMA public CASCADE;`;
        await prisma.$executeRaw `CREATE SCHEMA public;`;
        // Run migrations
        await prisma.$executeRaw `GRANT ALL ON SCHEMA public TO novus;`;
        await prisma.$executeRaw `GRANT ALL ON SCHEMA public TO public;`;
        console.log('Database reset successful');
    }
    catch (error) {
        console.error('Error resetting database:', error);
        process.exit(1);
    }
    finally {
        await prisma.$disconnect();
    }
}
resetDatabase();
