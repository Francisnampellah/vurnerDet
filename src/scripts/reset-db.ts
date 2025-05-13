import { PrismaClient } from '@prisma/client';
import { execSync } from 'child_process';

async function resetDatabase() {
  try {
    console.log('🔄 Resetting database...');
    
    // Run Prisma migrations reset
    execSync('npx prisma migrate reset --force', { stdio: 'inherit' });
    
    // Run Prisma generate to update client
    execSync('npx prisma generate', { stdio: 'inherit' });
    
    console.log('✅ Database reset completed successfully');
  } catch (error) {
    console.error('❌ Error resetting database:', error);
    process.exit(1);
  }
}

resetDatabase(); 