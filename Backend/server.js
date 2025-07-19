import app from './index.js';
import dotenv from 'dotenv';
import prisma from './db/db.js';

dotenv.config();

const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    // Validate required env variables
    if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN || !process.env.DATABASE_URL) {
      throw new Error("Missing required environment variables");
    }

    // Test DB Connection
    await prisma.$connect();
    console.log('✅ Database connected successfully');

    // Start Express Server
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
    });

    // Graceful Shutdown
    process.on('SIGINT', async () => {
      await prisma.$disconnect();
      console.log('🔌 Database disconnected');
      process.exit(0);
    });

  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
}

startServer();
