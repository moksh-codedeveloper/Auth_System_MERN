// server.js
import app from './index.js';
import dotenv from 'dotenv';
import prisma from './db/db.js';

dotenv.config();

const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    // Test DB Connection
    await prisma.$connect();
    console.log('✅ Database connected successfully');

    // Start Express Server
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('❌ Failed to connect to database:', error);
    process.exit(1); // Exit if DB connection fails
  }
}

startServer();
