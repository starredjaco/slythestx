import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { config } from './config';
import { logger } from './utils/logger';
import uploadRoutes from './api/upload';
import analysisRoutes from './api/analysis';
import { initDatabase } from './db/init';
import adbRoutes from "./api/adb";
import iosRoutes from './api/ios';

const app = express();

app.use(cors({
  origin: process.env.CORS_ORIGINS?.split(',') || '*',
  credentials: true,
}));

/* =======================
   SECURITY
   ======================= */
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginOpenerPolicy: { policy: 'unsafe-none' },
}));

/* =======================
   LOGGING
   ======================= */
app.use(
  morgan('combined', {
    stream: { write: (msg) => logger.info(msg.trim()) },
  })
);

/* =======================
   BODY PARSERS
   ======================= */
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

/* =======================
   API ROUTES
   ======================= */
app.use('/api/v1/upload', uploadRoutes);
app.use('/api/v1/analysis', analysisRoutes);
app.use('/api/v1/adb', adbRoutes);
app.use('/api/v1/ios', iosRoutes);
/* =======================
   404 HANDLER
   ======================= */
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

/* =======================
   ERROR HANDLER
   ======================= */
app.use(
  (err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    logger.error('Error:', err);
    res.status(err.status || 500).json({
      error: err.message || 'Internal server error',
      ...(config.nodeEnv !== 'production' && { stack: err.stack }),
    });
  }
);

async function start() {
  try {
    logger.info('🗄️ Initializing database...');
    await initDatabase();
    logger.info('✅ Database initialized');

    app.listen(config.port, '0.0.0.0', () => {
      logger.info('🚀 Slythestx v1.0.1');
      logger.info(`🌍 Server running on http://localhost:${config.port}`);
      logger.info(`📊 Environment: ${config.nodeEnv}`);
    });
  } catch (err) {
    logger.error('❌ Failed to start server', err);
    process.exit(1);
  }
}

start();

export default app;
