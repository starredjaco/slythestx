import dotenv from 'dotenv';

dotenv.config();

export const config = {
  
  appName: process.env.APP_NAME || 'Slythestx',
  appVersion: process.env.APP_VERSION || '1.0.2',
  nodeEnv: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '3001', 10),
  
 
  databaseUrl: process.env.DATABASE_URL || 'postgresql://postgres:postgres@db:5432/mobile_security',

  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  
 
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:5173'],
  
  
  maxUploadSize: parseInt(process.env.MAX_UPLOAD_SIZE || '524288000', 10), 
  allowedExtensions: ['.apk', '.ipa', '.aab'],
  uploadDir: process.env.UPLOAD_DIR || './uploads',
  analysisResultsDir: process.env.ANALYSIS_RESULTS_DIR || './analysis_results',
  
 
  analysisTimeout: parseInt(process.env.ANALYSIS_TIMEOUT || '3600', 10), 
  maxConcurrentAnalyses: parseInt(process.env.MAX_CONCURRENT_ANALYSES || '5', 10),
};

export default config;
