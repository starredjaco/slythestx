import Queue from 'bull';
import { config } from '../config';
import { logger } from '../utils/logger';

export const queue = new Queue('analysis', config.redisUrl, {
  defaultJobOptions: {
    removeOnComplete: true,
    removeOnFail: 50,
    attempts: 1,
    timeout: 600000,
  },
  settings: {
    maxStalledCount: 0,
    stalledInterval: 300000,
    lockDuration: 600000,
  },
});

async function cleanQueue() {
  try {
    const waiting = await queue.getWaiting();
    const active = await queue.getActive();
    const delayed = await queue.getDelayed();
    
    logger.info(`Queue status: ${waiting.length} waiting, ${active.length} active, ${delayed.length} delayed`);
    
  } catch (error) {
    logger.error('Error checking queue:', error);
  }
}

cleanQueue();

queue.on('completed', (job, result) => {
  logger.info(`Job ${job.id} completed`, { result });
});

queue.on('failed', (job, err) => {
  logger.error(`Job ${job?.id} failed`, { error: err.message });
});

queue.on('stalled', (job) => {
  logger.warn(`Job ${job.id} stalled - will NOT retry`);
});

queue.on('error', (error) => {
  logger.error('Queue error:', error);
});

queue.on('active', (job) => {
  logger.info(`Job ${job.id} started processing`);
});

logger.info('✅ Analysis queue initialized');

export default queue;
