import { Router, Request, Response } from 'express';
import multer from 'multer';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import { logger } from '../utils/logger';
import { queue } from '../workers/queue';
import { applicationModel } from '../db/models';

const router = Router();

const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || './uploads');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync(UPLOAD_DIR)) {
      fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    }
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix =
      Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (['.apk', '.ipa', '.aab'].includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only APK, IPA, and AAB files allowed'));
    }
  }
});

function safePath(filePath: string): string {
  const resolved = path.resolve(filePath);

  if (!resolved.startsWith(UPLOAD_DIR + path.sep)) {
    throw new Error('Invalid file path (possible traversal)');
  }

  return resolved;
}

router.post('/', upload.single('file'), async (req: Request, res: Response) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const file = req.file;
    logger.info(`File uploaded: ${file.originalname} (${file.size} bytes)`);

    const safeFilePath = safePath(file.path);

    const fileBuffer = fs.readFileSync(safeFilePath);
    const hash = crypto.createHash('sha256')
      .update(fileBuffer)
      .digest('hex');

    const existing = await applicationModel.findByHash(hash);

    if (existing) {
      fs.unlinkSync(safeFilePath);
      logger.info(`Duplicate file detected: ${hash}`);

      return res.json({
        message: 'File already analyzed',
        application: existing
      });
    }

    const ext = path.extname(file.originalname).toLowerCase();
    const platform =
      ext === '.apk' || ext === '.aab' ? 'ANDROID' : 'IOS';

    const application = await applicationModel.create({
      name: file.originalname,
      platform,
      file_hash: hash,
      file_size: file.size,
      file_path: safeFilePath,
      original_filename: file.originalname,
      uploaded_by_id: 1
    });

    logger.info(`Application created: ${application.id}`);

    const jobs = await queue.getJobs(['waiting', 'active', 'delayed']);
    const existingJob = jobs.find(
      j => j.data.applicationId === application.id
    );

    if (!existingJob) {
      await queue.add(
        'analyze',
        { applicationId: application.id },
        {
          jobId: `analyze-${application.id}`,
          removeOnComplete: true,
          removeOnFail: false
        }
      );
      logger.info(`Analysis job queued for ${application.id}`);
    }

    return res.status(201).json({
      message: 'File uploaded successfully',
      application
    });

  } catch (error: any) {
    logger.error('Upload error:', error);
    return res.status(500).json({
      error: 'Upload failed',
      detail: error.message
    });
  }
});

export default router;
