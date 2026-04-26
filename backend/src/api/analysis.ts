import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger';
import { applicationModel, analysisResultModel, vulnerabilityModel } from '../db/models';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

const router = Router();

router.get('/applications', async (req: Request, res: Response) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const pageSize = parseInt(req.query.page_size as string) || 20;
    const platform = req.query.platform as string;
    const status = req.query.status as string;

    const result = await applicationModel.findAll({ page, pageSize, platform, status });

    return res.json({
      applications: result.applications,
      total: result.total,
      page,
      page_size: pageSize,
      total_pages: Math.ceil(result.total / pageSize)
    });

  } catch (error: any) {
    logger.error('List applications error:', error);
    return res.status(500).json({ error: 'Failed to fetch applications' });
  }
});

router.get('/applications/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);

    const [application, analysisResult, vulnerabilities, summary] = await Promise.all([
      applicationModel.findById(id),
      analysisResultModel.findByApplicationId(id),
      vulnerabilityModel.findByApplicationId(id),
      vulnerabilityModel.getSummary(id)
    ]);

    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }

    return res.json({
      application,
      analysis_result: analysisResult,
      vulnerabilities,
      summary
    });

  } catch (error: any) {
    logger.error('Get application error:', error);
    return res.status(500).json({ error: 'Failed to fetch application' });
  }
});

router.get('/statistics', async (req: Request, res: Response) => {
  try {
    const stats = await applicationModel.getStatistics();
    return res.json(stats);
  } catch (error: any) {
    logger.error('Get statistics error:', error);
    return res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

router.delete('/applications/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    
    if (isNaN(id)) {
      return res.status(400).json({ error: 'Invalid application ID' });
    }

    const application = await applicationModel.findById(id);
    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }

    logger.info(`🗑️ Deleting application ${id}: ${application.name}`);

    if (application.file_path && fs.existsSync(application.file_path)) {
      fs.unlinkSync(application.file_path);
      logger.info(`  ✓ Deleted file: ${application.file_path}`);
    }

    if (application.file_path) {
      const workingDir = path.join(path.dirname(application.file_path), `analysis_${id}`);
      if (fs.existsSync(workingDir)) {
        fs.rmSync(workingDir, { recursive: true, force: true });
        logger.info(`  ✓ Deleted working directory`);
      }
    }

    const bundlesDir = '/app/analysis_results/bundles';
    if (fs.existsSync(bundlesDir)) {
      const files = fs.readdirSync(bundlesDir);
      for (const file of files) {
        if (file.includes(`_app${id}.`) || file.includes(`_app${id}_`)) {
          fs.unlinkSync(path.join(bundlesDir, file));
          logger.info(`  ✓ Deleted bundle: ${file}`);
        }
      }
    }

  
    await vulnerabilityModel.deleteByApplicationId(id);
    logger.info(`  ✓ Deleted vulnerabilities`);

    await analysisResultModel.deleteByApplicationId(id);
    logger.info(`  ✓ Deleted analysis results`);

    await applicationModel.delete(id);
    logger.info(`  ✓ Deleted application record`);

    logger.info(`✅ Application ${id} completely deleted`);

    return res.json({ 
      message: 'Application deleted successfully',
      deletedId: id,
      deletedName: application.name
    });

  } catch (error: any) {
    logger.error('Delete application error:', error);
    return res.status(500).json({ 
      error: 'Failed to delete application',
      detail: error.message 
    });
  }
});

router.get('/applications/:id/download-bundle', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    
    const application = await applicationModel.findById(id);
    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }

    const analysisResult = await analysisResultModel.findByApplicationId(id);
    if (!analysisResult) {
      return res.status(404).json({ error: 'Analysis not found' });
    }

    const manifestData = analysisResult.manifest_data as any;
    const bundlePath = manifestData?.react_analysis?.bundleFile;

    if (!bundlePath) {
      return res.status(404).json({ error: 'No React Native bundle found for this application' });
    }

    if (!fs.existsSync(bundlePath)) {
      logger.error(`Bundle file not found: ${bundlePath}`);
      return res.status(404).json({ error: 'Bundle file not found on disk' });
    }

    logger.info(`Downloading React Native bundle for app ${id}: ${bundlePath}`);
    
    const filename = `react-native-bundle-app${id}-${path.basename(bundlePath)}`;
    
    res.download(bundlePath, filename, (err) => {
      if (err) {
        logger.error('Download error:', err);
        if (!res.headersSent) {
          res.status(500).json({ error: 'Failed to download bundle' });
        }
      }
    });

  } catch (error: any) {
    logger.error('Download bundle error:', error);
    if (!res.headersSent) {
      return res.status(500).json({ error: 'Failed to download bundle' });
    }
  }
});

router.post('/applications/:id/patch-reflutter', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    
    const application = await applicationModel.findById(id);
    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }

    if (application.platform !== 'ANDROID') {
      return res.status(400).json({ error: 'ReFlutter only works with Android APKs' });
    }

    const analysisResult = await analysisResultModel.findByApplicationId(id);
    const flutterAnalysis = (analysisResult?.manifest_data as any)?.flutter_analysis;

    if (!flutterAnalysis?.isFlutter) {
      return res.status(400).json({ error: 'Not a Flutter application' });
    }

    if (!flutterAnalysis.reflutterAvailable) {
      return res.status(400).json({ error: 'ReFlutter is not installed on the server' });
    }

    logger.info(`Patching Flutter APK ${id} with ReFlutter...`);

    const apkPath = application.file_path;
    const outputDir = path.join(path.dirname(apkPath), `reflutter_${id}`);

    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const command = `reflutter "${apkPath}" -o "${outputDir}"`;
    
    const output = execSync(command, {
      encoding: 'utf-8',
      timeout: 300000, 
      maxBuffer: 50 * 1024 * 1024,
    });

    logger.info('ReFlutter patching completed');


    const patchedFiles = fs.readdirSync(outputDir).filter(f => f.endsWith('.apk'));
    
    if (patchedFiles.length === 0) {
      return res.status(500).json({ error: 'Patched APK not found' });
    }

    const patchedApk = path.join(outputDir, patchedFiles[0]);

    return res.json({
      success: true,
      message: 'APK patched successfully with ReFlutter',
      output: output,
      downloadUrl: `/api/v1/analysis/applications/${id}/download-patched`,
    });

  } catch (error: any) {
    logger.error('ReFlutter patching error:', error);
    return res.status(500).json({ 
      error: 'Failed to patch with ReFlutter',
      detail: error.message 
    });
  }
});

router.get('/applications/:id/download-patched', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    
    const application = await applicationModel.findById(id);
    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }

    const outputDir = path.join(path.dirname(application.file_path), `reflutter_${id}`);
    
    if (!fs.existsSync(outputDir)) {
      return res.status(404).json({ error: 'Patched APK not found' });
    }

    const patchedFiles = fs.readdirSync(outputDir).filter(f => f.endsWith('.apk'));
    
    if (patchedFiles.length === 0) {
      return res.status(404).json({ error: 'Patched APK not found' });
    }

    const patchedApk = path.join(outputDir, patchedFiles[0]);

    logger.info(`Downloading patched APK for app ${id}`);
    
    res.download(patchedApk, `reflutter-patched-${id}.apk`);

  } catch (error: any) {
    logger.error('Download patched APK error:', error);
    return res.status(500).json({ error: 'Failed to download patched APK' });
  }
});

router.get('/applications/:id/download-xamarin-dlls', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);

    const application = await applicationModel.findById(id);
    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }

    const analysisResult = await analysisResultModel.findByApplicationId(id);
    if (!analysisResult) {
      return res.status(404).json({ error: 'Analysis not found' });
    }

    const manifestData = analysisResult.manifest_data as any;
    const zipPath = manifestData?.xamarin_analysis?.outputZip;

    if (!zipPath) {
      return res.status(404).json({ error: 'No Xamarin DLLs found for this application' });
    }

    if (!fs.existsSync(zipPath)) {
      logger.error(`Xamarin DLL ZIP not found: ${zipPath}`);
      return res.status(404).json({ error: 'DLL ZIP not found on disk' });
    }

    logger.info(`Downloading Xamarin DLLs for app ${id}: ${zipPath}`);

    const filename = `xamarin-dlls-app${id}-${path.basename(zipPath)}`;

    res.download(zipPath, filename, (err) => {
      if (err) {
        logger.error('Xamarin DLL download error:', err);
        if (!res.headersSent) {
          res.status(500).json({ error: 'Failed to download Xamarin DLLs' });
        }
      }
    });

  } catch (error: any) {
    logger.error('Download Xamarin DLLs error:', error);
    if (!res.headersSent) {
      return res.status(500).json({ error: 'Failed to download Xamarin DLLs' });
    }
  }
});

//MAUI DLLS
router.get('/applications/:id/download-maui-dlls', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const application = await applicationModel.findById(id);
    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }
    const analysisResult = await analysisResultModel.findByApplicationId(id);
    if (!analysisResult) {
      return res.status(404).json({ error: 'Analysis not found' });
    }
    const manifestData = analysisResult.manifest_data as any;
    const zipPath = manifestData?.maui_analysis?.outputZip;
    if (!zipPath) {
      return res.status(404).json({ error: 'No .NET MAUI DLLs found for this application' });
    }
    if (!fs.existsSync(zipPath)) {
      logger.error(`MAUI DLL ZIP not found: ${zipPath}`);
      return res.status(404).json({ error: 'DLL ZIP not found on disk' });
    }
    logger.info(`Downloading .NET MAUI DLLs for app ${id}: ${zipPath}`);
    
    const filename = `maui-dlls-app${id}-${path.basename(zipPath)}`;
    res.download(zipPath, filename, (err) => {
      if (err) {
        logger.error('MAUI DLL download error:', err);
        if (!res.headersSent) {
          res.status(500).json({ error: 'Failed to download .NET MAUI DLLs' });
        }
      }
    });
  } catch (error: any) {
    logger.error('Download MAUI DLLs error:', error);
    if (!res.headersSent) {
      return res.status(500).json({ error: 'Failed to download .NET MAUI DLLs' });
    }
  }
});

export default router;
