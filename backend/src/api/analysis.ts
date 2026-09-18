import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger';
import { applicationModel, analysisResultModel, vulnerabilityModel } from '../db/models';
import { FlutterAnalyzer } from '../analyzers/FlutterAnalyzer';
import fs from 'fs';
import path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

const router = Router();

function buildFlutterAnalyzer(application: any, id: number): FlutterAnalyzer {
  const extractPath = path.join(path.dirname(application.file_path), `analysis_${id}`);
  return new FlutterAnalyzer(extractPath, application.platform, id, application.file_path);
}

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

// ─── ReFlutter patch ─────────────────────────────────────────────────────────
router.post('/applications/:id/patch-reflutter', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { burpIp, mode } = req.body as { burpIp?: string; mode?: 'traffic' | 'offset' };

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

    if ((mode ?? 'traffic') === 'traffic' && !burpIp) {
      return res.status(400).json({ error: 'burpIp is required for traffic interception mode' });
    }

    logger.info(`Patching Flutter APK ${id} with ReFlutter (mode=${mode ?? 'traffic'})...`);

    const analyzer = buildFlutterAnalyzer(application, id);
    const result = await analyzer.patchWithReflutter({ mode, burpIp });

    if (!result.success) {
      return res.status(500).json({
        error: 'Failed to patch with ReFlutter',
        detail: result.error,
      });
    }

    logger.info('ReFlutter patching completed');

    return res.json({
      success: true,
      message: 'APK patched successfully with ReFlutter',
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
      return res.status(404).json({ error: 'Patched APK not found — patch with ReFlutter first' });
    }

    const patchedFiles = fs.readdirSync(outputDir).filter(f => f.endsWith('.apk'));
    if (patchedFiles.length === 0) {
      return res.status(404).json({ error: 'Patched APK not found in output directory' });
    }

    const patchedApk = path.join(outputDir, patchedFiles[0]);

    logger.info(`Downloading patched APK for app ${id}: ${patchedFiles[0]}`);

    res.download(patchedApk, `app${id}_patched.apk`);

  } catch (error: any) {
    logger.error('Download patched APK error:', error);
    if (!res.headersSent) {
      return res.status(500).json({ error: 'Failed to download patched APK' });
    }
  }
});

// ─── Blutter ─────────────────────────────────────────────────────────────────
router.post('/applications/:id/run-blutter', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);

    const application = await applicationModel.findById(id);
    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }

    if (application.platform !== 'ANDROID') {
      return res.status(400).json({ ran: false, error: 'Blutter only supports Android APKs' });
    }

    const analysisResult = await analysisResultModel.findByApplicationId(id);
    const flutterAnalysis = (analysisResult?.manifest_data as any)?.flutter_analysis;
    if (!flutterAnalysis?.isFlutter) {
      return res.status(400).json({ ran: false, error: 'Not a Flutter application' });
    }

    logger.info(`Running Blutter deep analysis for app ${id}...`);

    const analyzer = buildFlutterAnalyzer(application, id);
    const blutter = await analyzer.runBlutterAnalysis();

    if (!blutter) {
      return res.status(400).json({ ran: false, error: 'Blutter only applies to Android Flutter apps' });
    }

    const manifestData = (analysisResult?.manifest_data as any) || {};
    manifestData.flutter_analysis = { ...(manifestData.flutter_analysis || {}), blutter };

    const { id: _resultId, application_id: _appId, created_at, ...restColumns } =
      (analysisResult as any) || {};

    await analysisResultModel.deleteByApplicationId(id);
    await analysisResultModel.create({
      application_id: id,
      ...restColumns,
      manifest_data: manifestData,
    });

    logger.info(`Blutter completed for app ${id}: ${blutter.totalClasses} classes, ${blutter.findings.length} findings`);

    return res.json({
      success: true,
      ran: blutter.ran,
      totalClasses: blutter.totalClasses,
      totalMethods: blutter.totalMethods,
      findings: blutter.findings.length,
      error: blutter.ran ? undefined : blutter.error,
    });

  } catch (error: any) {
    logger.error('run-blutter failed:', error);
    return res.status(500).json({ ran: false, error: 'Failed to run Blutter', detail: error.message });
  }
});

router.get('/applications/:id/download-blutter-frida', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const outputDir = path.join('/app/analysis_results/blutter', `app${id}`);
    const fridaScript = path.join(outputDir, 'blutter_frida.js');

    if (!fs.existsSync(fridaScript)) {
      return res.status(404).json({ error: 'Frida script not found — run Blutter first' });
    }

    res.download(fridaScript, `app${id}-blutter-frida.js`);
  } catch (error: any) {
    logger.error('Download Blutter frida script error:', error);
    return res.status(500).json({ error: 'Failed to download Frida script' });
  }
});

router.get('/applications/:id/download-blutter', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id);
  const outputDir = path.join('/app/analysis_results/blutter', `app${id}`);

  try {
    if (!fs.existsSync(outputDir)) {
      return res.status(404).json({ error: 'Blutter output not found — run Blutter first' });
    }

    const zipPath = path.join('/tmp', `blutter_app${id}_${Date.now()}.zip`);
    await execAsync(`zip -r -q "${zipPath}" .`, { cwd: outputDir, timeout: 60000 });

    res.download(zipPath, `app${id}-blutter-output.zip`, (err) => {
      fs.unlink(zipPath, () => {});
      if (err) logger.warn('download-blutter stream error:', err.message);
    });
  } catch (error: any) {
    logger.error('Failed to package Blutter output:', error);
    return res.status(500).json({ error: 'Failed to package Blutter output' });
  }
});


//XAMARIN //
// --------------------------------------------------------------------------------------//
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