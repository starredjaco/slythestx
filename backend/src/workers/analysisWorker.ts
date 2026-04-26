import { Job } from 'bull';
import path from 'path';
import fs from 'fs';
import { logger } from '../utils/logger';
import { queue } from './queue';
import { applicationModel, analysisResultModel, vulnerabilityModel } from '../db/models';
import { TechnologyDetector } from '../analyzers/technologyDetector';
import { PermissionAnalyzer } from '../analyzers/permissionAnalyzer';
import { SecretScanner } from '../analyzers/secretScanner';
import { ManifestAnalyzer } from '../analyzers/manifestAnalyzer';
import { ReactAnalyzer, ReactVulnerability } from '../analyzers/reactAnalyzer';
import { AppInfoParser } from '../analyzers/appInfoAnalyzer';
import { FlutterAnalyzer } from '../analyzers/flutterAnalyzer';
import { CordovaAnalyzer, CordovaFinding } from '../analyzers/cordovaAnalyzer';
import { SecurityMeasuresAnalyzer } from '../analyzers/securityMeasuresAnalyzer';
import { NativeAnalyzer, NativeFinding } from '../analyzers/nativeAnalyzer';
import { XamarinAnalyzer } from '../analyzers/xamarinAnalyzer';
import { DotNetMauiAnalyzer } from '../analyzers/dotnetMauiAnalyzer';

interface AnalysisJobData {
  applicationId: number;
}

queue.process('analyze', 1, async (job: Job<AnalysisJobData>) => {
  const { applicationId } = job.data;

  logger.info(`[Job ${job.id}] Starting analysis for application ${applicationId}`);

  try {
    const app = await applicationModel.findById(applicationId);
    if (!app) {
      logger.error(`[Job ${job.id}] Application ${applicationId} not found`);
      return { applicationId, status: 'not_found' };
    }

    if (app.analyzed_at) {
      logger.info(`[Job ${job.id}] Application ${applicationId} already analyzed. Skipping...`);
      return { applicationId, status: 'skipped' };
    }

    if (app.status === 'ANALYZING' || app.status === 'EXTRACTING') {
      logger.warn(`[Job ${job.id}] Application ${applicationId} is already being analyzed (status: ${app.status}). Skipping...`);
      return { applicationId, status: 'already_processing' };
    }

    const filePath = app.file_path;

    if (!fs.existsSync(filePath)) {
      logger.error(`[Job ${job.id}] File not found: ${filePath}`);
      await cleanupFailedAnalysis(applicationId, filePath);
      return { applicationId, status: 'file_not_found' };
    }

    await applicationModel.update(applicationId, { status: 'EXTRACTING', analysis_progress: 10 });

    const workingDir = path.join(path.dirname(filePath), `analysis_${applicationId}`);
    if (!fs.existsSync(workingDir)) fs.mkdirSync(workingDir, { recursive: true });

    // 1. Technology Detection (10-20%)
    await job.progress(20);
    await applicationModel.update(applicationId, { analysis_progress: 20 });

    const techDetector = new TechnologyDetector(filePath, workingDir);
    const techResults = await techDetector.detect();
    const extractPath = techDetector.getExtractPath();

    await applicationModel.update(applicationId, {
      technology: techResults.technology,
      status: 'ANALYZING',
    });

    logger.info(`Technology detected: ${techResults.technology}`);

    // 2. Permission Analysis (20-35%)
    await job.progress(35);
    await applicationModel.update(applicationId, { analysis_progress: 35 });

    const permAnalyzer = new PermissionAnalyzer(extractPath, techResults.platform);
    const permResults = await permAnalyzer.analyze();

    // 3. Secret Scanning (35-50%)
    await job.progress(50);
    await applicationModel.update(applicationId, { analysis_progress: 50 });

    const secretScanner = new SecretScanner(extractPath);
    const secretResults = await secretScanner.analyze();

    // 4. Manifest Analysis (50-60%)
    await job.progress(60);
    await applicationModel.update(applicationId, { analysis_progress: 60 });

    const manifestAnalyzer = new ManifestAnalyzer(extractPath, techResults.platform);
    const manifestResults = await manifestAnalyzer.analyze();

    // 5. React Native Analysis (60-65%)
    let reactResults = null;
    if (techResults.technology === 'REACT_NATIVE') {
      await job.progress(63);
      await applicationModel.update(applicationId, { analysis_progress: 63 });

      logger.info('⚛️ Analyzing React Native bundle...');
      const reactAnalyzer = new ReactAnalyzer(extractPath, techResults.platform, applicationId);
      reactResults = await reactAnalyzer.analyze();

      if (reactResults.hasHermes) {
        logger.warn('⚠️ Hermes bytecode detected');
      } else {
        logger.info(`React analyzed: ${reactResults.dependencies.total} deps, ${reactResults.vulnerabilities.length} vulnerabilities`);
      }
    }

    // 6. Flutter Analysis (65-70%)
    let flutterResults = null;
    if (techResults.technology === 'FLUTTER') {
      await job.progress(68);
      await applicationModel.update(applicationId, { analysis_progress: 68 });

      logger.info('🦋 Analyzing Flutter snapshot...');
      const flutterAnalyzer = new FlutterAnalyzer(extractPath, techResults.platform);
      flutterResults = await flutterAnalyzer.analyze();

      logger.info(
        `Flutter analyzed: Obfuscated=${flutterResults.snapshotInfo?.obfuscated}, Dart=${flutterResults.snapshotInfo?.dartVersion}`
      );
    }

    // 7. Cordova Analysis (70-75%)
    let cordovaResults = null;
    if (techResults.technology === 'CORDOVA') {
      await job.progress(73);
      await applicationModel.update(applicationId, { analysis_progress: 73 });

      logger.info('📱 Analyzing Cordova app...');
      const cordovaAnalyzer = new CordovaAnalyzer(extractPath, techResults.platform);
      cordovaResults = await cordovaAnalyzer.analyze();

      logger.info(
        `📦 Cordova analyzed: ${cordovaResults.plugins.length} plugins, ${cordovaResults.totalFindings} findings, ${cordovaResults.jsFiles} JS files scanned`
      );
    }

    // 8. Xamarin Analysis (75-78%)
    let xamarinResults = null;
    if (techResults.technology === 'XAMARIN') {
      await job.progress(77);
      await applicationModel.update(applicationId, { analysis_progress: 77 });

      logger.info('🧬 Analyzing Xamarin application...');
      const xamarinAnalyzer = new XamarinAnalyzer(extractPath, workingDir, techResults.platform);
      xamarinResults = await xamarinAnalyzer.analyze();

      logger.info(
        `🧬 Xamarin analyzed: ${xamarinResults.dllCount} DLLs, type=${xamarinResults.type}, lz4=${xamarinResults.compressed}`
      );
    }

    // 9. .NET MAUI Analysis (78-80%)
    let mauiResults = null;
    if (techResults.technology === 'DOTNET_MAUI') {
      await job.progress(79);
      await applicationModel.update(applicationId, { analysis_progress: 79 });

      logger.info('🧬 Analyzing .NET MAUI application...');
      const mauiAnalyzer = new DotNetMauiAnalyzer(extractPath, workingDir);
      mauiResults = await mauiAnalyzer.analyze();

      logger.info(`🧬 .NET MAUI analyzed: ${mauiResults.dllCount} DLLs, type=${mauiResults.type}`);
    }

    // 10. Native Analysis
    let nativeResults = null;
    if (techResults.platform === 'ANDROID') {
      await job.progress(83);
      await applicationModel.update(applicationId, { analysis_progress: 83 });

      logger.info('📦 Analyzing native code (Java/Kotlin)...');
      const nativeAnalyzer = new NativeAnalyzer(extractPath);
      nativeResults = await nativeAnalyzer.analyze();

      logger.info(
        `📦 Native analyzed: ${nativeResults.totalFindings} findings, ${nativeResults.filesScanned} files scanned`
      );
    }

    // 11. Security Measures Analysis (85-90%)
    await job.progress(88);
    await applicationModel.update(applicationId, { analysis_progress: 88 });

    logger.info('🛡️ Analyzing security measures...');
    const securityMeasuresAnalyzer = new SecurityMeasuresAnalyzer(extractPath, techResults.platform);
    const securityMeasuresResults = await securityMeasuresAnalyzer.analyze();

    logger.info(`Security measures analyzed: ${securityMeasuresResults.summary.implementedMeasures}/${securityMeasuresResults.summary.totalMeasures} implemented`);

    // 12. App Info (90-93%)
    await job.progress(92);
    await applicationModel.update(applicationId, { analysis_progress: 92 });

    const appInfoParser = new AppInfoParser(extractPath, techResults.platform, filePath);
    const appInfo = await appInfoParser.parse();

    await applicationModel.update(applicationId, {
      package_name: appInfo.packageName,
      version: appInfo.version,
      name: appInfo.appName,
      original_filename: appInfo.filename,
    });

    // 13. Security Score (93-96%)
    await job.progress(95);
    await applicationModel.update(applicationId, { analysis_progress: 95 });

    const securityScore = calculateSecurityScore({
      secrets: secretResults,
      permissions: permResults,
      manifest: manifestResults,
      react: reactResults,
      cordova: cordovaResults,
      native: nativeResults,
      securityMeasures: securityMeasuresResults,
    });

    // 14. Vulnerabilities (96-99%)
    await job.progress(98);
    await applicationModel.update(applicationId, { analysis_progress: 98 });

    const vulnerabilities = identifyVulnerabilities({
      secrets: secretResults,
      permissions: permResults,
      manifest: manifestResults,
      react: reactResults,
      cordova: cordovaResults,
      native: nativeResults,
    });

    await analysisResultModel.create({
      application_id: applicationId,
      manifest_data: {
        ...manifestResults,
        react_analysis: reactResults,
        flutter_analysis: flutterResults,
        native_analysis: nativeResults,
        xamarin_analysis: xamarinResults,
        maui_analysis: mauiResults,
        cordova_analysis: cordovaResults,
        security_measures: securityMeasuresResults,
      },
      permissions: permResults,
      secrets_found: secretResults,
      total_permissions: permResults.total_permissions,
      dangerous_permissions_count: permResults.dangerous_count,
    });

    const existingVulns = await vulnerabilityModel.findByApplicationId(applicationId);
    for (const vuln of vulnerabilities) {
      const exists = existingVulns.some(
        v => v.title === vuln.title && v.category === vuln.category
      );
      if (!exists) {
        await vulnerabilityModel.create({
          application_id: applicationId,
          title: vuln.title,
          description: vuln.description,
          severity: vuln.severity,
          category: vuln.category,
          evidences: JSON.stringify(vuln.evidences || []),
          occurrences: vuln.occurrences || 1,
          owasp_category: vuln.owaspCategory,
          recommendation: vuln.recommendation,
        });
      }
    }

    await applicationModel.update(applicationId, {
      status: 'COMPLETED',
      analysis_progress: 100,
      security_score: securityScore,
      analyzed_at: new Date(),
    });

    try {
      fs.rmSync(workingDir, { recursive: true, force: true });
    } catch {}

    logger.info(`[Job ${job.id}] ✅ Analysis completed for application ${applicationId} with score ${securityScore}`);

    return { applicationId, status: 'completed', securityScore };

  } catch (error: any) {
    logger.error(`[Job ${job.id}] ❌ Analysis failed for application ${applicationId}:`, error);
    
    const app = await applicationModel.findById(applicationId);
    if (app) {
      await cleanupFailedAnalysis(applicationId, app.file_path);
    }
    
    throw error;
  }
});

async function cleanupFailedAnalysis(applicationId: number, filePath?: string): Promise<void> {
  logger.info(`🗑️ Cleaning up failed analysis for application ${applicationId}`);

  try {
    if (filePath && fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      logger.info(`  ✓ Deleted file: ${filePath}`);
    }

    if (filePath) {
      const workingDir = path.join(path.dirname(filePath), `analysis_${applicationId}`);
      if (fs.existsSync(workingDir)) {
        fs.rmSync(workingDir, { recursive: true, force: true });
        logger.info(`  ✓ Deleted working directory`);
      }
    }

    const bundlesDir = '/app/analysis_results/bundles';
    if (fs.existsSync(bundlesDir)) {
      const files = fs.readdirSync(bundlesDir);
      for (const file of files) {
        if (file.includes(`_app${applicationId}.`) || file.includes(`_app${applicationId}_`)) {
          fs.unlinkSync(path.join(bundlesDir, file));
          logger.info(`  ✓ Deleted bundle: ${file}`);
        }
      }
    }

    await vulnerabilityModel.deleteByApplicationId(applicationId);
    await analysisResultModel.deleteByApplicationId(applicationId);
    await applicationModel.delete(applicationId);

    logger.info(`✅ Application ${applicationId} cleaned up due to analysis failure`);

  } catch (cleanupError) {
    logger.error(`Failed to cleanup application ${applicationId}:`, cleanupError);
  }
}

// --- Security Score Calculation ---
function calculateSecurityScore(results: any): number {
  let score = 100;

  //Secrets penalty
  const secretFindings = results.secrets?.findings || [];
  let secretPenalty = 0;

  for (const finding of secretFindings) {
    const severity = finding.severity?.toLowerCase() || 'medium';
    if (severity === 'critical') secretPenalty += 15;
    else if (severity === 'high') secretPenalty += 10;
    else if (severity === 'medium') secretPenalty += 5;
    else if (severity === 'low') secretPenalty += 2;
  }
  score -= Math.min(secretPenalty, 40);

  //Dangerous permissions
  const dangerousPerms = results.permissions?.dangerous_count || 0;
  score -= Math.min(dangerousPerms * 3, 30);

  // Security Flags
  const securityFlags = results.manifest?.securityFlags || [];
  let manifestPenalty = 0;

  for (const flag of securityFlags) {
    const severity = flag.severity?.toUpperCase() || 'MEDIUM';
    if (severity === 'CRITICAL') manifestPenalty += 15;
    else if (severity === 'HIGH') manifestPenalty += 10;
    else if (severity === 'MEDIUM') manifestPenalty += 5;
  }
  score -= Math.min(manifestPenalty, 30);

  //Exported Components sin protección
  const exportedComponents = results.manifest?.exportedComponents || [];
  const unprotectedExported = exportedComponents.filter(
    (c: any) => !c.permissions || c.permissions.length === 0
  );
  score -= Math.min(unprotectedExported.length * 5, 20);

  //React Native vulnerabilities
  if (results.react?.isReactNative) {
    const reactVulns = results.react.vulnerabilities || [];
    let reactPenalty = 0;

    for (const vuln of reactVulns) {
      const severity = vuln.severity?.toLowerCase() || 'medium';
      if (severity === 'critical') reactPenalty += 15;
      else if (severity === 'high') reactPenalty += 10;
      else if (severity === 'medium') reactPenalty += 5;
      else if (severity === 'low') reactPenalty += 2;
    }
    score -= Math.min(reactPenalty, 40);
  }

  //Cordova penalties
  if (results.cordova?.isCordova) {
    const cordova = results.cordova;
    let cordovaPenalty = 0;

    const allFindings = Object.values(cordova.findings || {}).flat() as CordovaFinding[];

    for (const vuln of allFindings) {
      const severity = vuln.severity?.toLowerCase() || 'medium';
      if (severity === 'critical') cordovaPenalty += 15;
      else if (severity === 'high') cordovaPenalty += 10;
      else if (severity === 'medium') cordovaPenalty += 5;
      else if (severity === 'low') cordovaPenalty += 2;
    }
    score -= Math.min(cordovaPenalty, 40);
  }

  // Native penalties
  if (results.native?.totalFindings > 0) {
    const nativeFindings = Object.values(results.native.findings || {}).flat() as NativeFinding[];
    let nativePenalty = 0;

    for (const vuln of nativeFindings) {
      const sev = vuln.severity?.toLowerCase() || 'medium';
      if (sev === 'critical') nativePenalty += 15;
      else if (sev === 'high') nativePenalty += 10;
      else if (sev === 'medium') nativePenalty += 5;
      else if (sev === 'low') nativePenalty += 2;
    }
    score -= Math.min(nativePenalty, 40);
  }

  //Security Measure
  if (results.securityMeasures) {
    const measures = results.securityMeasures;
    let bonus = 0;

    if (measures.rootJailbreakDetection?.detected) bonus += 5;
    if (measures.emulatorDetection?.detected) bonus += 3;
    if (measures.sslPinning?.detected) bonus += 8;
    if (measures.certificateTransparency?.detected) bonus += 5;
    if (measures.developerModeDetection?.detected) bonus += 3;
    if (measures.usbDebuggingDetection?.detected) bonus += 3;
    if (measures.antiTampering?.detected) bonus += 5;
    if (measures.rasp?.detected) bonus += 10;
    if (measures.obfuscation?.detected) bonus += 5;

    score += Math.min(bonus, 30);
  }

  return Math.max(0, Math.min(100, score));
}

function identifyVulnerabilities(results: any): any[] {
  const rawVulnerabilities: any[] = [];

  //Dangerous permissions
  const dangerousPerms = results.permissions?.dangerous_count || 0;
  if (dangerousPerms > 5) {
    rawVulnerabilities.push({
      title: 'Excessive Dangerous Permissions',
      description: `Application requests ${dangerousPerms} dangerous permissions`,
      severity: 'MEDIUM',
      category: 'permissions',
      owaspCategory: 'M1: Improper Platform Usage',
      recommendation: 'Review and minimize dangerous permission requests to only what is necessary',
    });
  }

  //Security Flags
  if (results.manifest?.securityFlags) {
    for (const flag of results.manifest.securityFlags) {
      rawVulnerabilities.push({
        title: flag.flag,
        description: flag.description,
        severity: flag.severity,
        category: 'MANIFEST',
        filePath: flag.location,
        lineNumber: undefined,
        codeSnippet: flag.rawXml ? flag.rawXml.slice(0, 1000) : undefined,
        recommendation: flag.recommendation,
      });
    }
  }

  //Exported Components
  if (results.manifest?.exportedComponents) {
    const exported = results.manifest.exportedComponents;

    const grouped: Record<string, any[]> = {};
    for (const comp of exported) {
      if (!grouped[comp.type]) grouped[comp.type] = [];
      grouped[comp.type].push(comp);
    }

    const typeNames: Record<string, string> = {
      activity: 'Activities',
      service: 'Services',
      receiver: 'Broadcast Receivers',
      provider: 'Content Providers',
    };

    for (const [type, components] of Object.entries(grouped)) {
      const withoutPermission = components.filter(
        c => !c.permissions || c.permissions.length === 0
      );

      const severity = withoutPermission.length > 0 ? 'HIGH' : 'MEDIUM';
      const componentList = components.map(c => `• ${c.name}`).join('\n');

      rawVulnerabilities.push({
        title: `Exported ${typeNames[type] || type}: ${components.length} component(s)`,
        description: `${components.length} ${type}(s) are exported and accessible by other applications.\n\nComponents:\n${componentList}\n\n${
          withoutPermission.length > 0
            ? `⚠️ ${withoutPermission.length} component(s) have no permission protection.`
            : '✓ All components have permission protection.'
        }`,
        severity,
        category: 'exported_components',
        codeSnippet: components.map(c => c.rawXml).filter(Boolean).join('\n\n---\n\n'),
        owaspCategory: 'M1: Improper Platform Usage',
        recommendation: withoutPermission.length > 0
          ? 'Protect exported components with appropriate permissions or set android:exported="false" if they do not need external access.'
          : 'Verify that all exported components actually need to be externally accessible.',
      });
    }
  }

  //React Native vulnerabilities
  if (results.react?.isReactNative && results.react.vulnerabilities) {
    for (const vuln of results.react.vulnerabilities as ReactVulnerability[]) {
      rawVulnerabilities.push({
        title: vuln.title,
        description: vuln.description,
        severity: vuln.severity.toUpperCase(),
        category: vuln.category,
        filePath: vuln.file,
        lineNumber: vuln.line,
        codeSnippet: vuln.codeSnippet,
        owaspCategory: vuln.owaspCategory,
        recommendation: vuln.recommendation,
      });
    }
  }

  //Native vulnerabilities
  if (results.native?.findings) {
    const allFindings = Object.values(results.native.findings).flat() as NativeFinding[];

    for (const vuln of allFindings) {
      rawVulnerabilities.push({
        title: vuln.title || 'Native insecure pattern',
        description: vuln.description || `${vuln.category}: ${vuln.value}`,
        severity: vuln.severity.toUpperCase(),
        category: vuln.category,
        filePath: vuln.file,
        lineNumber: vuln.line,
        codeSnippet: vuln.context,
        owaspCategory: vuln.owaspCategory,
        recommendation: vuln.recommendation,
      });
    }
  }

  //Cordova vulnerabilities
  if (results.cordova?.isCordova && results.cordova.findings) {
    const allFindings = Object.values(results.cordova.findings).flat() as CordovaFinding[];

    for (const vuln of allFindings) {
      rawVulnerabilities.push({
        title: vuln.title,
        description: vuln.description,
        severity: vuln.severity.toUpperCase(),
        category: vuln.category,
        filePath: vuln.file,
        lineNumber: vuln.line,
        codeSnippet: vuln.context,
        owaspCategory: vuln.owaspCategory,
        recommendation: vuln.recommendation,
      });
    }
  }

  return groupVulnerabilities(rawVulnerabilities);
}

function groupVulnerabilities(vulnerabilities: any[]): any[] {
  const grouped: Record<string, any> = {};

  for (const vuln of vulnerabilities) {
    const key = `${vuln.title}::${vuln.category}::${vuln.severity}`;

    if (!grouped[key]) {
      grouped[key] = {
        title: vuln.title,
        description: vuln.description,
        severity: vuln.severity,
        category: vuln.category,
        owaspCategory: vuln.owaspCategory,
        recommendation: vuln.recommendation,
        evidences: [],
        occurrences: 0,
      };
    }

    grouped[key].occurrences++;

    if (vuln.filePath || vuln.lineNumber || vuln.codeSnippet) {
      const evidenceKey = `${vuln.filePath || ''}-${vuln.lineNumber || ''}`;
      const exists = grouped[key].evidences.some(
        (e: any) => `${e.filePath || ''}-${e.lineNumber || ''}` === evidenceKey
      );

      if (!exists) {
        grouped[key].evidences.push({
          filePath: vuln.filePath,
          lineNumber: vuln.lineNumber,
          codeSnippet: vuln.codeSnippet,
        });
      }
    }
  }

  const severityOrder: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };

  return Object.values(grouped).sort((a, b) => {
    const aOrder = severityOrder[a.severity?.toUpperCase()] ?? 5;
    const bOrder = severityOrder[b.severity?.toUpperCase()] ?? 5;
    return aOrder - bOrder;
  });
}

logger.info('✅ Analysis worker started and listening for jobs');
