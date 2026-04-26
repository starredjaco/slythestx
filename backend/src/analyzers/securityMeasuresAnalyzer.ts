import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { logger } from '../utils/logger';

export interface SecurityMeasure {
  type: string;
  detected: boolean;
  confidence: 'high' | 'medium' | 'low';
  evidence: string[];
  description: string;
  recommendation: string;
}

export interface SecurityMeasuresResult {
  rootJailbreakDetection: SecurityMeasure;
  emulatorDetection: SecurityMeasure;
  sslPinning: SecurityMeasure;
  certificateTransparency: SecurityMeasure;
  developerModeDetection: SecurityMeasure;
  usbDebuggingDetection: SecurityMeasure;
  antiTampering: SecurityMeasure;
  rasp: SecurityMeasure;
  obfuscation: SecurityMeasure;
  summary: {
    totalMeasures: number;
    implementedMeasures: number;
    securityLevel: 'excellent' | 'good' | 'fair' | 'poor';
  };
}

interface SecurityRules {
  version: string;
  description: string;
  rules: {
    [key: string]: RuleDefinition;
  };
  confidenceThresholds: {
    high: number;
    medium: number;
  };
  securityLevelThresholds: {
    excellent: number;
    good: number;
    fair: number;
  };
}

interface RuleDefinition {
  android?: PlatformRule;
  ios?: PlatformRule;
  common?: PlatformRule;
  metadata: RuleMetadata;
}

interface PlatformRule {
  applicable?: boolean;
  codePatterns?: string[];
  libraryPatterns?: string[];
  libraryKeywords?: string[];
  binaryPatterns?: string[];
  configFiles?: {
    [key: string]: {
      path: string;
      indicators: string[];
    };
  };
  obfuscatedClassThreshold?: number;
  obfuscatedClassPatterns?: string[];
}

interface RuleMetadata {
  type?: string;
  androidType?: string;
  iosType?: string;
  descriptionDetected: string;
  descriptionNotDetected: string;
  recommendationDetected: string;
  recommendationNotDetected: string;
}

export class SecurityMeasuresAnalyzer {
  private searchPath: string;
  private baseDir: string;
  private rules: SecurityRules;

  constructor(
    private extractPath: string,
    private platform: 'ANDROID' | 'IOS',
    rulesPath?: string
  ) {
    this.rules = this.loadRules(rulesPath);
    const paths = this.detectSearchPaths();
    this.baseDir = paths.baseDir;
    this.searchPath = paths.searchPath;
  }

  private loadRules(rulesPath?: string): SecurityRules {
    const defaultRulesPath = '/app/rules/securityPatterns.json';
    const finalPath = rulesPath || defaultRulesPath;

    try {
      if (fs.existsSync(finalPath)) {
        const content = fs.readFileSync(finalPath, 'utf-8');
        logger.info(`Loaded security rules from: ${finalPath}`);
        return JSON.parse(content);
      }
    } catch (error) {
      logger.warn(`Failed to load rules from ${finalPath}, using defaults`);
    }

    return this.getDefaultRules();
  }

  private getDefaultRules(): SecurityRules {
    return {
      version: '1.0.0',
      description: 'Default embedded rules',
      rules: {},
      confidenceThresholds: { high: 3, medium: 1 },
      securityLevelThresholds: { excellent: 7, good: 5, fair: 2 },
    };
  }

  private detectSearchPaths(): { baseDir: string; searchPath: string } {
    if (this.platform !== 'ANDROID') {
      return { baseDir: this.extractPath, searchPath: this.extractPath };
    }

    const baseDir = this.extractPath.includes('/jadx') || this.extractPath.includes('/apktool')
      ? path.dirname(this.extractPath)
      : this.extractPath;

    const jadxPath = path.join(baseDir, 'jadx');
    const apktoolPath = path.join(baseDir, 'apktool');

    let searchPath = baseDir;

    if (fs.existsSync(jadxPath)) {
      searchPath = jadxPath;
      logger.info(`Using JADX path: ${jadxPath}`);
    } else if (fs.existsSync(apktoolPath)) {
      searchPath = apktoolPath;
      logger.info(`Using Apktool path: ${apktoolPath}`);
    } else {
      logger.info(`Using base directory: ${baseDir}`);
    }

    return { baseDir, searchPath };
  }

  async analyze(): Promise<SecurityMeasuresResult> {

    if (!fs.existsSync(this.searchPath)) {
      logger.error(`Search path does not exist: ${this.searchPath}`);
      return this.emptyResult();
    }

    const smaliCount = this.countFiles(this.searchPath, '.smali');
    const javaCount = this.countFiles(this.searchPath, '.java');
    logger.info(`📊 Files available: ${smaliCount} .smali, ${javaCount} .java`);

    if (smaliCount === 0 && javaCount === 0 && this.platform === 'ANDROID') {
      logger.warn('No .smali or .java files found for Android analysis');
    }

    const result: SecurityMeasuresResult = {
      rootJailbreakDetection: this.detectByRule('rootJailbreakDetection'),
      emulatorDetection: this.detectByRule('emulatorDetection'),
      sslPinning: this.detectSSLPinning(),
      certificateTransparency: this.detectByRule('certificateTransparency'),
      developerModeDetection: this.detectByRule('developerModeDetection'),
      usbDebuggingDetection: this.detectByRule('usbDebuggingDetection'),
      antiTampering: this.detectByRule('antiTampering'),
      rasp: this.detectRASP(),
      obfuscation: this.detectObfuscation(),
      summary: {
        totalMeasures: 9,
        implementedMeasures: 0,
        securityLevel: 'poor',
      },
    };

    this.logResults(result);
    this.calculateSummary(result);

    return result;
  }

  private detectByRule(ruleName: string): SecurityMeasure {
    const rule = this.rules.rules[ruleName];
    
    if (!rule) {
      return this.createEmptyMeasure(ruleName);
    }

    const platformKey = this.platform.toLowerCase() as 'android' | 'ios';
    const platformRule = rule[platformKey];
    const commonRule = rule.common;

    if (platformRule?.applicable === false) {
      return {
        type: rule.metadata.type || ruleName,
        detected: false,
        confidence: 'low',
        evidence: [],
        description: `Not applicable for ${this.platform}`,
        recommendation: 'N/A',
      };
    }

    let evidence: string[] = [];

    const codePatterns = platformRule?.codePatterns || commonRule?.codePatterns || [];
    if (codePatterns.length > 0) {
      if (this.platform === 'ANDROID') {
        evidence.push(...this.grepCode(codePatterns));
      } else {
        const binaryPatterns = platformRule?.binaryPatterns || [];
        evidence.push(...this.stringsIosBinary(binaryPatterns.length > 0 ? binaryPatterns : codePatterns));
      }
    }

 
    if (this.platform === 'IOS' && platformRule?.binaryPatterns) {
      evidence.push(...this.stringsIosBinary(platformRule.binaryPatterns));
    }


    const libPatterns = platformRule?.libraryPatterns || commonRule?.libraryPatterns || [];
    if (libPatterns.length > 0 && this.platform === 'ANDROID') {
      evidence.push(...this.stringsLibraries(libPatterns));
    }

    const detected = evidence.length > 0;
    const uniqueEvidence = [...new Set(evidence)];
    const type = this.getType(rule.metadata);

    return {
      type,
      detected,
      confidence: this.calculateConfidence(uniqueEvidence.length),
      evidence: uniqueEvidence.slice(0, 10),
      description: detected 
        ? this.interpolateDescription(rule.metadata.descriptionDetected, type)
        : this.interpolateDescription(rule.metadata.descriptionNotDetected, type),
      recommendation: detected 
        ? rule.metadata.recommendationDetected
        : rule.metadata.recommendationNotDetected,
    };
  }

  private getType(metadata: RuleMetadata): string {
    if (this.platform === 'ANDROID' && metadata.androidType) {
      return metadata.androidType;
    }
    if (this.platform === 'IOS' && metadata.iosType) {
      return metadata.iosType;
    }
    return metadata.type || 'Unknown';
  }

  private interpolateDescription(template: string, type: string): string {
    return template.replace('{type}', type.toLowerCase().replace(' detection', ''));
  }

  private calculateConfidence(evidenceCount: number): 'high' | 'medium' | 'low' {
    const thresholds = this.rules.confidenceThresholds;
    if (evidenceCount >= thresholds.high) return 'high';
    if (evidenceCount >= thresholds.medium) return 'medium';
    return 'low';
  }

  private detectSSLPinning(): SecurityMeasure {
    const rule = this.rules.rules['sslPinning'];
    if (!rule) return this.createEmptyMeasure('SSL Pinning');

    let evidence: string[] = [];

    if (this.platform === 'ANDROID') {
      
      const configFiles = rule.android?.configFiles;
      if (configFiles?.networkSecurityConfig) {
        const configPath = path.join(this.searchPath, configFiles.networkSecurityConfig.path);
        if (fs.existsSync(configPath)) {
          const content = fs.readFileSync(configPath, 'utf-8');
          const indicators = configFiles.networkSecurityConfig.indicators;
          if (indicators.some(ind => content.includes(ind))) {
            evidence.push(`network_security_config.xml (${configFiles.networkSecurityConfig.path})`);
          }
        }
      }

      
      const codePatterns = rule.android?.codePatterns || [];
      evidence.push(...this.grepCode(codePatterns));
      
     
      const libPatterns = rule.android?.libraryPatterns || [];
      evidence.push(...this.stringsLibraries(libPatterns));
    } else {
      const binaryPatterns = rule.ios?.binaryPatterns || [];
      evidence.push(...this.stringsIosBinary(binaryPatterns));
    }

    const detected = evidence.length > 0;
    const uniqueEvidence = [...new Set(evidence)];

    return {
      type: rule.metadata.type || 'SSL Pinning',
      detected,
      confidence: this.calculateConfidence(uniqueEvidence.length),
      evidence: uniqueEvidence.slice(0, 10),
      description: detected 
        ? rule.metadata.descriptionDetected
        : rule.metadata.descriptionNotDetected,
      recommendation: detected 
        ? rule.metadata.recommendationDetected
        : rule.metadata.recommendationNotDetected,
    };
  }

  private detectRASP(): SecurityMeasure {
    const rule = this.rules.rules['rasp'];
    if (!rule) return this.createEmptyMeasure('RASP');

    const evidence: string[] = [];
    const libraryKeywords = rule.common?.libraryKeywords || [];

    const libSearchPath = path.join(this.baseDir, 'lib');
    
    try {
      const findCmd = `find ${libSearchPath} -name '*.so' 2>/dev/null`;
      const soFilesStr = execSync(findCmd, { encoding: 'utf-8' }).trim();
      
      if (soFilesStr) {
        const soFiles = soFilesStr.split('\n');
        
        soFiles.forEach(file => {
          const fileName = path.basename(file).toLowerCase();
          
          libraryKeywords.forEach(keyword => {
            if (fileName.includes(keyword)) {
              const evidenceItem = `RASP Library: ${path.basename(file)}`;
              if (!evidence.includes(evidenceItem)) {
                evidence.push(evidenceItem);
              }
            }
          });
        });
      }
    } catch {}

    // Code patterns
    const codePatterns = rule.common?.codePatterns || [];
    evidence.push(...this.grepCode(codePatterns));

    const detected = evidence.length > 0;
    const uniqueEvidence = [...new Set(evidence)];

    return {
      type: rule.metadata.type || 'RASP',
      detected,
      confidence: this.calculateConfidence(uniqueEvidence.length),
      evidence: uniqueEvidence.slice(0, 10),
      description: detected 
        ? rule.metadata.descriptionDetected
        : rule.metadata.descriptionNotDetected,
      recommendation: detected 
        ? rule.metadata.recommendationDetected
        : rule.metadata.recommendationNotDetected,
    };
  }

  private detectObfuscation(): SecurityMeasure {
    const rule = this.rules.rules['obfuscation'];
    if (!rule) return this.createEmptyMeasure('Code Obfuscation');

    const evidence: string[] = [];
    let detected = false;

    if (this.platform === 'ANDROID') {
      const threshold = rule.android?.obfuscatedClassThreshold || 20;
      const patterns = rule.android?.obfuscatedClassPatterns || [];

      try {
        if (patterns.length > 0) {
          const findConditions = patterns.map(p => `-name '${p}'`).join(' -o ');
          const findCmd = `find "${this.searchPath}" \\( ${findConditions} \\) 2>/dev/null | wc -l`;
          const totalObfuscated = parseInt(execSync(findCmd, { encoding: 'utf-8' }).trim()) || 0;

          if (totalObfuscated > threshold) {
            detected = true;
            evidence.push(`${totalObfuscated} obfuscated classes detected`);
          }
        }
      } catch {}

      const codePatterns = rule.android?.codePatterns || [];
      const obfEv = this.grepCode(codePatterns);
      if (obfEv.length > 0) {
        detected = true;
        evidence.push('ProGuard/R8 references found');
      }
    }

    return {
      type: rule.metadata.type || 'Code Obfuscation',
      detected,
      confidence: this.calculateConfidence(evidence.length),
      evidence: evidence.slice(0, 5),
      description: detected 
        ? rule.metadata.descriptionDetected
        : rule.metadata.descriptionNotDetected,
      recommendation: detected 
        ? rule.metadata.recommendationDetected
        : rule.metadata.recommendationNotDetected,
    };
  }

  private logResults(result: SecurityMeasuresResult): void {
    logger.info('📊 Security Measures Detection Results:');
    logger.info(`  🔒 Root/Jailbreak: ${result.rootJailbreakDetection.detected} (${result.rootJailbreakDetection.evidence.length} evidence) - ${result.rootJailbreakDetection.confidence}`);
    logger.info(`  💻 Emulator: ${result.emulatorDetection.detected} (${result.emulatorDetection.evidence.length} evidence) - ${result.emulatorDetection.confidence}`);
    logger.info(`  🔐 SSL Pinning: ${result.sslPinning.detected} (${result.sslPinning.evidence.length} evidence) - ${result.sslPinning.confidence}`);
    logger.info(`  📜 Cert Transparency: ${result.certificateTransparency.detected} (${result.certificateTransparency.evidence.length} evidence) - ${result.certificateTransparency.confidence}`);
    logger.info(`  ⚙️ Developer Mode: ${result.developerModeDetection.detected} (${result.developerModeDetection.evidence.length} evidence) - ${result.developerModeDetection.confidence}`);
    logger.info(`  🔌 USB Debugging: ${result.usbDebuggingDetection.detected} (${result.usbDebuggingDetection.evidence.length} evidence) - ${result.usbDebuggingDetection.confidence}`);
    logger.info(`  🛡️ Anti-Tampering: ${result.antiTampering.detected} (${result.antiTampering.evidence.length} evidence) - ${result.antiTampering.confidence}`);
    logger.info(`  🚨 RASP: ${result.rasp.detected} (${result.rasp.evidence.length} evidence) - ${result.rasp.confidence}`);
    logger.info(`  🎭 Obfuscation: ${result.obfuscation.detected} (${result.obfuscation.evidence.length} evidence) - ${result.obfuscation.confidence}`);
  }

  private calculateSummary(result: SecurityMeasuresResult): void {
    const thresholds = this.rules.securityLevelThresholds;
    
    result.summary.implementedMeasures = [
      result.rootJailbreakDetection,
      result.emulatorDetection,
      result.sslPinning,
      result.certificateTransparency,
      result.developerModeDetection,
      result.usbDebuggingDetection,
      result.antiTampering,
      result.rasp,
      result.obfuscation,
    ].filter(m => m.detected).length;

    if (result.summary.implementedMeasures >= thresholds.excellent) {
      result.summary.securityLevel = 'excellent';
    } else if (result.summary.implementedMeasures >= thresholds.good) {
      result.summary.securityLevel = 'good';
    } else if (result.summary.implementedMeasures >= thresholds.fair) {
      result.summary.securityLevel = 'fair';
    }

    logger.info(`✅ Security measures: ${result.summary.implementedMeasures}/${result.summary.totalMeasures} (${result.summary.securityLevel})`);
  }

  private emptyResult(): SecurityMeasuresResult {
    return {
      rootJailbreakDetection: this.createEmptyMeasure('Root/Jailbreak Detection'),
      emulatorDetection: this.createEmptyMeasure('Emulator Detection'),
      sslPinning: this.createEmptyMeasure('SSL Pinning'),
      certificateTransparency: this.createEmptyMeasure('Certificate Transparency'),
      developerModeDetection: this.createEmptyMeasure('Developer Mode Detection'),
      usbDebuggingDetection: this.createEmptyMeasure('USB Debugging Detection'),
      antiTampering: this.createEmptyMeasure('Anti-Tampering'),
      rasp: this.createEmptyMeasure('RASP'),
      obfuscation: this.createEmptyMeasure('Code Obfuscation'),
      summary: {
        totalMeasures: 9,
        implementedMeasures: 0,
        securityLevel: 'poor',
      },
    };
  }

  private createEmptyMeasure(type: string): SecurityMeasure {
    return {
      type,
      detected: false,
      confidence: 'low',
      evidence: [],
      description: 'Analysis not performed - extract path not found',
      recommendation: 'N/A',
    };
  }

  private countFiles(dir: string, extension: string): number {
    try {
      const cmd = `find "${dir}" -name '*${extension}' 2>/dev/null | wc -l`;
      const output = execSync(cmd, { encoding: 'utf-8' }).trim();
      return parseInt(output) || 0;
    } catch {
      return 0;
    }
  }

  private filePathToPackagePath(filePath: string): string {
    let relativePath = filePath.replace(this.searchPath, '').replace(/^\//, '');
    relativePath = relativePath.replace(/^sources\//, '').replace(/^smali[^\/]*\//, '');
    relativePath = relativePath.replace(/\.(java|smali)$/, '');
    return relativePath;
  }

  private grepCode(patterns: string[]): string[] {
    const evidence: string[] = [];
    
    try {
      const escapedPatterns = patterns.map(p => p.replace(/[.*+?^${}()\\[\]]/g, '\\$&'));
      const grepPattern = escapedPatterns.join('|');

      const cmd = `grep -rIiH -E '${grepPattern}' "${this.searchPath}" --include='*.java' --include='*.smali' 2>/dev/null`;
      
      const output = execSync(cmd, { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 }).trim();
      
      if (output) {
        const lines = output.split('\n');
        const matchedFiles = new Map<string, string[]>();

        lines.forEach(line => {
          const colonIndex = line.indexOf(':');
          if (colonIndex > 0) {
            const filePath = line.substring(0, colonIndex);
            const content = line.substring(colonIndex + 1);
            
            patterns.forEach(pattern => {
              if (new RegExp(pattern, 'i').test(content)) {
                if (!matchedFiles.has(pattern)) {
                  matchedFiles.set(pattern, []);
                }
                const files = matchedFiles.get(pattern)!;
                if (!files.includes(filePath)) {
                  files.push(filePath);
                }
              }
            });
          }
        });

        matchedFiles.forEach((files, pattern) => {
          const packagePath = this.filePathToPackagePath(files[0]);
          evidence.push(`${pattern} (${packagePath})`);
        });
      }
    } catch (error: any) {
      
    }
    
    return evidence;
  }

  private stringsLibraries(patterns: string[]): string[] {
    const evidence: string[] = [];
    
    try {
      const libSearchPath = path.join(this.baseDir, 'lib');
      const findCmd = `find ${libSearchPath} -name '*.so' 2>/dev/null`;
      const soFilesStr = execSync(findCmd, { encoding: 'utf-8' }).trim();
      
      if (!soFilesStr) return evidence;

      const soFiles = soFilesStr.split('\n');
      
      soFiles.forEach(soFile => {
        try {
          const stringsCmd = `strings "${soFile}" 2>/dev/null`;
          const output = execSync(stringsCmd, { encoding: 'utf-8', maxBuffer: 5 * 1024 * 1024 }).trim();
          
          patterns.forEach(pattern => {
            if (new RegExp(pattern, 'i').test(output)) {
              const evidenceItem = `${pattern} (in ${path.basename(soFile)})`;
              if (!evidence.includes(evidenceItem)) {
                evidence.push(evidenceItem);
              }
            }
          });
        } catch {}
      });
    } catch {}
    
    return evidence;
  }

  private stringsIosBinary(patterns: string[]): string[] {
    const evidence: string[] = [];
    
    try {
      const payloadDir = path.join(this.searchPath, 'Payload');
      if (!fs.existsSync(payloadDir)) return evidence;

      const appDirs = fs.readdirSync(payloadDir).filter(f => f.endsWith('.app'));
      if (appDirs.length === 0) return evidence;

      const appDir = path.join(payloadDir, appDirs[0]);
      const files = fs.readdirSync(appDir);
      
      const executable = files.find(f => {
        const fullPath = path.join(appDir, f);
        try {
          const stat = fs.statSync(fullPath);
          return stat.isFile() && !path.extname(f);
        } catch {
          return false;
        }
      });

      if (!executable) return evidence;

      const execPath = path.join(appDir, executable);
      const stringsCmd = `strings "${execPath}" 2>/dev/null`;
      const output = execSync(stringsCmd, { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 }).trim();
      
      patterns.forEach(pattern => {
        if (new RegExp(pattern, 'i').test(output)) {
          evidence.push(`${pattern} (in ${executable})`);
        }
      });
    } catch {}
    
    return evidence;
  }
}
