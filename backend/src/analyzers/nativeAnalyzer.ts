import fs from 'fs';
import path from 'path';
import { logger } from '../utils/logger';

export interface NativeFinding {
  category: string;
  value: string;
  file: string;
  line: number;
  context: string;
  contextHtml: string;
  matchedText: string;
  severity: string;
  title?: string;
  description?: string;
  owaspCategory: string;
  recommendation?: string;
}

export interface NativeAnalysisResult {
  isNative: boolean;
  platform: 'ANDROID';
  findings: Record<string, NativeFinding[]>;
  totalFindings: number;
  filesScanned: number;
  totalLines: number;
  skippedDirs: number;
}

export class NativeAnalyzer {
  private rulesPath = '/app/rules/android/nativeSecurity.json';
  private rules: any;
  private skippedDirs = 0;
 
  private readonly ignoreDirs = [
    // Google & Android
    'com/google',
    'com/android',
    'android',
    'google',
    
    // Facebook
    'com/facebook',
    'bolts',
    
    // Kotlin/Java core
    'kotlin',
    'kotlinx',
    'javax',
    'java',
    'org/intellij',
    'org/jetbrains',
    
    // Network libraries
    'okhttp3',
    'okhttp',
    'okio',
    'retrofit',
    'retrofit2',
    'com/squareup',
    
    // Dependency Injection
    'dagger',
    'javax/inject',
    'hilt',
    
    // Image loading
    'com/bumptech',
    'com/squareup/picasso',
    'coil',
    
    // React Native
    'com/swmansion',
    'com/horcrux',
    'com/reactnative',
    
    // Flutter
    'io/flutter',
    
    // Misc third-party
    'com/airbnb',
    'com/pierfrancescosoffritti',
    'org/apache',
    'org/json',
    'io/reactivex',
    'rx',
    'rxjava',
    'rxandroid',
    'com/jakewharton',
    'com/github',
    'io/realm',
    'com/crashlytics',
    'com/newrelic',
    'com/appsflyer',
    'com/adjust',
    'com/stripe',
    'com/braintree',
    'com/paypal',
    
    // Analytics
    'com/mixpanel',
    'com/amplitude',
    'com/segment',
    'com/flurry',
    
    // Ads
    'com/mopub',
    'com/applovin',
    'com/unity3d',
    'com/ironsource',
    'com/chartboost',
    'com/inmobi',
    'com/vungle',
    
    // Testing
    'junit',
    'org/junit',
    'org/mockito',
    'org/robolectric',
    'androidx/test',
    
    // Other SDKs
    'io/sentry',
    'com/datadog',
    'com/bugsnag',
    'org/slf4j',
    'ch/qos',
    'timber',
  ];

  constructor(private extractPath: string) {
    this.rules = this.loadRules();
  }

  private loadRules() {
    try {
      const content = fs.readFileSync(this.rulesPath, 'utf-8');
      const rules = JSON.parse(content);
      logger.info(`📋 Loaded ${Object.keys(rules.patterns || {}).length} rule categories`);
      return rules;
    } catch (err: any) {
      logger.warn(`Native Android rules not found: ${err.message}`);
      return { patterns: {} };
    }
  }

  async analyze(): Promise<NativeAnalysisResult> {
    logger.info('Analyzing native Android code (Java/Kotlin)...');

    this.skippedDirs = 0;
    const files = this.findScopedFiles();

    if (files.length === 0) {
      logger.warn('No Java/Kotlin files found to scan');
      return this.emptyResult();
    }

    const { findings, totalLines } = this.scanFiles(files);
    const totalFindings = Object.values(findings).flat().length;

    return {
      isNative: true,
      platform: 'ANDROID',
      findings,
      totalFindings,
      filesScanned: files.length,
      totalLines,
      skippedDirs: this.skippedDirs,
    };
  }


  private findScopedFiles(): string[] {
    const results: string[] = [];
    const root = path.join(this.extractPath, '..', 'jadx', 'sources');

    logger.info(`🔎 Scanning native files in: ${root}`);

    if (!fs.existsSync(root)) {
      logger.warn(`⚠️ JADX sources directory not found: ${root}`);
      return results;
    }

    const walk = (dir: string) => {
      let entries: string[];
      try {
        entries = fs.readdirSync(dir);
      } catch {
        return;
      }

      for (const entry of entries) {
        const fullPath = path.join(dir, entry);
        let stat;

        try {
          stat = fs.statSync(fullPath);
        } catch {
          continue;
        }

        if (stat.isDirectory()) {
          const relPath = path.relative(root, fullPath).replace(/\\/g, '/');

          if (this.shouldIgnoreDir(relPath)) {
            this.skippedDirs++;
            continue;
          }

          walk(fullPath);
        } else if (stat.isFile() && this.isCodeFile(fullPath)) {
          results.push(fullPath);
        }
      }
    };

    walk(root);
    logger.info(`Found ${results.length} app code files to scan`);
    return results;
  }

  private shouldIgnoreDir(relPath: string): boolean {
    const normalizedPath = relPath.toLowerCase();

    return this.ignoreDirs.some(ignoreDir => {
      const normalizedIgnore = ignoreDir.toLowerCase();
      return normalizedPath === normalizedIgnore ||
             normalizedPath.startsWith(normalizedIgnore + '/');
    });
  }

  private isCodeFile(file: string): boolean {
    const lower = file.toLowerCase();
    return lower.endsWith('.java') || lower.endsWith('.kt');
  }

  private scanFiles(
    files: string[]
  ): { findings: Record<string, NativeFinding[]>; totalLines: number } {
    const findings: Record<string, NativeFinding[]> = {};
    let totalLines = 0;

    const jadxRoot = path.join(this.extractPath, '..', 'jadx', 'sources');

    for (const category of Object.keys(this.rules.patterns || {})) {
      findings[category] = [];
    }

    for (const file of files) {
      let content: string;
      try {
        content = fs.readFileSync(file, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n');
      totalLines += lines.length;

      const relativePath = path.relative(jadxRoot, file);

      for (const [category, rules] of Object.entries(this.rules.patterns || {})) {
        for (const rule of rules as any[]) {
          try {
            const regex = new RegExp(rule.pattern, 'gi');

            lines.forEach((line, idx) => {
              const trimmed = line.trim();
              if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
                return;
              }

              const match = regex.exec(line);
              if (match) {
                regex.lastIndex = 0;

                const { context, contextHtml } = this.createHighlightedContext(
                  lines,
                  idx,
                  match[0],
                  rule.pattern
                );

                findings[category].push({
                  category,
                  value: line.trim().slice(0, 200),
                  file: relativePath,
                  line: idx + 1,
                  context,
                  contextHtml,
                  matchedText: match[0],
                  severity: rule.severity,
                  title: rule.title,
                  description: rule.description,
                  owaspCategory: rule.owaspCategory,
                  recommendation: rule.recommendation,
                });
              }
            });
          } catch {
            logger.warn(`⚠️ Invalid regex pattern: ${rule.pattern}`);
          }
        }
      }
    }

    return { findings, totalLines };
  }

  private createHighlightedContext(
    lines: string[],
    vulnerableLine: number,
    matchedText: string,
    pattern: string
  ): { context: string; contextHtml: string } {
    const startLine = Math.max(0, vulnerableLine - 3);
    const endLine = Math.min(lines.length, vulnerableLine + 4);
    const contextLines = lines.slice(startLine, endLine);

    const contextParts: string[] = [];
    const htmlParts: string[] = [];

    contextLines.forEach((line, idx) => {
      const lineNum = startLine + idx + 1;
      const isVulnerable = lineNum === vulnerableLine + 1;
      const paddedNum = lineNum.toString().padStart(4);

      if (isVulnerable) {
        
        contextParts.push(`► ${paddedNum} │ ${line}`);

        
        const highlightedLine = this.highlightMatch(line, pattern);
        htmlParts.push(
          `<div class="line vulnerable">` +
          `<span class="line-num">${lineNum}</span>` +
          `<span class="code">${highlightedLine}</span>` +
          `</div>`
        );
      } else {
        contextParts.push(`  ${paddedNum} │ ${line}`);
        htmlParts.push(
          `<div class="line">` +
          `<span class="line-num">${lineNum}</span>` +
          `<span class="code">${this.escapeHtml(line)}</span>` +
          `</div>`
        );
      }
    });

    return {
      context: contextParts.join('\n'),
      contextHtml: htmlParts.join('\n'),
    };
  }

  private highlightMatch(line: string, pattern: string): string {
    try {
      const regex = new RegExp(`(${pattern})`, 'gi');
      const escaped = this.escapeHtml(line);
      const parts: string[] = [];
      let lastIndex = 0;
      let match;

      const originalRegex = new RegExp(pattern, 'gi');
      
      while ((match = originalRegex.exec(line)) !== null) {
        const beforeMatch = line.substring(lastIndex, match.index);
        parts.push(this.escapeHtml(beforeMatch));
        
        parts.push(
          `<mark class="vulnerability-highlight">${this.escapeHtml(match[0])}</mark>`
        );
        
        lastIndex = match.index + match[0].length;
      }

      parts.push(this.escapeHtml(line.substring(lastIndex)));

      return parts.join('');
    } catch {
      return this.escapeHtml(line);
    }
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  private emptyResult(): NativeAnalysisResult {
    return {
      isNative: false,
      platform: 'ANDROID',
      findings: {},
      totalFindings: 0,
      filesScanned: 0,
      totalLines: 0,
      skippedDirs: this.skippedDirs,
    };
  }
}
