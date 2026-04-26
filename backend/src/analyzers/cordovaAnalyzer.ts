import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { logger } from '../utils/logger';

export interface CordovaPlugin {
  id: string;
  name: string;
  version: string;
  description?: string;
  source?: string;
}

export interface CordovaFinding {
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

export interface CordovaAnalysisResult {
  isCordova: boolean;
  cordovaVersion?: string;
  appId?: string;
  appName?: string;
  plugins: CordovaPlugin[];
  findings: Record<string, CordovaFinding[]>;
  totalFindings: number;
  jsFiles: number;
  totalLines: number;
  dependencies?: any[];
}

export class CordovaAnalyzer {
  private readonly MAX_FILE_SIZE = 5 * 1024 * 1024;
  private readonly MAX_CONTEXT = 400;

  private readonly PYTHON_BEAUTIFIER = '/app/tools/jspythonbeautifier.py';

  private readonly EXCLUDE_DIRS = [
    'cordova',
    'plugins',
    'css',
    'img',
    'images',
    'fonts',
    'lib',
    'libs',
    'vendor',
    'node_modules',
    'bower_components'
  ];

  private rulesPath = '/app/rules/cordovaSecurity.json';
  private rules: any;

  constructor(
    private extractPath: string,
    private platform: 'ANDROID' | 'IOS'
  ) {
    this.rules = this.loadRules();
  }

  private loadRules(): any {
    try {
      const raw = fs.readFileSync(this.rulesPath, 'utf-8');
      const json = JSON.parse(raw);
      logger.info(`📜 Cordova rules loaded v${json.version ?? 'unknown'}`);
      return json;
    } catch (e) {
      logger.error('❌ Failed loading Cordova rules', e);
      return { patterns: {}, dependencies: [] };
    }
  }

  async analyze(): Promise<CordovaAnalysisResult> {
    logger.info('📱 Analyzing Cordova application');

    const config = this.parseConfigXml();
    const plugins = this.enumeratePlugins();
    const wwwDir = this.getWwwDirectory();

    if (!wwwDir) return this.emptyResult();

    const jsFiles = this.findJavaScriptFiles(wwwDir);

    
    this.runPythonBeautifier(jsFiles);

    const findings = this.scanWithRules(jsFiles);

    let totalLines = 0;
    jsFiles.forEach(f => {
      try {
        totalLines += fs.readFileSync(f, 'utf-8').split('\n').length;
      } catch {}
    });

    const totalFindings = Object.values(findings).reduce((s, a) => s + a.length, 0);

    logger.info(`✅ Cordova analysis done: ${totalFindings} findings`);

    return {
      isCordova: true,
      cordovaVersion: config.cordovaVersion,
      appId: config.appId,
      appName: config.appName,
      plugins,
      findings,
      totalFindings,
      jsFiles: jsFiles.length,
      totalLines,
      dependencies: this.rules.dependencies ?? [],
    };
  }


  private parseConfigXml(): { cordovaVersion?: string; appId?: string; appName?: string } {
    const candidates =
      this.platform === 'ANDROID'
        ? [
            path.join(this.extractPath, 'assets/www/config.xml'),
            path.join(this.extractPath, 'res/xml/config.xml'),
          ]
        : this.findFiles(this.extractPath, 'config.xml');

    const configPath = candidates.find(p => fs.existsSync(p));
    if (!configPath) return {};

    try {
      const xml = fs.readFileSync(configPath, 'utf-8');
      return {
        cordovaVersion: xml.match(/cdv-version=["']([^"']+)["']/i)?.[1],
        appId: xml.match(/id=["']([^"']+)["']/i)?.[1],
        appName: xml.match(/<name[^>]*>([^<]+)<\/name>/i)?.[1]?.trim(),
      };
    } catch {
      return {};
    }
  }


  private enumeratePlugins(): CordovaPlugin[] {
    const pluginsFile = this.findFiles(this.extractPath, 'cordova_plugins.js')[0];
    if (!pluginsFile) return [];

    try {
      const content = fs.readFileSync(pluginsFile, 'utf-8');
      const ids = [...content.matchAll(/"id"\s*:\s*"([^"]+)"/g)].map(m => m[1]);

      return [...new Set(ids)].map(id => ({
        id,
        name: id.split('.').pop() || id,
        version: content.match(
          new RegExp(`${id}[^}]*"version"\\s*:\\s*"([^"]+)"`, 's')
        )?.[1] ?? 'unknown',
        source: this.getPluginSource(id),
      }));
    } catch {
      return [];
    }
  }

  private getPluginSource(id: string): string {
    if (id.startsWith('cordova-plugin-')) return 'Apache Cordova';
    if (id.includes('ionic')) return 'Ionic';
    if (id.includes('phonegap')) return 'PhoneGap';
    return 'Third-party / Custom';
  }

  private getWwwDirectory(): string | undefined {
    if (this.platform === 'ANDROID') {
      const p = path.join(this.extractPath, 'assets/');
      return fs.existsSync(p) ? p : undefined;
    }

    const payload = path.join(this.extractPath, 'Payload');
    if (!fs.existsSync(payload)) return;

    const app = fs.readdirSync(payload).find(f => f.endsWith('.app'));
    return app ? path.join(payload, app, 'www') : undefined;
  }

  private findJavaScriptFiles(dir: string): string[] {
    const results: string[] = [];

    const walk = (d: string) => {
      try {
        for (const f of fs.readdirSync(d)) {
          const full = path.join(d, f);
          const stat = fs.statSync(full);

          if (stat.isDirectory()) {
            if (!this.EXCLUDE_DIRS.includes(f)) walk(full);
          } else if (
            stat.isFile() &&
            f.endsWith('.js') &&
            stat.size < this.MAX_FILE_SIZE &&
            this.isReadableJS(full)
          ) {
            results.push(full);
          }
        }
      } catch {}
    };

    walk(dir);
    return results;
  }

  private isReadableJS(file: string): boolean {
    try {
      const buf = fs.readFileSync(file);
      const printable = buf.filter(b => b >= 9 && b <= 126).length;
      return printable / buf.length > 0.85;
    } catch {
      return false;
    }
  }

  private runPythonBeautifier(files: string[]) {
    if (!fs.existsSync(this.PYTHON_BEAUTIFIER)) return;

    for (const file of files) {
      try {
        execSync(
          `python3 "${this.PYTHON_BEAUTIFIER}" "${file}"`,
          {
            stdio: 'ignore',
            timeout: 300000,
          }
        );
      } catch {
        logger.debug(`⚠️ Skipped beautifier for ${file}`);
      }
    }
  }


  private scanWithRules(files: string[]): Record<string, CordovaFinding[]> {
    const findings: Record<string, CordovaFinding[]> = {};

    for (const category of Object.keys(this.rules.patterns || {})) {
      findings[category] = [];
    }

    for (const file of files) {
      let lines: string[];
      try {
        lines = fs.readFileSync(file, 'utf-8').split('\n');
      } catch {
        continue;
      }

      const relativePath = path.relative(this.extractPath, file);

      for (const [category, rules] of Object.entries(this.rules.patterns)) {
        for (const rule of rules as any[]) {
          try {
            const regex = new RegExp(rule.pattern, 'gi');

            lines.forEach((line, idx) => {
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

    return findings;
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
      const parts: string[] = [];
      let lastIndex = 0;
      let match;

      const originalRegex = new RegExp(pattern, 'gi');

      while ((match = originalRegex.exec(line)) !== null) {
        
        const beforeMatch = line.substring(lastIndex, match.index);
        parts.push(this.escapeHtml(beforeMatch));

        
        parts.push(
          `<span class="vulnerability-highlight">${this.escapeHtml(match[0])}</span>`
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

  // -------------------- HELPERS --------------------

  private findFiles(root: string, filename: string): string[] {
    const results: string[] = [];

    const walk = (d: string) => {
      try {
        for (const f of fs.readdirSync(d)) {
          const full = path.join(d, f);
          const stat = fs.statSync(full);
          if (stat.isDirectory()) walk(full);
          else if (f === filename) results.push(full);
        }
      } catch {}
    };

    walk(root);
    return results;
  }

  private emptyResult(): CordovaAnalysisResult {
    return {
      isCordova: false,
      plugins: [],
      findings: {},
      totalFindings: 0,
      jsFiles: 0,
      totalLines: 0,
      dependencies: [],
    };
  }
}
