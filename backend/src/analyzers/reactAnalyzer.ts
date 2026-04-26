import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

export interface ReactVulnerability {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  owaspCategory: string;
  recommendation: string;
  cve?: string;
  file?: string;
  line?: number;
  codeSnippet?: string;
  contextHtml?: string;
  matchedText?: string;
}

export interface ReactAnalysisResult {
  isReactNative: boolean;
  hasHermes: boolean;
  bundleFile?: string;
  beautifiedBundleFile?: string;
  hermesInfo?: {
    message: string;
    tools: string[];
    downloadable: boolean;
  };
  dependencies: {
    total: number;
    list: Record<string, string>;
  };
  vulnerabilities: ReactVulnerability[];
  jsFiles: number;
  totalLines: number;
  minified: boolean;
}

interface SecurityRules {
  version: string;
  dependencies: any[];
  patterns: Record<string, any[]>;
  hermes: any;
  scoring: any;
}

export class ReactAnalyzer {
  private readonly beautifierScript = '/app/tools/jspythonbeautifier.py';
  private readonly rulesPath = '/app/rules/reactSecurity.json';
  private rules: SecurityRules;

  constructor(
    private extractPath: string,
    private platform: 'ANDROID' | 'IOS',
    private applicationId?: number
  ) {
    this.rules = this.loadRules();
  }

  private loadRules(): SecurityRules {
    try {
      const content = fs.readFileSync(this.rulesPath, 'utf-8');
      return JSON.parse(content);
    } catch {
      return {
        version: '0.0.0',
        dependencies: [],
        patterns: {},
        hermes: {},
        scoring: { severityWeights: {}, maxPenalty: {} }
      };
    }
  }

  async analyze(): Promise<ReactAnalysisResult> {
    const bundleFile = this.findBundle();
    if (!bundleFile) {
      return { ...this.emptyResult(), isReactNative: true };
    }

    const hasHermes = this.detectHermes(bundleFile);

    if (hasHermes) {
      const permanentBundlePath = this.copyBundleToPermanent(bundleFile);
      const hermesRule = this.rules.hermes?.detected || {};

      return {
        isReactNative: true,
        hasHermes: true,
        bundleFile: permanentBundlePath,
        hermesInfo: {
          message: hermesRule.description,
          tools: hermesRule.tools || [],
          downloadable: hermesRule.downloadable ?? true,
        },
        dependencies: { total: 0, list: {} },
        vulnerabilities: [],
        jsFiles: 0,
        totalLines: 0,
        minified: false,
      };
    }

    const { beautifiedPath, dependencies } = await this.runBeautifier(bundleFile);
    const jsContent = fs.readFileSync(beautifiedPath || bundleFile, 'utf-8');
    const vulnerabilities = this.analyzeWithRules(jsContent, bundleFile, dependencies);

    const permanentBundlePath = this.copyBundleToPermanent(bundleFile);
    const permanentBeautifiedPath = beautifiedPath
      ? this.copyBundleToPermanent(beautifiedPath, '_beautified')
      : undefined;

    return {
      isReactNative: true,
      hasHermes: false,
      bundleFile: permanentBundlePath,
      beautifiedBundleFile: permanentBeautifiedPath,
      dependencies: {
        total: Object.keys(dependencies).length,
        list: dependencies,
      },
      vulnerabilities,
      jsFiles: 1,
      totalLines: jsContent.split('\n').length,
      minified: this.isMinified(jsContent),
    };
  }

  private analyzeWithRules(
    content: string,
    filePath: string,
    dependencies: Record<string, string>
  ): ReactVulnerability[] {
    const vulnerabilities: ReactVulnerability[] = [];
    vulnerabilities.push(...this.analyzeDependencies(dependencies));
    vulnerabilities.push(...this.analyzePatterns(content, filePath));
    return this.deduplicateVulnerabilities(vulnerabilities);
  }

  private analyzeDependencies(dependencies: Record<string, string>): ReactVulnerability[] {
    const vulnerabilities: ReactVulnerability[] = [];

    for (const [pkg, version] of Object.entries(dependencies)) {
      const cleanVersion = this.cleanVersion(version);

      for (const rule of this.rules.dependencies) {
        if (pkg === rule.package || pkg.includes(rule.package)) {
          if (this.isVulnerableVersion(cleanVersion, rule.vulnerableVersions)) {
            vulnerabilities.push({
              id: rule.id,
              title: rule.title,
              description: `${rule.description}\n\nDetected: ${pkg}@${version}`,
              severity: rule.severity,
              category: 'vulnerable_dependency',
              owaspCategory: rule.owaspCategory,
              recommendation: rule.recommendation,
              cve: rule.cve || undefined,
            });
          }
        }
      }
    }

    return vulnerabilities;
  }

  private analyzePatterns(content: string, filePath: string): ReactVulnerability[] {
    const vulnerabilities: ReactVulnerability[] = [];
    const lines = content.split('\n');

    for (const [category, rules] of Object.entries(this.rules.patterns)) {
      for (const rule of rules as any[]) {
        try {
          const regex = new RegExp(rule.pattern, 'gi');

          lines.forEach((line, index) => {
            const match = regex.exec(line);
            if (match) {
              regex.lastIndex = 0;

              const exists = vulnerabilities.some(
                v => v.id === rule.id && v.line === index + 1
              );

              if (!exists) {
                const { context, contextHtml } = this.createHighlightedContext(
                  lines, index, match[0], rule.pattern
                );

                vulnerabilities.push({
                  id: rule.id,
                  title: rule.title,
                  description: rule.description,
                  severity: rule.severity,
                  category,
                  owaspCategory: rule.owaspCategory,
                  recommendation: rule.recommendation,
                  file: path.basename(filePath),
                  line: index + 1,
                  codeSnippet: context,
                  contextHtml,
                  matchedText: match[0],
                });
              }
            }
          });
        } catch {}
      }
    }

    return vulnerabilities;
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
      const regex = new RegExp(pattern, 'gi');

      while ((match = regex.exec(line)) !== null) {
        parts.push(this.escapeHtml(line.substring(lastIndex, match.index)));
        parts.push(`<span class="vulnerability-highlight">${this.escapeHtml(match[0])}</span>`);
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

  private async runBeautifier(bundlePath: string): Promise<{
    beautifiedPath?: string;
    dependencies: Record<string, string>;
  }> {
    let dependencies: Record<string, string> = {};
    let beautifiedPath: string | undefined;

    try {
      if (!fs.existsSync(this.beautifierScript)) return { dependencies };

      const absoluteBundlePath = path.resolve(bundlePath);
      const bundleDir = path.dirname(absoluteBundlePath);
      const bundleBaseName = path.basename(absoluteBundlePath, path.extname(absoluteBundlePath));

      if (!fs.existsSync(absoluteBundlePath)) return { dependencies };

      execSync(`python3 "${this.beautifierScript}" "${absoluteBundlePath}"`, {
        timeout: 600000,
        maxBuffer: 1024 * 1024 * 200,
        cwd: bundleDir,
      });

      const expectedBeautified = path.join(bundleDir, `${bundleBaseName}_beautified.js`);
      const expectedJson = path.join(bundleDir, `${bundleBaseName}_analysis.json`);

      if (fs.existsSync(expectedBeautified)) beautifiedPath = expectedBeautified;
      if (fs.existsSync(expectedJson)) {
        dependencies = JSON.parse(fs.readFileSync(expectedJson, 'utf-8')).dependencies || {};
      }
    } catch {}

    return { beautifiedPath, dependencies };
  }

  private cleanVersion(version: string): string {
    return version.replace(/^[\^~>=<]+/, '').replace(/\s.*/g, '').trim();
  }

  private isVulnerableVersion(version: string, vulnerableRange: string): boolean {
    try {
      const currentParts = this.parseVersion(version);
      if (!currentParts) return false;

      const match = vulnerableRange.match(/^([<>=]+)?(\d+(?:\.\d+)*)$/);
      if (!match) return false;

      const operator = match[1] || '=';
      const targetParts = this.parseVersion(match[2]);
      if (!targetParts) return false;

      const comparison = this.compareVersions(currentParts, targetParts);

      switch (operator) {
        case '<': return comparison < 0;
        case '<=': return comparison <= 0;
        case '>': return comparison > 0;
        case '>=': return comparison >= 0;
        default: return comparison === 0;
      }
    } catch {
      return false;
    }
  }

  private parseVersion(version: string): number[] | null {
    const cleaned = version.replace(/^[vV]/, '').split('-')[0];
    const parts = cleaned.split('.').map(p => parseInt(p, 10));
    if (parts.some(isNaN)) return null;
    while (parts.length < 3) parts.push(0);
    return parts;
  }

  private compareVersions(a: number[], b: number[]): number {
    const maxLength = Math.max(a.length, b.length);
    for (let i = 0; i < maxLength; i++) {
      const aPart = a[i] || 0;
      const bPart = b[i] || 0;
      if (aPart < bPart) return -1;
      if (aPart > bPart) return 1;
    }
    return 0;
  }

  private deduplicateVulnerabilities(vulns: ReactVulnerability[]): ReactVulnerability[] {
    const seen = new Set<string>();
    return vulns.filter(v => {
      const key = `${v.id}-${v.file || ''}-${v.line || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private copyBundleToPermanent(bundlePath: string, suffix: string = ''): string {
    if (!this.applicationId) return bundlePath;

    const bundlesDir = '/app/analysis_results/bundles';
    if (!fs.existsSync(bundlesDir)) fs.mkdirSync(bundlesDir, { recursive: true });

    const originalExt = path.extname(bundlePath);
    const baseName = path.basename(bundlePath, originalExt);
    const permanentPath = path.join(bundlesDir, `${baseName}_app${this.applicationId}${suffix}${originalExt}`);

    fs.copyFileSync(bundlePath, permanentPath);
    return permanentPath;
  }

  private findBundle(): string | undefined {
    if (this.platform === 'ANDROID') {
      const locations = [
        path.join(this.extractPath, 'assets/index.android.bundle'),
        path.join(this.extractPath, 'assets/index.bundle'),
      ];
      for (const loc of locations) {
        if (fs.existsSync(loc)) return loc;
      }
    } else {
      const payloadDir = path.join(this.extractPath, 'Payload');
      if (!fs.existsSync(payloadDir)) return undefined;

      const appDirs = fs.readdirSync(payloadDir).filter(f => f.endsWith('.app'));
      if (appDirs.length === 0) return undefined;

      const bundlePath = path.join(payloadDir, appDirs[0], 'main.jsbundle');
      if (fs.existsSync(bundlePath)) return bundlePath;
    }
    return undefined;
  }

  private detectHermes(bundleFile: string): boolean {
    try {
      const buffer = fs.readFileSync(bundleFile);
      const header = buffer.slice(0, 8).toString('hex');

      if (header.includes('c61f') || header.includes('1f1e')) return true;

      const sample = buffer.slice(0, 1024).toString('utf-8', 0, Math.min(buffer.length, 1024));
      const nonPrintableRatio = (sample.match(/[^\x20-\x7E\n\r\t]/g) || []).length / sample.length;

      return nonPrintableRatio > 0.3;
    } catch {
      return false;
    }
  }

  private isMinified(content: string): boolean {
    const lines = content.split('\n');
    if (lines.length < 10) return true;
    return content.length / lines.length > 500;
  }

  private emptyResult(): ReactAnalysisResult {
    return {
      isReactNative: false,
      hasHermes: false,
      dependencies: { total: 0, list: {} },
      vulnerabilities: [],
      jsFiles: 0,
      totalLines: 0,
      minified: false,
    };
  }

  getBundlePath(): string | undefined {
    return this.findBundle();
  }
}
