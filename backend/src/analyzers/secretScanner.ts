import fs from 'fs';
import path from 'path';
import { logger } from '../utils/logger';

export interface SecretMatch {
  type: string;
  value: string;
  line: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface GroupedFinding {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  count: number;
  samples: { value: string; line: number; file: string }[];
}

export interface SecretScanResult {
  findings: GroupedFinding[];
  secrets_by_file: Record<string, SecretMatch[]>;
  summary: {
    total_findings: number;
    total_occurrences: number;
    by_severity: { critical: number; high: number; medium: number; low: number; info: number; };
    by_type: Record<string, number>;
  };
}

export class SecretScanner {
  private patterns = {
    api_key: /['"]?([A-Z0-9_]+_(API_KEY|KEY|TOKEN|SECRET|API))['"]?\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
    aws_key: /AKIA[0-9A-Z]{16}/g,
    github_token: /gh[ps]_[a-zA-Z0-9]{36,}/g,
    slack_token: /xox[pboa]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}/g,
    stripe_key: /sk_live_[0-9a-zA-Z]{24,}/g,
    private_key: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,
    jwt: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    bearer_token: /[Bb]earer\s+[A-Za-z0-9\-_]{20,}/g,
    oauth_token: /['"](access_token|AUTH0_DOMAIN|AUTH0_CLIENT_ID|refresh_token)['"]\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]/gi,
    secret: /['"](secret|password|passwd|pwd|token|api_secret)['"]\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
    database_url: /(mongodb|postgres|mysql|redis):\/\/[^\s'"]+/gi,
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    url: /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/g,
    endpoint: /['"`](\/api\/[a-zA-Z0-9\/\-_{}:]+)['"`]/g,
  };

  private infoTypes = ['email', 'url', 'endpoint'];

  private excludeUrlRegex = /(apache\.org|android\.com|iana\.org|apple\.com|unicode\.com|medium\.com|adobe\.com|github|facebook|mozilla|w3\.org|webkit|csswg|google|reactnavigation|microsoft\.com|goo|dottoro|momentjs|fxtf|fb\.me|reactjs|npmjs|yarnpkg|cdnjs|unpkg|jsdelivr|cloudflare|googleapis|gstatic|localhost|example\.com|127\.0\.0\.1)/i;

  constructor(private extractPath: string) {}

  async analyze(): Promise<SecretScanResult> {
    logger.info('🔍 Scanning for secrets...');
    const secretsByFile: Record<string, SecretMatch[]> = {};
    const allFiles = this.findFiles(this.extractPath);
    logger.info(`Found ${allFiles.length} files to scan`);

    for (const file of allFiles) {
      const secrets = this.scanFile(file);
      if (secrets.length > 0) {
        secretsByFile[path.relative(this.extractPath, file)] = secrets;
      }
    }

    const findings = this.groupFindings(secretsByFile);
    const summary = this.calculateSummary(findings, secretsByFile);

    return { findings, secrets_by_file: secretsByFile, summary };
  }

  private getSeverity(type: string) {
    if (['api_key', 'aws_key', 'private_key', 'stripe_key'].includes(type)) return 'critical';
    if (['jwt', 'bearer_token', 'oauth_token', 'secret', 'github_token', 'slack_token', 'database_url'].includes(type)) return 'high';
    if (this.infoTypes.includes(type)) return 'info';
    return 'medium';
  }

  private groupFindings(secretsByFile: Record<string, SecretMatch[]>): GroupedFinding[] {
    const grouped: Record<string, GroupedFinding> = {};
    for (const [file, secrets] of Object.entries(secretsByFile)) {
      for (const secret of secrets) {
        if (!grouped[secret.type]) {
          grouped[secret.type] = { type: secret.type, severity: this.getSeverity(secret.type), count: 0, samples: [] };
        }
        grouped[secret.type].count++;
        grouped[secret.type].samples.push({ value: secret.value, line: secret.line, file });
      }
    }
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return Object.values(grouped).sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  }

	private findFiles(dir: string): string[] {
	  const files: string[] = [];
	  const maxFiles = 10000;
	  const excludeDirs = ['node_modules', '.git', '__pycache__', 'build', 'dist', 'plugins', 'cordova', 'css', 'vendor', 'bower_components'];

	  const scanDir = (currentDir: string) => {
	    if (files.length >= maxFiles) return;
	    try {
	      const items = fs.readdirSync(currentDir);
	      for (const item of items) {
		if (files.length >= maxFiles) break;
		const fullPath = path.join(currentDir, item);
		const stat = fs.statSync(fullPath);
		if (stat.isDirectory()) {
		  if (!excludeDirs.includes(item)) {
		    scanDir(fullPath);
		  }
		} else if (stat.isFile() && !this.isBinaryOrTooLarge(fullPath)) {
		  files.push(fullPath);
		}
	      }
	    } catch {}
	  };

	  scanDir(dir);
	  return files;
	}

  private isBinaryOrTooLarge(filePath: string): boolean {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 5 * 1024 * 1024) return true;
      const fd = fs.openSync(filePath, 'r');
      const buffer = Buffer.alloc(512);
      fs.readSync(fd, buffer, 0, 512, 0);
      fs.closeSync(fd);
      return buffer.includes(0);
    } catch {
      return true;
    }
  }

  private scanFile(filePath: string): SecretMatch[] {
    const secrets: SecretMatch[] = [];
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');
      lines.forEach((line, index) => {
        const lineNum = index + 1;
        for (const [type, pattern] of Object.entries(this.patterns)) {
          for (const match of line.matchAll(pattern)) {
            let value = match[0];
            if (['api_key','secret','oauth_token'].includes(type)) value = match[2] || match[0];

            if ((type === 'url' && this.excludeUrlRegex.test(value)) ||
                ((type === 'email' || type === 'secret') && this.isCommonPlaceholder(value)) ||
                (type === 'email' && /@[\w\-]+(\.png|\.svg|\.ico|@2x|@3x)/i.test(value))) continue;

            secrets.push({ type, value: value.length > 100 ? value.substring(0, 100) + '...' : value, line: lineNum, severity: this.getSeverity(type) });
          }
        }
      });
    } catch {}
    return this.deduplicate(secrets);
  }

  private isCommonPlaceholder(value: string): boolean {
    const placeholders = [
      'example','test','demo','placeholder','your_','your-','xxx','***','...','todo','fixme','changeme',
      'xxxxxxxxx','12345','password','secret','sample','key','token','auth'
    ];
    const lower = value.toLowerCase();
    return placeholders.some(p => lower.includes(p));
  }

  private deduplicate(secrets: SecretMatch[]): SecretMatch[] {
    const seen = new Set<string>();
    return secrets.filter(s => {
      const key = `${s.type}-${s.value}-${s.line}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private calculateSummary(findings: GroupedFinding[], secretsByFile: Record<string, SecretMatch[]>): SecretScanResult['summary'] {
    const summary = { total_findings: findings.length, total_occurrences: 0, by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, by_type: {} as Record<string, number> };
    for (const f of findings) {
      summary.by_severity[f.severity] += f.count;
      summary.by_type[f.type] = f.count;
      summary.total_occurrences += f.count;
    }
    return summary;
  }
}
