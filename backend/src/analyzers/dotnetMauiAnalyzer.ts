import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import AdmZip from 'adm-zip';
import { logger } from '../utils/logger';

export interface DotNetMauiAnalysisResult {
  platform: 'ANDROID';
  type: '.NET MAUI';
  dllCount: number;
  outputZip: string;
  indicators: string[];
}

export class DotNetMauiAnalyzer {

  private readonly MAUI_EXTRACT_SCRIPT = '/app/tools/pymauistore.py';
  private readonly FINAL_DLL_OUTPUT_DIR = '/app/analysis_results/dlls';

  constructor(
    private extractPath: string,
    private workingDir: string
  ) {}

  async analyze(): Promise<DotNetMauiAnalysisResult> {
    logger.info('🔥 Analyzing .NET MAUI (Android) application');

    const indicators: string[] = [];

    const assembliesBlob = this.findMauiAssembliesBlob();
    const outputDir = this.prepareOutputDir();

    execSync(
      `python3 "${this.MAUI_EXTRACT_SCRIPT}" "${assembliesBlob}" "${outputDir}"`,
      { stdio: 'inherit' }
    );

    const zipPath = this.zipOutput(outputDir);

    return {
      platform: 'ANDROID',
      type: '.NET MAUI',
      dllCount: this.countDlls(outputDir),
      outputZip: zipPath,
      indicators,
    };
  }

  private findMauiAssembliesBlob(): string {
    let found: string | null = null;

    const walk = (dir: string) => {
      for (const entry of fs.readdirSync(dir)) {
        const fullPath = path.join(dir, entry);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
          walk(fullPath);
          if (found) return;
        } else if (
          entry.startsWith('libassemblies.') &&
          entry.endsWith('.blob.so')
        ) {
          found = fullPath;
          return;
        }
      }
    };

    walk(this.extractPath);

    if (!found) {
      throw new Error('libassemblies.<ARCH>.blob.so not found');
    }

    return found;
  }

  private prepareOutputDir(): string {
    const dir = path.join(
      this.workingDir,
      'outputs',
      'dotnet_maui',
      Date.now().toString(),
      'dlls'
    );

    fs.mkdirSync(dir, { recursive: true });
    return dir;
  }

  private zipOutput(dir: string): string {
    if (!fs.existsSync(this.FINAL_DLL_OUTPUT_DIR)) {
      fs.mkdirSync(this.FINAL_DLL_OUTPUT_DIR, { recursive: true });
    }

    const zip = new AdmZip();
    zip.addLocalFolder(dir);

    const zipName = `dotnet_maui_${Date.now()}.zip`;
    const finalZipPath = path.join(this.FINAL_DLL_OUTPUT_DIR, zipName);

    zip.writeZip(finalZipPath);
    return finalZipPath;
  }

  private countDlls(dir: string): number {
    return fs.readdirSync(dir).filter(f => f.endsWith('.dll')).length;
  }
}
