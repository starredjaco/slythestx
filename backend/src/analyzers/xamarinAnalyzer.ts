import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import AdmZip from 'adm-zip';
import { logger } from '../utils/logger';

export interface XamarinAnalysisResult {
  platform: 'ANDROID' | 'IOS';
  type: 'XAMARIN' | 'Xamarin AssemblyStore Blobs';
  dllCount: number;
  compressed: boolean;
  outputZip: string;
  indicators: string[];
}

export class XamarinAnalyzer {

  private readonly LZ4_EXTRACT_SCRIPT = '/app/tools/Xamarin_XALZ_decompress.py';
  private readonly BLOB_EXTRACT_SCRIPT = '/app/tools/pyxamstore.py';
  private readonly FINAL_DLL_OUTPUT_DIR = '/app/analysis_results/dlls';

  constructor(
    private extractPath: string,
    private workingDir: string,
    private platform: 'ANDROID' | 'IOS'
  ) {}

  async analyze(): Promise<XamarinAnalysisResult> {
    logger.info('🧬 Analyzing Xamarin application');

    const files = this.collectFiles();
    const indicators: string[] = [];

    if (this.platform === 'IOS') {
      if (!this.isXamarinClassic(files)) {
        throw new Error('Not a Xamarin iOS application');
      }

      indicators.push('Xamarin iOS classic detected');
      return this.handleXamarinClassic(files, indicators);
    }

    if (this.isXamarinClassic(files)) {
      indicators.push('Xamarin Android classic detected');
      return this.handleXamarinClassic(files, indicators);
    }

    if (this.isXamarinBlob(files)) {
      indicators.push('Xamarin Android blob detected');
      return this.handleXamarinBlob(indicators);
    }

    throw new Error('Not a Xamarin application');
  }

  private collectFiles(): string[] {
    const results: string[] = [];

    const walk = (dir: string) => {
      for (const entry of fs.readdirSync(dir)) {
        const full = path.join(dir, entry);
        const stat = fs.statSync(full);

        if (stat.isDirectory()) walk(full);
        else results.push(full.replace(/\\/g, '/'));
      }
    };

    walk(this.extractPath);
    return results;
  }

  private isXamarinClassic(files: string[]): boolean {
    return files.some(f => f.endsWith('.dll'));
  }

  private isXamarinBlob(files: string[]): boolean {
    return files.some(f =>
      f.endsWith('assemblies.blob') &&
      files.some(x => x.endsWith('assemblies.manifest'))
    );
  }

  private async handleXamarinClassic(
    files: string[],
    indicators: string[]
  ): Promise<XamarinAnalysisResult> {

    const dlls = files.filter(f => f.endsWith('.dll'));
    const outputDir = this.prepareOutputDir();

    let compressed = false;

    for (const dll of dlls) {
      const outDll = path.join(outputDir, path.basename(dll));

      if (this.isLz4Dll(dll)) {
        compressed = true;
        indicators.push(`LZ4 compressed DLL: ${path.basename(dll)}`);

        execSync(
          `python3 "${this.LZ4_EXTRACT_SCRIPT}" "${dll}" "${outDll}"`
        );
      } else {
        fs.copyFileSync(dll, outDll);
      }
    }

    const zipPath = this.zipOutput(outputDir);

    return {
      platform: this.platform,
      type: 'XAMARIN',
      dllCount: dlls.length,
      compressed,
      outputZip: zipPath,
      indicators,
    };
  }

  private async handleXamarinBlob(
    indicators: string[]
  ): Promise<XamarinAnalysisResult> {

    const assembliesDir = this.findAssembliesDir();
    const outputDir = this.prepareOutputDir();

    logger.info(`🧬 Extracting Xamarin blob from ${assembliesDir}`);

    execSync(
      `python3 "${this.BLOB_EXTRACT_SCRIPT}" unpack -d "${assembliesDir}" "${outputDir}"`,
      { stdio: 'inherit' }
    );

    const zipPath = this.zipOutput(outputDir);

    return {
      platform: this.platform,
      type: 'Xamarin AssemblyStore Blobs',
      dllCount: this.countDlls(outputDir),
      compressed: false,
      outputZip: zipPath,
      indicators,
    };
  }

  private findAssembliesDir(): string {
    const candidates: string[] = [];

    const walk = (dir: string) => {
      for (const entry of fs.readdirSync(dir)) {
        const full = path.join(dir, entry);
        const stat = fs.statSync(full);

        if (stat.isDirectory()) {
          const blob = path.join(full, 'assemblies.blob');
          const manifest = path.join(full, 'assemblies.manifest');

          if (fs.existsSync(blob) && fs.existsSync(manifest)) {
            candidates.push(full);
          }

          walk(full);
        }
      }
    };

    walk(this.extractPath);

    if (candidates.length === 0) {
      throw new Error('assemblies.blob directory not found');
    }

    return candidates[0];
  }

  private isLz4Dll(file: string): boolean {
    try {
      const fd = fs.openSync(file, 'r');
      const buffer = Buffer.alloc(4);
      fs.readSync(fd, buffer, 0, 4, 0);
      fs.closeSync(fd);

      return buffer.toString('ascii') === 'XALZ';
    } catch {
      return false;
    }
  }

  private prepareOutputDir(): string {
    const dir = path.join(
      this.workingDir,
      'outputs',
      'xamarin',
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

    const zipName = `xamarin_${Date.now()}.zip`;
    const finalZipPath = path.join(this.FINAL_DLL_OUTPUT_DIR, zipName);

    zip.writeZip(finalZipPath);

    return finalZipPath;
  }

  private countDlls(dir: string): number {
    return fs.readdirSync(dir).filter(f => f.endsWith('.dll')).length;
  }
}
