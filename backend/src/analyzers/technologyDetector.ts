import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import AdmZip from 'adm-zip';
import { logger } from '../utils/logger';

export interface TechnologyDetectionResult {
  platform: 'ANDROID' | 'IOS';
  technology:
    | 'NATIVE'
    | 'REACT_NATIVE'
    | 'FLUTTER'
    | 'CORDOVA'
    | 'IONIC'
    | 'XAMARIN'
    | 'DOTNET_MAUI'
    | 'UNKNOWN';
  confidence: number;
  indicators: string[];
}

export class TechnologyDetector {
  private extractPath: string;
  private excludeDirs = [
    'plugins',
    'cordova',
    'css',
    'vendor',
    'node_modules',
    'bower_components',
  ];

  constructor(private filePath: string, private workingDir: string) {
    this.extractPath = path.join(this.workingDir, 'apktool');
  }

  async detect(): Promise<TechnologyDetectionResult> {
    const ext = path.extname(this.filePath).toLowerCase();

    if (ext === '.apk' || ext === '.aab') return this.detectAndroid();
    if (ext === '.ipa') return this.detectIOS();

    throw new Error(`Unsupported file type: ${ext}`);
  }

  private async detectAndroid(): Promise<TechnologyDetectionResult> {
    logger.info('🤖 Detectando tecnología Android...');

    const zip = new AdmZip(this.filePath);
    const fileNames = zip
      .getEntries()
      .map(e => e.entryName)
      .filter(f => !this.excludeDirs.some(dir => f.startsWith(dir + '/')));

    const indicators: string[] = [];
    let technology: TechnologyDetectionResult['technology'] = 'UNKNOWN';
    let confidence = 0;

    if (this.checkReactNativeFiles(fileNames)) {
      technology = 'REACT_NATIVE';
      confidence = 90;
      indicators.push('React Native bundle found');

    } else if (this.checkFlutterFiles(fileNames)) {
      technology = 'FLUTTER';
      confidence = 95;
      indicators.push('Flutter assets found');

    } else if (this.checkCordovaFiles(fileNames)) {
      technology = 'CORDOVA';
      confidence = 85;
      indicators.push('Cordova/Ionic files found');

    } else if (this.detectDotNetMaui(fileNames)) {
      technology = 'DOTNET_MAUI';
      confidence = 75;
      indicators.push('Detected .NET MAUI native runtime artifacts');

    } else if (this.detectXamarinAndroid(fileNames)) {
      technology = 'XAMARIN';
      confidence = 90;
      indicators.push('Xamarin Android classic artifacts detected');

    } else {
      technology = 'NATIVE';
      confidence = 80;
      indicators.push('Native Android application');
    }

    await this.decompileWithAPKTool();

    await this.decompileWithJADX();

    return { platform: 'ANDROID', technology, confidence, indicators };
  }

  private async detectIOS(): Promise<TechnologyDetectionResult> {
    logger.info('🍎 Detectando tecnología iOS...');

    if (!fs.existsSync(this.extractPath)) {
      fs.mkdirSync(this.extractPath, { recursive: true });
    }

    const zip = new AdmZip(this.filePath);
    const entries = zip
      .getEntries()
      .map(e => e.entryName)
      .filter(f => !this.excludeDirs.some(dir => f.startsWith(dir + '/')));

    const payloadDir = entries.find(f => /^Payload\/[^/]+\.app/.test(f));
    if (!payloadDir) {
      logger.error('No .app directory found. Entradas detectadas:', entries);
      throw new Error('.app directory not found');
    }

    const indicators: string[] = [];
    let technology: TechnologyDetectionResult['technology'] = 'UNKNOWN';
    let confidence = 0;

    if (this.checkReactNativeFiles(entries)) {
      technology = 'REACT_NATIVE';
      confidence = 90;
      indicators.push('React Native bundle found');
    } else if (this.checkFlutterFiles(entries)) {
      technology = 'FLUTTER';
      confidence = 95;
      indicators.push('Flutter framework found');
    } else if (this.checkCordovaFiles(entries)) {
      technology = 'CORDOVA';
      confidence = 85;
      indicators.push('Cordova framework found');
    } else if (this.detectXamarinIOS(entries)) {
      technology = 'XAMARIN';
      confidence = 90;
      indicators.push('Xamarin iOS classic detected');
    } else {
      technology = 'NATIVE';
      confidence = 80;
      indicators.push('Native iOS application');
    }

    zip.extractAllTo(this.extractPath, true);

    return {
      platform: 'IOS',
      technology,
      confidence,
      indicators,
    };
  }

  private async decompileWithAPKTool(): Promise<void> {
    logger.info('🔧 Decompilando APK con APKTool (recursos, manifest, assets)...');
    try {
      execSync(
        `apktool d --keep-broken-res -f "${this.filePath}" -o "${this.extractPath}"`,
        { stdio: 'ignore', timeout: 180000 }
      );
      logger.info('✅ APKTool completado');
    } catch (err: any) {
      logger.error('❌ APKTool failed:', err.message);
      throw new Error('APKTool decompilation failed');
    }
  }

  private async decompileWithJADX(): Promise<void> {
    logger.info('🔍 Decompilando código Java/Kotlin con JADX...');
    const jadxOut = path.join(this.workingDir, 'jadx');
    
    try {
      
      if (!fs.existsSync(jadxOut)) {
        fs.mkdirSync(jadxOut, { recursive: true });
      }

      execSync(`jadx -d "${jadxOut}" "${this.filePath}"`, {
        stdio: 'ignore',
        timeout: 300000,
      });
      
      
      const sourcesDir = path.join(jadxOut, 'sources');
      if (fs.existsSync(sourcesDir)) {
        const files = this.countFiles(sourcesDir);
      } else {
      }
    } catch (err: any) {
      logger.warn('⚠️ JADX failed', err.message);
    }
  }

  private checkReactNativeFiles(files: string[]): boolean {
    return files.some(
      f =>
        f.endsWith('index.android.bundle') ||
        f.endsWith('main.jsbundle') ||
        f.includes('libreactnativejni.so')
    );
  }

  private checkFlutterFiles(files: string[]): boolean {
    return files.some(
      f => f.includes('flutter_assets') || f.includes('Flutter.framework')
    );
  }

  private checkCordovaFiles(files: string[]): boolean {
    return files.some(
      f => f.endsWith('cordova.js') || f.endsWith('cordova_plugins.js')
    );
  }

  private detectXamarinAndroid(files: string[]): boolean {
    const f = files.map(x => x.replace(/\\/g, '/'));
    return (
      f.some(x => x.endsWith('Mono.Android.dll')) ||
      f.some(x => x.endsWith('libmonodroid.so')) ||
      f.some(x => x.endsWith('libmonosgen-2.0.so')) ||
      f.some(x => x.endsWith('assemblies.blob')) ||
      f.some(x => x.endsWith('assemblies.manifest'))
    );
  }

  private detectXamarinIOS(files: string[]): boolean {
    return files.some(f =>
      f.endsWith('Xamarin.iOS.dll') ||
      f.endsWith('Maui.Skeleton.dll') ||
      f.endsWith('Microsoft.iOS.dll')
    );
  }

  private detectDotNetMaui(files: string[]): boolean {
    const f = files.map(x => x.replace(/\\/g, '/'));
    return (
      f.some(x => x.includes('libassemblies.') && x.endsWith('.blob.so')) ||
      f.some(x => x.endsWith('libassembly-store.so')) &&
      f.some(x => x.endsWith('libxamarin-app.so'))
    );
  }


  private countFiles(dir: string): number {
    let count = 0;
    const walk = (d: string) => {
      for (const entry of fs.readdirSync(d)) {
        const full = path.join(d, entry);
        const stat = fs.statSync(full);
        if (stat.isDirectory()) {
          walk(full);
        } else if (stat.isFile() && (full.endsWith('.java') || full.endsWith('.kt'))) {
          count++;
        }
      }
    };
    try {
      walk(dir);
    } catch {}
    return count;
  }

  getExtractPath(): string {
    return this.extractPath;
  }
}
