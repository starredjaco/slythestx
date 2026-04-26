import fs from 'fs'
import path from 'path'
import { execSync } from 'child_process'
import { logger } from '../utils/logger'

export interface FlutterAnalysisResult {
  isFlutter: boolean
  soFiles: string[]
  snapshotInfo?: {
    os: string
    hash?: string
    flags?: string[]
    compilationMode?: string
    obfuscated?: boolean
    dartVersion?: string
    engineFingerprint?: string
    arch?: string
    buildMode?: string
  }
  reflutterAvailable: boolean
  canPatch: boolean
  error?: string
}

export class FlutterAnalyzer {
  private readonly scriptPath = '/app/tools/extract_dart_info.py';
  constructor(
    private extractPath: string,
    private platform: 'ANDROID' | 'IOS'
  ) {}

  async analyze(): Promise<FlutterAnalysisResult> {
    logger.info('🦋 Analizando aplicación Flutter...')
	
    if (!this.detectFlutter()) {
      return {
        isFlutter: false,
        soFiles: [],
        reflutterAvailable: false,
        canPatch: false
      }
    }

    if (!fs.existsSync(this.scriptPath)) {
      return {
        isFlutter: true,
        soFiles: [],
        reflutterAvailable: false,
        canPatch: false,
        error: 'Flutter analysis script not found'
      }
    }

    const targetDir =
      this.platform === 'ANDROID'
        ? this.getAndroidLibDir()
        : this.extractPath

    if (!targetDir) {
      return {
        isFlutter: true,
        soFiles: [],
        reflutterAvailable: false,
        canPatch: false,
        error: 'No valid Flutter directory found'
      }
    }

    try {
      const output = execSync(
        `python3 "${this.scriptPath}" "${targetDir}"`,
        { encoding: 'utf-8', timeout: 30000 }
      ).trim()

      const result = JSON.parse(output)
		
      const snapshotInfo = {
        os: result.platform,
        hash: result.snapshot_hash || undefined,
        flags: result.flags || [],
        compilationMode: result.build_mode || undefined,
        obfuscated: result.obfuscation === 'yes',
        dartVersion: result.dart_version || undefined,
        engineFingerprint: result.engine_fingerprint || undefined,
        arch: result.arch || undefined,
        buildMode: result.build_mode || undefined
      }

      const reflutterAvailable =
        this.platform === 'ANDROID' ? this.checkReFlutter() : false

      if (this.platform === 'IOS') {
        logger.info('ReFlutter iOS not supported')
      }

      return {
        isFlutter: true,
        soFiles: this.platform === 'ANDROID' ? fs.readdirSync(targetDir) : [],
        snapshotInfo,
        reflutterAvailable,
        canPatch: this.platform === 'ANDROID' && reflutterAvailable
      }

    } catch (err: any) {
      logger.error('Error analyzing Flutter:', err.message)

      return {
        isFlutter: true,
        soFiles: [],
        reflutterAvailable: false,
        canPatch: false,
        error: err.message
      }
    }
  }


  private detectFlutter(): boolean {
    if (this.platform === 'ANDROID') {
      return fs.existsSync(path.join(this.extractPath, 'lib'))
    }

    const payload = path.join(this.extractPath, 'Payload')
    if (!fs.existsSync(payload)) return false

    return fs
      .readdirSync(payload)
      .some(d => d.endsWith('.app'))
  }


  private getAndroidLibDir(): string | null {
    const libRoot = path.join(this.extractPath, 'lib')
    if (!fs.existsSync(libRoot)) return null

    const dirs = fs
      .readdirSync(libRoot)
      .filter(d =>
        fs.statSync(path.join(libRoot, d)).isDirectory()
      )

    if (dirs.length === 0) return null

    const selected = path.join(libRoot, dirs[0])
    logger.info(`Analyzing android libs ${dirs[0]}`)

    return selected
  }


  private checkReFlutter(): boolean {
    try {
      execSync('which reflutter', { stdio: 'ignore' })
      return true
    } catch {
      return false
    }
  }
}
