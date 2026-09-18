import fs from 'fs'
import path from 'path'
import { exec, spawn } from 'child_process'
import { promisify } from 'util'
import { logger } from '../utils/logger'

const execAsync = promisify(exec)

const BLUTTER_DIR = '/app/tools/blutter'
const BLUTTER_OUTPUT_BASE = '/app/analysis_results/blutter'
const UBER_APK_SIGNER_JAR = '/app/tools/uber-apk-signer-1.3.0.jar'

// Cola de concurrencia compartida por Blutter y el patch de ReFlutter — ambos
// son procesos nativos pesados (compilación / re-empaquetado) que pueden
// competir por RAM/CPU si corren en paralelo y afectar otros scans en curso.
let nativeToolsQueue: Promise<void> = Promise.resolve()

async function withNativeToolsConcurrencyLimit<T>(fn: () => Promise<T>): Promise<T> {
  const previous = nativeToolsQueue
  let release: () => void = () => {}
  nativeToolsQueue = new Promise<void>(resolve => { release = resolve })
  await previous
  try {
    return await fn()
  } finally {
    release()
  }
}

const INTERESTING_PATTERNS: Array<{ pattern: RegExp; category: string }> = [
  { pattern: /auth/i, category: 'Authentication' },
  { pattern: /login|signin|logout|signout/i, category: 'Authentication' },
  { pattern: /token|credential|password|secret/i, category: 'Credentials' },
  { pattern: /crypto|cipher|encrypt|decrypt|aes|rsa|hmac/i, category: 'Cryptography' },
  { pattern: /ssl|tls|certificate|pinning|x509/i, category: 'TLS/Certificate Pinning' },
  { pattern: /api.*client|http.*client|rest.*client|network/i, category: 'Networking' },
  { pattern: /storage|database|(?:^|[^r])db(?:[^a-z]|$)|prefs|keychain|keystore/i, category: 'Storage' },
  { pattern: /payment|billing|purchase|stripe|paypal/i, category: 'Payment' },
  { pattern: /biometric|fingerprint|face.*id/i, category: 'Biometrics' },
]

export interface BlutterFinding {
  type: 'api_endpoint' | 'hardcoded_string' | 'interesting_class' | 'crypto_usage' | 'authentication'
  value: string
  context?: string
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
}

export interface BlutterClass {
  name: string
  library: string
  methods: string[]
  isInteresting: boolean
  interestingReason?: string
}

export interface BlutterResult {
  available: boolean
  ran: boolean
  outputDir?: string
  totalClasses: number
  totalMethods: number
  packages: string[]
  interestingClasses: BlutterClass[]
  findings: BlutterFinding[]
  fridaScriptAvailable: boolean
  error?: string
}

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
  canPatch: boolean
  blutter?: BlutterResult
  error?: string
}

export interface ReflutterPatchResult {
  success: boolean
  patchedApkPath?: string
  error?: string
}

// reflutter es un wizard interactivo: por stdin pide elegir modo (1 o 2) y,
// si es modo 1, la IP de Burp para invisible proxying. No tiene flags de CLI
// para saltarse esas preguntas.
//   'traffic' → opción 1: parchea para interceptar tráfico vía Burp (requiere burpIp)
//   'offset'  → opción 2: parchea solo para exponer offsets de funciones (no pide IP)
export type ReflutterMode = 'traffic' | 'offset'

export class FlutterAnalyzer {
  private readonly scriptPath = '/app/tools/extract_dart_info.py'

  constructor(
    private extractPath: string,
    private platform: 'ANDROID' | 'IOS',
    private applicationId?: number,
    private apkPath?: string
  ) {}

  async analyze(): Promise<FlutterAnalysisResult> {
    logger.info('🦋 Analizando aplicación Flutter...')

    if (!this.detectFlutter()) {
      return { isFlutter: false, soFiles: [], canPatch: false }
    }

    if (!fs.existsSync(this.scriptPath)) {
      return {
        isFlutter: true,
        soFiles: [],
        canPatch: false,
        error: 'Flutter analysis script not found',
      }
    }

    const targetDir =
      this.platform === 'ANDROID' ? this.getAndroidLibDir() : this.extractPath

    if (!targetDir) {
      return {
        isFlutter: true,
        soFiles: [],
        canPatch: false,
        error: 'No valid Flutter directory found',
      }
    }

    try {
      const { stdout } = await execAsync(
        `python3 "${this.scriptPath}" "${targetDir}"`,
        { timeout: 30000 }
      )
      const result = JSON.parse(stdout.trim())

      const snapshotInfo = {
        os: result.platform,
        hash: result.snapshot_hash || undefined,
        flags: result.flags || [],
        compilationMode: result.build_mode || undefined,
        obfuscated: result.obfuscation === 'yes',
        dartVersion: result.dart_version || undefined,
        engineFingerprint: result.engine_fingerprint || undefined,
        arch: result.arch || undefined,
        buildMode: result.build_mode || undefined,
      }

      if (this.platform === 'IOS') {
        logger.info('ReFlutter iOS not supported')
      }

      return {
        isFlutter: true,
        soFiles: this.platform === 'ANDROID' ? fs.readdirSync(targetDir) : [],
        snapshotInfo,
        canPatch: this.platform === 'ANDROID',
      }
    } catch (err: any) {
      logger.error('Error analyzing Flutter:', err.message)
      return {
        isFlutter: true,
        soFiles: [],
        canPatch: false,
        error: err.message,
      }
    }
  }

  private detectFlutter(): boolean {
    if (this.platform === 'ANDROID') {
      return fs.existsSync(path.join(this.extractPath, 'lib'))
    }
    const payload = path.join(this.extractPath, 'Payload')
    if (!fs.existsSync(payload)) return false
    return fs.readdirSync(payload).some(d => d.endsWith('.app'))
  }

  private getAndroidLibDir(): string | null {
    const libRoot = path.join(this.extractPath, 'lib')
    if (!fs.existsSync(libRoot)) return null

    const dirs = fs
      .readdirSync(libRoot)
      .filter(d => fs.statSync(path.join(libRoot, d)).isDirectory())

    if (dirs.length === 0) return null

    const selected = path.join(libRoot, dirs[0])
    logger.info(`Analyzing android libs ${dirs[0]}`)
    return selected
  }

  private findArchLibDir(root: string): string | null {
    if (!fs.existsSync(root)) return null

    const supported = ['arm64-v8a', 'x86_64']
    const SKIP_DIRS = new Set(['smali', 'sources', 'unknown', '.git', 'node_modules', 'META-INF'])
    const MAX_DEPTH = 8

    const search = (dir: string, depth: number): string | null => {
      if (depth > MAX_DEPTH) return null

      const base = path.basename(dir)
      if (supported.includes(base) && fs.existsSync(path.join(dir, 'libapp.so'))) {
        return dir
      }

      let entries: fs.Dirent[]
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true })
      } catch {
        return null
      }

      for (const entry of entries) {
        if (!entry.isDirectory() || SKIP_DIRS.has(entry.name)) continue
        const found = search(path.join(dir, entry.name), depth + 1)
        if (found) return found
      }
      return null
    }

    const result = search(root, 0)
    if (result) logger.info(`Blutter will use ${path.basename(result)} (found at ${result})`)
    return result
  }

  private getBlutterOutputDir(): string {
    return this.applicationId
      ? path.join(BLUTTER_OUTPUT_BASE, `app${this.applicationId}`)
      : path.join(BLUTTER_OUTPUT_BASE, `tmp_${Date.now()}`)
  }

  // ─── Blutter ────────────────────────────────────────────────────────────────
  async runBlutterAnalysis(): Promise<BlutterResult | undefined> {
    if (this.platform !== 'ANDROID') return undefined

    const blutterDir = this.findArchLibDir(this.extractPath)
    if (!blutterDir) {
      logger.info(`Blutter skipped — no arm64-v8a/x86_64 with libapp.so found under ${this.extractPath}`)
      return {
        available: true,
        ran: false,
        totalClasses: 0,
        totalMethods: 0,
        packages: [],
        interestingClasses: [],
        findings: [],
        fridaScriptAvailable: false,
        error: `No arm64-v8a or x86_64 with libapp.so found under ${this.extractPath} — make sure the app was analyzed after the working dir started being preserved, or re-run the analysis`,
      }
    }

    logger.info('🔬 Running Blutter deep Dart analysis (post-analysis step)...')
    const result = await this.runBlutter(blutterDir)

    if (result.ran) {
      logger.info(
        `Blutter: ${result.totalClasses} classes, ${result.totalMethods} methods, ${result.findings.length} findings`
      )
    } else {
      logger.warn(`Blutter did not complete: ${result.error}`)
    }

    return result
  }

  private isBlutterInstalled(): boolean {
    return fs.existsSync(path.join(BLUTTER_DIR, 'blutter.py'))
  }

  private async runBlutter(libDir: string): Promise<BlutterResult> {
    if (!this.isBlutterInstalled()) {
      return {
        available: false,
        ran: false,
        totalClasses: 0,
        totalMethods: 0,
        packages: [],
        interestingClasses: [],
        findings: [],
        fridaScriptAvailable: false,
        error: `Blutter not found at ${BLUTTER_DIR} — verify it was installed in the Docker image`,
      }
    }

    const outputDir = this.getBlutterOutputDir()

    if (!fs.existsSync(BLUTTER_OUTPUT_BASE)) fs.mkdirSync(BLUTTER_OUTPUT_BASE, { recursive: true })
    fs.mkdirSync(outputDir, { recursive: true })

    logger.info(`Blutter: ${path.basename(libDir)} → ${outputDir}`)

    return withNativeToolsConcurrencyLimit(async () => {
      const logFile = path.join(outputDir, 'blutter.log')
      try {
        await execAsync(
          `python3 "${BLUTTER_DIR}/blutter.py" "${libDir}" "${outputDir}" > "${logFile}" 2>&1`,
          { timeout: 1800000, maxBuffer: 1024 * 1024 * 10 }
        )
      } catch (err: any) {
        let detail = err.message?.slice(0, 200) || 'Unknown error'
        try {
          const log = fs.readFileSync(logFile, 'utf-8')
          detail = log.slice(-2000)
        } catch {}
        logger.error('Blutter execution failed:\n' + detail)
        return {
          available: true,
          ran: false,
          outputDir,
          totalClasses: 0,
          totalMethods: 0,
          packages: [],
          interestingClasses: [],
          findings: [],
          fridaScriptAvailable: false,
          error: detail,
        }
      }

      return this.parseBlutterOutput(outputDir)
    })
  }

  private parseBlutterOutput(outputDir: string): BlutterResult {
    const fridaScript = path.join(outputDir, 'blutter_frida.js')
    const objsDir = path.join(outputDir, 'objs')

    if (!fs.existsSync(fridaScript)) {
      return {
        available: true,
        ran: false,
        outputDir,
        totalClasses: 0,
        totalMethods: 0,
        packages: [],
        interestingClasses: [],
        findings: [],
        fridaScriptAvailable: false,
        error: 'Blutter output incomplete — frida script not generated',
      }
    }

    const packages = new Set<string>()
    const interestingClasses: BlutterClass[] = []
    const findings: BlutterFinding[] = []
    let totalClasses = 0
    let totalMethods = 0

    if (fs.existsSync(objsDir)) {
      for (const file of fs.readdirSync(objsDir).filter(f => f.endsWith('.txt'))) {
        try {
          const content = fs.readFileSync(path.join(objsDir, file), 'utf-8')
          const stats = this.parseObjsContent(content, packages, interestingClasses, findings)
          totalClasses += stats.classes
          totalMethods += stats.methods
        } catch {
        }
      }
    }

    try {
      const fridaContent = fs.readFileSync(fridaScript, 'utf-8')
      this.extractFridaStrings(fridaContent, findings)
    } catch {}

    return {
      available: true,
      ran: true,
      outputDir,
      totalClasses,
      totalMethods,
      packages: Array.from(packages).sort(),
      interestingClasses: interestingClasses.slice(0, 100),
      findings: this.deduplicateFindings(findings).slice(0, 200),
      fridaScriptAvailable: true,
    }
  }

  private parseObjsContent(
    content: string,
    packages: Set<string>,
    interestingClasses: BlutterClass[],
    findings: BlutterFinding[]
  ): { classes: number; methods: number } {
    let classes = 0
    let methods = 0
    let currentLibrary = ''
    let currentClass: BlutterClass | null = null

    const SKIP_KEYWORDS = new Set(['if', 'else', 'return', 'this', 'super', 'null', 'true', 'false', 'var', 'final'])

    for (const line of content.split('\n')) {
      const trimmed = line.trim()
      if (!trimmed) continue

      const libMatch = trimmed.match(/^Library\s+['"]([^'"]+)['"]/i)
      if (libMatch) {
        currentLibrary = libMatch[1]
        const pkgMatch = currentLibrary.match(/^package:([^/]+)/)
        if (pkgMatch) packages.add(pkgMatch[1])
        currentClass = null
        continue
      }

      const classMatch = trimmed.match(/^Class[:\s]+(\w[\w$]*)/)
      if (classMatch) {
        classes++
        const className = classMatch[1]
        const hit = INTERESTING_PATTERNS.find(p => p.pattern.test(className))

        currentClass = {
          name: className,
          library: currentLibrary,
          methods: [],
          isInteresting: !!hit,
          interestingReason: hit?.category,
        }

        if (hit) {
          interestingClasses.push(currentClass)
          findings.push({
            type: 'interesting_class',
            value: className,
            context: `${hit.category} — ${currentLibrary}`,
            severity: 'INFO',
          })
        }
        continue
      }

      const methodMatch =
        trimmed.match(/^(?:method|function)[:\s]+(\w[\w$]*)/i) ||
        trimmed.match(/^\s{2,}(\w[\w$]*)\s*\(/)
      if (methodMatch && currentClass) {
        const name = methodMatch[1]
        if (name && !SKIP_KEYWORDS.has(name)) {
          currentClass.methods.push(name)
          methods++

          if (currentClass.isInteresting) {
            const hit = INTERESTING_PATTERNS.find(p => p.pattern.test(name))
            if (hit) {
              findings.push({
                type: 'interesting_class',
                value: `${currentClass.name}.${name}()`,
                context: hit.category,
                severity: 'MEDIUM',
              })
            }
          }
        }
        continue
      }

      const strRe = /["']([^"'\n\r]{8,300})["']/g
      let m: RegExpExecArray | null
      while ((m = strRe.exec(trimmed)) !== null) {
        this.classifyString(m[1], findings)
      }
    }

    return { classes, methods }
  }

  private extractFridaStrings(fridaContent: string, findings: BlutterFinding[]): void {
    const strRe = /["']([^"'\n\r]{8,300})["']/g
    let m: RegExpExecArray | null
    while ((m = strRe.exec(fridaContent)) !== null) {
      this.classifyString(m[1], findings)
    }
  }

  private classifyString(value: string, findings: BlutterFinding[]): void {
    if (/^(?:dart|flutter|package:flutter):/i.test(value)) return
    if (/^_(?:klass|offset|type|field|iso)/i.test(value)) return
    if (/^[A-Z_]{5,}$/.test(value)) return

    if (/^_?(?:[A-Z][a-z0-9]*){3,}$/.test(value)) return

    if (/^https?:\/\/[a-z0-9]/i.test(value)) {
      findings.push({ type: 'api_endpoint', value, severity: 'HIGH' })
      return
    }
    if (/^\/(?:api|v\d+|rest|graphql|gql)\//i.test(value)) {
      findings.push({ type: 'api_endpoint', value, severity: 'MEDIUM' })
      return
    }
    if (/(?:bearer|authorization|x-api-key|apikey|api[_-]?key|secret[_-]?key|access[_-]?token)/i.test(value)) {
      findings.push({
        type: 'authentication',
        value: value.length > 80 ? value.slice(0, 77) + '...' : value,
        severity: 'HIGH',
      })
      return
    }
    if (
      /^[A-Za-z0-9+/=_-]{40,}$/.test(value) &&
      !/^[A-Za-z]+$/.test(value) &&
      !/^\d+$/.test(value) &&
      /[0-9]/.test(value)
    ) {
      findings.push({
        type: 'hardcoded_string',
        value: value.length > 80 ? value.slice(0, 77) + '...' : value,
        context: 'Possible encoded secret or token',
        severity: 'MEDIUM',
      })
      return
    }
    if (/(?:aes|rsa|hmac|sha-?256|sha-?512|pbkdf2|bcrypt|ecdsa)/i.test(value)) {
      findings.push({ type: 'crypto_usage', value, severity: 'INFO' })
    }
  }

  private deduplicateFindings(findings: BlutterFinding[]): BlutterFinding[] {
    const seen = new Set<string>()
    return findings.filter(f => {
      const key = `${f.type}:${f.value}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
  }

  // ─── ReFlutter patch ───────────────────────────────────────────────────────

  async patchWithReflutter(options: { mode?: ReflutterMode; burpIp?: string } = {}): Promise<ReflutterPatchResult> {
    const mode = options.mode ?? 'traffic'

    if (this.platform !== 'ANDROID') {
      return { success: false, error: 'ReFlutter patching only supports Android APKs' }
    }
    if (!this.apkPath || !fs.existsSync(this.apkPath)) {
      return { success: false, error: 'Original APK path not provided or not found' }
    }
    if (mode === 'traffic' && !options.burpIp) {
      return { success: false, error: 'burpIp is required when mode is "traffic" (invisible proxying)' }
    }

    const apkDir = path.dirname(this.apkPath!)
    const outputDir = path.join(apkDir, `reflutter_${this.applicationId ?? Date.now()}`)

    fs.rmSync(outputDir, { recursive: true, force: true })
    fs.mkdirSync(outputDir, { recursive: true })

    const stdinLines = mode === 'traffic' ? ['1', options.burpIp!] : ['2']
    const stdinInput = stdinLines.join('\n') + '\n'

    return withNativeToolsConcurrencyLimit(async () => {
      try {
        await this.runInteractive('reflutter', [this.apkPath!], stdinInput, {
          cwd: outputDir,
          timeoutMs: 5 * 60 * 1000,
        })
      } catch (err: any) {
        return { success: false, error: (err.message || 'reflutter failed').slice(0, 500) }
      }

      const rawOutputName = fs.readdirSync(outputDir).find(f => f.endsWith('.RE.apk'))
      if (!rawOutputName) {
        return { success: false, error: 'reflutter finished but no new .apk was produced' }
      }

      const reflutterOutputPath = path.join(outputDir, rawOutputName)

      let signedPath: string
      try {
        await execAsync(
          `java -jar "${UBER_APK_SIGNER_JAR}" --apks "${reflutterOutputPath}" --out "${outputDir}" --allowResign`,
          { timeout: 2 * 60 * 1000, maxBuffer: 10 * 1024 * 1024 }
        )
        const signedName = `${path.basename(rawOutputName, '.apk')}-aligned-debugSigned.apk`
        signedPath = path.join(outputDir, signedName)
        if (!fs.existsSync(signedPath)) {
          return { success: false, error: `uber-apk-signer finished but ${signedName} was not found` }
        }
      } catch (err: any) {
        return { success: false, error: `uber-apk-signer failed: ${(err.message || '').slice(0, 400)}` }
      }

      const finalName = `app${this.applicationId ?? Date.now()}_patched.apk`
      const finalPath = path.join(outputDir, finalName)
      fs.renameSync(signedPath, finalPath)
      fs.rmSync(reflutterOutputPath, { force: true })

      logger.info(`ReFlutter+signed patch produced ${finalName} (mode=${mode})`)
      return { success: true, patchedApkPath: finalPath }
    })
  }

  private runInteractive(
    cmd: string,
    args: string[],
    stdinInput: string,
    opts: { cwd?: string; timeoutMs: number }
  ): Promise<{ stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      const child = spawn(cmd, args, { cwd: opts.cwd })
      let stdout = ''
      let stderr = ''

      const timer = setTimeout(() => {
        child.kill('SIGKILL')
        reject(new Error(`Timed out after ${opts.timeoutMs}ms waiting for "${cmd}" — still prompting for input?`))
      }, opts.timeoutMs)

      child.stdout?.on('data', d => { stdout += d.toString() })
      child.stderr?.on('data', d => { stderr += d.toString() })

      child.on('error', err => {
        clearTimeout(timer)
        reject(err)
      })

      child.on('close', code => {
        clearTimeout(timer)
        if (code === 0) {
          resolve({ stdout, stderr })
        } else {
          reject(new Error(`"${cmd}" exited with code ${code}: ${(stderr || stdout).slice(-500)}`))
        }
      })

      child.stdin?.write(stdinInput)
      child.stdin?.end()
    })
  }
}