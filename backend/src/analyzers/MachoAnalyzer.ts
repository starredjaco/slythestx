import fs from 'fs'
import path from 'path'
import { exec } from 'child_process'
import { promisify } from 'util'
import { logger } from '../utils/logger'

const execAsync = promisify(exec)

const IPSW_MAX_CONCURRENCY = 3
const IPSW_TIMEOUT_MS = 60_000

async function mapWithConcurrencyLimit<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results: R[] = new Array(items.length)
  let next = 0

  async function worker() {
    while (true) {
      const i = next++
      if (i >= items.length) return
      results[i] = await fn(items[i], i)
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return results
}

// ─── Patrones de clasificación ampliados ────────────────────────────────────

const INTERESTING_CLASS_PATTERNS: Array<{ pattern: RegExp; category: string }> = [
  { pattern: /auth|session|oauth|saml|jwt|openid/i, category: 'Authentication' },
  { pattern: /login|signin|logout|signout|register|signup|password|credential/i, category: 'Authentication' },
  { pattern: /token|secret|apiKey|bearer|oauthtoken|keychain/i, category: 'Credentials' },
  { pattern: /crypto|cipher|encrypt|decrypt|aes|rsa|hmac|iv|salt|digest|hash/i, category: 'Cryptography' },
  { pattern: /pinning|certificate|trust|eval|ssl|tls|hostname/i, category: 'TLS/Certificate Pinning' },
  { pattern: /apiclient|httpclient|restclient|network|urlsession|afnetworking|alamofire|moya|gRPC/i, category: 'Networking' },
  { pattern: /keychain|userdefaults|coredata|realm|sqlite|database|storage|mmkv|encryptedstore/i, category: 'Storage' },
  { pattern: /payment|billing|purchase|stripe|paypal|applepay|checkout|braintree/i, category: 'Payment' },
  { pattern: /biometric|touchid|faceid|localauthentication/i, category: 'Biometrics' },
  { pattern: /jailbreak|cydia|substrate|frida|debugger|antitamper|hook|rebind|sandbox|integrity/i, category: 'Anti-Tampering' },
  { pattern: /firebase|analytics|adjust|appsflyer|branch|mixpanel|sentry|datadog/i, category: 'Third-Party SDKs' },
]

const RISKY_ENTITLEMENTS: Array<{ pattern: RegExp; severity: MachoFinding['severity']; note: string }> = [
  { pattern: /^get-task-allow$/, severity: 'HIGH', note: 'Binario permite adjuntar debugger — no debería estar en un build de producción' },
  { pattern: /^com\.apple\.security\.get-task-allow$/, severity: 'HIGH', note: 'Binario permite adjuntar debugger — no debería estar en un build de producción' },
  { pattern: /^com\.apple\.security\.cs\.disable-library-validation$/, severity: 'HIGH', note: 'Permite cargar dylibs sin firmar de Apple — vector de inyección de código' },
  { pattern: /^com\.apple\.security\.cs\.allow-unsigned-executable-memory$/, severity: 'HIGH', note: 'Permite ejecutar memoria sin firmar — debilita code signing' },
  { pattern: /^com\.apple\.security\.cs\.allow-jit$/, severity: 'MEDIUM', note: 'JIT habilitado' },
  { pattern: /^com\.apple\.security\.cs\.disable-executable-page-protection$/, severity: 'HIGH', note: 'Debilita protección de páginas ejecutables' },
  { pattern: /^keychain-access-groups$/, severity: 'MEDIUM', note: 'Revisar si el grupo se comparte más ampliamente de lo necesario' },
  { pattern: /^com\.apple\.security\.application-groups$/, severity: 'MEDIUM', note: 'Contenedor compartido entre apps/extensions — revisar qué datos viven ahí' },
  { pattern: /^aps-environment$/, severity: 'INFO', note: 'Entorno de push notifications (dev/production)' },
  { pattern: /^com\.apple\.developer\.associated-domains$/, severity: 'INFO', note: 'Universal Links — revisar validación de apple-app-site-association' },
  { pattern: /^com\.apple\.developer\.networking\.networkextension$/, severity: 'MEDIUM', note: 'Puede interceptar/redirigir tráfico de red del dispositivo' },
  { pattern: /^com\.apple\.developer\.icloud/, severity: 'INFO', note: 'Uso de iCloud (containers/servicios)' },
  { pattern: /^com\.apple\.developer\.applesignin$/, severity: 'INFO', note: 'Soporte de Sign in with Apple' },
  { pattern: /^com\.apple\.developer\.nfc\.readersession\.formats$/, severity: 'MEDIUM', note: 'Acceso a NFC — revisar uso de tarjetas o lectura de tags' },
]

export interface MachoFinding {
  type:
    | 'api_endpoint'
    | 'hardcoded_string'
    | 'interesting_class'
    | 'crypto_usage'
    | 'authentication'
    | 'anti_tampering'
    | 'entitlement_risk'
    | 'ats_misconfig'
    | 'url_scheme'
    | 'encryption'
    | 'potential_secret'
    | 'third_party_sdk'
    | 'insecure_storage'
  value: string
  context?: string
  binary?: string
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
}

export interface MachoClass {
  name: string
  isInteresting: boolean
  interestingReason?: string
}

export interface MachoBinaryInfo {
  path: string
  relativePath: string
  name: string
  binaryType: 'main_executable' | 'framework' | 'extension' | 'dylib' | 'other'
  architectures: string[]
  uuid?: string
  minOSVersion?: string
  pie: boolean
  encrypted: boolean
  hasStackProtector: boolean
  entitlements: Array<{ key: string; raw: string }>
  interestingClasses: MachoClass[]
  totalClasses: number
  findings: MachoFinding[]
  analyzed: boolean
  error?: string
}

export interface MachoInfoPlistSummary {
  bundleId?: string
  bundleExecutable?: string
  atsAllowsArbitraryLoads: boolean
  atsExceptionDomains: string[]
  urlSchemes: string[]
  backgroundModes: string[]
  usageDescriptions: Record<string, string>
  queriesSchemes?: string[]
}

export interface MachoAnalysisResult {
  available: boolean
  ran: boolean
  isIOSApp: boolean
  appDir?: string
  totalBinaries: number
  binaries: MachoBinaryInfo[]
  infoPlist?: MachoInfoPlistSummary
  aggregatedFindings: MachoFinding[]
  error?: string
}

export class MachoAnalyzer {
  constructor(
    private extractPath: string,
    private platform: 'ANDROID' | 'IOS'
  ) {}

  async runMachoAnalysis(): Promise<MachoAnalysisResult> {
    if (this.platform !== 'IOS') {
      return this.emptyResult(false, false, 'Mach-O analysis only applies to iOS apps')
    }

    if (!(await this.isIpswAvailable())) {
      return this.emptyResult(false, false, 'ipsw binary not found in PATH')
    }

    const appDir = this.findAppBundle()
    if (!appDir) {
      return this.emptyResult(true, false, 'No .app bundle found under Payload/')
    }

    logger.info('🍎 Running ipsw Mach-O analysis...')

    let infoPlist: MachoInfoPlistSummary | undefined
    try {
      infoPlist = await this.parseInfoPlist(path.join(appDir, 'Info.plist'))
    } catch (err: any) {
      logger.warn('Info.plist parsing failed:', err.message)
    }

    const machoFiles = this.findMachOFiles(appDir)
    if (machoFiles.length === 0) {
      return {
        available: true,
        ran: false,
        isIOSApp: true,
        appDir,
        totalBinaries: 0,
        binaries: [],
        infoPlist,
        aggregatedFindings: [],
        error: 'No Mach-O binaries found inside the .app bundle',
      }
    }

    logger.info(`Found ${machoFiles.length} Mach-O binaries — analyzing with ipsw (max ${IPSW_MAX_CONCURRENCY} in parallel)`)

    const binaries = await mapWithConcurrencyLimit(machoFiles, IPSW_MAX_CONCURRENCY, file =>
      this.analyzeBinary(file, appDir)
    )

    const aggregatedFindings = this.deduplicateFindings([
      ...binaries.flatMap(b => b.findings),
      ...this.plistFindings(infoPlist),
    ]).slice(0, 300)

    const okCount = binaries.filter(b => b.analyzed).length
    logger.info(`ipsw: ${okCount}/${binaries.length} binaries analyzed, ${aggregatedFindings.length} findings`)

    return {
      available: true,
      ran: true,
      isIOSApp: true,
      appDir,
      totalBinaries: binaries.length,
      binaries,
      infoPlist,
      aggregatedFindings,
    }
  }

  private emptyResult(available: boolean, ran: boolean, error: string): MachoAnalysisResult {
    return {
      available,
      ran,
      isIOSApp: this.platform === 'IOS',
      totalBinaries: 0,
      binaries: [],
      aggregatedFindings: [],
      error,
    }
  }

  private async isIpswAvailable(): Promise<boolean> {
    try {
      await execAsync('which ipsw', { timeout: 5000 })
      return true
    } catch {
      return false
    }
  }

  private findAppBundle(): string | null {
    const payload = path.join(this.extractPath, 'Payload')
    if (!fs.existsSync(payload)) return null
    const app = fs.readdirSync(payload).find(d => d.endsWith('.app'))
    return app ? path.join(payload, app) : null
  }

  private findMachOFiles(appDir: string): string[] {
    const found: string[] = []

    const walk = (dir: string) => {
      let entries: fs.Dirent[]
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true })
      } catch {
        return
      }
      for (const entry of entries) {
        const full = path.join(dir, entry.name)
        if (entry.isDirectory()) {
          walk(full)
        } else if (entry.isFile() && this.isMachO(full)) {
          found.push(full)
        }
      }
    }

    walk(appDir)
    return found
  }

  private isMachO(filePath: string): boolean {
    let fd: number
    try {
      fd = fs.openSync(filePath, 'r')
    } catch {
      return false
    }
    try {
      const buf = Buffer.alloc(4)
      const bytesRead = fs.readSync(fd, buf, 0, 4, 0)
      if (bytesRead < 4) return false
      const magic = buf.readUInt32BE(0)
      return [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca].includes(magic)
    } catch {
      return false
    } finally {
      fs.closeSync(fd)
    }
  }

  private classifyBinaryType(relativePath: string): MachoBinaryInfo['binaryType'] {
    if (relativePath.includes('.appex/')) return 'extension'
    if (relativePath.includes('.framework/')) return 'framework'
    if (relativePath.endsWith('.dylib')) return 'dylib'
    if (!relativePath.includes('/')) return 'main_executable'
    return 'other'
  }

  private async analyzeBinary(filePath: string, appDir: string): Promise<MachoBinaryInfo> {
    const relativePath = path.relative(appDir, filePath)
    const name = path.basename(filePath)
    const binaryType = this.classifyBinaryType(relativePath)

    const base: MachoBinaryInfo = {
      path: filePath,
      relativePath,
      name,
      binaryType,
      architectures: [],
      pie: false,
      encrypted: false,
      hasStackProtector: false,
      entitlements: [],
      interestingClasses: [],
      totalClasses: 0,
      findings: [],
      analyzed: false,
    }

    try {
      const structural = await this.runIpsw(filePath, ['-d', '-l', '-s', '-e'])
      this.parseStructural(structural, base)

      const objc = await this.runIpsw(filePath, ['-o'], 30 * 1024 * 1024)
      this.parseObjc(objc, base)

      const strings = await this.runIpsw(filePath, ['-c'], 50 * 1024 * 1024)
      this.parseStrings(strings, base)

      base.analyzed = true
    } catch (err: any) {
      base.error = (err.message || 'ipsw failed').slice(0, 300)
      logger.warn(`ipsw failed on ${relativePath}: ${base.error}`)
    }

    return base
  }

  private async runIpsw(filePath: string, flags: string[], maxBuffer = 5 * 1024 * 1024): Promise<string> {
    const { stdout } = await execAsync(
      `ipsw macho info ${flags.join(' ')} "${filePath}"`,
      { timeout: IPSW_TIMEOUT_MS, maxBuffer }
    )
    return stdout
  }

  private parseStructural(output: string, info: MachoBinaryInfo): void {
    const uuidMatch = output.match(/UUID\s*[:=]?\s*([0-9A-Fa-f-]{20,})/)
    if (uuidMatch) info.uuid = uuidMatch[1]

    const archMatches = output.matchAll(/\b(ARM64E?|ARMV7[SK]?|X86_64|I386)\b/gi)
    const archSet = new Set<string>()
    for (const m of archMatches) archSet.add(m[1].toUpperCase())
    info.architectures = Array.from(archSet)

    const minOsMatch = output.match(/(?:MinOS|Minimum OS|Platform)\s*[:=]?\s*(iOS\s*)?(\d+\.\d+(?:\.\d+)?)/i)
    if (minOsMatch) info.minOSVersion = minOsMatch[2]

    info.pie = /\bPIE\b/i.test(output)

    const encMatch = output.match(/LC_ENCRYPTION_INFO[^\n]*\n(?:[^\n]*\n){0,4}?[^\n]*cryptid\s*[:=]?\s*(\d+)/i)
    info.encrypted = !!encMatch && encMatch[1] !== '0'
    if (info.encrypted) {
      info.findings.push({
        type: 'encryption',
        value: 'Binary is FairPlay-encrypted (cryptid != 0)',
        context: 'Static strings/ObjC dump for this binary will be incomplete until it is decrypted (frida-ios-dump / bagbak, etc.)',
        binary: info.relativePath,
        severity: 'INFO',
      })
    }

    info.hasStackProtector = /__stack_chk_fail/i.test(output)

    const keyMatches = output.matchAll(/<key>([^<]+)<\/key>\s*(?:<(\w+)\/?>)?/g)
    for (const m of keyMatches) {
      const key = m[1].trim()
      info.entitlements.push({ key, raw: m[2] || '' })

      const risky = RISKY_ENTITLEMENTS.find(r => r.pattern.test(key))
      if (risky) {
        info.findings.push({
          type: 'entitlement_risk',
          value: key,
          context: risky.note,
          binary: info.relativePath,
          severity: risky.severity,
        })
      }
    }
  }

  private parseObjc(output: string, info: MachoBinaryInfo): void {
    const classMatches = output.matchAll(/@interface\s+(\w[\w$]*)/g)
    const seen = new Set<string>()

    for (const m of classMatches) {
      const className = m[1]
      if (seen.has(className)) continue
      seen.add(className)
      info.totalClasses++

      const hit = INTERESTING_CLASS_PATTERNS.find(p => p.pattern.test(className))
      if (hit) {
        info.interestingClasses.push({ name: className, isInteresting: true, interestingReason: hit.category })
        info.findings.push({
          type: hit.category === 'Anti-Tampering' ? 'anti_tampering' : 'interesting_class',
          value: className,
          context: hit.category,
          binary: info.relativePath,
          severity: hit.category === 'Third-Party SDKs' ? 'LOW' : 'INFO',
        })
      }
    }

    info.interestingClasses = info.interestingClasses.slice(0, 100)
  }

  private parseStrings(output: string, info: MachoBinaryInfo): void {
    const strRe = /^(.{8,300})$/gm
    let m: RegExpExecArray | null
    let count = 0
    while ((m = strRe.exec(output)) !== null && count < 5000) {
      this.classifyString(m[1].trim(), info)
      count++
    }
  }

  private classifyString(value: string, info: MachoBinaryInfo): void {
    if (!value || value.length < 8) return
    if (/^(?:_\$s|_T0|__Z|_OBJC_)/.test(value)) return 

    // URLs y Endpoints
    if (/^https?:\/\/[a-z0-9]/i.test(value)) {
      info.findings.push({ type: 'api_endpoint', value, binary: info.relativePath, severity: 'HIGH' })
      return
    }
    if (/^\/(?:api|v\d+|rest|graphql|gql|ws|wss)\//i.test(value)) {
      info.findings.push({ type: 'api_endpoint', value, binary: info.relativePath, severity: 'MEDIUM' })
      return
    }

    // Credenciales, Tokens y Autorización
    if (/(?:bearer|authorization|x-api-key|apikey|api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|jwt)/i.test(value)) {
      info.findings.push({
        type: 'authentication',
        value: value.length > 80 ? value.slice(0, 77) + '...' : value,
        binary: info.relativePath,
        severity: 'HIGH',
      })
      return
    }

    // Secrets específicos de plataformas comunes (AWS, Firebase, Google APIs, Slack, etc.)
    if (/AIza[0-9A-Za-z-_]{35}/.test(value)) {
      info.findings.push({ type: 'potential_secret', value: 'Google API Key detectada', context: value, binary: info.relativePath, severity: 'HIGH' })
      return
    }
    if (/sk_live_[0-9a-zA-Z]{24,}/.test(value) || /pk_live_[0-9a-zA-Z]{24,}/.test(value)) {
      info.findings.push({ type: 'potential_secret', value: 'Stripe API Key detectada', context: value, binary: info.relativePath, severity: 'HIGH' })
      return
    }
    if (/AKIA[0-9A-Z]{16}/.test(value)) {
      info.findings.push({ type: 'potential_secret', value: 'AWS Access Key ID detectada', context: value, binary: info.relativePath, severity: 'HIGH' })
      return
    }

    // Cadenas codificadas de alta entropía / base64 sospechosas
    if (/^[A-Za-z0-9+/=_-]{40,}$/.test(value) && !/^[A-Za-z]+$/.test(value) && !/^\d+$/.test(value)) {
      info.findings.push({
        type: 'hardcoded_string',
        value: value.length > 80 ? value.slice(0, 77) + '...' : value,
        context: 'Possible encoded secret or token',
        binary: info.relativePath,
        severity: 'MEDIUM',
      })
      return
    }

    // Uso de criptografía
    if (/(?:aes|rsa|hmac|sha-?256|sha-?512|pbkdf2|bcrypt|ecdsa|cryptokit)/i.test(value)) {
      info.findings.push({ type: 'crypto_usage', value, binary: info.relativePath, severity: 'INFO' })
    }
  }

  // ─── Info.plist ampliado ───────────────────────────────────────────────────
  private async parseInfoPlist(plistPath: string): Promise<MachoInfoPlistSummary | undefined> {
    if (!fs.existsSync(plistPath)) return undefined

    let json: any
    try {
      const { stdout } = await execAsync(`ipsw plist "${plistPath}" --json`, {
        timeout: 15000,
        maxBuffer: 10 * 1024 * 1024,
      })
      json = JSON.parse(stdout)
    } catch (err: any) {
      logger.warn('ipsw plist failed on Info.plist, skipping ATS/URL-scheme extraction:', err.message)
      return undefined
    }

    const ats = json?.NSAppTransportSecurity || {}
    const exceptionDomains: string[] = ats.NSExceptionDomains ? Object.keys(ats.NSExceptionDomains) : []

    const urlSchemes: string[] = (json?.CFBundleURLTypes || [])
      .flatMap((t: any) => t?.CFBundleURLSchemes || [])
      .filter(Boolean)

    const queriesSchemes: string[] = json?.LSApplicationQueriesSchemes || []

    const usageDescriptions: Record<string, string> = {}
    for (const [key, value] of Object.entries(json || {})) {
      if (key.endsWith('UsageDescription') && typeof value === 'string') {
        usageDescriptions[key] = value
      }
    }

    return {
      bundleId: json?.CFBundleIdentifier,
      bundleExecutable: json?.CFBundleExecutable,
      atsAllowsArbitraryLoads: ats.NSAllowsArbitraryLoads === true,
      atsExceptionDomains: exceptionDomains,
      urlSchemes,
      queriesSchemes,
      backgroundModes: json?.UIBackgroundModes || [],
      usageDescriptions,
    }
  }

  private plistFindings(plist?: MachoInfoPlistSummary): MachoFinding[] {
    if (!plist) return []
    const findings: MachoFinding[] = []

    if (plist.atsAllowsArbitraryLoads) {
      findings.push({
        type: 'ats_misconfig',
        value: 'NSAllowsArbitraryLoads = true',
        context: 'App Transport Security deshabilitado globalmente — permite HTTP sin cifrar a cualquier dominio',
        severity: 'HIGH',
      })
    }
    for (const domain of plist.atsExceptionDomains) {
      findings.push({
        type: 'ats_misconfig',
        value: domain,
        context: 'Dominio con excepción de ATS — revisar si permite HTTP inseguro o TLS débil',
        severity: 'MEDIUM',
      })
    }
    for (const scheme of plist.urlSchemes) {
      findings.push({
        type: 'url_scheme',
        value: scheme,
        context: 'Custom URL scheme — superficie potencial de URL scheme hijacking / deep link injection',
        severity: 'INFO',
      })
    }
    if (plist.queriesSchemes && plist.queriesSchemes.length > 0) {
      findings.push({
        type: 'url_scheme',
        value: `LSApplicationQueriesSchemes (${plist.queriesSchemes.length} schemes)`,
        context: `Esquemas consultables: ${plist.queriesSchemes.slice(0, 10).join(', ')}... — permite detectar otras apps instaladas en el dispositivo`,
        severity: 'LOW',
      })
    }

    return findings
  }

  private deduplicateFindings(findings: MachoFinding[]): MachoFinding[] {
    const seen = new Set<string>()
    return findings.filter(f => {
      const key = `${f.type}:${f.binary || ''}:${f.value}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
  }
}