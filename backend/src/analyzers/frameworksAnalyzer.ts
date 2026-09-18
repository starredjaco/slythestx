import fs from 'fs'
import path from 'path'
import { logger } from '../utils/logger'

const plist = require('plist')

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type FrameworkSource =
  | 'BUNDLED'
  | 'SYSTEM'
  | 'NATIVE_LIB'
  | 'JAVA_PACKAGE'

export type FrameworkKind =
  | 'UI'
  | 'NETWORKING'
  | 'DATABASE'
  | 'ANALYTICS'
  | 'SECURITY'
  | 'MEDIA'
  | 'MAPS'
  | 'PAYMENTS'
  | 'AUTH'
  | 'PUSH'
  | 'CRASH_REPORTING'
  | 'AD'
  | 'ML'
  | 'STORAGE'
  | 'CORE'
  | 'TESTING'
  | 'UNKNOWN'

export interface DetectedFrameworkEntry {
  name: string
  version?: string
  identifier?: string
  source: FrameworkSource
  kind: FrameworkKind
  vendor?: string
  path: string
  architectures?: string[]
  minOsVersion?: string
}

export interface FrameworksSummary {
  byKind: Record<FrameworkKind, string[]>
  bySource: Record<FrameworkSource, number>
  topVendors: string[]
  hasPaymentSdk: boolean
  hasAnalyticsSdk: boolean
  hasAdSdk: boolean
  hasMlSdk: boolean
  hasAuthSdk: boolean
}

export interface FrameworksAnalysisResult {
  platform: 'ANDROID' | 'IOS'
  totalFrameworks: number
  frameworks: DetectedFrameworkEntry[]
  summary: FrameworksSummary
}

interface KnownFramework {
  pattern: RegExp
  kind: FrameworkKind
  vendor?: string
  displayName?: string
}

// ─────────────────────────────────────────────────────────────────────────────
// Framework catalog
// ─────────────────────────────────────────────────────────────────────────────

const KNOWN_FRAMEWORKS: KnownFramework[] = [
  { pattern: /firebase/i, kind: 'ANALYTICS', vendor: 'Google Firebase' },
  { pattern: /crashlytics/i, kind: 'CRASH_REPORTING', vendor: 'Google Firebase' },
  { pattern: /stripe/i, kind: 'PAYMENTS', vendor: 'Stripe' },
  { pattern: /paypal/i, kind: 'PAYMENTS', vendor: 'PayPal' },
  { pattern: /braintree/i, kind: 'PAYMENTS', vendor: 'Braintree' },
  { pattern: /okhttp/i, kind: 'NETWORKING', vendor: 'Square' },
  { pattern: /retrofit/i, kind: 'NETWORKING', vendor: 'Square' },
  { pattern: /volley/i, kind: 'NETWORKING', vendor: 'Google' },
  { pattern: /realm/i, kind: 'DATABASE', vendor: 'Realm' },
  { pattern: /sqlite/i, kind: 'DATABASE', vendor: 'SQLite' },
  { pattern: /room/i, kind: 'DATABASE', vendor: 'Google' },
  { pattern: /auth0/i, kind: 'AUTH', vendor: 'Auth0' },
  { pattern: /okta/i, kind: 'AUTH', vendor: 'Okta' },
  { pattern: /onesignal/i, kind: 'PUSH', vendor: 'OneSignal' },
  { pattern: /googlemaps/i, kind: 'MAPS', vendor: 'Google' },
  { pattern: /mapbox/i, kind: 'MAPS', vendor: 'Mapbox' },
  { pattern: /tensorflow/i, kind: 'ML', vendor: 'Google' },
  { pattern: /mlkit/i, kind: 'ML', vendor: 'Google' },
  { pattern: /glide/i, kind: 'UI', vendor: 'Google' },
  { pattern: /picasso/i, kind: 'UI', vendor: 'Square' },
  { pattern: /lottie/i, kind: 'UI', vendor: 'Airbnb' },
  { pattern: /exoplayer/i, kind: 'MEDIA', vendor: 'Google' },
  { pattern: /avfoundation/i, kind: 'MEDIA', vendor: 'Apple' },
  { pattern: /openssl/i, kind: 'SECURITY', vendor: 'OpenSSL' },
]

// ─────────────────────────────────────────────────────────────────────────────
// Analyzer
// ─────────────────────────────────────────────────────────────────────────────

export class FrameworksAnalyzer {
  constructor(
    private readonly extractPath: string,
    private readonly platform: 'ANDROID' | 'IOS',
    private readonly workingDir: string
  ) {}

  async analyze(): Promise<FrameworksAnalysisResult> {
    logger.info(`📦 Framework analysis (${this.platform})`)

    const frameworks =
      this.platform === 'IOS'
        ? this.analyzeIOS()
        : this.analyzeAndroid()

    const summary = this.buildSummary(frameworks)

    return {
      platform: this.platform,
      totalFrameworks: frameworks.length,
      frameworks,
      summary,
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // iOS
  // ══════════════════════════════════════════════════════════════════════════

  private analyzeIOS(): DetectedFrameworkEntry[] {
    const results: DetectedFrameworkEntry[] = []

    const frameworks = this.findDirectoriesByExtension(
      this.extractPath,
      '.framework'
    )

    for (const frameworkDir of frameworks) {
      const frameworkName = path.basename(
        frameworkDir,
        '.framework'
      )

      const parsed = this.parseIOSFramework(
        frameworkDir,
        frameworkName,
        'BUNDLED'
      )

      if (parsed) {
        results.push(parsed)
      }
    }

    const dylibs = this.findFilesByExtension(
      this.extractPath,
      '.dylib'
    )

    for (const dylib of dylibs) {
      const name = path.basename(dylib, '.dylib')

      results.push(
        this.buildEntry({
          name,
          relPath: path.relative(this.extractPath, dylib),
          source: 'BUNDLED',
          archs: this.readMachOArchs(dylib),
        })
      )
    }

    return this.dedup(results)
  }

  private parseIOSFramework(
    frameworkDir: string,
    name: string,
    source: FrameworkSource
  ): DetectedFrameworkEntry | null {
    let version: string | undefined
    let identifier: string | undefined
    let minOsVersion: string | undefined

    const plistFiles = this.findFilesByName(
      frameworkDir,
      'Info.plist'
    )

    for (const plistFile of plistFiles) {
      try {
        const raw = fs.readFileSync(plistFile, 'utf-8')

        const data = plist.parse(raw)

        version =
          data.CFBundleShortVersionString ||
          data.CFBundleVersion

        identifier = data.CFBundleIdentifier

        minOsVersion =
          data.MinimumOSVersion ||
          data.LSMinimumSystemVersion

        break
      } catch {}
    }

    const binary = this.findFrameworkBinary(
      frameworkDir
    )

    const archs = binary
      ? this.readMachOArchs(binary)
      : []

    return this.buildEntry({
      name,
      version,
      identifier,
      relPath: path.relative(
        this.extractPath,
        frameworkDir
      ),
      source,
      archs,
      minOs: minOsVersion,
    })
  }

  private findFrameworkBinary(
    frameworkDir: string
  ): string | null {
    const frameworkName = path.basename(
      frameworkDir,
      '.framework'
    )

    const directBinary = path.join(
      frameworkDir,
      frameworkName
    )

    try {
      if (
        fs.existsSync(directBinary) &&
        fs.statSync(directBinary).isFile()
      ) {
        return directBinary
      }
    } catch {}

    const files = this.findFilesRecursive(
      frameworkDir
    )

    for (const file of files) {
      try {
        const stat = fs.statSync(file)

        if (!stat.isFile()) {
          continue
        }

        const ext = path.extname(file)

        if (!ext) {
          const archs =
            this.readMachOArchs(file)

          if (archs.length > 0) {
            return file
          }
        }
      } catch {}
    }

    return null
  }

  private readMachOArchs(
    filePath: string
  ): string[] {
    try {
      const fd = fs.openSync(filePath, 'r')

      const buf = Buffer.alloc(8)

      fs.readSync(fd, buf, 0, 8, 0)

      fs.closeSync(fd)

      const magic = buf.readUInt32BE(0)

      if (magic === 0xcafebabe) {
        return ['arm64', 'armv7']
      }

      if (
        magic === 0xfeedfacf ||
        magic === 0xcffaedfe
      ) {
        return ['arm64']
      }

      if (
        magic === 0xfeedface ||
        magic === 0xcefaedfe
      ) {
        return ['armv7']
      }
    } catch {}

    return []
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Android
  // ══════════════════════════════════════════════════════════════════════════

  private analyzeAndroid(): DetectedFrameworkEntry[] {
    const results: DetectedFrameworkEntry[] = []

    const sdkVersions =
      this.extractAndroidSdkVersions()

    results.push(
      ...this.parseAndroidNativeLibraries(
        sdkVersions
      )
    )

    results.push(
      ...this.parseAndroidPackages(
        sdkVersions
      )
    )

    return this.dedup(results)
  }

  private parseAndroidNativeLibraries(
    sdkVersions: Map<string, string>
  ): DetectedFrameworkEntry[] {
    const results: DetectedFrameworkEntry[] = []

    const soFiles = this.findFilesByExtension(
      this.extractPath,
      '.so'
    )

    const grouped = new Map<
      string,
      string[]
    >()

    for (const file of soFiles) {
      const rawName = path.basename(file)
        .replace(/^lib/i, '')
        .replace(/\.so$/i, '')

      const normalized =
        this.normalizeLibraryName(rawName)

      const abi = path.basename(
        path.dirname(file)
      )

      if (!grouped.has(normalized)) {
        grouped.set(normalized, [])
      }

      grouped
        .get(normalized)!
        .push(abi)
    }

    for (const [name, archs] of grouped.entries()) {
      const version =
        sdkVersions.get(
          name.toLowerCase()
        )

      results.push(
        this.buildEntry({
          name,
          version,
          relPath: name,
          source: 'NATIVE_LIB',
          archs: [...new Set(archs)],
        })
      )
    }

    return results
  }

  private parseAndroidPackages(
    sdkVersions: Map<string, string>
  ): DetectedFrameworkEntry[] {
    const results: DetectedFrameworkEntry[] = []

    const smaliFiles =
      this.findFilesByExtension(
        this.extractPath,
        '.smali'
      )

    const packages = new Set<string>()

    for (const file of smaliFiles) {
      try {
        const content =
          fs.readFileSync(
            file,
            'utf-8'
          )

        const matches = content.match(
          /L([a-zA-Z0-9/_$-]+);/g
        )

        if (!matches) {
          continue
        }

        for (const match of matches) {
          const cleaned = match
            .replace(/^L/, '')
            .replace(/;$/, '')
            .replace(/\//g, '.')

          const normalized =
            this.normalizePackageName(
              cleaned
            )

          if (
            this.isIgnoredPackage(
              normalized
            )
          ) {
            continue
          }

          packages.add(normalized)
        }
      } catch {}
    }

    for (const pkg of packages) {
      const version =
        sdkVersions.get(
          pkg.toLowerCase()
        )

      results.push(
        this.buildEntry({
          name: pkg,
          identifier: pkg,
          version,
          relPath: pkg,
          source: 'JAVA_PACKAGE',
        })
      )
    }

    return results
  }

  private extractAndroidSdkVersions():
  Map<string, string> {
    const versions = new Map<
      string,
      string
    >()

    const propertyFiles =
      this.findFilesByExtension(
        this.extractPath,
        '.properties'
      )

    for (const file of propertyFiles) {
      try {
        const content =
          fs.readFileSync(
            file,
            'utf-8'
          )

        const versionMatch =
          content.match(
            /version\s*=\s*([^\n]+)/i
          )

        if (!versionMatch) {
          continue
        }

        const rawName = path.basename(
          file,
          '.properties'
        )

        const normalized =
          this.normalizePackageName(
            rawName
          )

        versions.set(
          normalized.toLowerCase(),
          versionMatch[1].trim()
        )
      } catch {}
    }

    return versions
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Package normalization
  // ══════════════════════════════════════════════════════════════════════════

  private normalizePackageName(
    pkg: string
  ): string {
    const parts = pkg
      .split('.')
      .filter(Boolean)

    if (parts.length >= 3) {
      return parts
        .slice(0, 3)
        .join('.')
    }

    if (parts.length >= 2) {
      return parts
        .slice(0, 2)
        .join('.')
    }

    return pkg
  }

  private isIgnoredPackage(
    pkg: string
  ): boolean {
    return [
      'java.',
      'javax.',
      'kotlin.',
      'android.',
      'androidx.',
      'sun.',
      'org.intellij.',
    ].some(prefix =>
      pkg.startsWith(prefix)
    )
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Generic recursive discovery
  // ══════════════════════════════════════════════════════════════════════════

  private walk(
    dir: string,
    callback: (
      fullPath: string
    ) => void
  ): void {
    let entries: fs.Dirent[]

    try {
      entries = fs.readdirSync(dir, {
        withFileTypes: true,
      })
    } catch {
      return
    }

    for (const entry of entries) {
      const full = path.join(
        dir,
        entry.name
      )

      callback(full)

      if (entry.isDirectory()) {
        this.walk(full, callback)
      }
    }
  }

  private findDirectoriesByExtension(
    dir: string,
    extension: string
  ): string[] {
    const results: string[] = []

    this.walk(dir, full => {
      try {
        if (
          fs.statSync(full).isDirectory() &&
          full.endsWith(extension)
        ) {
          results.push(full)
        }
      } catch {}
    })

    return results
  }

  private findFilesByExtension(
    dir: string,
    extension: string
  ): string[] {
    const results: string[] = []

    this.walk(dir, full => {
      try {
        if (
          fs.statSync(full).isFile() &&
          full.endsWith(extension)
        ) {
          results.push(full)
        }
      } catch {}
    })

    return results
  }

  private findFilesByName(
    dir: string,
    filename: string
  ): string[] {
    const results: string[] = []

    this.walk(dir, full => {
      try {
        if (
          fs.statSync(full).isFile() &&
          path.basename(full) === filename
        ) {
          results.push(full)
        }
      } catch {}
    })

    return results
  }

  private findFilesRecursive(
    dir: string
  ): string[] {
    const results: string[] = []

    this.walk(dir, full => {
      try {
        if (
          fs.statSync(full).isFile()
        ) {
          results.push(full)
        }
      } catch {}
    })

    return results
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Shared
  // ══════════════════════════════════════════════════════════════════════════

  private normalizeLibraryName(
    name: string
  ): string {
    return name
      .replace(/_/g, '-')
      .replace(/\s+/g, '-')
      .trim()
  }

  private buildEntry(opts: {
    name: string
    identifier?: string
    version?: string
    relPath: string
    source: FrameworkSource
    archs?: string[]
    minOs?: string
  }): DetectedFrameworkEntry {
    const known = this.matchKnown(
      opts.name
    )

    return {
      name:
        known?.displayName ??
        this.prettifyName(
          opts.name
        ),

      version: opts.version,

      identifier:
        opts.identifier,

      source: opts.source,

      kind:
        known?.kind ??
        'UNKNOWN',

      vendor:
        known?.vendor,

      path: opts.relPath,

      architectures:
        opts.archs?.length
          ? [
              ...new Set(
                opts.archs
              ),
            ]
          : undefined,

      minOsVersion:
        opts.minOs,
    }
  }

  private matchKnown(
    name: string
  ): KnownFramework | undefined {
    return KNOWN_FRAMEWORKS.find(
      k =>
        k.pattern.test(name)
    )
  }

  private prettifyName(
    raw: string
  ): string {
    return raw
      .split(/[._/-]/)
      .filter(Boolean)
      .map(
        part =>
          part.charAt(0)
            .toUpperCase() +
          part.slice(1)
      )
      .join(' ')
  }

  private dedup(
    frameworks:
    DetectedFrameworkEntry[]
  ): DetectedFrameworkEntry[] {
    const seen =
      new Set<string>()

    return frameworks.filter(
      framework => {
        const key =
          (
            framework.identifier ||
            framework.name
          ).toLowerCase()

        if (seen.has(key)) {
          return false
        }

        seen.add(key)

        return true
      }
    )
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Summary
  // ══════════════════════════════════════════════════════════════════════════

  private buildSummary(
    frameworks:
    DetectedFrameworkEntry[]
  ): FrameworksSummary {
    const byKind:
    Record<
      FrameworkKind,
      string[]
    > = {
      UI: [],
      NETWORKING: [],
      DATABASE: [],
      ANALYTICS: [],
      SECURITY: [],
      MEDIA: [],
      MAPS: [],
      PAYMENTS: [],
      AUTH: [],
      PUSH: [],
      CRASH_REPORTING: [],
      AD: [],
      ML: [],
      STORAGE: [],
      CORE: [],
      TESTING: [],
      UNKNOWN: [],
    }

    const bySource:
    Record<
      FrameworkSource,
      number
    > = {
      BUNDLED: 0,
      SYSTEM: 0,
      NATIVE_LIB: 0,
      JAVA_PACKAGE: 0,
    }

    const vendors:
    Record<string, number> =
      {}

    for (const framework of frameworks) {
      byKind[
        framework.kind
      ].push(framework.name)

      bySource[
        framework.source
      ]++

      if (framework.vendor) {
        vendors[
          framework.vendor
        ] =
          (
            vendors[
              framework.vendor
            ] || 0
          ) + 1
      }
    }

    const topVendors =
      Object.entries(vendors)
        .sort(
          (a, b) =>
            b[1] - a[1]
        )
        .slice(0, 5)
        .map(
          ([vendor]) =>
            vendor
        )

    return {
      byKind,
      bySource,
      topVendors,
      hasPaymentSdk:
        byKind.PAYMENTS
          .length > 0,
      hasAnalyticsSdk:
        byKind.ANALYTICS
          .length > 0,
      hasAdSdk:
        byKind.AD.length >
        0,
      hasMlSdk:
        byKind.ML.length >
        0,
      hasAuthSdk:
        byKind.AUTH.length >
        0,
    }
  }
}