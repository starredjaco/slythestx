import { useState } from 'react'

interface MachoFinding {
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
  value: string
  context?: string
  binary?: string
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
}

interface MachoClass {
  name: string
  isInteresting: boolean
  interestingReason?: string
}

interface MachoBinaryInfo {
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

interface MachoInfoPlistSummary {
  bundleId?: string
  bundleExecutable?: string
  atsAllowsArbitraryLoads: boolean
  atsExceptionDomains: string[]
  urlSchemes: string[]
  backgroundModes: string[]
  usageDescriptions: Record<string, string>
}

export interface MachoAnalysis {
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

interface Props {
  machoAnalysis: MachoAnalysis
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, string> = {
  HIGH:   'bg-red-500/10 border-red-500/30',
  MEDIUM: 'bg-orange-500/10 border-orange-500/30',
  LOW:    'bg-blue-500/10 border-blue-500/30',
  INFO:   'bg-gray-700/40 border-gray-600/30',
}

const SEVERITY_BADGE: Record<string, string> = {
  HIGH:   'bg-red-500/20 text-red-400',
  MEDIUM: 'bg-orange-500/20 text-orange-400',
  LOW:    'bg-blue-500/20 text-blue-400',
  INFO:   'bg-gray-600/40 text-gray-400',
}

const TYPE_BADGE: Record<string, string> = {
  api_endpoint:      'bg-cyan-500/20 text-cyan-400',
  authentication:    'bg-red-500/20 text-red-400',
  crypto_usage:      'bg-yellow-500/20 text-yellow-400',
  hardcoded_string:  'bg-orange-500/20 text-orange-400',
  interesting_class: 'bg-purple-500/20 text-purple-400',
  anti_tampering:    'bg-indigo-500/20 text-indigo-400',
  entitlement_risk:  'bg-pink-500/20 text-pink-400',
  ats_misconfig:     'bg-red-500/20 text-red-400',
  url_scheme:        'bg-teal-500/20 text-teal-400',
  encryption:        'bg-gray-500/20 text-gray-300',
}

const TYPE_LABEL: Record<string, string> = {
  api_endpoint:      'API Endpoint',
  authentication:    'Auth / Token',
  crypto_usage:      'Crypto',
  hardcoded_string:  'Hardcoded String',
  interesting_class: 'Interesting Class',
  anti_tampering:    'Anti-Tampering',
  entitlement_risk:  'Entitlement Risk',
  ats_misconfig:     'ATS Misconfig',
  url_scheme:        'URL Scheme',
  encryption:        'Encryption',
}

const BINARY_TYPE_LABEL: Record<string, string> = {
  main_executable: 'Main Executable',
  framework: 'Framework',
  extension: 'Extension (.appex)',
  dylib: 'Dylib',
  other: 'Other',
}

const BINARY_TYPE_BADGE: Record<string, string> = {
  main_executable: 'bg-emerald-500/20 text-emerald-400',
  framework: 'bg-blue-500/20 text-blue-400',
  extension: 'bg-purple-500/20 text-purple-400',
  dylib: 'bg-gray-600/40 text-gray-400',
  other: 'bg-gray-600/40 text-gray-400',
}

// ─── Findings section (reusable) ──────────────────────────────────────────────

function FindingsSection({ findings, title = 'Security Findings' }: { findings: MachoFinding[]; title?: string }) {
  const [activeFilter, setActiveFilter] = useState<string>('all')

  if (!findings || findings.length === 0) return null

  const findingTypes = Array.from(new Set(findings.map(f => f.type)))
  const filtered = activeFilter === 'all' ? findings : findings.filter(f => f.type === activeFilter)

  return (
    <div>
      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
        <h4 className="text-sm font-semibold text-gray-300">{title}</h4>
        <div className="flex gap-1.5 flex-wrap justify-end">
          <button
            onClick={() => setActiveFilter('all')}
            className={`px-2 py-0.5 rounded text-xs font-medium transition ${
              activeFilter === 'all' ? 'bg-gray-600 text-white' : 'bg-gray-700/50 text-gray-400 hover:bg-gray-700'
            }`}
          >
            All ({findings.length})
          </button>
          {findingTypes.map(type => (
            <button
              key={type}
              onClick={() => setActiveFilter(type)}
              className={`px-2 py-0.5 rounded text-xs font-medium transition ${
                activeFilter === type ? 'bg-gray-600 text-white' : 'bg-gray-700/50 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {TYPE_LABEL[type] || type} ({findings.filter(f => f.type === type).length})
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
        {filtered.map((f, i) => (
          <div key={i} className={`p-3 rounded-lg border text-sm ${SEVERITY_STYLES[f.severity] || SEVERITY_STYLES.INFO}`}>
            <div className="flex items-start gap-2 flex-wrap">
              <span className={`px-1.5 py-0.5 rounded text-xs font-bold shrink-0 ${SEVERITY_BADGE[f.severity] || SEVERITY_BADGE.INFO}`}>
                {f.severity}
              </span>
              <span className={`px-1.5 py-0.5 rounded text-xs font-medium shrink-0 ${TYPE_BADGE[f.type] || 'bg-gray-600/40 text-gray-400'}`}>
                {TYPE_LABEL[f.type] || f.type}
              </span>
              {f.binary && (
                <span className="px-1.5 py-0.5 rounded text-xs font-mono shrink-0 bg-gray-900/60 text-gray-400">
                  {f.binary}
                </span>
              )}
              <span className="font-mono text-white break-all">{f.value}</span>
            </div>
            {f.context && <p className="text-xs text-gray-400 mt-1 ml-1">{f.context}</p>}
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Info.plist section ────────────────────────────────────────────────────────

function InfoPlistSection({ plist }: { plist: MachoInfoPlistSummary }) {
  const usageEntries = Object.entries(plist.usageDescriptions || {})

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6 space-y-4">
      <h3 className="text-lg font-bold text-white flex items-center gap-2">
        <span>📄</span><span>Info.plist</span>
      </h3>

      <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 bg-gray-900/50 rounded-lg">
          <dt className="text-sm text-gray-400 mb-1">Bundle ID</dt>
          <dd className="font-mono text-sm text-white break-all">{plist.bundleId || '—'}</dd>
        </div>
        <div className={`p-4 rounded-lg border ${
          plist.atsAllowsArbitraryLoads ? 'bg-red-500/10 border-red-500/30' : 'bg-emerald-500/10 border-emerald-500/30'
        }`}>
          <dt className="text-sm text-gray-400 mb-1">App Transport Security</dt>
          <dd className={`font-bold ${plist.atsAllowsArbitraryLoads ? 'text-red-400' : 'text-emerald-400'}`}>
            {plist.atsAllowsArbitraryLoads ? '⚠ Disabled globally (HTTP permitido)' : '✓ Enforced'}
          </dd>
        </div>
      </dl>

      {plist.atsExceptionDomains?.length > 0 && (
        <div>
          <p className="text-sm font-semibold text-gray-300 mb-2">ATS Exception Domains</p>
          <div className="flex flex-wrap gap-1.5">
            {plist.atsExceptionDomains.map((d, i) => (
              <span key={i} className="px-2 py-1 bg-orange-500/10 border border-orange-500/30 text-orange-300 text-xs rounded font-mono">
                {d}
              </span>
            ))}
          </div>
        </div>
      )}

      {plist.urlSchemes?.length > 0 && (
        <div>
          <p className="text-sm font-semibold text-gray-300 mb-2">Custom URL Schemes</p>
          <div className="flex flex-wrap gap-1.5">
            {plist.urlSchemes.map((s, i) => (
              <span key={i} className="px-2 py-1 bg-teal-500/10 border border-teal-500/30 text-teal-300 text-xs rounded font-mono">
                {s}://
              </span>
            ))}
          </div>
        </div>
      )}

      {plist.backgroundModes?.length > 0 && (
        <div>
          <p className="text-sm font-semibold text-gray-300 mb-2">Background Modes</p>
          <div className="flex flex-wrap gap-1.5">
            {plist.backgroundModes.map((m, i) => (
              <span key={i} className="px-2 py-1 bg-gray-900/60 border border-gray-700 text-gray-300 text-xs rounded font-mono">
                {m}
              </span>
            ))}
          </div>
        </div>
      )}

      {usageEntries.length > 0 && (
        <div>
          <p className="text-sm font-semibold text-gray-300 mb-2">Privacy Usage Descriptions</p>
          <div className="space-y-1">
            {usageEntries.map(([key, value]) => (
              <div key={key} className="text-sm bg-gray-900/50 px-3 py-2 rounded">
                <span className="font-mono text-xs text-gray-500">{key}</span>
                <p className="text-gray-300 mt-0.5">{value}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Binary list (expandable) ──────────────────────────────────────────────────

function BinariesSection({ binaries }: { binaries: MachoBinaryInfo[] }) {
  const [expanded, setExpanded] = useState<number | null>(null)

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
      <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
        <span>🔩</span><span>Mach-O Binaries</span>
        <span className="ml-1 px-2 py-0.5 bg-gray-600/40 text-gray-400 text-xs rounded-full">{binaries.length}</span>
      </h3>

      <div className="space-y-2 max-h-[32rem] overflow-y-auto pr-1">
        {binaries.map((bin, i) => (
          <div key={i} className="bg-gray-900/50 rounded-lg border border-gray-700 overflow-hidden">
            <button
              className="w-full p-3 text-left flex items-center justify-between hover:bg-gray-800/50 transition"
              onClick={() => setExpanded(expanded === i ? null : i)}
            >
              <div className="flex items-center gap-2 min-w-0 flex-wrap">
                <span className={`px-1.5 py-0.5 rounded text-xs font-medium shrink-0 ${BINARY_TYPE_BADGE[bin.binaryType]}`}>
                  {BINARY_TYPE_LABEL[bin.binaryType]}
                </span>
                <span className="font-mono text-sm font-semibold text-white truncate">{bin.name}</span>
                {bin.encrypted && (
                  <span className="px-1.5 py-0.5 bg-gray-700/60 text-gray-300 text-xs rounded-full shrink-0" title="FairPlay-encrypted — strings/ObjC dump incompleto">
                    🔒 encrypted
                  </span>
                )}
                {!bin.analyzed && (
                  <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 text-xs rounded-full shrink-0">error</span>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0 ml-2">
                <span className="text-xs text-gray-500">{bin.findings?.length || 0} findings</span>
                <span className="text-gray-500 text-xs">{expanded === i ? '▲' : '▼'}</span>
              </div>
            </button>

            {expanded === i && (
              <div className="px-3 pb-3 border-t border-gray-700/50 space-y-3">
                <p className="text-xs text-gray-500 font-mono truncate mt-2">{bin.relativePath}</p>

                <dl className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                  <div className="bg-gray-800/60 rounded p-2">
                    <dt className="text-gray-500">Arch</dt>
                    <dd className="text-white font-mono">{bin.architectures.join(', ') || '—'}</dd>
                  </div>
                  <div className="bg-gray-800/60 rounded p-2">
                    <dt className="text-gray-500">PIE</dt>
                    <dd className={bin.pie ? 'text-emerald-400' : 'text-orange-400'}>{bin.pie ? 'Yes' : 'No'}</dd>
                  </div>
                  <div className="bg-gray-800/60 rounded p-2">
                    <dt className="text-gray-500">Stack Protector</dt>
                    <dd className={bin.hasStackProtector ? 'text-emerald-400' : 'text-orange-400'}>
                      {bin.hasStackProtector ? 'Yes' : 'No'}
                    </dd>
                  </div>
                  <div className="bg-gray-800/60 rounded p-2">
                    <dt className="text-gray-500">Classes</dt>
                    <dd className="text-white">{bin.totalClasses.toLocaleString()}</dd>
                  </div>
                </dl>

                {bin.error && (
                  <p className="text-xs text-red-400 font-mono bg-red-500/10 border border-red-500/30 rounded p-2">
                    {bin.error}
                  </p>
                )}

                {bin.entitlements?.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-gray-400 mb-1">Entitlements ({bin.entitlements.length})</p>
                    <div className="flex flex-wrap gap-1">
                      {bin.entitlements.map((e, j) => {
                        const risky = bin.findings.some(f => f.type === 'entitlement_risk' && f.value === e.key)
                        return (
                          <span
                            key={j}
                            className={`px-2 py-0.5 text-xs rounded font-mono ${
                              risky ? 'bg-red-500/10 border border-red-500/30 text-red-300' : 'bg-gray-800/60 text-gray-400'
                            }`}
                          >
                            {e.key}
                          </span>
                        )
                      })}
                    </div>
                  </div>
                )}

                {bin.interestingClasses?.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-gray-400 mb-1">Interesting Classes ({bin.interestingClasses.length})</p>
                    <div className="flex flex-wrap gap-1">
                      {bin.interestingClasses.slice(0, 40).map((c, j) => (
                        <span key={j} className="px-2 py-0.5 bg-purple-500/10 border border-purple-500/30 text-purple-300 text-xs rounded font-mono">
                          {c.name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {bin.findings?.length > 0 && <FindingsSection findings={bin.findings} title="Findings" />}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

export default function MachoTab({ machoAnalysis }: Props) {
  if (!machoAnalysis) return null

  if (!machoAnalysis.isIOSApp) return null

  if (!machoAnalysis.available) {
    return (
      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-6">
        <div className="flex items-center gap-3">
          <span className="text-3xl">⚠️</span>
          <div>
            <p className="font-semibold text-yellow-300">ipsw not available</p>
            <p className="text-sm text-yellow-200/80 mt-1">{machoAnalysis.error || 'ipsw binary not found on the server'}</p>
          </div>
        </div>
      </div>
    )
  }

  if (!machoAnalysis.ran) {
    return (
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <h3 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
          <span>🔩</span><span>Mach-O Analysis</span>
        </h3>
        <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
          <p className="text-sm font-semibold text-yellow-300">Analysis did not complete</p>
          {machoAnalysis.error && <p className="text-xs text-yellow-200/70 mt-1 font-mono">{machoAnalysis.error}</p>}
        </div>
      </div>
    )
  }

  const highCount = machoAnalysis.aggregatedFindings.filter(f => f.severity === 'HIGH').length
  const mediumCount = machoAnalysis.aggregatedFindings.filter(f => f.severity === 'MEDIUM').length
  const encryptedCount = machoAnalysis.binaries.filter(b => b.encrypted).length

  return (
    <div className="space-y-6">
      {/* Header banner */}
      <div className="bg-gradient-to-r from-blue-500/10 to-cyan-500/10 border border-blue-500/30 rounded-xl p-6">
        <div className="flex items-center gap-3">
          <span className="text-4xl">🍎</span>
          <div>
            <h3 className="text-xl font-bold text-white">iOS Mach-O Analysis</h3>
            <p className="text-sm text-gray-400">Extracted via ipsw from the app bundle's binaries</p>
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3 bg-gray-900/60 rounded-lg text-center border border-gray-700/50">
          <p className="text-2xl font-bold text-cyan-400">{machoAnalysis.totalBinaries}</p>
          <p className="text-xs text-gray-400 mt-1">Binaries</p>
        </div>
        <div className="p-3 bg-gray-900/60 rounded-lg text-center border border-gray-700/50">
          <p className="text-2xl font-bold text-orange-400">{machoAnalysis.aggregatedFindings.length}</p>
          <p className="text-xs text-gray-400 mt-1">Findings</p>
          {(highCount > 0 || mediumCount > 0) && (
            <p className="text-xs mt-0.5">
              {highCount > 0 && <span className="text-red-400">{highCount}H </span>}
              {mediumCount > 0 && <span className="text-orange-400">{mediumCount}M</span>}
            </p>
          )}
        </div>
        <div className="p-3 bg-gray-900/60 rounded-lg text-center border border-gray-700/50">
          <p className="text-2xl font-bold text-gray-300">{encryptedCount}</p>
          <p className="text-xs text-gray-400 mt-1">Encrypted (FairPlay)</p>
        </div>
        <div className={`p-3 rounded-lg text-center border ${
          machoAnalysis.infoPlist?.atsAllowsArbitraryLoads
            ? 'bg-red-500/10 border-red-500/30'
            : 'bg-gray-900/60 border-gray-700/50'
        }`}>
          <p className={`text-2xl font-bold ${machoAnalysis.infoPlist?.atsAllowsArbitraryLoads ? 'text-red-400' : 'text-emerald-400'}`}>
            {machoAnalysis.infoPlist?.atsAllowsArbitraryLoads ? '⚠' : '✓'}
          </p>
          <p className="text-xs text-gray-400 mt-1">ATS</p>
        </div>
      </div>

      {/* Aggregated findings */}
      {machoAnalysis.aggregatedFindings.length > 0 && (
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
          <FindingsSection findings={machoAnalysis.aggregatedFindings} />
        </div>
      )}

      {/* Info.plist */}
      {machoAnalysis.infoPlist && <InfoPlistSection plist={machoAnalysis.infoPlist} />}

      {/* Binaries */}
      {machoAnalysis.binaries?.length > 0 && <BinariesSection binaries={machoAnalysis.binaries} />}
    </div>
  )
}
