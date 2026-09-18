import { useState } from 'react'
import { analysisApi } from '../../services/api'

// ─── Types ────────────────────────────────────────────────────────────────────

interface SnapshotInfo {
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

interface BlutterFinding {
  type: 'api_endpoint' | 'hardcoded_string' | 'interesting_class' | 'crypto_usage' | 'authentication'
  value: string
  context?: string
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
}

interface BlutterClass {
  name: string
  library: string
  methods: string[]
  isInteresting: boolean
  interestingReason?: string
}

interface BlutterResult {
  available: boolean
  ran: boolean
  outputDir?: string
  totalClasses: number
  totalMethods: number
  packages: string[]
  interestingClasses: BlutterClass[]
  findings: BlutterFinding[]
  fridaScriptAvailable: boolean
  wasUpdated?: boolean
  error?: string
}

export interface FlutterAnalysis {
  isFlutter: boolean
  soFiles: string[]
  snapshotInfo?: SnapshotInfo
  canPatch: boolean
  blutter?: BlutterResult
  error?: string
}

interface Props {
  flutterAnalysis: FlutterAnalysis
  applicationId: number
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
}

const TYPE_LABEL: Record<string, string> = {
  api_endpoint:      'API Endpoint',
  authentication:    'Auth / Token',
  crypto_usage:      'Crypto',
  hardcoded_string:  'Hardcoded String',
  interesting_class: 'Interesting Class',
}

// ─── Snapshot section ──────────────────────────────────────────────────────────

function SnapshotSection({ analysis }: { analysis: FlutterAnalysis }) {
  const { snapshotInfo, soFiles, error } = analysis

  if (!snapshotInfo) {
    return (
      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-6">
        <div className="flex items-center gap-3">
          <span className="text-3xl">⚠️</span>
          <div>
            <p className="font-semibold text-yellow-300">Could not analyze Flutter snapshot</p>
            <p className="text-sm text-yellow-200/80 mt-1">{error || 'An error occurred during analysis'}</p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <span>📱</span><span>Framework Detection</span>
        </h3>
        <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 bg-gray-900/50 rounded-lg">
            <dt className="text-sm text-gray-400 mb-1">Operating System</dt>
            <dd className="font-semibold text-white">{snapshotInfo.os?.toUpperCase()}</dd>
          </div>
          <div className="p-4 bg-gray-900/50 rounded-lg">
            <dt className="text-sm text-gray-400 mb-1">.SO Files Found</dt>
            <dd className="font-semibold text-white">{soFiles?.length || 0}</dd>
          </div>
        </dl>
        {soFiles?.length > 0 && (
          <div className="mt-4">
            <p className="text-sm font-semibold text-gray-300 mb-2">Files:</p>
            <div className="space-y-1">
              {soFiles.map((file, i) => (
                <div key={i} className="text-sm font-mono text-gray-400 bg-gray-900/50 px-3 py-2 rounded">
                  📄 {file}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <span>🎯</span><span>Dart Snapshot</span>
        </h3>
        <dl className="space-y-3">
          <div className="p-4 bg-gradient-to-r from-purple-500/10 to-pink-500/10 rounded-lg border border-purple-500/30">
            <dt className="text-sm text-purple-400 mb-1">Snapshot Hash</dt>
            <dd className="font-mono text-sm text-white break-all">{snapshotInfo.hash}</dd>
          </div>
          {snapshotInfo.flags && snapshotInfo.flags.length > 0 && (
            <div className="p-4 bg-blue-500/10 rounded-lg border border-blue-500/30">
              <dt className="text-sm text-blue-400 mb-2">Snapshot Flags</dt>
              <dd className="flex flex-wrap gap-2">
                {snapshotInfo.flags.map((flag, i) => (
                  <span key={i} className="px-2 py-1 bg-blue-500/20 text-blue-300 text-xs rounded-full font-medium">
                    {flag}
                  </span>
                ))}
              </dd>
            </div>
          )}
        </dl>
      </div>

      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <span>⚙️</span><span>Compilation Mode</span>
        </h3>
        <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className={`p-4 rounded-lg ${
            snapshotInfo.compilationMode === 'AOT'
              ? 'bg-emerald-500/10 border border-emerald-500/30'
              : 'bg-yellow-500/10 border border-yellow-500/30'
          }`}>
            <dt className="text-sm text-gray-400 mb-1">Mode</dt>
            <dd className="font-bold text-2xl text-white">{snapshotInfo.compilationMode}</dd>
            <p className="text-xs text-gray-400 mt-2">
              {snapshotInfo.compilationMode === 'AOT'
                ? 'Ahead-of-Time Compilation (Production)'
                : 'Just-in-Time Compilation'}
            </p>
          </div>
          <div className="p-4 bg-gray-900/50 rounded-lg">
            <dt className="text-sm text-gray-400 mb-1">Evidence</dt>
            <dd className="text-sm text-white font-mono">
              {snapshotInfo.compilationMode === 'AOT'
                ? 'SnapshotInstructions symbol present'
                : 'Snapshot symbol detected'}
            </dd>
          </div>
        </dl>
      </div>

      <div className={`border-2 rounded-xl p-6 ${
        snapshotInfo.obfuscated
          ? 'bg-orange-500/10 border-orange-500/30'
          : 'bg-emerald-500/10 border-emerald-500/30'
      }`}>
        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <span>{snapshotInfo.obfuscated ? '🔒' : '🔓'}</span>
          <span>Code Obfuscation</span>
        </h3>
        <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 bg-gray-900/50 rounded-lg">
            <dt className="text-sm text-gray-400 mb-1">Status</dt>
            <dd className={`font-bold text-2xl ${snapshotInfo.obfuscated ? 'text-orange-400' : 'text-emerald-400'}`}>
              {snapshotInfo.obfuscated ? 'Enabled ✓' : 'Disabled ✗'}
            </dd>
          </div>
          <div className="p-4 bg-gray-900/50 rounded-lg">
            <dt className="text-sm text-gray-400 mb-1">Evidence</dt>
            <dd className="text-sm text-white">
              {snapshotInfo.obfuscated ? 'Very few Dart symbols exposed' : 'Dart symbols are visible'}
            </dd>
          </div>
        </dl>
        {snapshotInfo.obfuscated && (
          <div className="mt-4 p-4 bg-orange-500/10 border-l-4 border-orange-500 rounded">
            <p className="text-sm text-orange-200">
              <strong>⚠️ Warning:</strong> Code is obfuscated, making static analysis difficult.
              Blutter can still recover class/method names from the snapshot binary.
            </p>
          </div>
        )}
      </div>

      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <span>🎯</span><span>Dart SDK</span>
        </h3>
        <div className="p-4 bg-blue-500/10 rounded-lg border border-blue-500/30">
          <dt className="text-sm text-blue-400 mb-1">Dart Version</dt>
          <dd className="font-mono text-3xl font-bold text-white">{snapshotInfo.dartVersion}</dd>
        </div>
        {snapshotInfo.engineFingerprint && (
          <div className="mt-3 p-3 bg-gray-900/50 rounded-lg">
            <dt className="text-xs text-gray-500 mb-1">Engine Fingerprint</dt>
            <dd className="font-mono text-xs text-gray-400 break-all">{snapshotInfo.engineFingerprint}</dd>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Blutter section ──────────────────────────────────────────────────────────

function BlutterSection({ blutter, applicationId }: { blutter: BlutterResult; applicationId: number }) {
  const [activeFilter, setActiveFilter] = useState<string>('all')
  const [showAllPackages, setShowAllPackages] = useState(false)
  const [expandedClass, setExpandedClass] = useState<number | null>(null)

  if (!blutter.ran) {
    return (
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <h3 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
          <span>🔬</span><span>Blutter — Dart Reverse Engineering</span>
        </h3>
        <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
          <p className="text-sm font-semibold text-yellow-300">
            {blutter.available ? 'Blutter did not complete' : 'Blutter not available'}
          </p>
          {blutter.error && (
            <p className="text-xs text-yellow-200/70 mt-1 font-mono">{blutter.error}</p>
          )}
          {!blutter.available && (
            <p className="text-xs text-gray-400 mt-2">
              Missing container deps: <span className="font-mono">cmake ninja-build python3-pip</span>
            </p>
          )}
        </div>
      </div>
    )
  }

  const findingTypes = Array.from(new Set(blutter.findings.map(f => f.type)))
  const filteredFindings = activeFilter === 'all'
    ? blutter.findings
    : blutter.findings.filter(f => f.type === activeFilter)

  const highCount = blutter.findings.filter(f => f.severity === 'HIGH').length
  const mediumCount = blutter.findings.filter(f => f.severity === 'MEDIUM').length

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6 space-y-6">
      <div className="flex items-start justify-between">
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <span>🔬</span>
          <span>Blutter — Dart Reverse Engineering</span>
          {blutter.wasUpdated && (
            <span className="px-2 py-0.5 bg-cyan-500/20 text-cyan-400 text-xs rounded-full font-medium">
              Updated
            </span>
          )}
        </h3>
        <div className="flex gap-2 shrink-0">
          {blutter.fridaScriptAvailable && (
            <a
              href={`/api/v1/analysis/applications/${applicationId}/download-blutter-frida`}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-green-600/20 hover:bg-green-600/30 border border-green-600/40 text-green-400 rounded-lg text-xs font-medium transition"
              download
            >
              ⬇ Frida Script
            </a>
          )}
          <a
            href={`/api/v1/analysis/applications/${applicationId}/download-blutter`}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-600/40 text-cyan-400 rounded-lg text-xs font-medium transition"
            download
          >
            ⬇ Full Output
          </a>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3 bg-gray-900/60 rounded-lg text-center border border-gray-700/50">
          <p className="text-2xl font-bold text-cyan-400">{blutter.totalClasses.toLocaleString()}</p>
          <p className="text-xs text-gray-400 mt-1">Classes</p>
        </div>
        <div className="p-3 bg-gray-900/60 rounded-lg text-center border border-gray-700/50">
          <p className="text-2xl font-bold text-indigo-400">{blutter.totalMethods.toLocaleString()}</p>
          <p className="text-xs text-gray-400 mt-1">Methods</p>
        </div>
        <div className="p-3 bg-gray-900/60 rounded-lg text-center border border-gray-700/50">
          <p className="text-2xl font-bold text-purple-400">{blutter.packages?.length || 0}</p>
          <p className="text-xs text-gray-400 mt-1">Packages</p>
        </div>
        <div className="p-3 bg-gray-900/60 rounded-lg text-center border border-gray-700/50">
          <p className="text-2xl font-bold text-orange-400">{blutter.findings?.length || 0}</p>
          <p className="text-xs text-gray-400 mt-1">Findings</p>
          {(highCount > 0 || mediumCount > 0) && (
            <p className="text-xs mt-0.5">
              {highCount > 0 && <span className="text-red-400">{highCount}H </span>}
              {mediumCount > 0 && <span className="text-orange-400">{mediumCount}M</span>}
            </p>
          )}
        </div>
      </div>

      {blutter.findings?.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-sm font-semibold text-gray-300">Security Findings</h4>
            <div className="flex gap-1.5 flex-wrap justify-end">
              <button
                onClick={() => setActiveFilter('all')}
                className={`px-2 py-0.5 rounded text-xs font-medium transition ${
                  activeFilter === 'all' ? 'bg-gray-600 text-white' : 'bg-gray-700/50 text-gray-400 hover:bg-gray-700'
                }`}
              >
                All ({blutter.findings.length})
              </button>
              {findingTypes.map(type => (
                <button
                  key={type}
                  onClick={() => setActiveFilter(type)}
                  className={`px-2 py-0.5 rounded text-xs font-medium transition ${
                    activeFilter === type ? 'bg-gray-600 text-white' : 'bg-gray-700/50 text-gray-400 hover:bg-gray-700'
                  }`}
                >
                  {TYPE_LABEL[type] || type} ({blutter.findings.filter(f => f.type === type).length})
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
            {filteredFindings.map((f, i) => (
              <div key={i} className={`p-3 rounded-lg border text-sm ${SEVERITY_STYLES[f.severity] || SEVERITY_STYLES.INFO}`}>
                <div className="flex items-start gap-2 flex-wrap">
                  <span className={`px-1.5 py-0.5 rounded text-xs font-bold shrink-0 ${SEVERITY_BADGE[f.severity] || SEVERITY_BADGE.INFO}`}>
                    {f.severity}
                  </span>
                  <span className={`px-1.5 py-0.5 rounded text-xs font-medium shrink-0 ${TYPE_BADGE[f.type] || 'bg-gray-600/40 text-gray-400'}`}>
                    {TYPE_LABEL[f.type] || f.type}
                  </span>
                  <span className="font-mono text-white break-all">{f.value}</span>
                </div>
                {f.context && (
                  <p className="text-xs text-gray-400 mt-1 ml-1">{f.context}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {blutter.interestingClasses?.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-gray-300 mb-3">
            Security-Relevant Classes
            <span className="ml-2 px-2 py-0.5 bg-purple-500/20 text-purple-400 text-xs rounded-full">
              {blutter.interestingClasses.length}
            </span>
          </h4>

          <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
            {blutter.interestingClasses.map((cls, i) => (
              <div key={i} className="bg-gray-900/50 rounded-lg border border-gray-700 overflow-hidden">
                <button
                  className="w-full p-3 text-left flex items-center justify-between hover:bg-gray-800/50 transition"
                  onClick={() => setExpandedClass(expandedClass === i ? null : i)}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="font-mono text-sm font-semibold text-white truncate">{cls.name}</span>
                    {cls.interestingReason && (
                      <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 text-xs rounded-full shrink-0">
                        {cls.interestingReason}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 shrink-0 ml-2">
                    <span className="text-xs text-gray-500">{cls.methods?.length || 0} methods</span>
                    <span className="text-gray-500 text-xs">{expandedClass === i ? '▲' : '▼'}</span>
                  </div>
                </button>

                {expandedClass === i && (
                  <div className="px-3 pb-3 border-t border-gray-700/50">
                    <p className="text-xs text-gray-500 font-mono truncate mt-2 mb-2">{cls.library}</p>
                    {cls.methods?.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {cls.methods.map((m, j) => (
                          <span key={j} className="px-2 py-0.5 bg-gray-700/60 text-gray-300 text-xs rounded font-mono">
                            {m}()
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {blutter.packages?.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-gray-300 mb-3">
            Dart Packages
            <span className="ml-2 px-2 py-0.5 bg-gray-600/40 text-gray-400 text-xs rounded-full">
              {blutter.packages.length}
            </span>
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {(showAllPackages ? blutter.packages : blutter.packages.slice(0, 30)).map((pkg, i) => (
              <span key={i} className="px-2 py-1 bg-gray-900/60 border border-gray-700 text-gray-300 text-xs rounded font-mono">
                {pkg}
              </span>
            ))}
          </div>
          {blutter.packages.length > 30 && (
            <button
              onClick={() => setShowAllPackages(!showAllPackages)}
              className="mt-2 text-xs text-cyan-400 hover:text-cyan-300 transition"
            >
              {showAllPackages ? '▲ Show less' : `▼ Show ${blutter.packages.length - 30} more`}
            </button>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Action types ─────────────────────────────────────────────────────────────

type ActionStatus = 'idle' | 'loading' | 'success' | 'error'

interface ActionResult {
  message: string
  detail?: string
}

// ─── Actions panel ────────────────────────────────────────────────────────────

function ActionsPanel({
  applicationId,
  flutterAnalysis,
  onBlutterComplete,
}: {
  applicationId: number
  flutterAnalysis: FlutterAnalysis
  onBlutterComplete: () => void
}) {
  const [blutterStatus, setBlutterStatus] = useState<ActionStatus>('idle')
  const [reflutterStatus, setReflutterStatus] = useState<ActionStatus>('idle')
  const [offsetStatus, setOffsetStatus] = useState<ActionStatus>('idle')
  const [blutterResult, setBlutterResult] = useState<ActionResult | null>(null)
  const [reflutterResult, setReflutterResult] = useState<ActionResult | null>(null)
  const [offsetResult, setOffsetResult] = useState<ActionResult | null>(null)

  // IP de Burp para el modo "traffic" de ReFlutter — cada analista tiene la suya
  const [burpIp, setBurpIp] = useState('')

  const runBlutter = async () => {
    setBlutterStatus('loading')
    setBlutterResult(null)
    try {
      const res = await analysisApi.runBlutter(applicationId)
      const d = res.data
      if (d.ran) {
        setBlutterResult({
          message: `Completed — ${d.totalClasses} classes, ${d.totalMethods} methods, ${d.findings} findings`,
        })
        setBlutterStatus('success')
        onBlutterComplete()
      } else {
        setBlutterResult({ message: 'Blutter did not complete', detail: d.error })
        setBlutterStatus('error')
      }
    } catch (err: any) {
      setBlutterResult({ message: 'Request failed', detail: err.response?.data?.error || err.message })
      setBlutterStatus('error')
    }
  }

  const patchReFlutter = async () => {
    if (!burpIp.trim()) {
      setReflutterResult({ message: 'Burp IP is required' })
      setReflutterStatus('error')
      return
    }

    setReflutterStatus('loading')
    setReflutterResult(null)
    try {
      await analysisApi.patchReFlutter(applicationId, { burpIp: burpIp.trim(), mode: 'traffic' })
      setReflutterResult({ message: 'APK patched successfully' })
      setReflutterStatus('success')
    } catch (err: any) {
      setReflutterResult({ message: 'Patching failed', detail: err.response?.data?.detail || err.response?.data?.error || err.message })
      setReflutterStatus('error')
    }
  }

  const extractOffset = async () => {
    setOffsetStatus('loading')
    setOffsetResult(null)
    try {
      const res = await analysisApi.extractOffset(applicationId)
      const d = res.data
      setOffsetResult({
        message: `${d.totalHooks} hooks extracted — ${d.sslMethods?.length ?? 0} SSL, ${d.authMethods?.length ?? 0} Auth`,
      })
      setOffsetStatus('success')
    } catch (err: any) {
      const detail = err.response?.data?.detail || err.response?.data?.error || err.message
      setOffsetResult({ message: 'Extraction failed', detail })
      setOffsetStatus('error')
    }
  }

  const canReFlutter = flutterAnalysis.canPatch
  const blutterRan = flutterAnalysis.blutter?.ran

  const statusIcon = (s: ActionStatus) => {
    if (s === 'loading') return <span className="animate-spin inline-block">⏳</span>
    if (s === 'success') return <span className="text-emerald-400">✓</span>
    if (s === 'error') return <span className="text-red-400">✗</span>
    return null
  }

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
      <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
        <span>⚡</span><span>Actions</span>
      </h3>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

        {/* Run Blutter */}
        <div className="bg-gray-900/60 border border-gray-700 rounded-lg p-4 flex flex-col gap-3">
          <div>
            <p className="text-sm font-semibold text-white flex items-center gap-2">
              🔬 Run Blutter {statusIcon(blutterStatus)}
            </p>
            <p className="text-xs text-gray-400 mt-1">
              Deep Dart analysis — extracts classes, methods, secrets and generates Frida hooks
            </p>
          </div>
          <button
            onClick={runBlutter}
            disabled={blutterStatus === 'loading'}
            className="mt-auto w-full py-2 px-4 bg-cyan-600/20 hover:bg-cyan-600/30 disabled:opacity-50 disabled:cursor-not-allowed border border-cyan-600/40 text-cyan-400 rounded-lg text-sm font-medium transition"
          >
            {blutterStatus === 'loading' ? 'Running… (may take 20+ min)' : blutterRan ? 'Re-run Blutter' : 'Run Blutter'}
          </button>
          {blutterResult && (
            <div className={`text-xs rounded p-2 ${blutterStatus === 'success' ? 'bg-emerald-500/10 text-emerald-300' : 'bg-red-500/10 text-red-300'}`}>
              <p className="font-medium">{blutterResult.message}</p>
              {blutterResult.detail && <p className="mt-0.5 opacity-80 break-all">{blutterResult.detail}</p>}
            </div>
          )}
        </div>

        {/* Patch ReFlutter */}
        <div className="bg-gray-900/60 border border-gray-700 rounded-lg p-4 flex flex-col gap-3">
          <div>
            <p className="text-sm font-semibold text-white flex items-center gap-2">
              🩹 Patch with ReFlutter {statusIcon(reflutterStatus)}
            </p>
            <p className="text-xs text-gray-400 mt-1">
              Patches the APK to enable Dart debugging — allows intercepting traffic without SSL bypass
            </p>
            {!canReFlutter && (
              <p className="text-xs text-yellow-400/80 mt-1">⚠ Android APK required</p>
            )}
          </div>

          {/* Burp IP — requerida antes de patchear */}
          <input
            type="text"
            value={burpIp}
            onChange={e => setBurpIp(e.target.value)}
            placeholder="Burp IP (e.g. 192.168.1.154)"
            disabled={!canReFlutter || reflutterStatus === 'loading'}
            className="w-full px-3 py-1.5 bg-gray-950/60 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 disabled:opacity-40 focus:outline-none focus:border-purple-500/60"
          />

          <div className="mt-auto flex flex-col gap-2">
            <button
              onClick={patchReFlutter}
              disabled={!canReFlutter || reflutterStatus === 'loading'}
              className="w-full py-2 px-4 bg-purple-600/20 hover:bg-purple-600/30 disabled:opacity-40 disabled:cursor-not-allowed border border-purple-600/40 text-purple-400 rounded-lg text-sm font-medium transition"
            >
              {reflutterStatus === 'loading' ? 'Patching…' : 'Patch APK'}
            </button>
            {reflutterStatus === 'success' && (
              <a
                href={`/api/v1/analysis/applications/${applicationId}/download-patched`}
                className="w-full py-1.5 px-4 bg-green-600/20 hover:bg-green-600/30 border border-green-600/40 text-green-400 rounded-lg text-xs font-medium transition text-center"
                download
              >
                ⬇ Download Patched APK
              </a>
            )}
          </div>
          {reflutterResult && (
            <div className={`text-xs rounded p-2 ${reflutterStatus === 'success' ? 'bg-emerald-500/10 text-emerald-300' : 'bg-red-500/10 text-red-300'}`}>
              <p className="font-medium">{reflutterResult.message}</p>
              {reflutterResult.detail && <p className="mt-0.5 opacity-80">{reflutterResult.detail}</p>}
            </div>
          )}
        </div>

        {/* Extract Offset / Universal Script */}
        <div className="bg-gray-900/60 border border-gray-700 rounded-lg p-4 flex flex-col gap-3">
          <div>
            <p className="text-sm font-semibold text-white flex items-center gap-2">
              📍 Extract Offset {statusIcon(offsetStatus)}
            </p>
            <p className="text-xs text-gray-400 mt-1">
              Extracts method offsets and generates a universal Frida hook script — works when ReFlutter fails
            </p>
            {!blutterRan && (
              <p className="text-xs text-yellow-400/80 mt-1">⚠ Requires Blutter to run first</p>
            )}
          </div>
          <div className="mt-auto flex flex-col gap-2">
            <button
              onClick={extractOffset}
              disabled={!blutterRan || offsetStatus === 'loading'}
              className="w-full py-2 px-4 bg-orange-600/20 hover:bg-orange-600/30 disabled:opacity-40 disabled:cursor-not-allowed border border-orange-600/40 text-orange-400 rounded-lg text-sm font-medium transition"
            >
              {offsetStatus === 'loading' ? 'Extracting…' : 'Extract Offsets'}
            </button>
            {offsetStatus === 'success' && (
              <a
                href={`/api/v1/analysis/applications/${applicationId}/download-universal-hooks`}
                className="w-full py-1.5 px-4 bg-green-600/20 hover:bg-green-600/30 border border-green-600/40 text-green-400 rounded-lg text-xs font-medium transition text-center"
                download
              >
                ⬇ Download Hook Script
              </a>
            )}
          </div>
          {offsetResult && (
            <div className={`text-xs rounded p-2 ${offsetStatus === 'success' ? 'bg-emerald-500/10 text-emerald-300' : 'bg-red-500/10 text-red-300'}`}>
              <p className="font-medium">{offsetResult.message}</p>
              {offsetResult.detail && <p className="mt-0.5 opacity-80 break-all">{offsetResult.detail}</p>}
            </div>
          )}
        </div>

      </div>
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function FlutterTab({ flutterAnalysis, applicationId }: Props) {
  const [localAnalysis, setLocalAnalysis] = useState(flutterAnalysis)

  const handleBlutterComplete = async () => {
    try {
      const res = await analysisApi.getApp(applicationId)
      const updated = res.data?.analysis_result?.manifest_data?.flutter_analysis
      if (updated) setLocalAnalysis(updated)
    } catch {}
  }

  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-blue-500/10 to-indigo-500/10 border border-blue-500/30 rounded-xl p-6">
        <div className="flex items-center gap-3">
          <span className="text-4xl">🦋</span>
          <div>
            <h3 className="text-xl font-bold text-white">Flutter Detected</h3>
            <p className="text-sm text-gray-400">This application is built with Flutter Framework</p>
          </div>
        </div>
      </div>

      <ActionsPanel
        applicationId={applicationId}
        flutterAnalysis={localAnalysis}
        onBlutterComplete={handleBlutterComplete}
      />

      <SnapshotSection analysis={localAnalysis} />

      {localAnalysis.blutter ? (
        <BlutterSection blutter={localAnalysis.blutter} applicationId={applicationId} />
      ) : (
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
          <h3 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
            <span>🔬</span><span>Blutter — Dart Reverse Engineering</span>
          </h3>
          <div className="p-4 bg-gray-700/30 border border-gray-600/30 rounded-lg flex items-center gap-3">
            <span className="animate-pulse text-xl">⏳</span>
            <div>
              <p className="text-sm font-semibold text-gray-300">Pending</p>
              <p className="text-xs text-gray-500 mt-0.5">
                Use the "Run Blutter" button above, or wait for the automatic post-analysis run to complete.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}