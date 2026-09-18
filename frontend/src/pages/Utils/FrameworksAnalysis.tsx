import { useState, useMemo } from 'react'
import {
  Package, Wifi, Database, BarChart2, Shield, Film,
  Map, CreditCard, Lock, Bell, AlertTriangle, Megaphone,
  Brain, HardDrive, Cpu, FlaskConical, HelpCircle,
  ChevronDown, ChevronUp, Server, Search, SlidersHorizontal
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type FrameworkSource = 'BUNDLED' | 'SYSTEM' | 'NATIVE_LIB' | 'JAVA_PACKAGE'

type FrameworkKind =
  | 'UI' | 'NETWORKING' | 'DATABASE' | 'ANALYTICS' | 'SECURITY'
  | 'MEDIA' | 'MAPS' | 'PAYMENTS' | 'AUTH' | 'PUSH' | 'CRASH_REPORTING'
  | 'AD' | 'ML' | 'STORAGE' | 'CORE' | 'TESTING' | 'UNKNOWN'

interface DetectedFrameworkEntry {
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

interface FrameworksSummary {
  byKind: Record<FrameworkKind, string[]>
  bySource: Record<FrameworkSource, number>
  topVendors: string[]
  hasPaymentSdk: boolean
  hasAnalyticsSdk: boolean
  hasAdSdk: boolean
  hasMlSdk: boolean
  hasAuthSdk: boolean
}

interface FrameworksAnalysisResult {
  platform: 'ANDROID' | 'IOS'
  totalFrameworks: number
  frameworks: DetectedFrameworkEntry[]
  summary: FrameworksSummary
}

// ─── Config ───────────────────────────────────────────────────────────────────

const KIND_META: Record<FrameworkKind, {
  label: string
  icon: React.ReactNode
  color: string
  bg: string
  border: string
  dot: string
}> = {
  PAYMENTS:       { label: 'Payments',     icon: <CreditCard size={13} />,    color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/25', dot: 'bg-emerald-400' },
  AUTH:           { label: 'Auth',         icon: <Lock size={13} />,          color: 'text-indigo-400',  bg: 'bg-indigo-500/10',  border: 'border-indigo-500/25',  dot: 'bg-indigo-400' },
  ANALYTICS:      { label: 'Analytics',    icon: <BarChart2 size={13} />,     color: 'text-yellow-400',  bg: 'bg-yellow-500/10',  border: 'border-yellow-500/25',  dot: 'bg-yellow-400' },
  CRASH_REPORTING:{ label: 'Crash',        icon: <AlertTriangle size={13} />, color: 'text-red-400',     bg: 'bg-red-500/10',     border: 'border-red-500/25',     dot: 'bg-red-400' },
  AD:             { label: 'Ads',          icon: <Megaphone size={13} />,     color: 'text-rose-400',    bg: 'bg-rose-500/10',    border: 'border-rose-500/25',    dot: 'bg-rose-400' },
  SECURITY:       { label: 'Security',     icon: <Shield size={13} />,        color: 'text-green-400',   bg: 'bg-green-500/10',   border: 'border-green-500/25',   dot: 'bg-green-400' },
  ML:             { label: 'ML / AI',      icon: <Brain size={13} />,         color: 'text-violet-400',  bg: 'bg-violet-500/10',  border: 'border-violet-500/25',  dot: 'bg-violet-400' },
  NETWORKING:     { label: 'Networking',   icon: <Wifi size={13} />,          color: 'text-cyan-400',    bg: 'bg-cyan-500/10',    border: 'border-cyan-500/25',    dot: 'bg-cyan-400' },
  UI:             { label: 'UI',           icon: <Package size={13} />,       color: 'text-blue-400',    bg: 'bg-blue-500/10',    border: 'border-blue-500/25',    dot: 'bg-blue-400' },
  DATABASE:       { label: 'Database',     icon: <Database size={13} />,      color: 'text-purple-400',  bg: 'bg-purple-500/10',  border: 'border-purple-500/25',  dot: 'bg-purple-400' },
  PUSH:           { label: 'Push',         icon: <Bell size={13} />,          color: 'text-orange-400',  bg: 'bg-orange-500/10',  border: 'border-orange-500/25',  dot: 'bg-orange-400' },
  MAPS:           { label: 'Maps',         icon: <Map size={13} />,           color: 'text-teal-400',    bg: 'bg-teal-500/10',    border: 'border-teal-500/25',    dot: 'bg-teal-400' },
  MEDIA:          { label: 'Media',        icon: <Film size={13} />,          color: 'text-pink-400',    bg: 'bg-pink-500/10',    border: 'border-pink-500/25',    dot: 'bg-pink-400' },
  STORAGE:        { label: 'Storage',      icon: <HardDrive size={13} />,     color: 'text-sky-400',     bg: 'bg-sky-500/10',     border: 'border-sky-500/25',     dot: 'bg-sky-400' },
  CORE:           { label: 'Core',         icon: <Cpu size={13} />,           color: 'text-gray-400',    bg: 'bg-gray-500/10',    border: 'border-gray-600/25',    dot: 'bg-gray-400' },
  TESTING:        { label: 'Testing',      icon: <FlaskConical size={13} />,  color: 'text-lime-400',    bg: 'bg-lime-500/10',    border: 'border-lime-500/25',    dot: 'bg-lime-400' },
  UNKNOWN:        { label: 'Unknown',      icon: <HelpCircle size={13} />,    color: 'text-gray-600',    bg: 'bg-gray-700/20',    border: 'border-gray-700/30',    dot: 'bg-gray-600' },
}

const SOURCE_META: Record<FrameworkSource, { label: string; color: string; bg: string; border: string }> = {
  BUNDLED:      { label: 'Bundled',      color: 'text-blue-400',   bg: 'bg-blue-500/10',   border: 'border-blue-500/20' },
  NATIVE_LIB:   { label: 'Native (.so)', color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/20' },
  JAVA_PACKAGE: { label: 'Java/Kotlin',  color: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/20' },
  SYSTEM:       { label: 'System',       color: 'text-gray-400',   bg: 'bg-gray-500/10',   border: 'border-gray-500/20' },
}

const KIND_ORDER: FrameworkKind[] = [
  'PAYMENTS', 'AUTH', 'SECURITY', 'ANALYTICS', 'CRASH_REPORTING',
  'AD', 'ML', 'PUSH', 'NETWORKING', 'MAPS', 'DATABASE',
  'MEDIA', 'UI', 'STORAGE', 'CORE', 'TESTING', 'UNKNOWN',
]

// ─── Sub-components ───────────────────────────────────────────────────────────

function KindBadge({ kind }: { kind: FrameworkKind }) {
  const m = KIND_META[kind]
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-xs font-medium ${m.color} ${m.bg} ${m.border}`}>
      {m.icon}
      {m.label}
    </span>
  )
}

function SourceBadge({ source }: { source: FrameworkSource }) {
  const m = SOURCE_META[source]
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded border text-xs ${m.color} ${m.bg} ${m.border}`}>
      {m.label}
    </span>
  )
}

function ArchBadge({ arch }: { arch: string }) {
  return (
    <span className="px-1.5 py-0.5 rounded bg-gray-700/60 border border-gray-600/30 text-xs text-gray-400 font-mono">
      {arch}
    </span>
  )
}

function FrameworkRow({ fw }: { fw: DetectedFrameworkEntry }) {
  const [open, setOpen] = useState(false)
  const hasDetail = !!(fw.identifier || fw.architectures?.length || fw.minOsVersion || fw.path)

  return (
    <div className="border-b border-gray-700/30 last:border-0">
      <div
        className={`flex items-center gap-3 px-4 py-2.5 transition-colors ${hasDetail ? 'cursor-pointer hover:bg-gray-700/20' : ''}`}
        onClick={() => hasDetail && setOpen(v => !v)}
      >
        {/* Left: name + vendor */}
        <div className="flex-1 min-w-0">
          <div className="flex items-baseline gap-2 flex-wrap">
            <span className="text-sm text-white font-medium">{fw.name}</span>
            {fw.version && (
              <span className="font-mono text-xs text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded border border-blue-500/20">
                v{fw.version}
              </span>
            )}
          </div>
          {fw.vendor && (
            <span className="text-xs text-gray-500 mt-0.5 block">{fw.vendor}</span>
          )}
        </div>

        {/* Right: badges + toggle */}
        <div className="flex items-center gap-1.5 shrink-0 flex-wrap justify-end">
          <SourceBadge source={fw.source} />
          {fw.architectures?.map(a => <ArchBadge key={a} arch={a} />)}
          {hasDetail && (
            open
              ? <ChevronUp size={13} className="text-gray-500 ml-1" />
              : <ChevronDown size={13} className="text-gray-500 ml-1" />
          )}
        </div>
      </div>

      {open && hasDetail && (
        <div className="mx-4 mb-3 rounded-lg bg-gray-900/50 border border-gray-700/40 divide-y divide-gray-700/30">
          {fw.identifier && (
            <div className="flex items-start gap-3 px-3 py-2">
              <span className="text-xs text-gray-500 w-20 shrink-0 pt-0.5">Identifier</span>
              <span className="font-mono text-xs text-gray-300 break-all">{fw.identifier}</span>
            </div>
          )}
          {fw.minOsVersion && (
            <div className="flex items-center gap-3 px-3 py-2">
              <span className="text-xs text-gray-500 w-20 shrink-0">Min OS</span>
              <span className="text-xs text-gray-300">{fw.minOsVersion}</span>
            </div>
          )}
          {fw.path && (
            <div className="flex items-start gap-3 px-3 py-2">
              <span className="text-xs text-gray-500 w-20 shrink-0 pt-0.5">Path</span>
              <span className="font-mono text-xs text-gray-500 break-all">{fw.path}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function KindSection({
  kind,
  frameworks,
  defaultOpen,
}: {
  kind: FrameworkKind
  frameworks: DetectedFrameworkEntry[]
  defaultOpen: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  const m = KIND_META[kind]

  return (
    <div className={`rounded-lg border ${m.border} overflow-hidden`}>
      <button
        onClick={() => setOpen(v => !v)}
        className={`w-full flex items-center justify-between px-4 py-2.5 ${m.bg} transition-all`}
      >
        <div className="flex items-center gap-2">
          <span className={m.color}>{m.icon}</span>
          <span className={`text-sm font-semibold ${m.color}`}>{m.label}</span>
          <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${m.bg} ${m.color} border ${m.border}`}>
            {frameworks.length}
          </span>
        </div>
        {open
          ? <ChevronUp size={13} className={m.color} />
          : <ChevronDown size={13} className={m.color} />}
      </button>

      {open && (
        <div className="bg-gray-800/40">
          {frameworks.map((fw, i) => (
            <FrameworkRow key={`${fw.name}-${i}`} fw={fw} />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Main ─────────────────────────────────────────────────────────────────────

interface FrameworksAnalysisProps {

  analysis: FrameworksAnalysisResult | null | undefined
}

export function FrameworksAnalysis({ analysis }: FrameworksAnalysisProps) {
  const [search, setSearch] = useState('')
  const [filterKind, setFilterKind] = useState<FrameworkKind | 'ALL'>('ALL')
  const [filterSource, setFilterSource] = useState<FrameworkSource | 'ALL'>('ALL')
  const [showFilters, setShowFilters] = useState(false)

  if (!analysis) {
    return (
      <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700/50 text-sm text-gray-500">
        No framework analysis data available.
      </div>
    )
  }

  const { frameworks, summary, totalFrameworks, platform } = analysis

  
  const activeKinds = KIND_ORDER.filter(k => summary.byKind[k].length > 0)

  
  const filtered = useMemo(() => {
    return frameworks.filter(fw => {
      if (search) {
        const q = search.toLowerCase()
        const hit = fw.name.toLowerCase().includes(q)
          || fw.vendor?.toLowerCase().includes(q)
          || fw.identifier?.toLowerCase().includes(q)
          || fw.version?.toLowerCase().includes(q)
        if (!hit) return false
      }
      if (filterKind !== 'ALL' && fw.kind !== filterKind) return false
      if (filterSource !== 'ALL' && fw.source !== filterSource) return false
      return true
    })
  }, [frameworks, search, filterKind, filterSource])

  
  const byKind = useMemo(() => {
    return filtered.reduce<Partial<Record<FrameworkKind, DetectedFrameworkEntry[]>>>((acc, fw) => {
      if (!acc[fw.kind]) acc[fw.kind] = []
      acc[fw.kind]!.push(fw)
      return acc
    }, {})
  }, [filtered])

  const visibleKinds = KIND_ORDER.filter(k => (byKind[k]?.length ?? 0) > 0)

  const HIGH_PRIORITY: FrameworkKind[] = ['PAYMENTS', 'AUTH', 'AD', 'SECURITY', 'CRASH_REPORTING']

  const isFiltering = search || filterKind !== 'ALL' || filterSource !== 'ALL'

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white">
        Bundled Frameworks &amp; Libraries
        <span className="ml-2 text-sm font-normal text-gray-500">
          {platform === 'IOS' ? 'iOS' : 'Android'}
        </span>
      </h3>

      {/* ── Stat cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {/* Total */}
        <div className="p-3 bg-gray-800/50 rounded-lg border border-gray-700/50">
          <div className="flex items-center gap-1.5 mb-1 text-gray-400">
            <Package size={13} />
            <span className="text-xs">Total</span>
          </div>
          <div className="text-xl font-bold text-white">{totalFrameworks}</div>
        </div>

        {/* Payments */}
        <div className={`p-3 rounded-lg border ${summary.hasPaymentSdk
          ? 'bg-emerald-500/10 border-emerald-500/30'
          : 'bg-gray-800/50 border-gray-700/50'}`}>
          <div className={`flex items-center gap-1.5 mb-1 ${summary.hasPaymentSdk ? 'text-emerald-400' : 'text-gray-500'}`}>
            <CreditCard size={13} />
            <span className="text-xs">Payments</span>
          </div>
          <div className={`text-sm font-bold ${summary.hasPaymentSdk ? 'text-emerald-300' : 'text-gray-600'}`}>
            {summary.hasPaymentSdk
              ? `${summary.byKind.PAYMENTS.length} SDK${summary.byKind.PAYMENTS.length > 1 ? 's' : ''}`
              : 'None'}
          </div>
          {summary.hasPaymentSdk && (
            <div className="text-xs text-emerald-500 mt-0.5 truncate">
              {summary.byKind.PAYMENTS.slice(0, 2).join(', ')}
            </div>
          )}
        </div>

        {/* Ads */}
        <div className={`p-3 rounded-lg border ${summary.hasAdSdk
          ? 'bg-rose-500/10 border-rose-500/30'
          : 'bg-gray-800/50 border-gray-700/50'}`}>
          <div className={`flex items-center gap-1.5 mb-1 ${summary.hasAdSdk ? 'text-rose-400' : 'text-gray-500'}`}>
            <Megaphone size={13} />
            <span className="text-xs">Ad SDKs</span>
          </div>
          <div className={`text-sm font-bold ${summary.hasAdSdk ? 'text-rose-300' : 'text-gray-600'}`}>
            {summary.hasAdSdk
              ? `${summary.byKind.AD.length} SDK${summary.byKind.AD.length > 1 ? 's' : ''}`
              : 'None'}
          </div>
          {summary.hasAdSdk && (
            <div className="text-xs text-rose-500 mt-0.5 truncate">
              {summary.byKind.AD.slice(0, 2).join(', ')}
            </div>
          )}
        </div>

        {/* Analytics */}
        <div className={`p-3 rounded-lg border ${summary.hasAnalyticsSdk
          ? 'bg-yellow-500/10 border-yellow-500/30'
          : 'bg-gray-800/50 border-gray-700/50'}`}>
          <div className={`flex items-center gap-1.5 mb-1 ${summary.hasAnalyticsSdk ? 'text-yellow-400' : 'text-gray-500'}`}>
            <BarChart2 size={13} />
            <span className="text-xs">Analytics</span>
          </div>
          <div className={`text-sm font-bold ${summary.hasAnalyticsSdk ? 'text-yellow-300' : 'text-gray-600'}`}>
            {summary.hasAnalyticsSdk
              ? `${summary.byKind.ANALYTICS.length} SDK${summary.byKind.ANALYTICS.length > 1 ? 's' : ''}`
              : 'None'}
          </div>
          {summary.hasAnalyticsSdk && (
            <div className="text-xs text-yellow-600 mt-0.5 truncate">
              {summary.byKind.ANALYTICS.slice(0, 2).join(', ')}
            </div>
          )}
        </div>
      </div>

    
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* Sources */}
        <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700/50">
          <p className="text-xs text-gray-500 mb-3 flex items-center gap-1.5">
            <Server size={11} /> Source breakdown
          </p>
          <div className="space-y-2">
            {(Object.entries(summary.bySource) as [FrameworkSource, number][])
              .filter(([, count]) => count > 0)
              .sort((a, b) => b[1] - a[1])
              .map(([src, count]) => {
                const m = SOURCE_META[src]
                const pct = Math.round((count / totalFrameworks) * 100)
                return (
                  <div key={src}>
                    <div className="flex items-center justify-between mb-1">
                      <span className={`text-xs ${m.color}`}>{m.label}</span>
                      <span className="text-xs text-gray-400">{count} ({pct}%)</span>
                    </div>
                    <div className="h-1.5 bg-gray-700/50 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${m.bg} border-r ${m.border}`}
                        style={{ width: `${pct}%`, backgroundColor: 'currentColor', opacity: 0.6 }}
                      />
                    </div>
                  </div>
                )
              })}
          </div>
        </div>

        {/* Top vendors */}
        <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700/50">
          <p className="text-xs text-gray-500 mb-3">Top vendors</p>
          <div className="space-y-1.5">
            {summary.topVendors.length > 0
              ? summary.topVendors.map(v => (
                  <div key={v} className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-gray-500 shrink-0" />
                    <span className="text-sm text-gray-300">{v}</span>
                  </div>
                ))
              : <span className="text-xs text-gray-600">No vendor data</span>
            }
          </div>
        </div>
      </div>

      
      <div className="flex flex-wrap gap-2">
        {activeKinds.map(k => {
          const m = KIND_META[k]
          const count = summary.byKind[k].length
          return (
            <button
              key={k}
              onClick={() => setFilterKind(prev => prev === k ? 'ALL' : k)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-medium transition-all ${
                filterKind === k
                  ? `${m.color} ${m.bg} ${m.border} ring-1 ring-inset ring-current`
                  : `text-gray-400 bg-gray-800/50 border-gray-700/50 hover:${m.color} hover:${m.border}`
              }`}
            >
              {m.icon}
              {m.label}
              <span className={`px-1 rounded-full text-xs font-bold ${filterKind === k ? m.bg : 'bg-gray-700'}`}>
                {count}
              </span>
            </button>
          )
        })}
      </div>

    
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            placeholder="Search name, vendor, identifier…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-gray-500"
          />
        </div>
        <button
          onClick={() => setShowFilters(v => !v)}
          className={`flex items-center gap-1.5 px-3 py-2 rounded-lg border text-sm transition-colors ${
            showFilters || filterSource !== 'ALL'
              ? 'bg-blue-500/10 border-blue-500/30 text-blue-400'
              : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-white'
          }`}
        >
          <SlidersHorizontal size={13} />
          Filter
        </button>
      </div>

      {showFilters && (
        <div className="flex flex-wrap gap-2 p-3 bg-gray-800/50 rounded-lg border border-gray-700/50">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-gray-500">Source:</span>
            {(['ALL', 'BUNDLED', 'NATIVE_LIB', 'JAVA_PACKAGE', 'SYSTEM'] as const).map(s => (
              <button
                key={s}
                onClick={() => setFilterSource(s)}
                className={`px-2.5 py-1 rounded border text-xs transition-colors ${
                  filterSource === s
                    ? s === 'ALL'
                      ? 'bg-gray-600 text-white border-gray-500'
                      : `${SOURCE_META[s].color} ${SOURCE_META[s].bg} ${SOURCE_META[s].border}`
                    : 'text-gray-500 bg-gray-800 border-gray-700 hover:text-gray-300'
                }`}
              >
                {s === 'ALL' ? 'All' : SOURCE_META[s].label}
              </button>
            ))}
          </div>
          {isFiltering && (
            <button
              onClick={() => { setSearch(''); setFilterKind('ALL'); setFilterSource('ALL') }}
              className="ml-auto text-xs text-gray-500 hover:text-white underline"
            >
              Clear all
            </button>
          )}
        </div>
      )}

      
      {isFiltering && (
        <p className="text-xs text-gray-500">
          Showing {filtered.length} of {totalFrameworks} frameworks
        </p>
      )}

     
      {filtered.length === 0 ? (
        <div className="p-8 bg-gray-800/50 rounded-lg border border-gray-700/50 text-center">
          <HelpCircle size={24} className="text-gray-600 mx-auto mb-2" />
          <p className="text-sm text-gray-500">No frameworks match the current filters.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {visibleKinds.map(kind => (
            <KindSection
              key={kind}
              kind={kind}
              frameworks={byKind[kind]!}
              defaultOpen={HIGH_PRIORITY.includes(kind)}
            />
          ))}
        </div>
      )}
    </div>
  )
}
