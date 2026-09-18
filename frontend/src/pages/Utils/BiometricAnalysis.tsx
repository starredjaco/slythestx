import { Shield, Eye, Fingerprint, Mic, Brain, FileSearch, Layers, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react'
import { useState } from 'react'

// ─── Types (mirror del analyzer) ─────────────────────────────────────────────

type BiometricType =
  | 'FACE_ID' | 'FINGERPRINT' | 'IRIS' | 'VOICE'
  | 'BEHAVIOR' | 'LIVENESS' | 'DOCUMENT_SCAN' | 'MULTI_MODAL'

type FrameworkCategory =
  | 'NATIVE_OS' | 'THIRD_PARTY' | 'KYC'
  | 'COMMERCIAL' | 'CLOUD_API' | 'ENTERPRISE'
  | 'STANDARD' | 'HARDWARE'

type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW'

interface FrameworkEvidence {
  file: string
  line: number
  snippet: string
  matchedPattern: string
}

interface DetectedFramework {
  name: string
  version?: string
  vendor?: string
  biometricTypes: BiometricType[]
  platform: 'ANDROID' | 'IOS' | 'CROSS_PLATFORM'
  category: FrameworkCategory
  pricingModel?: 'FREE' | 'FREEMIUM' | 'COMMERCIAL' | 'ENTERPRISE' | 'OPEN_SOURCE'
  confidence: ConfidenceLevel
  reference?: string
  notes?: string
  evidence: FrameworkEvidence[]
  signalCount: number
}

interface AnalysisSummary {
  byCategory: Record<FrameworkCategory, string[]>
  totalFrameworks: number
  hasKycSdk: boolean
  hasCommercialSdk: boolean
  hasCloudApi: boolean
  hasEnterpriseGrade: boolean
  hasNativeOnly: boolean
}

interface FaceIdAnalysisResult {
  hasBiometrics: boolean
  detectedFrameworks: DetectedFramework[]
  biometricTypes: BiometricType[]
  scannedFiles: number
  summary: AnalysisSummary
}

// ─── Config maps ─────────────────────────────────────────────────────────────

const CATEGORY_META: Record<FrameworkCategory, { label: string; color: string; bg: string; border: string }> = {
  NATIVE_OS:   { label: 'Native OS',    color: 'text-blue-400',   bg: 'bg-blue-500/10',   border: 'border-blue-500/30' },
  HARDWARE:    { label: 'Hardware',     color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/30' },
  THIRD_PARTY: { label: 'Third Party',  color: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/30' },
  STANDARD:    { label: 'Standard',     color: 'text-cyan-400',   bg: 'bg-cyan-500/10',   border: 'border-cyan-500/30' },
  KYC:         { label: 'KYC',          color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30' },
  COMMERCIAL:  { label: 'Commercial',   color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30' },
  CLOUD_API:   { label: 'Cloud API',    color: 'text-sky-400',    bg: 'bg-sky-500/10',    border: 'border-sky-500/30' },
  ENTERPRISE:  { label: 'Enterprise',   color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/30' },
}

const BIOMETRIC_META: Record<BiometricType, { label: string; icon: React.ReactNode; color: string }> = {
  FACE_ID:       { label: 'Face ID',       icon: <Eye size={12} />,         color: 'text-blue-300 bg-blue-500/15 border-blue-500/25' },
  FINGERPRINT:   { label: 'Fingerprint',   icon: <Fingerprint size={12} />, color: 'text-green-300 bg-green-500/15 border-green-500/25' },
  IRIS:          { label: 'Iris',          icon: <Eye size={12} />,         color: 'text-purple-300 bg-purple-500/15 border-purple-500/25' },
  VOICE:         { label: 'Voice',         icon: <Mic size={12} />,         color: 'text-yellow-300 bg-yellow-500/15 border-yellow-500/25' },
  BEHAVIOR:      { label: 'Behavioral',    icon: <Brain size={12} />,       color: 'text-orange-300 bg-orange-500/15 border-orange-500/25' },
  LIVENESS:      { label: 'Liveness',      icon: <Shield size={12} />,      color: 'text-cyan-300 bg-cyan-500/15 border-cyan-500/25' },
  DOCUMENT_SCAN: { label: 'Document Scan', icon: <FileSearch size={12} />,  color: 'text-pink-300 bg-pink-500/15 border-pink-500/25' },
  MULTI_MODAL:   { label: 'Multi-Modal',   icon: <Layers size={12} />,      color: 'text-indigo-300 bg-indigo-500/15 border-indigo-500/25' },
}

const CONFIDENCE_META: Record<ConfidenceLevel, { label: string; color: string; dot: string }> = {
  HIGH:   { label: 'High',   color: 'text-green-400',  dot: 'bg-green-400' },
  MEDIUM: { label: 'Medium', color: 'text-yellow-400', dot: 'bg-yellow-400' },
  LOW:    { label: 'Low',    color: 'text-gray-500',   dot: 'bg-gray-500' },
}

const PRICING_META: Record<string, { label: string; color: string }> = {
  FREE:        { label: 'Free',        color: 'text-green-400 bg-green-500/10 border-green-500/20' },
  FREEMIUM:    { label: 'Freemium',    color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  OPEN_SOURCE: { label: 'Open Source', color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' },
  COMMERCIAL:  { label: 'Commercial',  color: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
  ENTERPRISE:  { label: 'Enterprise',  color: 'text-red-400 bg-red-500/10 border-red-500/20' },
}

const PLATFORM_LABEL: Record<string, string> = {
  ANDROID: 'Android',
  IOS: 'iOS',
  CROSS_PLATFORM: 'Cross-Platform',
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function BiometricTypeBadge({ type }: { type: BiometricType }) {
  const meta = BIOMETRIC_META[type]
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${meta.color}`}>
      {meta.icon}
      {meta.label}
    </span>
  )
}

function CategoryBadge({ category }: { category: FrameworkCategory }) {
  const meta = CATEGORY_META[category]
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded border text-xs font-semibold ${meta.color} ${meta.bg} ${meta.border}`}>
      {meta.label}
    </span>
  )
}

function ConfidenceDot({ level }: { level: ConfidenceLevel }) {
  const meta = CONFIDENCE_META[level]
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs ${meta.color}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${meta.dot}`} />
      {meta.label} confidence
    </span>
  )
}

function FrameworkCard({ framework }: { framework: DetectedFramework }) {
  const [expanded, setExpanded] = useState(false)
  const catMeta = CATEGORY_META[framework.category]
  const pricing = framework.pricingModel ? PRICING_META[framework.pricingModel] : null

  return (
    <div className={`rounded-lg border ${catMeta.border} bg-gray-800/50 overflow-hidden`}>
      {/* Header */}
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <CategoryBadge category={framework.category} />
              {pricing && (
                <span className={`inline-flex items-center px-2 py-0.5 rounded border text-xs font-medium ${pricing.color}`}>
                  {pricing.label}
                </span>
              )}
              <span className="text-xs text-gray-500">{PLATFORM_LABEL[framework.platform]}</span>
            </div>

            <div className="flex items-baseline gap-2">
              <h4 className="font-semibold text-white text-sm">{framework.name}</h4>
              {framework.version && (
                <span className="text-xs text-gray-500 font-mono">v{framework.version}</span>
              )}
            </div>

            {framework.vendor && (
              <p className="text-xs text-gray-500 mt-0.5">{framework.vendor}</p>
            )}
          </div>

          <div className="flex flex-col items-end gap-2 shrink-0">
            <ConfidenceDot level={framework.confidence} />
            <span className="text-xs text-gray-600">{framework.signalCount} signals</span>
          </div>
        </div>

        {/* Biometric types */}
        <div className="flex flex-wrap gap-1.5 mt-3">
          {framework.biometricTypes.map(t => (
            <BiometricTypeBadge key={t} type={t} />
          ))}
        </div>

        {/* Notes */}
        {framework.notes && (
          <p className="text-xs text-gray-400 mt-2 leading-relaxed">{framework.notes}</p>
        )}
      </div>

      {/* Evidence toggle */}
      {framework.evidence.length > 0 && (
        <>
          <button
            onClick={() => setExpanded(v => !v)}
            className="w-full flex items-center justify-between px-4 py-2 bg-gray-700/30 hover:bg-gray-700/50 transition-colors text-xs text-gray-400 hover:text-gray-300 border-t border-gray-700/50"
          >
            <span>{framework.evidence.length} evidence location{framework.evidence.length !== 1 ? 's' : ''}</span>
            <div className="flex items-center gap-2">
              {framework.reference && (
                <a
                  href={framework.reference}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={e => e.stopPropagation()}
                  className="text-blue-400 hover:text-blue-300 flex items-center gap-1"
                >
                  Docs <ExternalLink size={10} />
                </a>
              )}
              {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </div>
          </button>

          {expanded && (
            <div className="border-t border-gray-700/50 divide-y divide-gray-700/30">
              {framework.evidence.map((ev, i) => (
                <div key={i} className="px-4 py-3">
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="font-mono text-xs text-gray-400 truncate flex-1">{ev.file}</span>
                    <span className="text-xs text-gray-600 shrink-0">:{ev.line}</span>
                  </div>
                  <code className="block text-xs text-green-300/80 bg-gray-900/50 rounded px-2 py-1.5 font-mono overflow-x-auto whitespace-pre">
                    {ev.snippet}
                  </code>
                  <p className="text-xs text-gray-600 mt-1 font-mono">pattern: {ev.matchedPattern}</p>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function SummaryCard({ icon, label, value, active }: {
  icon: React.ReactNode
  label: string
  value: string | number
  active?: boolean
}) {
  return (
    <div className={`p-3 rounded-lg border ${active ? 'bg-blue-500/10 border-blue-500/30' : 'bg-gray-800/50 border-gray-700/50'}`}>
      <div className={`flex items-center gap-2 mb-1 ${active ? 'text-blue-400' : 'text-gray-400'}`}>
        {icon}
        <span className="text-xs">{label}</span>
      </div>
      <div className={`text-sm font-semibold ${active ? 'text-blue-300' : 'text-white'}`}>{value}</div>
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────
/** Comes from data.analysis_result.manifest_data.faceid_analysis */
interface BiometricAnalysisProps {

  analysis: FaceIdAnalysisResult | null | undefined
}

export function BiometricAnalysis({ analysis }: BiometricAnalysisProps) {
  const [filterCategory, setFilterCategory] = useState<FrameworkCategory | 'ALL'>('ALL')

  if (!analysis) {
    return (
      <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700/50 text-sm text-gray-500">
        No biometric analysis data available.
      </div>
    )
  }

  if (!analysis.hasBiometrics) {
    return (
      <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700/50 flex items-center gap-3">
        <Shield size={18} className="text-gray-600" />
        <div>
          <p className="text-sm text-gray-300">No biometric frameworks detected</p>
          <p className="text-xs text-gray-500 mt-0.5">{analysis.scannedFiles} files scanned</p>
        </div>
      </div>
    )
  }

  const { summary, detectedFrameworks, biometricTypes } = analysis

  // Active categories (those that have at least one detection)
  const activeCategories = (Object.keys(summary.byCategory) as FrameworkCategory[])
    .filter(c => summary.byCategory[c].length > 0)

  const filtered = filterCategory === 'ALL'
    ? detectedFrameworks
    : detectedFrameworks.filter(f => f.category === filterCategory)

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-bold text-white mb-4">Biometric &amp; FaceID Analysis</h3>

        {/* Summary cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
          <SummaryCard
            icon={<Layers size={14} />}
            label="Frameworks"
            value={summary.totalFrameworks}
            active
          />
          <SummaryCard
            icon={<FileSearch size={14} />}
            label="Files Scanned"
            value={analysis.scannedFiles}
          />
          <SummaryCard
            icon={<Eye size={14} />}
            label="KYC SDK"
            value={summary.hasKycSdk ? 'Detected' : 'None'}
            active={summary.hasKycSdk}
          />
          <SummaryCard
            icon={<Shield size={14} />}
            label="Enterprise Grade"
            value={summary.hasEnterpriseGrade ? 'Detected' : 'None'}
            active={summary.hasEnterpriseGrade}
          />
        </div>

        {/* Biometric types detected */}
        <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700/50 mb-6">
          <p className="text-xs text-gray-400 mb-2">Biometric capabilities present</p>
          <div className="flex flex-wrap gap-2">
            {biometricTypes.map(t => (
              <BiometricTypeBadge key={t} type={t} />
            ))}
          </div>
        </div>

        {/* Category breakdown */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-6">
          {activeCategories.map(cat => {
            const meta = CATEGORY_META[cat]
            const count = summary.byCategory[cat].length
            return (
              <div key={cat} className={`p-3 rounded-lg border ${meta.bg} ${meta.border}`}>
                <p className={`text-xs font-semibold ${meta.color}`}>{meta.label}</p>
                <p className="text-white font-bold text-lg">{count}</p>
                <p className="text-xs text-gray-500 truncate">
                  {summary.byCategory[cat].slice(0, 2).join(', ')}
                  {count > 2 ? ` +${count - 2}` : ''}
                </p>
              </div>
            )
          })}
        </div>

        {/* Filter tabs */}
        <div className="flex flex-wrap gap-2 mb-4">
          <button
            onClick={() => setFilterCategory('ALL')}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              filterCategory === 'ALL'
                ? 'bg-gray-600 text-white'
                : 'bg-gray-800/50 text-gray-400 hover:text-white border border-gray-700/50'
            }`}
          >
            All ({detectedFrameworks.length})
          </button>
          {activeCategories.map(cat => {
            const meta = CATEGORY_META[cat]
            const count = summary.byCategory[cat].length
            const isActive = filterCategory === cat
            return (
              <button
                key={cat}
                onClick={() => setFilterCategory(cat)}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors border ${
                  isActive
                    ? `${meta.bg} ${meta.color} ${meta.border}`
                    : 'bg-gray-800/50 text-gray-400 hover:text-white border-gray-700/50'
                }`}
              >
                {meta.label} ({count})
              </button>
            )
          })}
        </div>

        {/* Framework cards */}
        <div className="space-y-3">
          {filtered.map((fw, i) => (
            <FrameworkCard key={`${fw.name}-${i}`} framework={fw} />
          ))}
        </div>
      </div>
    </div>
  )
}