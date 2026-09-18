import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { analysisApi } from '../services/api';
import FlutterTab from './Technologies/Flutter';
import { BiometricAnalysis } from './Utils/BiometricAnalysis'
import { FrameworksAnalysis } from './Utils/FrameworksAnalysis'
import MachoTab from './Utils/MachoAnalysis'

interface SecurityMeasure {
  type: string;
  detected: boolean;
  confidence: 'high' | 'medium' | 'low';
  evidence: string[];
  description: string;
  recommendation: string;
}

interface SecurityMeasureCardProps {
  measure: SecurityMeasure;
  icon: string;
  title: string;
}

const SecurityMeasureCard = ({ measure, icon, title }: SecurityMeasureCardProps) => {
  const parseEvidence = (evidenceItem: string) => {
    const match = evidenceItem.match(/^(.+?)\s+\((.+)\)$/);
    if (match) {
      return { pattern: match[1], path: match[2] };
    }
    return { pattern: evidenceItem, path: null };
  };

  return (
    <div
      className={`p-4 rounded-xl border-2 transition-all ${
        measure?.detected 
          ? 'bg-emerald-500/10 border-emerald-500/30' 
          : 'bg-gray-800/50 border-gray-700'
      } hover:shadow-lg`}
    >
      <div className="flex items-start gap-3">
        <span className="text-2xl">{icon}</span>
        <div className="flex-1">
          <div className="flex items-center justify-between mb-2">
            <h4 className="font-semibold text-white">{title}</h4>
            <span
              className={`px-2 py-1 rounded text-xs font-medium ${
                measure?.confidence === 'high'
                  ? 'bg-emerald-500/20 text-emerald-400'
                  : measure?.confidence === 'medium'
                  ? 'bg-yellow-500/20 text-yellow-400'
                  : 'bg-gray-500/20 text-gray-400'
              }`}
            >
              {measure?.confidence || 'low'}
            </span>
          </div>

          <p className="text-sm text-gray-400 mb-2">{measure?.description}</p>

          {measure?.evidence && measure.evidence.length > 0 && (
            <details className="mt-2">
              <summary className="cursor-pointer text-sm font-medium text-cyan-400 hover:text-cyan-300">
                View {measure.evidence.length} evidence item
                {measure.evidence.length > 1 ? 's' : ''}
              </summary>
              <div className="mt-2 space-y-1">
                {measure.evidence.slice(0, 10).map((item: string, idx: number) => {
                  const { pattern, path } = parseEvidence(item);
                  return (
                    <div key={idx} className="text-xs bg-gray-900 p-2 rounded border border-gray-700">
                      <div className="font-mono text-gray-200 font-semibold">{pattern}</div>
                      {path && (
                        <div className="font-mono text-gray-500 text-[10px] mt-1">📁 {path}</div>
                      )}
                    </div>
                  );
                })}
              </div>
            </details>
          )}

          <div
            className={`mt-3 p-2 rounded text-sm ${
              measure?.detected 
                ? 'bg-emerald-500/10 text-emerald-300' 
                : 'bg-orange-500/10 text-orange-300'
            }`}
          >
            💡 {measure?.recommendation}
          </div>
        </div>
      </div>
    </div>
  );
};

function CodeSnippet({ code, vulnerableLine }: { code: string; vulnerableLine?: number }) {
  const lines = code.split('\n');
  
  return (
    <div className="code-context">
      {lines.map((line, idx) => {

        const isVulnerable = line.startsWith('►') || line.includes('► ');
        const cleanLine = line.replace(/^►\s*/, '');
        
        const lineNumMatch = cleanLine.match(/^\s*(\d+)\s*│/);
        const lineNum = lineNumMatch ? lineNumMatch[1] : '';
        const codeContent = lineNumMatch 
          ? cleanLine.replace(/^\s*\d+\s*│\s?/, '') 
          : cleanLine;

        return (
          <div key={idx} className={`line ${isVulnerable ? 'vulnerable' : ''}`}>
            {lineNum && <span className="line-num">{lineNum}</span>}
            <span className="code">{codeContent}</span>
          </div>
        );
      })}
    </div>
  );
}


function groupVulnerabilitiesForDisplay(vulnerabilities: any[]): any[] {
  const grouped: Record<string, any> = {};

  for (const vuln of vulnerabilities) {
    const key = `${vuln.title}-${vuln.category}-${vuln.severity}`;

    if (!grouped[key]) {
      grouped[key] = {
        ...vuln,
        evidences: [],
        occurrences: 0,
      };
    }

    grouped[key].occurrences++;

    let existingEvidences: any[] = [];
    if (typeof vuln.evidences === 'string') {
      try {
        existingEvidences = JSON.parse(vuln.evidences);
      } catch {}
    } else if (Array.isArray(vuln.evidences)) {
      existingEvidences = vuln.evidences;
    }

    for (const ev of existingEvidences) {
      const evidenceKey = `${ev.filePath || ev.file_path || ''}-${ev.lineNumber || ev.line_number || ''}`;
      const exists = grouped[key].evidences.some(
        (e: any) =>
          `${e.filePath || e.file_path || ''}-${e.lineNumber || e.line_number || ''}` === evidenceKey
      );
      if (!exists && (ev.filePath || ev.file_path || ev.lineNumber || ev.line_number)) {
        grouped[key].evidences.push(ev);
      }
    }

    if (vuln.file_path || vuln.line_number || vuln.code_snippet) {
      const evidenceKey = `${vuln.file_path || ''}-${vuln.line_number || ''}`;
      const exists = grouped[key].evidences.some(
        (e: any) =>
          `${e.filePath || e.file_path || ''}-${e.lineNumber || e.line_number || ''}` === evidenceKey
      );
      if (!exists) {
        grouped[key].evidences.push({
          filePath: vuln.file_path,
          lineNumber: vuln.line_number,
          codeSnippet: vuln.code_snippet,
        });
      }
    }
  }

  const severityOrder: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };

  return Object.values(grouped).sort((a, b) => {
    const aOrder = severityOrder[a.severity?.toUpperCase()] ?? 5;
    const bOrder = severityOrder[b.severity?.toUpperCase()] ?? 5;
    return aOrder - bOrder;
  });
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [expandedSecrets, setExpandedSecrets] = useState<Set<string>>(new Set());
  const [expandedVulns, setExpandedVulns] = useState<Set<number | string>>(new Set());

  useEffect(() => {
    if (id) {
      loadAnalysis();
    }
  }, [id]);

  const loadAnalysis = async () => {
    try {
      const response = await analysisApi.getApp(Number(id));
      setData(response.data);
    } catch (err: any) {
      console.error('Error loading analysis:', err);
      setError(err.response?.data?.error || err.message || 'Failed to load analysis');
    } finally {
      setLoading(false);
    }
  };

  const toggleSecretExpand = (key: string) => {
    const newExpanded = new Set(expandedSecrets);
    if (newExpanded.has(key)) {
      newExpanded.delete(key);
    } else {
      newExpanded.add(key);
    }
    setExpandedSecrets(newExpanded);
  };

  const downloadBundle = async () => {
    try {
      window.open(`/api/v1/analysis/applications/${id}/download-bundle`, '_blank');
    } catch (error) {
      alert('Error downloading bundle');
    }
  };

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
      HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      INFO: 'bg-gray-500/20 text-gray-400 border-gray-500/30'
    };
    return colors[severity?.toUpperCase()] || 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-400';
    if (score >= 60) return 'text-yellow-400';
    return 'text-red-400';
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400">Loading analysis...</p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="w-20 h-20 bg-red-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
            <span className="text-4xl">❌</span>
          </div>
          <h2 className="text-2xl font-bold text-white mb-2">Error</h2>
          <p className="text-gray-400 mb-4">{error || 'Analysis not found'}</p>
          <Link to="/scans" className="text-cyan-400 hover:text-cyan-300 font-medium">
            ← Back to Scans
          </Link>
        </div>
      </div>
    );
  }

  const reactAnalysis = data.analysis_result?.manifest_data?.react_analysis;
  const hasReactAnalysis = reactAnalysis && reactAnalysis.isReactNative;
  
  const flutterAnalysis = data.analysis_result?.manifest_data?.flutter_analysis;
  const hasFlutterAnalysis = flutterAnalysis && flutterAnalysis.isFlutter;

  const cordovaAnalysis = data.analysis_result?.manifest_data?.cordova_analysis;
  const hasCordovaAnalysis = cordovaAnalysis && cordovaAnalysis.isCordova;
  
  const securityMeasures = data.analysis_result?.manifest_data?.security_measures;
  
  const xamarinAnalysis = data.analysis_result?.manifest_data?.xamarin_analysis;
  const hasXamarinAnalysis = !!xamarinAnalysis;

  const mauiAnalysis = data.analysis_result?.manifest_data?.maui_analysis;
  const hasMauiAnalysis = !!mauiAnalysis;
  
  const hasMachoAnalysis = data.application?.platform === 'IOS';

  const tabs = [
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '🔒' },
    { id: 'permissions', label: 'Permissions', icon: '🔑' },
    { id: 'deeplinks', label: 'Deep Links', icon: '🔗' },
    { id: 'components', label: 'Components', icon: '📦' },
    { id: 'secrets', label: 'Secrets', icon: '🔐' },
    { id: 'security', label: 'Security Measures', icon: '🛡️' },
  ];

  if (hasReactAnalysis) tabs.push({ id: 'react', label: 'React Native', icon: '⚛️' });
  if (hasFlutterAnalysis) tabs.push({ id: 'flutter', label: 'Flutter', icon: '🦋' });
  if (hasCordovaAnalysis) tabs.push({ id: 'cordova', label: 'Cordova', icon: '📱' });
  if (hasXamarinAnalysis) tabs.push({ id: 'xamarin', label: 'Xamarin', icon: '🎰' });
  if (hasMauiAnalysis) tabs.push({ id: 'maui', label: '.NET MAUI', icon: '🃏' });
  if (hasMachoAnalysis) tabs.push({ id: 'macho', label: 'iOS Binaries', icon: '🍎' });

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <Link 
          to="/scans"
          className="inline-flex items-center gap-2 text-cyan-400 hover:text-cyan-300 font-medium mb-4 transition"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Back to Scans
        </Link>
        <h1 className="text-3xl font-bold text-white">{data.application.name}</h1>
        <div className="flex flex-wrap gap-4 mt-2 text-gray-400">
          <span className={data.application.platform === 'ANDROID' ? 'text-green-400' : 'text-blue-400'}>
            {data.application.platform === 'ANDROID' ? '🤖' : '🍎'} {data.application.platform}
          </span>
          <span>⚙️ {data.application.technology}</span>
          {data.application.package_name && <span className="font-mono text-sm">📦 {data.application.package_name}</span>}
        </div>
      </div>

      {/* Security Score */}
      <div className="bg-[#12121a] rounded-2xl p-8 mb-8 text-center border border-gray-800">
        <div className="mb-4">
          <span className={`text-8xl font-bold ${getScoreColor(data.application.security_score || 0)}`}>
            {data.application.security_score || 0}
          </span>
          <span className="text-4xl text-gray-600">/100</span>
        </div>
        <p className="text-xl text-gray-400">Security Score</p>
        <p className="text-sm text-gray-500 mt-2">
          {data.application.security_score >= 80 ? 'Excellent security posture' :
           data.application.security_score >= 60 ? 'Acceptable security level' :
           'Security improvements needed'}
        </p>
      </div>

	  {/* Stats Grid */}
	<div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 mb-8 w-full">
	  
	  {/* Total Vulnerabilities */}
	  <div className="bg-[#12121a] rounded-xl p-6 border border-gray-800 flex flex-col justify-center">
	    <p className="text-sm text-gray-400 mb-2">Total Vulnerabilities</p>
	    <p className="text-3xl font-bold text-white leading-none">
	      {data.summary?.total_vulnerabilities || data.vulnerabilities?.length || 0}
	    </p>
	  </div>

	  {/* Critical */}
	  <div className="bg-red-500/10 rounded-xl p-6 border border-red-500/30 flex flex-col justify-center">
	    <p className="text-sm text-red-400 mb-2 font-semibold">Critical</p>
	    <p className="text-3xl font-bold text-red-400 leading-none">
	      {data.summary?.critical_vulnerabilities || 0}
	    </p>
	  </div>

	  {/* High */}
	  <div className="bg-orange-500/10 rounded-xl p-6 border border-orange-500/30 flex flex-col justify-center">
	    <p className="text-sm text-orange-400 mb-2 font-semibold">High</p>
	    <p className="text-3xl font-bold text-orange-400 leading-none">
	      {data.summary?.high_vulnerabilities || 0}
	    </p>
	  </div>

	  {/* Medium */}
	  <div className="bg-yellow-500/10 rounded-xl p-6 border border-yellow-500/30 flex flex-col justify-center">
	    <p className="text-sm text-yellow-400 mb-2 font-semibold">Medium</p>
	    <p className="text-3xl font-bold text-yellow-400 leading-none">
	      {data.summary?.medium_vulnerabilities || 0}
	    </p>
	  </div>

	  {/* Low */}
	  <div className="bg-blue-500/10 rounded-xl p-6 border border-blue-500/30 flex flex-col justify-center">
	    <p className="text-sm text-blue-400 mb-2 font-semibold">Low</p>
	    <p className="text-3xl font-bold text-blue-400 leading-none">
	      {data.summary?.low_vulnerabilities || 0}
	    </p>
	  </div>

	  {/* Info (Corregido 'grey' por 'gray' que es el estándar de Tailwind) */}
	  <div className="bg-gray-500/10 rounded-xl p-6 border border-gray-500/30 flex flex-col justify-center">
	    <p className="text-sm text-gray-400 mb-2 font-semibold">Info</p>
	    <p className="text-3xl font-bold text-gray-400 leading-none">
	      {data.summary?.info_vulnerabilities || 0}
	    </p>
	  </div>
	  
	</div>
      

      {/* Tabs */}
      <div className="bg-[#12121a] rounded-2xl border border-gray-800 overflow-hidden">
        <div className="border-b border-gray-800 overflow-x-auto">
          <div className="flex">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex-shrink-0 px-6 py-4 text-sm font-medium transition whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'border-b-2 border-cyan-500 text-cyan-400 bg-cyan-500/5'
                    : 'text-gray-400 hover:text-white hover:bg-white/5'
                }`}
              >
                <span className="mr-2">{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="p-6">
          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-white mb-4">Application Information</h3>
                <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 bg-gray-800/50 rounded-lg">
                    <dt className="text-sm text-gray-400 mb-1">Package Name</dt>
                    <dd className="font-mono text-sm text-white">{data.application.package_name || 'N/A'}</dd>
                  </div>
                  <div className="p-4 bg-gray-800/50 rounded-lg">
                    <dt className="text-sm text-gray-400 mb-1">Version</dt>
                    <dd className="font-semibold text-white">{data.application.version || 'N/A'}</dd>
                  </div>
                  <div className="p-4 bg-gray-800/50 rounded-lg">
                    <dt className="text-sm text-gray-400 mb-1">Filename</dt>
                    <dd className="font-mono text-sm text-white">{data.application.original_filename || 'N/A'}</dd>
                  </div>
                  <div className="p-4 bg-gray-800/50 rounded-lg">
                    <dt className="text-sm text-gray-400 mb-1">Analysis Date</dt>
                    <dd className="font-mono text-sm text-white">
                      {data.application.analyzed_at 
                        ? new Date(data.application.analyzed_at).toLocaleString()
                        : 'N/A'}
                    </dd>
                  </div>
                </dl>
              </div>
              <div><FrameworksAnalysis analysis={data.analysis_result?.manifest_data?.frameworks_analysis} /></div>
              <div><BiometricAnalysis analysis={data.analysis_result?.manifest_data?.faceid_analysis}/></div>

              {data.analysis_result && (
                <div>
                  <h3 className="text-lg font-bold text-white mb-4">Analysis Summary</h3>
                  <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="p-4 bg-blue-500/10 rounded-lg border border-blue-500/30">
                      <dt className="text-sm text-blue-400 mb-1">Total Permissions</dt>
                      <dd className="text-2xl font-bold text-white">
                        {data.analysis_result.total_permissions || 0}
                      </dd>
                    </div>
                    <div className="p-4 bg-red-500/10 rounded-lg border border-red-500/30">
                      <dt className="text-sm text-red-400 mb-1">Dangerous Permissions</dt>
                      <dd className="text-2xl font-bold text-white">
                        {data.analysis_result.dangerous_permissions_count || 0}
                      </dd>
                    </div>
                    <div className="p-4 bg-purple-500/10 rounded-lg border border-purple-500/30">
                      <dt className="text-sm text-purple-400 mb-1">Deep Links</dt>
                      <dd className="text-2xl font-bold text-white">
                        {data.analysis_result.manifest_data?.deeplinks?.length || 0}
                      </dd>
                    </div>
                    <div className="p-4 bg-emerald-500/10 rounded-lg border border-emerald-500/30">
                      <dt className="text-sm text-emerald-400 mb-1">Exported Components</dt>
                      <dd className="text-2xl font-bold text-white">
                        {data.analysis_result.manifest_data?.exportedComponents?.length || 0}
                      </dd>
                    </div>
                  </dl>
                </div>
              )}
            </div>
          )}

	{/* Vulnerabilities Tab */}
	{activeTab === 'vulnerabilities' && (
	  <div className="space-y-4 w-full">

	    {!data.vulnerabilities || data.vulnerabilities.length === 0 ? (
	      <div className="text-center py-12 px-4">
		<div className="text-6xl mb-4">🎉</div>
		<p className="text-xl font-semibold text-white mb-2">
		  No se encontraron vulnerabilidades
		</p>
		<p className="text-gray-400 break-words">
		  Esta aplicación parece estar libre de vulnerabilidades conocidas
		</p>
	      </div>
	    ) : (
	      (() => {
		const groupedVulns = groupVulnerabilitiesForDisplay(data.vulnerabilities);

		return groupedVulns.map((vuln: any, idx: number) => {
		  const evidences =
		    vuln.evidences ||
		    (vuln.file_path
		      ? [{ filePath: vuln.file_path, lineNumber: vuln.line_number, codeSnippet: vuln.code_snippet, contextHtml: vuln.context_html }]
		      : []);

		  return (
		    <div
		      key={vuln.id || idx}
		      className={`border rounded-xl p-4 sm:p-5 w-full overflow-hidden ${getSeverityColor(vuln.severity)}`}
		    >

		      {/* HEADER */}
		      <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
		        <h3 className="text-lg font-bold text-white flex-1 min-w-0 break-words">
		          {vuln.title}
		        </h3>

		        <div className="flex flex-wrap items-center gap-2 shrink-0">
		          {vuln.occurrences > 1 && (
		            <span className="px-2 py-1 bg-gray-700 text-gray-300 rounded-full text-xs whitespace-nowrap">
		              {vuln.occurrences} ocurrencias
		            </span>
		          )}

		          <span
		            className={`px-3 py-1 rounded-full text-xs font-medium border whitespace-nowrap ${getSeverityColor(vuln.severity)}`}
		          >
		            {vuln.severity}
		          </span>
		        </div>
		      </div>

		      {/* DESCRIPTION */}
		      <p className="text-gray-300 mb-3 whitespace-pre-wrap break-words leading-relaxed">
		        {vuln.description}
		      </p>

		      {/* EVIDENCES */}
		      {evidences.length > 0 && (
		        <details className="mb-3" open={evidences.length <= 3}>
		          <summary className="cursor-pointer text-sm font-semibold text-cyan-400 hover:text-cyan-300">
		            📍 {evidences.length} ubicación
		            {evidences.length !== 1 ? "es" : ""} encontrada
		            {evidences.length !== 1 ? "s" : ""}
		          </summary>

		          <div className="space-y-2 mt-3 max-h-96 overflow-y-auto">
		            {evidences
		              .slice(
		                0,
		                expandedVulns?.has(vuln.id || idx)
		                  ? evidences.length
		                  : 5
		              )
		              .map((evidence: any, i: number) => (
		                <div
		                  key={i}
		                  className="p-3 bg-gray-900/50 rounded border border-gray-700"
		                >
				{(evidence.filePath || evidence.file_path) && (
				  <div className="font-mono text-sm text-gray-200 mb-2 break-all">
				    📁 {evidence.filePath || evidence.file_path}
				  </div>
				)}
		                  {(evidence.contextHtml || evidence.context_html) ? (
		                   
		                    <div 
		                      className="code-context"
		                      dangerouslySetInnerHTML={{ 
		                        __html: evidence.contextHtml || evidence.context_html 
		                      }}
		                    />
		                  ) : (evidence.codeSnippet || evidence.code_snippet) ? (

		                    <CodeSnippet 
		                      code={evidence.codeSnippet || evidence.code_snippet}
		                      vulnerableLine={evidence.lineNumber || evidence.line_number}
		                    />
		                  ) : null}
		                </div>
		              ))}

		            {evidences.length > 5 && (
		              <button
		                onClick={() => {
		                  const newSet = new Set(expandedVulns || []);
		                  newSet.has(vuln.id || idx)
		                    ? newSet.delete(vuln.id || idx)
		                    : newSet.add(vuln.id || idx);
		                  setExpandedVulns(newSet);
		                }}
		                className="w-full py-2 px-4 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-gray-300 transition"
		              >
		                {expandedVulns?.has(vuln.id || idx)
		                  ? "▲ Mostrar menos"
		                  : `▼ Ver ${evidences.length - 5} más`}
		              </button>
		            )}
		          </div>
		        </details>
		      )}

		      {/* RECOMMENDATION */}
		      {vuln.recommendation && (
		        <div className="mt-4 p-4 bg-cyan-500/10 border-l-4 border-cyan-500 rounded">
		          <p className="text-sm font-semibold text-cyan-300 mb-1">
		            💡 Recomendación:
		          </p>
		          <p className="text-sm text-cyan-200 break-words">
		            {vuln.recommendation}
		          </p>
		        </div>
		      )}

		      {/* META */}
		      <div className="mt-4 flex flex-wrap gap-2 text-xs text-gray-500">
		        {vuln.category && (
		          <span className="px-2 py-1 bg-gray-800 rounded break-all">
		            Categoría: {vuln.category}
		          </span>
		        )}
		        {vuln.owasp_category && (
		          <span className="px-2 py-1 bg-gray-800 rounded break-all">
		            OWASP: {vuln.owasp_category}
		          </span>
		        )}
		      </div>
		    </div>
		  );
		});
	      })()
	    )}
	  </div>
	)}

          {/* Permissions Tab */}
          {activeTab === 'permissions' && (
            <div>
              {data.analysis_result?.permissions ? (
                <div className="space-y-6">
                  {data.analysis_result.permissions.dangerous_permissions?.length > 0 && (
                    <div>
                      <h3 className="text-lg font-bold text-red-400 mb-4 flex items-center gap-2">
                        <span>⚠️</span>
                        Dangerous Permissions ({data.analysis_result.permissions.dangerous_count || data.analysis_result.permissions.dangerous_permissions.length})
                      </h3>
                      <div className="space-y-3">
                        {data.analysis_result.permissions.dangerous_permissions.map((perm: any, i: number) => (
                          <div key={i} className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                            <div className="font-mono text-sm font-semibold text-red-300 mb-1">
                              {perm.name || perm}
                            </div>
                            {perm.description && (
                              <p className="text-sm text-red-200/70">{perm.description}</p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {data.analysis_result.permissions.normal_permissions?.length > 0 && (
                    <div>
                      <h3 className="text-lg font-bold text-white mb-4">
                        Normal Permissions ({data.analysis_result.permissions.normal_permissions.length})
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {data.analysis_result.permissions.normal_permissions.map((perm: any, i: number) => (
                          <div key={i} className="p-3 bg-gray-800/50 border border-gray-700 rounded-lg font-mono text-sm text-gray-300">
                            {perm.name || perm}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {(!data.analysis_result.permissions.dangerous_permissions || data.analysis_result.permissions.dangerous_permissions.length === 0) &&
                   (!data.analysis_result.permissions.normal_permissions || data.analysis_result.permissions.normal_permissions.length === 0) && (
                    <div className="text-center py-12">
                      <p className="text-gray-400">No permissions found</p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-12">
                  <p className="text-gray-400">No permission information available</p>
                </div>
              )}
            </div>
          )}

          {/* Deep Links Tab */}
          {activeTab === 'deeplinks' && (
            <div>
              {data.analysis_result?.manifest_data?.deeplinks && data.analysis_result.manifest_data.deeplinks.length > 0 ? (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                    <div className="p-4 bg-blue-500/10 rounded-lg border border-blue-500/30">
                      <div className="text-sm text-blue-400 mb-1">Total Deep Links</div>
                      <div className="text-2xl font-bold text-white">
                        {data.analysis_result.manifest_data.deeplinks.length}
                      </div>
                    </div>
                    <div className="p-4 bg-emerald-500/10 rounded-lg border border-emerald-500/30">
                      <div className="text-sm text-emerald-400 mb-1">App Links / Universal</div>
                      <div className="text-2xl font-bold text-white">
                        {data.analysis_result.manifest_data.deeplinks.filter((d: any) => 
                          d.type === 'app-link' || d.type === 'universal-link'
                        ).length}
                      </div>
                    </div>
                    <div className="p-4 bg-purple-500/10 rounded-lg border border-purple-500/30">
                      <div className="text-sm text-purple-400 mb-1">Custom Schemes</div>
                      <div className="text-2xl font-bold text-white">
                        {data.analysis_result.manifest_data.deeplinks.filter((d: any) => 
                          d.type === 'custom-scheme'
                        ).length}
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    {data.analysis_result.manifest_data.deeplinks.map((deeplink: any, i: number) => (
                      <div key={i} className="border border-gray-700 rounded-xl p-5 bg-gray-800/30 hover:bg-gray-800/50 transition">
                        <div className="flex justify-between items-start mb-3">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                              <span className="text-2xl">
                                {deeplink.type === 'app-link' || deeplink.type === 'universal-link' ? '🌐' : '🔗'}
                              </span>
                              <div>
                                <div className="font-mono text-lg font-semibold text-white">
                                  {deeplink.scheme}://{deeplink.host || ''}
                                  {deeplink.pathPrefix || ''}
                                </div>
                                <div className="text-sm text-gray-400 mt-1">
                                  {deeplink.type === 'app-link' && 'Android App Link (Verified)'}
                                  {deeplink.type === 'universal-link' && 'iOS Universal Link'}
                                  {deeplink.type === 'intent-filter' && 'Intent Filter (Unverified)'}
                                  {deeplink.type === 'custom-scheme' && 'Custom URL Scheme'}
                                </div>
                              </div>
                            </div>

                            {deeplink.autoVerify && (
                              <div className="inline-flex items-center gap-1 px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs rounded-full">
                                ✓ Auto-Verified
                              </div>
                            )}
                          </div>

                          <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                            deeplink.type === 'app-link' || deeplink.type === 'universal-link'
                              ? 'bg-emerald-500/20 text-emerald-400'
                              : 'bg-blue-500/20 text-blue-400'
                          }`}>
                            {deeplink.type.replace('-', ' ').toUpperCase()}
                          </span>
                        </div>

                        {deeplink.rawXml && (
                          <details className="mt-4">
                            <summary className="cursor-pointer text-sm font-semibold text-cyan-400 hover:text-cyan-300 mb-2">
                              📄 View configuration
                            </summary>
                            <div className="flex justify-end mb-2">
                              <button
                                onClick={() => navigator.clipboard.writeText(deeplink.rawXml)}
                                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
                              >
                                📋 Copy
                              </button>
                            </div>
                            <pre className="bg-gray-950 text-gray-100 p-4 rounded-lg text-xs overflow-x-auto max-h-96">
                              <code>{deeplink.rawXml}</code>
                            </pre>
                          </details>
                        )}

                        <div className="mt-4 p-3 bg-cyan-500/10 border-l-4 border-cyan-500 rounded">
                          <p className="text-sm text-cyan-200">
                            <strong>💡 Tip:</strong> {
                              deeplink.type === 'app-link' || deeplink.type === 'universal-link'
                                ? 'This link is verified and will open directly in the app without showing a selector.'
                                : 'This link can be intercepted by other apps. Consider using verified App Links for better security.'
                            }
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="text-center py-12">
                  <div className="w-20 h-20 bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-4">
                    <span className="text-4xl">🔗</span>
                  </div>
                  <p className="text-xl font-semibold text-white mb-2">
                    No Deep Links Found
                  </p>
                  <p className="text-gray-400">
                    This application has no URL schemes configured
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Components Tab */}
          {activeTab === 'components' && (
            <div>
              {data.analysis_result?.manifest_data?.exportedComponents && 
               data.analysis_result.manifest_data.exportedComponents.length > 0 ? (
                <div className="space-y-6">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                    {['activity', 'service', 'receiver', 'provider'].map(type => {
                      const count = data.analysis_result.manifest_data.exportedComponents.filter(
                        (c: any) => c.type === type
                      ).length;
                      const icon = {
                        activity: '📱',
                        service: '⚙️',
                        receiver: '📡',
                        provider: '🗄️'
                      }[type];
                      const label = {
                        activity: 'Activities',
                        service: 'Services',
                        receiver: 'Receivers',
                        provider: 'Providers'
                      }[type];

                      return (
                        <div key={type} className="p-4 bg-gray-800/50 border border-gray-700 rounded-lg">
                          <div className="text-2xl mb-2">{icon}</div>
                          <div className="text-sm text-gray-400">{label}</div>
                          <div className="text-2xl font-bold text-white">{count}</div>
                        </div>
                      );
                    })}
                  </div>

                  <div className="space-y-4">
                    {data.analysis_result.manifest_data.exportedComponents.map((component: any, i: number) => (
                      <div key={i} className="border border-gray-700 rounded-xl p-5 bg-gray-800/30">
                        <div className="flex justify-between items-start mb-3">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2">
                              <span className="text-xl">
                                {{
                                  activity: '📱',
                                  service: '⚙️',
                                  receiver: '📡',
                                  provider: '🗄️'
                                }[component.type]}
                              </span>
                              <h4 className="font-mono text-sm font-semibold text-white break-all">
                                {component.name}
                              </h4>
                            </div>

                            <div className="flex flex-wrap gap-2 mt-2">
                              <span className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded">
                                {component.type.toUpperCase()}
                              </span>
                              {component.exported && (
                                <span className="px-2 py-1 bg-orange-500/20 text-orange-400 text-xs rounded">
                                  ⚠️ EXPORTED
                                </span>
                              )}
                              {component.hasIntentFilter && (
                                <span className="px-2 py-1 bg-purple-500/20 text-purple-400 text-xs rounded">
                                  Has Intent Filter
                                </span>
                              )}
                              {component.permissions && component.permissions.length > 0 && (
                                <span className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs rounded">
                                  🔒 Protected
                                </span>
                              )}
                            </div>

                            {component.permissions && component.permissions.length > 0 && (
                              <div className="mt-3">
                                <div className="text-sm font-semibold text-gray-300 mb-1">Permissions:</div>
                                {component.permissions.map((perm: string, pi: number) => (
                                  <div key={pi} className="text-sm font-mono text-gray-400 ml-4">
                                    • {perm}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>

                        {component.rawXml && (
                          <details className="mt-4">
                            <summary className="cursor-pointer text-sm font-semibold text-cyan-400 hover:text-cyan-300 mb-2">
                              📄 View manifest declaration
                            </summary>
                            <div className="flex justify-end mb-2">
                              <button
                                onClick={() => navigator.clipboard.writeText(component.rawXml)}
                                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
                              >
                                📋 Copy
                              </button>
                            </div>
                            <pre className="bg-gray-950 text-gray-100 p-4 rounded-lg text-xs overflow-x-auto max-h-96">
                              <code>{component.rawXml}</code>
                            </pre>
                          </details>
                        )}

                        {component.exported && (!component.permissions || component.permissions.length === 0) && (
                          <div className="mt-4 p-3 bg-orange-500/10 border-l-4 border-orange-500 rounded">
                            <p className="text-sm text-orange-300">
                              <strong>⚠️ Warning:</strong> This component is exported without permission protection and can be accessed by any application.
                            </p>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="text-center py-12">
                  <div className="w-20 h-20 bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-4">
                    <span className="text-4xl">📦</span>
                  </div>
                  <p className="text-xl font-semibold text-white mb-2">
                    No Exported Components
                  </p>
                  <p className="text-gray-400">
                    All components are private
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Secrets Tab */}
          {activeTab === 'secrets' && (
            <div>
              {data.analysis_result?.secrets_found && 
               (data.analysis_result.secrets_found.summary?.total_findings > 0 || 
                data.analysis_result.secrets_found.summary?.total_secrets > 0) ? (
                <div className="space-y-6">
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                    <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-center">
                      <p className="text-sm text-red-400 mb-1">Critical</p>
                      <p className="text-3xl font-bold text-white">
                        {data.analysis_result.secrets_found.summary.by_severity?.critical || 0}
                      </p>
                    </div>
                    <div className="p-4 bg-orange-500/10 border border-orange-500/30 rounded-lg text-center">
                      <p className="text-sm text-orange-400 mb-1">High</p>
                      <p className="text-3xl font-bold text-white">
                        {data.analysis_result.secrets_found.summary.by_severity?.high || 0}
                      </p>
                    </div>
                    <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-center">
                      <p className="text-sm text-yellow-400 mb-1">Medium</p>
                      <p className="text-3xl font-bold text-white">
                        {data.analysis_result.secrets_found.summary.by_severity?.medium || 0}
                      </p>
                    </div>
                    <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg text-center">
                      <p className="text-sm text-blue-400 mb-1">Info</p>
                      <p className="text-3xl font-bold text-white">
                        {data.analysis_result.secrets_found.summary.by_severity?.info || 0}
                      </p>
                    </div>
                    <div className="p-4 bg-gray-800/50 border border-gray-700 rounded-lg text-center">
                      <p className="text-sm text-gray-400 mb-1">Total</p>
                      <p className="text-3xl font-bold text-white">
                        {data.analysis_result.secrets_found.summary.total_occurrences || 
                         data.analysis_result.secrets_found.summary.total_secrets || 0}
                      </p>
                    </div>
                  </div>

                  {data.analysis_result.secrets_found.findings && 
                   data.analysis_result.secrets_found.findings.length > 0 && (
                    <div className="space-y-4">
                      <h3 className="font-semibold text-lg text-white">Findings by Type</h3>
                      {data.analysis_result.secrets_found.findings.map((finding: any, idx: number) => (
                        <div 
                          key={idx} 
                          className={`border rounded-xl p-5 ${getSeverityColor(finding.severity)}`}
                        >
                          <div className="flex justify-between items-start mb-3">
                            <h4 className="font-bold text-white flex items-center gap-2">
                              <span>
                                {finding.type === 'url' ? '🌐' :
                                 finding.type === 'endpoint' ? '🔌' :
                                 finding.type === 'email' ? '📧' :
                                 finding.type === 'api_key' ? '🔑' :
                                 finding.type === 'jwt' ? '🎫' :
                                 finding.type === 'private_key' ? '🔐' :
                                 finding.type === 'database_url' ? '🗄️' :
                                 '🔍'}
                              </span>
                              <span className="capitalize">{finding.type.replace(/_/g, ' ')}</span>
                            </h4>
                            <div className="flex items-center gap-2">
                              <span className="px-3 py-1 bg-gray-700 text-gray-300 text-xs rounded-full font-medium">
                                {finding.count} found
                              </span>
                              <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                                {finding.severity}
                              </span>
                            </div>
                          </div>

                          {finding.samples && finding.samples.length > 0 && (
                            <div className="space-y-2">
                              {finding.samples.slice(0, expandedSecrets.has(`finding-${idx}`) ? finding.samples.length : 3).map((sample: any, i: number) => (
                                <div key={i} className="p-3 rounded-lg border bg-gray-900/50 border-gray-700">
                                  <code className="text-sm break-all block text-gray-200">{sample.value}</code>
                                  <p className="text-xs text-gray-500 mt-1">
                                    📁 {sample.file} : Line {sample.line}
                                  </p>
                                </div>
                              ))}
                              
                              {finding.samples.length > 3 && (
                                <button
                                  onClick={() => toggleSecretExpand(`finding-${idx}`)}
                                  className="w-full py-2 px-4 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm font-medium text-gray-300 transition"
                                >
                                  {expandedSecrets.has(`finding-${idx}`) 
                                    ? '▲ Show less' 
                                    : `▼ View ${finding.samples.length - 3} more (${finding.count} total)`}
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-12">
                  <div className="w-20 h-20 bg-emerald-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                    <span className="text-4xl">🔐</span>
                  </div>
                  <p className="text-xl font-semibold text-white mb-2">
                    No Secrets Found
                  </p>
                  <p className="text-gray-400">
                    No API keys, tokens or other secrets detected in the code
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Security Measures Tab */}
          {activeTab === 'security' && (
            <div className="space-y-6">
              <div className={`rounded-xl p-6 border-2 ${
                securityMeasures?.summary?.securityLevel === 'excellent' ? 'bg-emerald-500/10 border-emerald-500/30' :
                securityMeasures?.summary?.securityLevel === 'good' ? 'bg-blue-500/10 border-blue-500/30' :
                securityMeasures?.summary?.securityLevel === 'fair' ? 'bg-yellow-500/10 border-yellow-500/30' :
                'bg-red-500/10 border-red-500/30'
              }`}>
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <span className="text-5xl">🛡️</span>
                    <div>
                      <h3 className="text-2xl font-bold text-white">Security Measures</h3>
                      <p className="text-sm text-gray-400 mt-1">
                        Defensive mechanisms implemented in the application
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`text-4xl font-bold ${
                      securityMeasures?.summary?.securityLevel === 'excellent' ? 'text-emerald-400' :
                      securityMeasures?.summary?.securityLevel === 'good' ? 'text-blue-400' :
                      securityMeasures?.summary?.securityLevel === 'fair' ? 'text-yellow-400' :
                      'text-red-400'
                    }`}>
                      {securityMeasures?.summary?.implementedMeasures || 0}/{securityMeasures?.summary?.totalMeasures || 9}
                    </div>
                    <div className="text-sm font-semibold mt-1 uppercase text-gray-400">
                      {securityMeasures?.summary?.securityLevel || 'poor'}
                    </div>
                  </div>
                </div>

                <div className="mt-4">
                  <div className="flex justify-between text-sm text-gray-400 mb-2">
                    <span>Implementation Progress</span>
                    <span>{Math.round(((securityMeasures?.summary?.implementedMeasures || 0) / (securityMeasures?.summary?.totalMeasures || 9)) * 100)}%</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-3 overflow-hidden">
                    <div 
                      className={`h-3 rounded-full transition-all duration-500 ${
                        securityMeasures?.summary?.securityLevel === 'excellent' ? 'bg-emerald-500' :
                        securityMeasures?.summary?.securityLevel === 'good' ? 'bg-blue-500' :
                        securityMeasures?.summary?.securityLevel === 'fair' ? 'bg-yellow-500' :
                        'bg-red-500'
                      }`}
                      style={{ width: `${((securityMeasures?.summary?.implementedMeasures || 0) / (securityMeasures?.summary?.totalMeasures || 9)) * 100}%` }}
                    />
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <SecurityMeasureCard
                  measure={securityMeasures?.rootJailbreakDetection}
                  icon="🔒"
                  title={data.application.platform === 'ANDROID' ? 'Root Detection' : 'Jailbreak Detection'}
                />

                <SecurityMeasureCard
                  measure={securityMeasures?.emulatorDetection}
                  icon="💻"
                  title="Emulator/Simulator Detection"
                />

                <SecurityMeasureCard
                  measure={securityMeasures?.sslPinning}
                  icon="🔐"
                  title="SSL Pinning"
                />

                <SecurityMeasureCard
                  measure={securityMeasures?.certificateTransparency}
                  icon="📜"
                  title="Certificate Transparency"
                />

                <SecurityMeasureCard
                  measure={securityMeasures?.developerModeDetection}
                  icon="⚙️"
                  title="Developer Mode Detection"
                />

                <SecurityMeasureCard
                  measure={securityMeasures?.usbDebuggingDetection}
                  icon="🔌"
                  title="USB Debugging Detection"
                />

                <SecurityMeasureCard
                  measure={securityMeasures?.antiTampering}
                  icon="🛡️"
                  title="Anti-Tampering"
                />

                <SecurityMeasureCard
                  measure={securityMeasures?.rasp}
                  icon="🚨"
                  title="RASP Protection"
                />

                <SecurityMeasureCard
                  measure={securityMeasures?.obfuscation}
                  icon="🎭"
                  title="Code Obfuscation"
                />
              </div>

              <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-lg p-4">
                <p className="text-sm text-cyan-200">
                  <strong>ℹ️ About Security Measures:</strong> These are defensive mechanisms that help protect the app against 
                  reverse engineering, tampering, and runtime attacks. More implemented measures indicate better security posture.
                </p>
              </div>
            </div>
          )}

          {/* React Native Tab */}
          {activeTab === 'react' && hasReactAnalysis && (
            <div className="space-y-6">
              <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <span className="text-4xl">⚛️</span>
                  <div>
                    <h3 className="text-xl font-bold text-white">React Native Detected</h3>
                    <p className="text-sm text-gray-400">
                      This application is built with React Native Framework
                    </p>
                  </div>
                </div>
              </div>

              {reactAnalysis.hasHermes ? (
                <div className="bg-orange-500/10 border-2 border-orange-500/30 rounded-xl p-6">
                  <div className="flex items-start gap-4 mb-6">
                    <div className="text-5xl">⚠️</div>
                    <div className="flex-1">
                      <h3 className="text-2xl font-bold text-orange-300 mb-2">
                        Hermes Bytecode Detected
                      </h3>
                      <p className="text-orange-200 mb-4">
                        {reactAnalysis.hermesInfo?.message || 'This bundle is compiled with Hermes'}
                      </p>
                      <div className="p-4 bg-gray-900/50 rounded-lg border border-orange-500/30">
                        <p className="font-semibold text-orange-300 mb-3">🛠️ Recommended Tools:</p>
                        <ul className="space-y-2">
                          {(reactAnalysis.hermesInfo?.tools || []).map((tool: string, i: number) => (
                            <li key={i} className="flex items-start gap-2 text-sm">
                              <span className="text-orange-400 mt-0.5">▸</span>
                              <span className="text-gray-300 font-mono">{tool}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>

                  {reactAnalysis.bundleFile && (
                    <div className="mt-6">
                      <button
                        onClick={downloadBundle}
                        className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition flex items-center justify-center gap-2"
                      >
                        <span>📥</span>
                        <span>Download Hermes Bundle</span>
                      </button>
                      <p className="text-sm text-gray-400 mt-3 text-center">
                        Download the bundle to analyze it with Hermes decompilation tools
                      </p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="space-y-6">
                  <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                    <h3 className="text-lg font-bold text-white mb-4">📦 Bundle Information</h3>
                    <dl className="grid grid-cols-2 md:grid-cols-3 gap-4">
                      <div className="p-3 bg-gray-900/50 rounded-lg">
                        <dt className="text-sm text-gray-400 mb-1">Total Lines</dt>
                        <dd className="text-2xl font-bold text-white">
                          {reactAnalysis.totalLines?.toLocaleString() || 0}
                        </dd>
                      </div>
                      <div className="p-3 bg-gray-900/50 rounded-lg">
                        <dt className="text-sm text-gray-400 mb-1">Minified</dt>
                        <dd className="text-2xl font-bold text-white">
                          {reactAnalysis.minified ? '✓ Yes' : '✗ No'}
                        </dd>
                      </div>
                      <div className="p-3 bg-gray-900/50 rounded-lg">
                        <dt className="text-sm text-gray-400 mb-1">JS Files</dt>
                        <dd className="text-2xl font-bold text-white">
                          {reactAnalysis.jsFiles || 1}
                        </dd>
                      </div>
                    </dl>
                  </div>

                  {reactAnalysis.bundleFile && (
                    <div className="bg-gradient-to-r from-blue-500/10 to-indigo-500/10 border border-blue-500/30 rounded-xl p-6">
                      <div className="flex items-start gap-4">
                        <div className="text-4xl">📦</div>
                        <div className="flex-1">
                          <h3 className="text-xl font-bold text-white mb-2">Download Bundle</h3>
                          <p className="text-sm text-gray-400 mb-4">
                            Download the React Native bundle for offline analysis or advanced decompilation.
                          </p>
                          <button
                            onClick={downloadBundle}
                            className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition flex items-center gap-2"
                          >
                            <span>📥</span>
                            <span>Download JavaScript Bundle</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-lg p-4">
                    <p className="text-sm text-cyan-200">
                      <strong>ℹ️ Note:</strong> This analysis was performed on the React Native JavaScript bundle. 
                      Detected secrets are available in the <strong>Secrets</strong> tab with full file details.
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Xamarin Tab */}
          {activeTab === 'xamarin' && hasXamarinAnalysis && (
            <div className="space-y-6">
              <div className="bg-gradient-to-r from-purple-500/10 to-indigo-500/10 border border-purple-500/30 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <span className="text-4xl">🧬</span>
                  <div>
                    <h3 className="text-xl font-bold text-white">Xamarin Detected</h3>
                    <p className="text-sm text-gray-400">
                      This application is built with Xamarin Framework
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                  <span>📱</span>
                  <span>Framework Detection</span>
                </h3>

                <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 bg-gray-900/50 rounded-lg">
                    <dt className="text-sm text-gray-400 mb-1">Platform</dt>
                    <dd className="font-semibold text-white">
                      {xamarinAnalysis.platform?.toUpperCase()}
                    </dd>
                  </div>

                  <div className="p-4 bg-gray-900/50 rounded-lg">
                    <dt className="text-sm text-gray-400 mb-1">Xamarin Type</dt>
                    <dd className="font-semibold text-white">
                      {xamarinAnalysis.type}
                    </dd>
                  </div>

                  <div className="p-4 bg-gray-900/50 rounded-lg">
                    <dt className="text-sm text-gray-400 mb-1">DLLs Found</dt>
                    <dd className="font-semibold text-white">
                      {xamarinAnalysis.dllCount}
                    </dd>
                  </div>

                  <div className={`p-4 rounded-lg ${
                    xamarinAnalysis.compressed
                      ? 'bg-orange-500/10 border border-orange-500/30'
                      : 'bg-emerald-500/10 border border-emerald-500/30'
                  }`}>
                    <dt className="text-sm text-gray-400 mb-1">LZ4 Compression</dt>
                    <dd className="font-bold text-lg text-white">
                      {xamarinAnalysis.compressed ? 'Detected ⚠️' : 'Not Detected ✓'}
                    </dd>
                  </div>
                </dl>
              </div>

              {xamarinAnalysis.dlls?.length > 0 && (
                <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                  <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                    <span>📦</span>
                    <span>Assemblies (.dll)</span>
                  </h3>

                  <div className="space-y-2 max-h-80 overflow-auto">
                    {xamarinAnalysis.dlls.map((dll: string, i: number) => (
                      <div
                        key={i}
                        className="text-sm font-mono text-gray-300 bg-gray-900/50 px-3 py-2 rounded flex items-center gap-2"
                      >
                        📄 {dll}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {xamarinAnalysis.type === 'Xamarin AssemblyStore Blobs' && (
                <>
                  <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-6">
                    <div className="flex items-center gap-3">
                      <span className="text-3xl">⚠️</span>
                      <div>
                        <p className="font-semibold text-yellow-300">
                          Manual analysis required
                        </p>
                        <p className="text-sm text-yellow-200/80 mt-1">
                          For Xamarin Blob applications, manual analysis is required on the main application DLL to identify sensitive information, business logic, and insecure validations.
                        </p>
                        <p className="text-sm text-yellow-200/80 mt-2">
                          🔗 Recommended tools: dotPeek, dnSpy, ILSpy
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-6">
                    <div className="flex items-center gap-3">
                      <span className="text-3xl">🚨</span>
                      <div>
                        <p className="font-semibold text-red-300">
                          Limited extraction tool
                        </p>
                        <p className="text-sm text-red-200/80 mt-1">
                          If modifications, recompilation, or repackaging of the application are required, use the full <b>pyxamstore</b> script.
                        </p>
                        <p className="text-sm text-red-200/80 mt-2">
                          🔗 Original tool: <span className="font-mono">https://github.com/jakev/pyxamstore</span>
                        </p>
                      </div>
                    </div>
                  </div>
                </>
              )}

              {xamarinAnalysis.outputZip && (
                <div className="bg-indigo-500/10 border border-indigo-500/30 rounded-xl p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-bold text-white">
                        📥 Download Extracted DLLs
                      </h3>
                      <p className="text-sm text-gray-400 mt-1">
                        Assemblies were extracted and packaged automatically
                      </p>
                    </div>

                    <a
                      href={`/api/v1/analysis/applications/${id}/download-xamarin-dlls`}
                      className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-lg transition"
                    >
                      Download ZIP
                    </a>
                  </div>
                </div>
              )}

              {xamarinAnalysis.compressed && (
                <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-6">
                  <div className="flex items-center gap-3">
                    <span className="text-3xl">⚠️</span>
                    <div>
                      <p className="font-semibold text-orange-300">
                        LZ4-compressed assemblies detected
                      </p>
                      <p className="text-sm text-orange-200/80 mt-1">
                        DLLs were compressed with LZ4 (XALZ) and were automatically decompressed using specialized tools.
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* .NET MAUI Tab */}
          {activeTab === 'maui' && hasMauiAnalysis && (
            <div className="space-y-6">
              <div className="bg-gradient-to-r from-teal-500/10 to-cyan-500/10 border border-teal-500/30 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <span className="text-4xl">🔥</span>
                  <div>
                    <h3 className="text-xl font-bold text-white">.NET MAUI Detected</h3>
                    <p className="text-sm text-gray-400">
                      This application is built with .NET MAUI (Android)
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                  <span>📱</span>
                  <span>Framework Detection</span>
                </h3>

                <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 bg-gray-900/50 rounded-lg">
                    <dt className="text-sm text-gray-400 mb-1">Platform</dt>
                    <dd className="font-semibold text-white">{mauiAnalysis.platform}</dd>
                  </div>

                  <div className="p-4 bg-gray-900/50 rounded-lg">
                    <dt className="text-sm text-gray-400 mb-1">Technology</dt>
                    <dd className="font-semibold text-white">{mauiAnalysis.type}</dd>
                  </div>

                  <div className="p-4 bg-gray-900/50 rounded-lg">
                    <dt className="text-sm text-gray-400 mb-1">DLLs Found</dt>
                    <dd className="font-semibold text-white">{mauiAnalysis.dllCount}</dd>
                  </div>
                </dl>
              </div>

              {mauiAnalysis.type === '.NET MAUI' && (
                <>
                  <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-6">
                    <div className="flex items-center gap-3">
                      <span className="text-3xl">⚠️</span>
                      <div>
                        <p className="font-semibold text-yellow-300">
                          Manual analysis required
                        </p>
                        <p className="text-sm text-yellow-200/80 mt-1">
                          For .NET MAUI applications, manual analysis is required on the main application DLL to identify sensitive information, business logic, and insecure validations.
                        </p>
                        <div className="text-sm text-yellow-200/80 mt-2">
                          🔗 Recommended tools:
                          <ul className="list-disc ml-5 mt-1">
                            <li>dotPeek: https://www.jetbrains.com/decompiler/</li>
                            <li>dnSpy: https://dnspy.org/</li>
                            <li>ILSpy: https://ilspy.org/</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-6">
                    <div className="flex items-center gap-3">
                      <span className="text-3xl">🚨</span>
                      <div>
                        <p className="font-semibold text-red-300">
                          Limited extraction tool
                        </p>
                        <p className="text-sm text-red-200/80 mt-1">
                          If modifications, recompilation, or repackaging are required, use the full <b>pymauistore</b> script.
                        </p>
                        <p className="text-sm text-red-200/80 mt-2">
                          🔗 Original tool: <span className="font-mono">https://github.com/mwalkowski/pymauistore</span>
                        </p>
                      </div>
                    </div>
                  </div>
                </>
              )}

              {mauiAnalysis.dlls?.length > 0 && (
                <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                  <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                    <span>📦</span>
                    <span>Assemblies (.dll)</span>
                  </h3>

                  <div className="space-y-2 max-h-80 overflow-auto">
                    {mauiAnalysis.dlls.map((dll: string, i: number) => (
                      <div
                        key={i}
                        className="text-sm font-mono text-gray-300 bg-gray-900/50 px-3 py-2 rounded flex items-center gap-2"
                      >
                        📄 {dll}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {mauiAnalysis.outputZip && (
                <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-xl p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-bold text-white">📥 Download Extracted DLLs</h3>
                      <p className="text-sm text-gray-400 mt-1">
                        Assemblies were extracted and packaged automatically
                      </p>
                    </div>

                     <a
                      href={`/api/v1/analysis/applications/${id}/download-maui-dlls`}
                      className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm font-semibold rounded-lg transition"
                    >
                      Download ZIP
                    </a>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Flutter Tab */}
          {activeTab === 'flutter' && hasFlutterAnalysis && (
            <FlutterTab
              flutterAnalysis={flutterAnalysis}
              applicationId={data.application.id}
            />
          )}

          {/* Macho Tab */}
          {activeTab === 'macho' && hasMachoAnalysis && (
            <MachoTab
              machoAnalysis={data.analysis_result?.manifest_data?.macho_analysis}
            />
          )}

          {/* Cordova Tab */}
          {activeTab === 'cordova' && hasCordovaAnalysis && (
            <div className="space-y-6">
              <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <span className="text-4xl">📱</span>
                  <div>
                    <h3 className="text-xl font-bold text-white">Apache Cordova Detected</h3>
                    <p className="text-sm text-gray-400">
                      This application is built with Apache Cordova / PhoneGap
                    </p>
                  </div>
                </div>
                
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
                  {cordovaAnalysis.appName && (
                    <div className="p-3 bg-gray-900/50 rounded-lg border border-purple-500/20">
                      <p className="text-xs text-gray-400 mb-1">App Name</p>
                      <p className="text-sm font-semibold text-white">{cordovaAnalysis.appName}</p>
                    </div>
                  )}
                  {cordovaAnalysis.appId && (
                    <div className="p-3 bg-gray-900/50 rounded-lg border border-purple-500/20">
                      <p className="text-xs text-gray-400 mb-1">App ID</p>
                      <p className="text-sm font-mono text-white">{cordovaAnalysis.appId}</p>
                    </div>
                  )}
                  {cordovaAnalysis.cordovaVersion && (
                    <div className="p-3 bg-gray-900/50 rounded-lg border border-purple-500/20">
                      <p className="text-xs text-gray-400 mb-1">Cordova Version</p>
                      <p className="text-sm font-semibold text-white">{cordovaAnalysis.cordovaVersion}</p>
                    </div>
                  )}
                  <div className="p-3 bg-gray-900/50 rounded-lg border border-purple-500/20">
                    <p className="text-xs text-gray-400 mb-1">Total Plugins</p>
                    <p className="text-sm font-bold text-purple-400">{cordovaAnalysis.plugins?.length || 0}</p>
                  </div>
                </div>
              </div>

              {cordovaAnalysis.plugins && cordovaAnalysis.plugins.length > 0 && (
                <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                  <div className="flex justify-between items-start mb-4">
                    <h3 className="text-lg font-bold text-white flex items-center gap-2">
                      <span>🔌</span>
                      <span>Cordova Plugins</span>
                    </h3>
                    <span className="px-3 py-1 bg-purple-500/20 text-purple-400 text-xs rounded-full font-medium">
                      {cordovaAnalysis.plugins.length} plugin{cordovaAnalysis.plugins.length !== 1 ? 's' : ''}
                    </span>
                  </div>

                  <div className="space-y-2">
                    {cordovaAnalysis.plugins
                      .slice(0, expandedSecrets.has('cordova-plugins') ? cordovaAnalysis.plugins.length : 10)
                      .map((plugin: any, i: number) => (
                      <div key={i} className="p-4 bg-gray-900/50 rounded-lg border border-gray-700">
                        <div className="flex justify-between items-start">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-mono text-sm font-semibold text-white">{plugin.id}</span>
                              <span className="px-2 py-0.5 bg-gray-700 text-gray-300 text-xs rounded">
                                v{plugin.version}
                              </span>
                            </div>
                            <p className="text-xs text-gray-400">{plugin.name}</p>
                          </div>
                          <span className="px-2 py-1 bg-purple-500/20 text-purple-400 text-xs rounded font-medium">
                            {plugin.source || 'Unknown'}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>

{cordovaAnalysis.plugins.length > 10 && (
                    <button
                      onClick={() => toggleSecretExpand('cordova-plugins')}
                      className="mt-4 w-full py-2 px-4 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm font-medium text-gray-300 transition"
                    >
                      {expandedSecrets.has('cordova-plugins') 
                        ? '▲ Show less' 
                        : `▼ Show ${cordovaAnalysis.plugins.length - 10} more`}
                    </button>
                  )}
                </div>
              )}

              <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-lg p-4">
                <p className="text-sm text-cyan-200">
                  <strong>ℹ️ Note:</strong> This analysis examined the Cordova application's JavaScript code. 
                  Detected secrets are available in the <strong>Secrets</strong> tab.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
