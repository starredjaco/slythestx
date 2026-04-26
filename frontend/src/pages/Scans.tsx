import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { analysisApi, uploadApi } from '../services/api';

export default function Scans() {
  const [apps, setApps] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [uploadProgress, setUploadProgress] = useState(0);

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      if (apps.some(app => app.status === 'ANALYZING' || app.status === 'UPLOADED' || app.status === 'EXTRACTING')) {
        loadData();
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [apps]);

  const loadData = async () => {
    try {
      const appsRes = await analysisApi.listApps({ page: 1, page_size: 50 });
      setApps(appsRes.data.applications || []);
    } catch (error: any) {
      console.error('Error loading data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 500 * 1024 * 1024) {
      setUploadError('File too large (max. 500MB)');
      return;
    }

    const ext = file.name.split('.').pop()?.toLowerCase();
    if (!['apk', 'ipa', 'aab'].includes(ext || '')) {
      setUploadError('Only APK, IPA or AAB files');
      return;
    }

    setUploading(true);
    setUploadError('');
    setUploadProgress(0);

    try {
      await uploadApi.uploadApp(file, (progress) => {
        setUploadProgress(progress);
      });
      e.target.value = '';
      setTimeout(loadData, 1000);
    } catch (error: any) {
      setUploadError(error.response?.data?.error || 'Upload failed');
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  const handleDelete = async (id: number, name: string) => {
    if (!confirm(`Delete "${name}"?\n\nThis action cannot be undone.`)) return;
    
    try {
      await analysisApi.deleteApp(id);
      loadData();
    } catch (error) {
      alert('Error deleting application');
    }
  };

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      COMPLETED: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
      ANALYZING: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      EXTRACTING: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      FAILED: 'bg-red-500/20 text-red-400 border-red-500/30',
      UPLOADED: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    };
    return styles[status] || styles.UPLOADED;
  };

  const getScoreColor = (score: number | null) => {
    if (score === null || score === undefined) return 'text-gray-400';
    if (score >= 80) return 'text-emerald-400';
    if (score >= 60) return 'text-yellow-400';
    return 'text-red-400';
  };

  const getScoreBg = (score: number | null) => {
    if (score === null || score === undefined) return 'bg-gray-500/10 border-gray-500/30';
    if (score >= 80) return 'bg-emerald-500/10 border-emerald-500/30';
    if (score >= 60) return 'bg-yellow-500/10 border-yellow-500/30';
    return 'bg-red-500/10 border-red-500/30';
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400">Loading applications...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Security Scans</h1>
        <p className="text-gray-400">Upload and analyze mobile applications</p>
      </div>

      {/* Upload Section */}
      <div className="bg-[#12121a] rounded-2xl p-6 mb-8 border border-gray-800">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
          </svg>
          Upload Application
        </h2>
        
        <div className="relative">
          <input
            type="file"
            accept=".apk,.ipa,.aab"
            onChange={handleUpload}
            disabled={uploading}
            className="hidden"
            id="file-upload"
          />
          <label
            htmlFor="file-upload"
            className={`flex flex-col items-center justify-center w-full h-40 border-2 border-dashed rounded-xl cursor-pointer transition-all ${
              uploading 
                ? 'border-cyan-500/50 bg-cyan-500/5' 
                : 'border-gray-700 hover:border-cyan-500/50 hover:bg-white/5'
            }`}
          >
            {uploading ? (
              <div className="text-center">
                <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-3"></div>
                <p className="text-cyan-400 font-medium">Uploading... {uploadProgress}%</p>
                <div className="w-48 h-2 bg-gray-700 rounded-full mt-3 overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300"
                    style={{ width: `${uploadProgress}%` }}
                  />
                </div>
              </div>
            ) : (
              <div className="text-center">
                <svg className="w-12 h-12 text-gray-500 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
                <p className="text-gray-400 mb-1">
                  <span className="text-cyan-400 font-medium">Click to upload</span> or drag and drop
                </p>
                <p className="text-sm text-gray-500">APK, IPA, AAB (max. 500MB)</p>
              </div>
            )}
          </label>
        </div>

        {uploadError && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-2">
            <svg className="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-sm text-red-400">{uploadError}</p>
          </div>
        )}
      </div>

      {/* Applications List */}
      <div className="bg-[#12121a] rounded-2xl border border-gray-800">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
            Applications
          </h2>
          <span className="px-3 py-1 bg-gray-800 text-gray-400 text-sm rounded-full">
            {apps.length} total
          </span>
        </div>

        {apps.length === 0 ? (
          <div className="px-6 py-16 text-center">
            <div className="w-20 h-20 bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-4">
              <span className="text-4xl">📱</span>
            </div>
            <p className="text-xl font-semibold text-white mb-2">No applications yet</p>
            <p className="text-gray-400">Upload your first app to start scanning</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {apps.map((app) => (
              <div key={app.id} className="px-6 py-5 hover:bg-white/5 transition-all">
                <div className="flex items-start justify-between gap-4">
                  {/* App Info */}
                  <div className="flex items-start gap-4 flex-1 min-w-0">
                    <div className={`w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 ${
                      app.platform === 'ANDROID' ? 'bg-green-500/20' : 'bg-blue-500/20'
                    }`}>
                      <span className="text-2xl">{app.platform === 'ANDROID' ? '🤖' : '🍎'}</span>
                    </div>
                    
                    <div className="flex-1 min-w-0">
                      <h3 className="text-lg font-semibold text-white truncate">{app.name}</h3>
                      <div className="flex flex-wrap items-center gap-3 mt-1 text-sm text-gray-400">
                        <span className={app.platform === 'ANDROID' ? 'text-green-400' : 'text-blue-400'}>
                          {app.platform}
                        </span>
                        <span>•</span>
                        <span>{app.technology || 'Detecting...'}</span>
                        {app.package_name && (
                          <>
                            <span>•</span>
                            <span className="font-mono text-xs truncate max-w-[200px]">{app.package_name}</span>
                          </>
                        )}
                      </div>
                      
                      {/* Progress Bar for Analyzing */}
                      {(app.status === 'ANALYZING' || app.status === 'EXTRACTING') && (
                        <div className="mt-3">
                          <div className="flex justify-between text-xs text-gray-400 mb-1">
                            <span>{app.status === 'EXTRACTING' ? 'Extracting...' : 'Analyzing...'}</span>
                            <span>{app.analysis_progress || 0}%</span>
                          </div>
                          <div className="w-full h-2 bg-gray-700 rounded-full overflow-hidden">
                            <div 
                              className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-500"
                              style={{ width: `${app.analysis_progress || 0}%` }}
                            />
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Status & Score */}
                  <div className="flex items-center gap-4 flex-shrink-0">
                    <span className={`px-3 py-1 text-xs font-medium rounded-full border ${getStatusBadge(app.status)}`}>
                      {app.status === 'COMPLETED' ? 'Completed' :
                       app.status === 'ANALYZING' ? 'Analyzing' :
                       app.status === 'EXTRACTING' ? 'Extracting' :
                       app.status === 'FAILED' ? 'Failed' : app.status}
                    </span>

                    {app.status === 'COMPLETED' && app.security_score !== null && (
                      <div className={`px-4 py-2 rounded-xl border ${getScoreBg(app.security_score)}`}>
                        <span className={`text-2xl font-bold ${getScoreColor(app.security_score)}`}>
                          {app.security_score}
                        </span>
                        <span className="text-gray-500 text-sm">/100</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Actions */}
                {app.status === 'COMPLETED' && (
                  <div className="mt-4 flex items-center gap-4 pl-16">
                    <Link
                      to={`/scans/${app.id}`}
                      className="inline-flex items-center gap-2 text-cyan-400 hover:text-cyan-300 font-medium text-sm transition"
                    >
                      View Analysis
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                      </svg>
                    </Link>
                    <button
                      onClick={() => handleDelete(app.id, app.name)}
                      className="inline-flex items-center gap-2 text-red-400 hover:text-red-300 font-medium text-sm transition"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                      Delete
                    </button>
                  </div>
                )}

                {app.status === 'FAILED' && (
                  <div className="mt-4 pl-16">
                    <button
                      onClick={() => handleDelete(app.id, app.name)}
                      className="inline-flex items-center gap-2 text-red-400 hover:text-red-300 font-medium text-sm transition"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                      Remove
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
