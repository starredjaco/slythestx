import { useEffect, useState, useRef } from "react";
import axios from "axios";
import LogcatViewer from './LogcatViewer';

const API = "/api/v1/adb";

interface DeviceInfo {
  id: string;
  status: string;
  model?: string;
  android_version?: string;
  sdk?: string;
  isRooted?: boolean;
}

interface PackageInfo {
  name: string;
  path?: string;
  size?: string;
  version?: string;
  isSystem: boolean;
}

interface FileEntry {
  name: string;
  type: 'file' | 'directory' | 'symlink';
  size?: string;
  permissions?: string;
  path: string;
}

interface ExtractResult {
  success: boolean;
  package?: string;
  isSplit?: boolean;
  originalCount?: number;
  outputFile?: string;
  downloadUrl?: string;
  size?: number;
  sizeMB?: string;
  message?: string;
  error?: string;
}

interface AndroidDevicesProps {
  connectionStatus: 'connected' | 'disconnected' | 'checking';
  deviceInfo: DeviceInfo | null;
  isRooted: boolean;
  onRefresh: () => void;
}

export default function AndroidDevices({ connectionStatus, deviceInfo, isRooted, onRefresh }: AndroidDevicesProps) {
  // Tabs
  const [activeTab, setActiveTab] = useState<"apps" | "install" | "explorer" | "extract" | "shell" | "logcat">("apps");

  // Apps state
  const [packages, setPackages] = useState<PackageInfo[]>([]);
  const [packagesLoading, setPackagesLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [showSystemApps, setShowSystemApps] = useState(false);
  const [selectedPackage, setSelectedPackage] = useState<string | null>(null);

  // Install state
  const [apkFile, setApkFile] = useState<File | null>(null);
  const [installing, setInstalling] = useState(false);
  const [installProgress, setInstallProgress] = useState("");

  // Explorer state
  const [currentPath, setCurrentPath] = useState("/data/data");
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [filesLoading, setFilesLoading] = useState(false);
  const [pathHistory, setPathHistory] = useState<string[]>([]);
  const [explorerError, setExplorerError] = useState<string | null>(null);
  const [explorerIsRoot, setExplorerIsRoot] = useState<boolean>(false);

  // Extract state
  const [extracting, setExtracting] = useState<string | null>(null);
  const [extractLogs, setExtractLogs] = useState<Array<{ type: 'info' | 'success' | 'error' | 'download'; message: string; url?: string }>>([]);
  const [extractedFiles, setExtractedFiles] = useState<ExtractResult[]>([]);

  // Shell state
  const [shellCommand, setShellCommand] = useState("");
  const [shellOutput, setShellOutput] = useState<string[]>([]);
  const [shellRunning, setShellRunning] = useState(false);
  const [shellUseRoot, setShellUseRoot] = useState(true);

  // Refs
  const packagesLoaded = useRef(false);
  const lastShowSystemApps = useRef(showSystemApps);

  useEffect(() => {
    if (connectionStatus !== 'connected' || activeTab !== 'apps') return;
    if (!packagesLoaded.current) {
      packagesLoaded.current = true;
      loadPackages();
    }
  }, [connectionStatus, activeTab]);

  useEffect(() => {
    if (lastShowSystemApps.current !== showSystemApps) {
      lastShowSystemApps.current = showSystemApps;
      if (connectionStatus === 'connected' && activeTab === 'apps') {
        loadPackages();
      }
    }
  }, [showSystemApps]);

  // ==================== PACKAGES ====================
  async function loadPackages() {
    if (connectionStatus !== 'connected') return;
    try {
      setPackagesLoading(true);
      const res = await axios.get(`${API}/packages`, {
        params: { includeSystem: showSystemApps }
      });
      setPackages(res.data || []);
    } catch (e: any) {
      console.error("Failed to load packages", e);
    } finally {
      setPackagesLoading(false);
    }
  }

  async function manualLoadPackages() {
    if (connectionStatus !== 'connected') {
      alert("No Android device connected. Please configure in Settings.");
      return;
    }
    await loadPackages();
  }

  // ==================== INSTALL / UNINSTALL ====================
  async function installAPK() {
    if (!apkFile) {
      alert("Please select an APK file first");
      return;
    }

    try {
      setInstalling(true);
      setInstallProgress("Uploading APK...");

      const fd = new FormData();
      fd.append("apk", apkFile);

      const res = await axios.post(`${API}/install`, fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 180000,
        onUploadProgress: (e) => {
          if (e.total) {
            const pct = Math.round((e.loaded / e.total) * 100);
            setInstallProgress(`Uploading... ${pct}%`);
          }
        }
      });

      if (res.data.success) {
        alert("✅ APK installed successfully!");
        setApkFile(null);
        packagesLoaded.current = false;
        loadPackages();
      } else {
        alert("❌ Installation failed: " + res.data.error);
      }
    } catch (e: any) {
      alert("❌ Installation error: " + (e.response?.data?.error || e.message));
    } finally {
      setInstalling(false);
      setInstallProgress("");
    }
  }

  async function uninstallPackage(pkg: string) {
    if (!confirm(`Uninstall ${pkg}?\n\nThis will remove the app and all its data.`)) return;
    try {
      const res = await axios.post(`${API}/uninstall`, { package: pkg });
      if (res.data.success) {
        alert("✅ Package uninstalled");
        loadPackages();
      } else {
        alert("❌ Uninstall failed: " + (res.data.error || res.data.output));
      }
    } catch (e: any) {
      alert("❌ Error: " + (e.response?.data?.error || e.message));
    }
  }

  // ==================== FILE EXPLORER ====================
  async function loadDirectory(path: string) {
    if (connectionStatus !== 'connected') {
      setExplorerError("No device connected");
      return;
    }
    try {
      setFilesLoading(true);
      setExplorerError(null);
      const res = await axios.get(`${API}/ls`, { params: { path, root: true } });
      if (res.data.error) {
        setExplorerError(res.data.error);
        setFiles([]);
      } else {
        setFiles(res.data.files || []);
        setExplorerIsRoot(res.data.isRoot || false);
      }
      setCurrentPath(path);
    } catch (e: any) {
      setExplorerError(e.response?.data?.error || e.message);
      setFiles([]);
    } finally {
      setFilesLoading(false);
    }
  }

  function navigateTo(path: string) {
    setPathHistory(prev => [...prev, currentPath]);
    loadDirectory(path);
  }

  function navigateBack() {
    if (pathHistory.length > 0) {
      const prev = pathHistory[pathHistory.length - 1];
      setPathHistory(h => h.slice(0, -1));
      loadDirectory(prev);
    }
  }

  function navigateUp() {
    const parentPath = currentPath.split('/').slice(0, -1).join('/') || '/';
    if (parentPath !== currentPath) navigateTo(parentPath);
  }

  function navigateToPackageData(pkg: string) {
    setActiveTab('explorer');
    setPathHistory([]);
    loadDirectory(`/data/data/${pkg}`);
  }

  async function pullFile(filePath: string, fileName: string) {
    try {
      const res = await axios.get(`${API}/pull`, { params: { path: filePath } });
      if (res.data.success && res.data.content) {
        const byteCharacters = atob(res.data.content);
        const byteNumbers = new Array(byteCharacters.length);
        for (let i = 0; i < byteCharacters.length; i++) {
          byteNumbers[i] = byteCharacters.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteNumbers);
        const blob = new Blob([byteArray]);
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        a.click();
        window.URL.revokeObjectURL(url);
      } else {
        alert("Failed to download: " + (res.data.error || res.data.message));
      }
    } catch (e: any) {
      alert("Failed to download file: " + (e.response?.data?.error || e.message));
    }
  }

  async function viewFile(filePath: string, fileName: string) {
    try {
      const res = await axios.get(`${API}/cat`, { params: { path: filePath, maxSize: 50000 } });
      if (res.data.content !== undefined) {
        const win = window.open('', '_blank');
        if (win) {
          win.document.write(`<html><head><title>${fileName}</title><style>
            body { background: #1a1a2e; color: #eee; font-family: monospace; padding: 20px; white-space: pre-wrap; }
          </style></head><body>${escapeHtml(res.data.content)}</body></html>`);
        }
      } else {
        alert("Cannot view file: " + (res.data.error || "Unknown error"));
      }
    } catch (e: any) {
      alert("Failed to read file: " + (e.response?.data?.error || e.message));
    }
  }

  function escapeHtml(text: string): string {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  async function deleteFile(filePath: string) {
    if (!confirm(`Delete ${filePath}?`)) return;
    try {
      const res = await axios.post(`${API}/rm`, { path: filePath });
      if (res.data.success) loadDirectory(currentPath);
      else alert("Failed to delete: " + (res.data.error || res.data.output));
    } catch (e: any) {
      alert("Failed to delete: " + (e.response?.data?.error || e.message));
    }
  }

  // ==================== EXTRACT APK ====================
  function addLog(type: 'info' | 'success' | 'error' | 'download', message: string, url?: string) {
    const timestamp = new Date().toLocaleTimeString();
    setExtractLogs(prev => [...prev, { type, message: `[${timestamp}] ${message}`, url }]);
  }

  async function extractAPK(pkg: string) {
    if (!pkg.trim()) return;
    try {
      setExtracting(pkg);
      addLog('info', `Starting extraction: ${pkg}`);
      const res = await axios.post<ExtractResult>(`${API}/extract`, { package: pkg }, { timeout: 300000 });
      if (res.data.success) {
        if (res.data.isSplit) addLog('info', `Merged ${res.data.originalCount} split APKs`);
        addLog('success', `✅ ${res.data.message}`);
        addLog('download', `📦 Download: ${res.data.outputFile}`, res.data.downloadUrl);
        setExtractedFiles(prev => [res.data, ...prev]);
      } else {
        addLog('error', `❌ Failed: ${res.data.error}`);
      }
    } catch (e: any) {
      addLog('error', `❌ Error: ${e.response?.data?.error || e.message}`);
    } finally {
      setExtracting(null);
    }
  }

  async function clearExtractedFiles() {
    try {
      for (const file of extractedFiles) {
        if (file.outputFile) await axios.delete(`${API}/extracted/${file.outputFile}`);
      }
    } catch {} finally {
      setExtractedFiles([]);
    }
  }

  async function deleteExtractedFile(filename: string) {
    try {
      await axios.delete(`${API}/extracted/${filename}`);
      setExtractedFiles(prev => prev.filter(f => f.outputFile !== filename));
      addLog('info', `Deleted: ${filename}`);
    } catch (e: any) {
      addLog('error', `Failed to delete: ${e.message}`);
    }
  }

  function downloadExtractedAPK(url: string, filename: string) {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
  }

  // ==================== SHELL ====================
  async function executeShell() {
    if (!shellCommand.trim()) return;
    try {
      setShellRunning(true);
      const prefix = shellUseRoot ? '# ' : '$ ';
      setShellOutput(prev => [...prev, `${prefix}${shellCommand}`]);
      const res = await axios.post(`${API}/shell`, { command: shellCommand, root: shellUseRoot });
      if (res.data.output) setShellOutput(prev => [...prev, res.data.output]);
      if (res.data.error) setShellOutput(prev => [...prev, `Error: ${res.data.error}`]);
      setShellCommand("");
    } catch (e: any) {
      setShellOutput(prev => [...prev, `Error: ${e.response?.data?.error || e.message}`]);
    } finally {
      setShellRunning(false);
    }
  }

  const filteredPackages = packages.filter(p => p.name.toLowerCase().includes(search.toLowerCase()));

  // ==================== RENDER ====================
  return (
    <>
      <div className="flex gap-2 mb-6 flex-wrap">
        {[
          { id: 'apps', label: 'Applications', icon: '📦' },
          { id: 'install', label: 'Install APK', icon: '⬆️' },
          { id: 'explorer', label: 'File Explorer', icon: '📁' },
          { id: 'extract', label: 'Extract APK', icon: '📤' },
          { id: 'shell', label: 'Shell', icon: '💻' },
          { id: 'logcat', label: 'Logcat', icon: '📋' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-4 py-2 rounded-lg font-medium transition flex items-center gap-2 ${
              activeTab === tab.id
                ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                : "bg-gray-800/50 text-gray-400 hover:text-white border border-transparent"
            }`}
          >
            <span>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Applications Tab */}
      {activeTab === "apps" && (
        <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
          <div className="flex flex-wrap gap-4 mb-6">
            <div className="flex-1 min-w-[200px]">
              <input
                placeholder="🔍 Search packages..."
                className="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white focus:border-cyan-500 transition"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>

            <div className="flex items-center gap-4">
              <label className="flex items-center gap-2 text-gray-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={showSystemApps}
                  onChange={e => setShowSystemApps(e.target.checked)}
                  className="w-4 h-4 rounded bg-gray-800 border-gray-600"
                />
                Show system apps
              </label>

              <button
                onClick={manualLoadPackages}
                disabled={packagesLoading || connectionStatus !== 'connected'}
                className="px-4 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:opacity-50 rounded-xl text-white font-medium transition flex items-center gap-2"
              >
                {packagesLoading ? '⏳ Loading...' : '🔄 Refresh'}
              </button>
            </div>
          </div>

          <div className="mb-4 text-sm text-gray-400">
            {filteredPackages.length} package{filteredPackages.length !== 1 ? 's' : ''} found
          </div>

          <div className="max-h-[500px] overflow-auto space-y-2">
            {filteredPackages.length === 0 ? (
              <div className="text-center py-12 text-gray-500">
                {connectionStatus !== 'connected'
                  ? "Connect an Android device to view packages"
                  : packages.length === 0
                  ? "Click Refresh to load packages"
                  : "No packages match your search"}
              </div>
            ) : (
              filteredPackages.map(pkg => (
                <div
                  key={pkg.name}
                  className={`flex items-center justify-between p-4 rounded-xl border transition ${
                    selectedPackage === pkg.name
                      ? 'bg-cyan-500/10 border-cyan-500/30'
                      : 'bg-gray-900/50 border-gray-800 hover:border-gray-700'
                  }`}
                  onClick={() => setSelectedPackage(pkg.name === selectedPackage ? null : pkg.name)}
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <span className="text-2xl">{pkg.isSystem ? '⚙️' : '📱'}</span>
                    <div className="min-w-0">
                      <p className="font-mono text-sm text-white truncate">{pkg.name}</p>
                      {pkg.version && <p className="text-xs text-gray-500">v{pkg.version}</p>}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={(e) => { e.stopPropagation(); extractAPK(pkg.name); }}
                      disabled={extracting === pkg.name}
                      className="px-3 py-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 rounded-lg text-sm"
                    >
                      {extracting === pkg.name ? '⏳' : '📤'}
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); navigateToPackageData(pkg.name); }}
                      className="px-3 py-1.5 bg-yellow-500/20 hover:bg-yellow-500/30 text-yellow-400 rounded-lg text-sm"
                    >
                      📁
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); uninstallPackage(pkg.name); }}
                      className="px-3 py-1.5 bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded-lg text-sm"
                    >
                      🗑️
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Install Tab */}
      {activeTab === "install" && (
        <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
          <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
            <span className="text-2xl">⬆️</span>
            Install APK
          </h3>
          <div className="max-w-xl mx-auto">
            <div className="relative mb-6">
              <input
                type="file"
                accept=".apk"
                onChange={e => setApkFile(e.target.files?.[0] || null)}
                className="hidden"
                id="apk-upload"
              />
              <label
                htmlFor="apk-upload"
                className={`flex flex-col items-center justify-center w-full h-40 border-2 border-dashed rounded-xl cursor-pointer transition ${
                  apkFile ? 'border-cyan-500/50 bg-cyan-500/5' : 'border-gray-700 hover:border-cyan-500/50'
                }`}
              >
                {apkFile ? (
                  <div className="text-center">
                    <span className="text-4xl mb-2 block">📦</span>
                    <p className="text-cyan-400 font-medium">{apkFile.name}</p>
                    <p className="text-sm text-gray-500 mt-1">{(apkFile.size / 1024 / 1024).toFixed(2)} MB</p>
                  </div>
                ) : (
                  <div className="text-center">
                    <span className="text-4xl mb-2 block">📱</span>
                    <p className="text-gray-400">
                      <span className="text-cyan-400 font-medium">Click to select</span> or drag APK
                    </p>
                  </div>
                )}
              </label>
            </div>
            <button
              onClick={installAPK}
              disabled={!apkFile || installing || connectionStatus !== 'connected'}
              className="w-full px-6 py-4 bg-gradient-to-r from-emerald-500 to-green-500 hover:opacity-90 disabled:opacity-50 rounded-xl text-white font-semibold flex items-center justify-center gap-2"
            >
              {installing ? `⏳ ${installProgress || 'Installing...'}` : '⬆️ Install APK'}
            </button>
            {connectionStatus !== 'connected' && (
              <p className="text-sm text-yellow-400 mt-4 text-center">⚠️ Connect Android device first</p>
            )}
          </div>
        </div>
      )}

      {/* Explorer Tab */}
      {activeTab === "explorer" && (
        <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">📁 Root File Explorer</h3>
            <span className={`px-3 py-1 rounded-lg text-xs font-medium ${
              explorerIsRoot ? 'bg-orange-500/20 text-orange-400' : 'bg-gray-500/20 text-gray-400'
            }`}>
              {explorerIsRoot ? '🔓 ROOT' : '🔒 shell'}
            </span>
          </div>

          <div className="flex items-center gap-2 mb-4 p-3 bg-gray-900 rounded-xl">
            <button onClick={navigateBack} disabled={pathHistory.length === 0} className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 rounded-lg text-white">⬅️</button>
            <button onClick={navigateUp} disabled={currentPath === '/'} className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 rounded-lg text-white">⬆️</button>
            <button onClick={() => { setPathHistory([]); loadDirectory('/'); }} className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded-lg text-white">/</button>
            <div className="flex-1 font-mono text-sm text-cyan-400 truncate px-2">{currentPath}</div>
            <button onClick={() => loadDirectory(currentPath)} disabled={filesLoading} className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 disabled:opacity-50 rounded-lg text-white">
              {filesLoading ? '⏳' : '🔄'}
            </button>
          </div>

          <div className="flex flex-wrap gap-2 mb-4">
            {['/data/data', '/data/app', '/sdcard', '/sdcard/Download', '/system'].map(path => (
              <button
                key={path}
                onClick={() => { setPathHistory([]); loadDirectory(path); }}
                className={`px-3 py-1.5 rounded-lg text-sm ${
                  currentPath.startsWith(path) ? 'bg-cyan-500/20 text-cyan-400' : 'bg-gray-800 text-gray-300'
                }`}
              >
                {path}
              </button>
            ))}
          </div>

          {explorerError && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">
              ❌ {explorerError}
            </div>
          )}

          <div className="max-h-[400px] overflow-auto border border-gray-800 rounded-xl">
            {filesLoading ? (
              <div className="flex items-center justify-center py-12">
                <div className="w-8 h-8 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
              </div>
            ) : files.length === 0 ? (
              <div className="text-center py-12 text-gray-500">
                {connectionStatus !== 'connected' ? "Connect device" : "Empty"}
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-900/50 sticky top-0">
                  <tr className="text-left text-sm text-gray-400">
                    <th className="px-4 py-3">Name</th>
                    <th className="px-4 py-3 w-24">Size</th>
                    <th className="px-4 py-3 w-32">Permissions</th>
                    <th className="px-4 py-3 w-32 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {files.map((file, i) => (
                    <tr
                      key={i}
                      className="hover:bg-gray-800/50 cursor-pointer"
                      onClick={() => file.type === 'directory' && navigateTo(file.path)}
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span>{file.type === 'directory' ? '📁' : file.type === 'symlink' ? '🔗' : '📄'}</span>
                          <span className={`font-mono text-sm ${file.type === 'directory' ? 'text-cyan-400' : 'text-white'}`}>
                            {file.name}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500">{file.type === 'directory' ? '-' : file.size || '-'}</td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-500">{file.permissions || '-'}</td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1" onClick={e => e.stopPropagation()}>
                          {file.type === 'file' && (
                            <>
                              <button onClick={() => viewFile(file.path, file.name)} className="p-1.5 hover:bg-blue-500/20 rounded text-blue-400">👁️</button>
                              <button onClick={() => pullFile(file.path, file.name)} className="p-1.5 hover:bg-emerald-500/20 rounded text-emerald-400">⬇️</button>
                            </>
                          )}
                          <button onClick={() => deleteFile(file.path)} className="p-1.5 hover:bg-red-500/20 rounded text-red-400">🗑️</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* Extract Tab */}
      {activeTab === "extract" && (
        <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4">📤 Extract APK</h3>
          <div className="mb-6">
            <div className="flex gap-2">
              <input
                placeholder="com.example.app"
                className="flex-1 p-3 bg-gray-900 border border-gray-700 rounded-xl text-white font-mono"
                value={selectedPackage || ''}
                onChange={e => setSelectedPackage(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && selectedPackage && extractAPK(selectedPackage)}
              />
              <button
                onClick={() => selectedPackage && extractAPK(selectedPackage)}
                disabled={!selectedPackage || extracting !== null || connectionStatus !== 'connected'}
                className="px-6 py-3 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 rounded-xl text-white font-semibold"
              >
                {extracting ? '⏳' : '📤 Extract'}
              </button>
            </div>
          </div>

          {extractedFiles.length > 0 && (
            <div className="mb-6 space-y-2">
              {extractedFiles.map((file, i) => (
                <div key={i} className="flex items-center justify-between p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl">
                  <div>
                    <p className="text-white font-medium">{file.outputFile}</p>
                    <p className="text-xs text-gray-400">{file.package} • {file.sizeMB} MB</p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => downloadExtractedAPK(file.downloadUrl!, file.outputFile!)}
                      className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 rounded-lg text-white text-sm"
                    >
                      ⬇️ Download
                    </button>
                    <button
                      onClick={() => deleteExtractedFile(file.outputFile!)}
                      className="px-3 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg text-sm"
                    >
                      🗑️
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="bg-gray-900 rounded-xl p-4 max-h-[300px] overflow-auto font-mono text-sm">
            {extractLogs.length === 0 ? (
              <p className="text-gray-500">Logs...</p>
            ) : (
              extractLogs.map((log, i) => (
                <div
                  key={i}
                  className={`py-1 ${
                    log.type === 'success' ? 'text-emerald-400' : log.type === 'error' ? 'text-red-400' : 'text-gray-300'
                  }`}
                >
                  {log.message}
                </div>
              ))
            )}
          </div>

          {(extractLogs.length > 0 || extractedFiles.length > 0) && (
            <div className="flex gap-2 mt-4">
              <button onClick={() => setExtractLogs([])} className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-gray-300">
                🗑️ Clear Logs
              </button>
              {extractedFiles.length > 0 && (
                <button onClick={clearExtractedFiles} className="px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg text-sm">
                  🗑️ Delete All
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {/* Shell Tab */}
      {activeTab === "shell" && (
        <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">💻 ADB Shell</h3>
            <label className="flex items-center gap-2 cursor-pointer">
              <span className="text-sm text-gray-400">Root (su)</span>
              <div className="relative">
                <input
                  type="checkbox"
                  checked={shellUseRoot}
                  onChange={e => setShellUseRoot(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-700 rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-orange-500"></div>
              </div>
            </label>
          </div>

          <div className="bg-black rounded-xl p-4 h-[400px] overflow-auto font-mono text-sm mb-4">
            {shellOutput.length === 0 ? (
              <p className="text-gray-500">Output...</p>
            ) : (
              shellOutput.map((line, i) => (
                <div
                  key={i}
                  className={`py-0.5 whitespace-pre-wrap ${
                    line.startsWith('# ') ? 'text-orange-400' : line.startsWith('$ ') ? 'text-cyan-400' : line.startsWith('Error') ? 'text-red-400' : 'text-gray-300'
                  }`}
                >
                  {line}
                </div>
              ))
            )}
          </div>

          <div className="flex gap-2">
            <div className="flex-1 flex items-center bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
              <span className={`px-3 ${shellUseRoot ? 'text-orange-400' : 'text-cyan-400'}`}>
                {shellUseRoot ? '#' : '$'}
              </span>
              <input
                placeholder="Enter command..."
                className="flex-1 p-3 bg-transparent text-white font-mono outline-none"
                value={shellCommand}
                onChange={e => setShellCommand(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && executeShell()}
                disabled={shellRunning || connectionStatus !== 'connected'}
              />
            </div>
            <button
              onClick={executeShell}
              disabled={shellRunning || connectionStatus !== 'connected'}
              className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:opacity-50 rounded-xl text-white font-semibold"
            >
              {shellRunning ? '⏳' : '▶️ Run'}
            </button>
            <button onClick={() => setShellOutput([])} className="px-4 py-3 bg-gray-800 hover:bg-gray-700 rounded-xl text-white">
              🗑️
            </button>
          </div>

          <div className="mt-4 flex flex-wrap gap-2">
            {['id', 'whoami', 'pm list packages -3', 'dumpsys battery', 'ps -A | head -20'].map(cmd => (
              <button
                key={cmd}
                onClick={() => setShellCommand(cmd)}
                className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded-lg text-xs text-gray-300 font-mono"
              >
                {cmd}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Logcat Tab */}
      {activeTab === "logcat" && <LogcatViewer />}
    </>
  );
}
