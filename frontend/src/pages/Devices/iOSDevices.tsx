import { useState, useEffect, useRef } from 'react';
import axios from 'axios';

const API = '/api/v1/ios';

interface UserApp {
  bundleId: string;
  name: string;
  version: string;
  containerPath: string;
  bundlePath: string;
  documentsPath: string;
  executable?: string;
}

interface AppDetails {
  bundleId: string;
  name: string;
  version: string;
  bundlePath: string;
  dataPath: string;
  paths: {
    bundle: string;
    data: string;
    documents: string;
    library: string;
    caches: string;
    preferences: string;
  };
}

export default function IOSDevices() {
  const [status, setStatus] = useState<any>(null);
  const [deviceInfo, setDeviceInfo] = useState<any>(null);
  const [apps, setApps] = useState<UserApp[]>([]);
  const [selectedApp, setSelectedApp] = useState<UserApp | null>(null);
  const [appDetails, setAppDetails] = useState<AppDetails | null>(null);
  const [activeTab, setActiveTab] = useState<'info' | 'apps' | 'shell' | 'syslog' | 'files' | 'security'>('info');

  const [sshCommand, setSSHCommand] = useState('');
  const [sshOutput, setSSHOutput] = useState<string[]>([]);
  const [sshRunning, setSSHRunning] = useState(false);
  const [runAsRoot, setRunAsRoot] = useState(false);

  const [syslogRunning, setSyslogRunning] = useState(false);
  const [syslogLogs, setSyslogLogs] = useState<string[]>([]);
  const [syslogFilter, setSyslogFilter] = useState('');
  const syslogPollRef = useRef<NodeJS.Timeout | null>(null);
  const syslogIndexRef = useRef(0);

  const [screenshot, setScreenshot] = useState('');
  const [filePath, setFilePath] = useState('/');
  const [files, setFiles] = useState<any[]>([]);

  const [securityOutput, setSecurityOutput] = useState('');
  const [securityLoading, setSecurityLoading] = useState(false);

  const [extracting, setExtracting] = useState<string | null>(null);
  const [extractedIPAs, setExtractedIPAs] = useState<any[]>([]);

  useEffect(() => {
    checkStatus();
    return () => {
      if (syslogPollRef.current) clearInterval(syslogPollRef.current);
    };
  }, []);


//EXTRACT IPA  
async function extractIPA(bundleId: string) {
  setExtracting(bundleId);
  try {
    
    const detailsRes = await axios.get(`${API}/apps/${encodeURIComponent(bundleId)}`);
    const bundlePath = detailsRes.data?.bundlePath;

    if (!bundlePath) {
      alert('❌ Could not find app bundle path');
      setExtracting(null);
      return;
    }

    const res = await axios.post(`${API}/extract-ipa`, { bundleId, bundlePath });
    
    if (res.data.success) {
      alert(`✅ IPA extracted!\n\nFile: ${res.data.filename}\nSize: ${res.data.sizeMB} MB`);
      await fetchExtractedIPAs();
    } else {
      alert(`❌ ${res.data.error}`);
    }
  } catch (e: any) {
    alert(`❌ ${e.response?.data?.error || e.message}`);
  } finally {
    setExtracting(null);
  }
}

async function fetchExtractedIPAs() {
  try {
    const res = await axios.get(`${API}/extracted-ipas`);
    setExtractedIPAs(res.data || []);
  } catch {}
}

	async function deleteIPA(filename: string) {
	  try {
	    await axios.delete(`${API}/extracted-ipas/${encodeURIComponent(filename)}`);
	    setExtractedIPAs(prev => prev.filter(f => f.filename !== filename));
	  } catch (e: any) {
	    alert(`❌ ${e.response?.data?.error || e.message}`);
	  }
	}

	async function clearAllIPAs() {
	  if (!confirm('Delete all extracted IPAs?')) return;
	  try {
	    await axios.delete(`${API}/extracted-ipas`);
	    setExtractedIPAs([]);
	  } catch (e: any) {
	    alert(`❌ ${e.response?.data?.error || e.message}`);
	  }
	}

	function downloadIPA(url: string, filename: string) {
	  const a = document.createElement('a');
	  a.href = url;
	  a.download = filename;
	  a.click();
	}

  async function checkStatus() {
    try {
      const res = await axios.get(`${API}/status`);
      setStatus(res.data);

      if (res.data.udid || res.data.jailbroken) {
        fetchDeviceInfo();
        fetchApps();
      }
    } catch {}
  }

  async function fetchDeviceInfo() {
    try {
      const res = await axios.get(`${API}/info`);
      setDeviceInfo(res.data);
    } catch {}
  }

  async function fetchApps() {
    try {
      const res = await axios.get(`${API}/apps`);
      setApps(res.data || []);
    } catch {}
  }

async function selectApp(app: UserApp) {
  setSelectedApp(app);
  setAppDetails(null);
  
  try {
    const res = await axios.get(`${API}/apps/${encodeURIComponent(app.bundleId)}`);
    if (res.data && res.data.bundleId) {
      setAppDetails(res.data);
    }
  } catch (e: any) {
    console.error('Error:', e.response?.data?.error || e.message);
  }
}

  async function executeSSH() {
    if (!sshCommand.trim()) return;

    setSSHRunning(true);
    const prefix = runAsRoot ? '# ' : '$ ';
    setSSHOutput(prev => [...prev, `${prefix}${sshCommand}`]);

    try {
      const res = await axios.post(`${API}/ssh/shell`, { 
        command: sshCommand,
        asRoot: runAsRoot 
      });
      setSSHOutput(prev => [...prev, res.data.output || '(no output)']);
    } catch (e: any) {
      setSSHOutput(prev => [...prev, `Error: ${e.response?.data?.error || e.message}`]);
    } finally {
      setSSHCommand('');
      setSSHRunning(false);
    }
  }

  async function startSyslog() {
    try {
      await axios.post(`${API}/syslog/start`, { bundleId: syslogFilter || undefined });
      setSyslogRunning(true);
      setSyslogLogs([]);
      syslogIndexRef.current = 0;

      syslogPollRef.current = setInterval(async () => {
        try {
          const res = await axios.get(`${API}/syslog/logs`, {
            params: { since: syslogIndexRef.current }
          });
          if (res.data.logs?.length > 0) {
            setSyslogLogs(prev => [...prev, ...res.data.logs].slice(-1000));
            syslogIndexRef.current = res.data.newIndex;
          }
        } catch {}
      }, 500);
    } catch {}
  }

  async function stopSyslog() {
    await axios.post(`${API}/syslog/stop`);
    setSyslogRunning(false);
    if (syslogPollRef.current) {
      clearInterval(syslogPollRef.current);
      syslogPollRef.current = null;
    }
  }

  async function takeScreenshot() {
    try {
      const res = await axios.get(`${API}/screenshot`);
      if (res.data.success) {
        setScreenshot(res.data.image);
      } else {
        alert('❌ ' + (res.data.error || 'Screenshot failed'));
      }
    } catch (e: any) {
      alert('❌ ' + (e.response?.data?.error || e.message));
    }
  }

  async function fetchFiles(path: string) {
    try {
      const res = await axios.post(`${API}/file/list`, { path });
      setFiles(res.data || []);
      setFilePath(path);
    } catch (e: any) {
      alert('❌ ' + (e.response?.data?.error || e.message));
    }
  }

  function navigateToDir(name: string) {
    const newPath = filePath === '/' ? `/${name}` : `${filePath}/${name}`;
    fetchFiles(newPath);
  }

  function navigateUp() {
    const parts = filePath.split('/').filter(Boolean);
    parts.pop();
    fetchFiles('/' + parts.join('/') || '/');
  }

  async function runKeychain() {
    setSecurityLoading(true);
    setSecurityOutput('');
    try {
      const res = await axios.post(`${API}/security/keychain`, {
        bundleId: selectedApp?.bundleId
      });
      setSecurityOutput(res.data.output || res.data.error || 'No output');
    } catch (e: any) {
      setSecurityOutput(`Error: ${e.response?.data?.error || e.message}`);
    } finally {
      setSecurityLoading(false);
    }
  }

  async function runStrings() {
    if (!selectedApp || !appDetails) return;
    setSecurityLoading(true);
    setSecurityOutput('');
    try {
      const binaryPath = `${appDetails.paths.bundle}/${selectedApp.executable || selectedApp.name}`;
      const res = await axios.post(`${API}/security/strings`, { binaryPath });
      
      let output = `Total strings: ${res.data.totalStrings}\n`;
      output += `\n=== Sensitive Strings (${res.data.sensitiveStrings?.length || 0}) ===\n`;
      output += res.data.sensitiveStrings?.join('\n') || 'None found';
      
      setSecurityOutput(output);
    } catch (e: any) {
      setSecurityOutput(`Error: ${e.response?.data?.error || e.message}`);
    } finally {
      setSecurityLoading(false);
    }
  }

  async function runBinaryInfo() {
    if (!selectedApp || !appDetails) return;
    setSecurityLoading(true);
    setSecurityOutput('');
    try {
      const binaryPath = `${appDetails.paths.bundle}/${selectedApp.executable || selectedApp.name}`;
      const res = await axios.post(`${API}/security/binary-info`, { binaryPath });
      
      let output = `=== Binary Analysis ===\n`;
      output += `File: ${res.data.file || 'Unknown'}\n\n`;
      output += `PIE (ASLR): ${res.data.pie ? '✅ Enabled' : '❌ Disabled'}\n`;
      output += `Encrypted: ${res.data.encrypted ? '✅ Yes' : '❌ No'}\n`;
      output += `Stack Canary: ${res.data.stackCanary ? '✅ Enabled' : '❌ Disabled'}\n`;
      output += `ARC: ${res.data.arc ? '✅ Enabled' : '⚠️ Not detected'}\n`;
      output += `\n=== Frameworks (${res.data.frameworks?.length || 0}) ===\n`;
      output += res.data.frameworks?.slice(0, 20).join('\n') || 'None';
      
      setSecurityOutput(output);
    } catch (e: any) {
      setSecurityOutput(`Error: ${e.response?.data?.error || e.message}`);
    } finally {
      setSecurityLoading(false);
    }
  }

  async function runNSUserDefaults() {
    if (!selectedApp) return;
    setSecurityLoading(true);
    setSecurityOutput('');
    try {
      const res = await axios.post(`${API}/security/nsuserdefaults`, {
        bundleId: selectedApp.bundleId
      });
      setSecurityOutput(res.data.output || res.data.error || 'No preferences found');
    } catch (e: any) {
      setSecurityOutput(`Error: ${e.response?.data?.error || e.message}`);
    } finally {
      setSecurityLoading(false);
    }
  }

  async function runCookies() {
    setSecurityLoading(true);
    setSecurityOutput('');
    try {
      const res = await axios.post(`${API}/security/cookies`, {
        bundleId: selectedApp?.bundleId
      });
      setSecurityOutput(res.data.cookies?.join('\n\n') || 'No cookies found');
    } catch (e: any) {
      setSecurityOutput(`Error: ${e.response?.data?.error || e.message}`);
    } finally {
      setSecurityLoading(false);
    }
  }

  async function runSQLite(dbPath: string, query?: string) {
    setSecurityLoading(true);
    setSecurityOutput('');
    try {
      const res = await axios.post(`${API}/security/sqlite`, { dbPath, query });
      setSecurityOutput(`Query: ${res.data.query}\nPath: ${res.data.path}\n\n${res.data.output}`);
    } catch (e: any) {
      setSecurityOutput(`Error: ${e.response?.data?.error || e.message}`);
    } finally {
      setSecurityLoading(false);
    }
  }

  async function readPlist(path: string) {
    setSecurityLoading(true);
    setSecurityOutput('');
    try {
      const res = await axios.post(`${API}/security/plist`, { path });
      setSecurityOutput(res.data.output || 'Empty or invalid plist');
    } catch (e: any) {
      setSecurityOutput(`Error: ${e.response?.data?.error || e.message}`);
    } finally {
      setSecurityLoading(false);
    }
  }

  const isConnected = status?.udid || status?.jailbroken;
  const isSSH = status?.connectionType === 'ssh';
  const isRootless = status?.rootless;

  if (!isConnected) {
    return (
      <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-12 text-center">
        <div className="w-24 h-24 bg-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
          <span className="text-5xl">🍎</span>
        </div>
        <h2 className="text-2xl font-bold text-white mb-3">No iOS Device Connected</h2>
        <p className="text-gray-400 max-w-md mx-auto mb-6">
          Connect an iOS device via USB or SSH in Settings to get started.
        </p>
          <a
          href="/settings"
          className="inline-block px-6 py-3 bg-blue-600 hover:bg-blue-700 rounded-xl text-white font-semibold transition"
        >
          ⚙️ Go to Settings
        </a>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span className="text-2xl">🍎</span>
            iOS Device
          </h2>

          <div className="flex items-center gap-3">
            <span className={`px-3 py-1 rounded-full text-xs font-medium ${
              isSSH ? 'bg-orange-500/20 text-orange-400' : 'bg-blue-500/20 text-blue-400'
            }`}>
              {isSSH ? '🔐 SSH' : '🔌 USB'}
            </span>
            {isRootless && (
              <span className="px-3 py-1 rounded-full text-xs font-medium bg-purple-500/20 text-purple-400">
                Rootless
              </span>
            )}
            <button
              onClick={takeScreenshot}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white transition"
            >
              📸 Screenshot
            </button>
          </div>
        </div>

        {deviceInfo && (
          <div className="flex items-center gap-4 p-3 bg-gray-900/50 rounded-xl">
            <span className="text-3xl">📱</span>
            <div>
              <p className="text-white font-medium">
                {deviceInfo.name || deviceInfo.hostname || 'iOS Device'}
              </p>
              <p className="text-sm text-gray-400">
                {deviceInfo.model || deviceInfo.architecture} • iOS {deviceInfo.version}
                {deviceInfo.jailbreakType && ` • ${deviceInfo.jailbreakType}`}
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2">
        {['info', 'apps', 'extract', 'security', 'shell', 'syslog', 'files'].map(tab => (
          <button
            key={tab}
            onClick={() => {
              setActiveTab(tab as any);
              if (tab === 'files' && isSSH) fetchFiles('/');
            }}
            disabled={(tab === 'shell' || tab === 'security' || tab === 'files') && !isSSH}
            className={`px-4 py-2 rounded-lg font-medium transition ${
              activeTab === tab
                ? 'bg-blue-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700 disabled:opacity-50'
            }`}
          >
            {tab === 'info' && '📱 Info'}
            {tab === 'apps' && '📦 Apps'}
            {tab === 'extract' && '📤 Extract'}
            {tab === 'security' && '🔒 Security'}
            {tab === 'shell' && '🔐 Shell'}
            {tab === 'syslog' && '📋 Syslog'}
            {tab === 'files' && '📁 Files'}
          </button>
        ))}
      </div>

      {/* Info Tab */}
      {activeTab === 'info' && deviceInfo && (
        <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Device Information</h3>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            {Object.entries(deviceInfo).map(([key, value]) => (
              <div key={key} className="bg-gray-900 rounded-lg p-3">
                <div className="text-xs text-gray-500 uppercase">{key}</div>
                <div className="text-white font-mono text-sm truncate">{String(value)}</div>
              </div>
            ))}
          </div>
          {screenshot && (
            <div className="mt-6">
              <h4 className="text-sm font-medium text-gray-400 mb-2">Screenshot</h4>
              <img src={screenshot} alt="Screenshot" className="max-w-xs rounded-lg border border-gray-700" />
            </div>
          )}
        </div>
      )}

	{/* Apps Tab */}
	{activeTab === 'apps' && (
	  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
	    {/* App List */}
	    <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
	      <div className="flex items-center justify-between mb-4">
		<h3 className="text-lg font-semibold text-white">User Apps ({apps.length})</h3>
		<button
		  onClick={fetchApps}
		  className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-white"
		>
		  🔄
		</button>
	      </div>
	      <div className="space-y-2 max-h-[500px] overflow-y-auto">
		{apps.length === 0 ? (
		  <p className="text-gray-500 text-center py-4">No apps found</p>
		) : (
		  apps.map((app, i) => (
		    <div
		      key={i}
		      onClick={() => selectApp(app)}
		      className={`p-3 rounded-lg cursor-pointer transition ${
		        selectedApp?.bundleId === app.bundleId
		          ? 'bg-blue-600/20 border border-blue-500/50'
		          : 'bg-gray-900 hover:bg-gray-800'
		      }`}
		    >
		      <div className="flex items-center justify-between">
		        <div className="min-w-0 flex-1">
		          <div className="text-white font-medium truncate">{app.name}</div>
		          <div className="text-xs text-gray-500 font-mono truncate">{app.bundleId}</div>
		          {app.version && (
		            <div className="text-xs text-gray-400 mt-1">v{app.version}</div>
		          )}
		        </div>
		        {/* Extract IPA Button */}
		        {isSSH && (
		          <button
		            onClick={(e) => {
		              e.stopPropagation();
		              extractIPA(app.bundleId);
		            }}
		            disabled={extracting === app.bundleId}
		            className="ml-2 px-2 py-1 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 rounded text-xs text-white flex-shrink-0"
		            title="Extract IPA"
		          >
		            {extracting === app.bundleId ? '⏳' : '📤'}
		          </button>
		        )}
		      </div>
		    </div>
		  ))
		)}
	      </div>
	    </div>

	    {/* App Details */}
	    <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
	      <h3 className="text-lg font-semibold text-white mb-4">App Details</h3>
	      {selectedApp && appDetails ? (
		<div className="space-y-4">
		  <div className="p-3 bg-gray-900 rounded-lg">
		    <div className="text-white font-medium mb-2">{selectedApp.name}</div>
		    <div className="text-xs text-gray-400 font-mono">{selectedApp.bundleId}</div>
		    {appDetails.version && (
		      <div className="text-xs text-gray-500 mt-1">v{appDetails.version}</div>
		    )}
		  </div>

		  {appDetails.paths && Object.keys(appDetails.paths).length > 0 && (
		    <div className="space-y-2">
		      <p className="text-sm text-gray-400">Paths:</p>
		      {Object.entries(appDetails.paths).map(([key, value]) => (
		        value && (
		          <div
		            key={key}
		            onClick={() => {
		              setFilePath(value as string);
		              setActiveTab('files');
		              fetchFiles(value as string);
		            }}
		            className="p-2 bg-gray-900 rounded-lg cursor-pointer hover:bg-gray-800"
		          >
		            <div className="text-xs text-gray-500 uppercase">{key}</div>
		            <div className="text-xs text-blue-400 font-mono truncate">{value as string}</div>
		          </div>
		        )
		      ))}
		    </div>
		  )}

		  <div className="flex flex-wrap gap-2 pt-2">
		    {/* Extract IPA Button in Details */}
		    {isSSH && (
		      <button
		        onClick={() => extractIPA(selectedApp.bundleId)}
		        disabled={extracting === selectedApp.bundleId}
		        className="px-3 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 rounded-lg text-sm text-white"
		      >
		        {extracting === selectedApp.bundleId ? '⏳ Extracting...' : '📤 Extract IPA'}
		      </button>
		    )}
		    {appDetails.dataPath && (
		      <>
		        <button
		          onClick={() => {
		            setFilePath(appDetails.dataPath);
		            setActiveTab('files');
		            fetchFiles(appDetails.dataPath);
		          }}
		          className="px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm text-white"
		        >
		          📁 Browse Data
		        </button>
		        <button
		          onClick={() => {
		            setFilePath(`${appDetails.dataPath}/Documents`);
		            setActiveTab('files');
		            fetchFiles(`${appDetails.dataPath}/Documents`);
		          }}
		          className="px-3 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg text-sm text-white"
		        >
		          📄 Documents
		        </button>
		        <button
		          onClick={() => {
		            setFilePath(`${appDetails.dataPath}/Library`);
		            setActiveTab('files');
		            fetchFiles(`${appDetails.dataPath}/Library`);
		          }}
		          className="px-3 py-2 bg-orange-600 hover:bg-orange-700 rounded-lg text-sm text-white"
		        >
		          📚 Library
		        </button>
		      </>
		    )}
		    {appDetails.bundlePath && (
		      <button
		        onClick={() => {
		          setFilePath(appDetails.bundlePath);
		          setActiveTab('files');
		          fetchFiles(appDetails.bundlePath);
		        }}
		        className="px-3 py-2 bg-cyan-600 hover:bg-cyan-700 rounded-lg text-sm text-white"
		      >
		        📦 Bundle
		      </button>
		    )}
		  </div>
		</div>
	      ) : (
		<p className="text-gray-500 text-center py-8">Select an app to view details</p>
	      )}
	    </div>
	  </div>
	)}
      
	{/* Extract Tab */}
	{activeTab === 'extract' && (
	  <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
	    <div className="flex items-center justify-between mb-6">
	      <h3 className="text-lg font-semibold text-white flex items-center gap-2">
		<span className="text-2xl">📤</span>
		Extract IPA
	      </h3>
	      <button
		onClick={fetchExtractedIPAs}
		className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-white"
	      >
		🔄
	      </button>
	    </div>

	    {!isSSH ? (
	      <div className="text-center py-8 text-gray-500">
		<p>IPA extraction requires SSH connection to jailbroken device.</p>
	      </div>
	    ) : (
	      <>
		{/* App selector */}
		<div className="mb-6">
		  <p className="text-sm text-gray-400 mb-3">Select an app to extract:</p>
		  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 max-h-[300px] overflow-y-auto">
		    {apps.map((app, i) => (
		      <div
		        key={i}
		        className="flex items-center justify-between p-3 bg-gray-900 rounded-lg"
		      >
		        <div className="min-w-0 flex-1">
		          <div className="text-white text-sm font-medium truncate">{app.name}</div>
		          <div className="text-xs text-gray-500 truncate">{app.bundleId}</div>
		        </div>
		        <button
		          onClick={() => extractIPA(app.bundleId)}
		          disabled={extracting !== null}
		          className="ml-2 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 rounded-lg text-white text-sm flex items-center gap-1"
		        >
		          {extracting === app.bundleId ? (
		            <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
		          ) : (
		            '📤'
		          )}
		        </button>
		      </div>
		    ))}
		  </div>
		  {apps.length === 0 && (
		    <p className="text-gray-500 text-center py-4">
		      No apps loaded. Go to Apps tab and refresh.
		    </p>
		  )}
		</div>

		{/* Extracted IPAs */}
		{extractedIPAs.length > 0 && (
		  <div>
		    <div className="flex items-center justify-between mb-3">
		      <h4 className="text-sm font-medium text-gray-400">
		        Extracted IPAs ({extractedIPAs.length})
		      </h4>
		      <button
		        onClick={clearAllIPAs}
		        className="px-2 py-1 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded text-xs"
		      >
		        🗑️ Clear All
		      </button>
		    </div>
		    <div className="space-y-2">
		      {extractedIPAs.map((ipa, i) => (
		        <div
		          key={i}
		          className="flex items-center justify-between p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg"
		        >
		          <div className="flex items-center gap-3">
		            <span className="text-2xl">📦</span>
		            <div>
		              <p className="text-white font-medium">{ipa.filename}</p>
		              <p className="text-xs text-gray-400">{ipa.sizeMB} MB</p>
		            </div>
		          </div>
		          <div className="flex gap-2">
		            <button
		              onClick={() => downloadIPA(ipa.downloadUrl, ipa.filename)}
		              className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 rounded-lg text-white text-sm"
		            >
		              ⬇️ Download
		            </button>
		            <button
		              onClick={() => deleteIPA(ipa.filename)}
		              className="px-2 py-1.5 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg text-sm"
		            >
		              🗑️
		            </button>
		          </div>
		        </div>
		      ))}
		    </div>
		  </div>
		)}

		{/* Info */}
		<div className="mt-6 p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-lg">
		  <p className="text-sm text-cyan-300">
		    💡 <strong>How it works:</strong> The .app bundle is copied and zipped into an IPA file on the device, then transferred to the server for download.
		  </p>
		</div>
	      </>
	    )}
	  </div>
	)}
      {/* Security Tab */}
      {activeTab === 'security' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Security Tools */}
          <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Security Tools</h3>

            {selectedApp && (
              <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg mb-4">
                <div className="text-sm text-blue-300">Selected App:</div>
                <div className="text-white font-medium truncate">{selectedApp.name}</div>
              </div>
            )}

            <div className="space-y-2">
              <button
                onClick={runKeychain}
                disabled={securityLoading}
                className="w-full px-4 py-3 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-lg text-white font-medium text-left flex items-center gap-2"
              >
                🔑 Keychain Dump
              </button>

              <button
                onClick={runNSUserDefaults}
                disabled={securityLoading || !selectedApp}
                className="w-full px-4 py-3 bg-orange-600 hover:bg-orange-700 disabled:opacity-50 rounded-lg text-white font-medium text-left flex items-center gap-2"
              >
                📝 NSUserDefaults
              </button>

              <button
                onClick={runStrings}
                disabled={securityLoading || !selectedApp || !appDetails}
                className="w-full px-4 py-3 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 rounded-lg text-white font-medium text-left flex items-center gap-2"
              >
                🔤 Extract Strings
              </button>

              <button
                onClick={runBinaryInfo}
                disabled={securityLoading || !selectedApp || !appDetails}
                className="w-full px-4 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:opacity-50 rounded-lg text-white font-medium text-left flex items-center gap-2"
              >
                🔍 Binary Analysis
              </button>

              <button
                onClick={runCookies}
                disabled={securityLoading}
                className="w-full px-4 py-3 bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 rounded-lg text-white font-medium text-left flex items-center gap-2"
              >
                🍪 Cookies
              </button>
            </div>

            <div className="mt-4 p-3 bg-gray-900 rounded-lg">
              <p className="text-xs text-gray-400 mb-2">Quick Actions:</p>
              <div className="flex flex-wrap gap-2">
                {[
                  { label: 'Safari Cookies', action: () => runCookies() },
                  { label: 'All Keychain', action: () => runKeychain() },
                ].map(({ label, action }) => (
                  <button
                    key={label}
                    onClick={action}
                    disabled={securityLoading}
                    className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded text-xs text-gray-300"
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Output */}
          <div className="lg:col-span-2 bg-[#12121a] border border-gray-800 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Output</h3>
              {securityLoading && (
                <div className="flex items-center gap-2 text-cyan-400">
                  <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin"></div>
                  Running...
                </div>
              )}
            </div>

            <div className="bg-black rounded-xl p-4 h-[500px] overflow-auto font-mono text-xs">
              {securityOutput ? (
                <pre className="text-gray-300 whitespace-pre-wrap">{securityOutput}</pre>
              ) : (
                <p className="text-gray-500">
                  Select a tool to run security analysis.
                  {!selectedApp && '\n\nTip: Select an app in the Apps tab for app-specific analysis.'}
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Shell Tab */}
      {activeTab === 'shell' && (
        <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">SSH Shell</h3>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={runAsRoot}
                onChange={e => setRunAsRoot(e.target.checked)}
                className="w-4 h-4 rounded"
              />
              <span className="text-sm text-orange-400">Run as root (sudo)</span>
            </label>
          </div>

          <div className="bg-black rounded-xl p-4 h-[300px] overflow-auto font-mono text-sm mb-4">
            {sshOutput.length === 0 ? (
              <p className="text-gray-500">Shell output will appear here...</p>
            ) : (
              sshOutput.map((line, i) => (
                <div key={i} className={`py-0.5 whitespace-pre-wrap ${
                  line.startsWith('#') ? 'text-orange-400' :
                  line.startsWith('$') ? 'text-cyan-400' :
                  line.startsWith('Error') ? 'text-red-400' :
                  'text-gray-300'
                }`}>
                  {line}
                </div>
              ))
            )}
          </div>

          <div className="flex gap-2">
            <input
              placeholder="Enter command..."
              value={sshCommand}
              onChange={e => setSSHCommand(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && executeSSH()}
              disabled={sshRunning}
              className="flex-1 p-3 bg-gray-900 border border-gray-700 rounded-lg text-white font-mono disabled:opacity-50"
            />
            <button
              onClick={executeSSH}
              disabled={sshRunning}
              className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:opacity-50 rounded-lg text-white font-semibold"
            >
              {sshRunning ? '⏳' : '▶️ Run'}
            </button>
            <button
              onClick={() => setSSHOutput([])}
              className="px-4 py-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-white"
            >
              🗑️
            </button>
          </div>

          <div className="mt-4 flex flex-wrap gap-2">
            {[
              { cmd: 'uname -a', label: 'uname' },
              { cmd: 'sw_vers', label: 'iOS version' },
              { cmd: 'whoami', label: 'whoami' },
              { cmd: 'id', label: 'id' },
              { cmd: 'ls /var/jb 2>/dev/null || echo "Not rootless"', label: 'check rootless' },
              { cmd: 'dpkg -l | wc -l', label: 'pkg count' },
              { cmd: 'ps aux | head -20', label: 'processes' },
              { cmd: 'df -h', label: 'disk space' },
              { cmd: 'cat /etc/passwd', label: '/etc/passwd' },
            ].map(({ cmd, label }) => (
              <button
                key={cmd}
                onClick={() => setSSHCommand(cmd)}
                className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded-lg text-xs text-gray-300 font-mono"
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Syslog Tab */}
      {activeTab === 'syslog' && (
        <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4">System Log</h3>

          <div className="flex gap-4 mb-4">
            <input
              placeholder="Filter by bundle ID (optional)"
              value={syslogFilter}
              onChange={e => setSyslogFilter(e.target.value)}
              disabled={syslogRunning}
              className="flex-1 p-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
            />
            {!syslogRunning ? (
              <button
                onClick={startSyslog}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 rounded-lg text-white font-semibold"
              >
                ▶️ Start
              </button>
            ) : (
              <button
                onClick={stopSyslog}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-white font-semibold"
              >
                ⏹️ Stop
              </button>
            )}
          </div>

          <div className="bg-black rounded-xl p-4 h-[400px] overflow-auto font-mono text-xs">
            {syslogLogs.length === 0 ? (
              <p className="text-gray-500">Syslog output will appear here...</p>
            ) : (
              syslogLogs.map((line, i) => (
                <div key={i} className="py-0.5 text-gray-300 whitespace-pre-wrap">
                  {line}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Files Tab */}
      {activeTab === 'files' && (
        <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4">File System</h3>

          {!isSSH ? (
            <div className="text-center py-8 text-gray-500">
              <p>File browser requires SSH connection.</p>
            </div>
          ) : (
            <>
              <div className="flex items-center gap-2 mb-4">
                <button
                  onClick={navigateUp}
                  disabled={filePath === '/'}
                  className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-white disabled:opacity-50"
                >
                  ⬆️
                </button>
                <input
                  value={filePath}
                  onChange={e => setFilePath(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && fetchFiles(filePath)}
                  className="flex-1 p-2 bg-gray-900 border border-gray-700 rounded-lg text-white font-mono text-sm"
                />
                <button
                  onClick={() => fetchFiles(filePath)}
                  className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-white"
                >
                  🔄
                </button>
              </div>

              {/* Quick paths */}
              <div className="flex flex-wrap gap-2 mb-4">
                {[
                  { path: '/', label: '/' },
                  { path: '/var/mobile', label: '/var/mobile' },
                  { path: '/var/containers/Bundle/Application', label: 'App Bundles' },
                  { path: '/var/mobile/Containers/Data/Application', label: 'App Data' },
                  { path: '/var/jb', label: '/var/jb (rootless)' },
                ].map(({ path, label }) => (
                  <button
                    key={path}
                    onClick={() => fetchFiles(path)}
                    className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded text-xs text-gray-300"
                  >
                    {label}
                  </button>
                ))}
              </div>

              <div className="space-y-1 max-h-[400px] overflow-y-auto">
                {files.length === 0 ? (
                  <p className="text-gray-500 text-center py-4">Empty or not loaded</p>
                ) : (
                  files.map((file, i) => (
                    <div
                      key={i}
                      onClick={() => file.isDirectory && navigateToDir(file.name)}
                      className={`flex items-center justify-between p-2 rounded-lg ${
                        file.isDirectory
                          ? 'bg-gray-900 hover:bg-gray-800 cursor-pointer'
                          : 'bg-gray-900/50'
                      }`}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span>
                          {file.isSymlink ? '🔗' : file.isDirectory ? '📁' : '📄'}
                        </span>
                        <span className="text-white font-mono text-sm truncate">{file.name}</span>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-gray-500 shrink-0">
                        <span className="font-mono">{file.permissions}</span>
                        <span>{file.size}</span>
                        {!file.isDirectory && (
                          <button
                            onClick={e => {
                              e.stopPropagation();
                              const fullPath = filePath === '/' ? `/${file.name}` : `${filePath}/${file.name}`;
                              if (file.name.endsWith('.plist')) {
                                readPlist(fullPath);
                                setActiveTab('security');
                              } else if (file.name.endsWith('.db') || file.name.endsWith('.sqlite')) {
                                runSQLite(fullPath);
                                setActiveTab('security');
                              }
                            }}
                            className="px-2 py-0.5 bg-blue-600 hover:bg-blue-700 rounded text-white"
                          >
                            View
                          </button>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
