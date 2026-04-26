import { useEffect, useState } from "react";
import axios from "axios";

const ADB_API = "/api/v1/adb";
const IOS_API = "/api/v1/ios";

export default function Settings() {
  const [activeTab, setActiveTab] = useState<'android' | 'ios'>('android');

  // ==================== ANDROID STATE ====================
  const [adbDevices, setAdbDevices] = useState<any[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'checking'>('disconnected');
  const [deviceInfo, setDeviceInfo] = useState<any>(null);
  
  const [config, setConfig] = useState({
    deviceId: "",
    wireless: false,
    adbRunning: true,
  });

  const [wifiIp, setWifiIp] = useState("");
  const [wifiPort, setWifiPort] = useState("5555");
  const [connecting, setConnecting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  // ==================== iOS STATE ====================
  const [iosConnectionMode, setIosConnectionMode] = useState<'usb' | 'ssh'>(() => {
    return (localStorage.getItem('ios_connection_mode') as 'usb' | 'ssh') || 'usb';
  });
  const [iosDevices, setIosDevices] = useState<any[]>([]);
  const [iosSelectedDevice, setIosSelectedDevice] = useState('');
  const [iosDeviceInfo, setIosDeviceInfo] = useState<any>(null);
  const [iosConnectionStatus, setIosConnectionStatus] = useState<'connected' | 'disconnected' | 'checking'>('disconnected');
  const [iosRefreshing, setIosRefreshing] = useState(false);

  const [iosSSHConfig, setIosSSHConfig] = useState({
    host: localStorage.getItem('ios_ssh_host') || '',
    port: parseInt(localStorage.getItem('ios_ssh_port') || '22'),
    user: localStorage.getItem('ios_ssh_user') || 'mobile',
    password: localStorage.getItem('ios_ssh_password') || '',
  });
  const [iosSSHConnected, setIosSSHConnected] = useState(false);
  const [iosSSHConnecting, setIosSSHConnecting] = useState(false);

  // ==================== EFFECTS ====================
  useEffect(() => {
    localStorage.setItem('ios_connection_mode', iosConnectionMode);
    localStorage.setItem('ios_ssh_host', iosSSHConfig.host);
    localStorage.setItem('ios_ssh_port', String(iosSSHConfig.port));
    localStorage.setItem('ios_ssh_user', iosSSHConfig.user);
    localStorage.setItem('ios_ssh_password', iosSSHConfig.password);
  }, [iosConnectionMode, iosSSHConfig]);

  useEffect(() => {
    checkIosStatus();
  }, []);

  // ==================== iOS FUNCTIONS ====================
  async function checkIosStatus() {
    try {
      const res = await axios.get(`${IOS_API}/status`);
      if (res.data.connectionType === 'ssh' && res.data.jailbroken) {
        setIosSSHConnected(true);
        setIosConnectionMode('ssh');
        setIosConnectionStatus('connected');
        setIosDeviceInfo(res.data.deviceInfo);
      } else if (res.data.udid) {
        setIosSelectedDevice(res.data.udid);
        setIosConnectionStatus('connected');
        setIosDeviceInfo(res.data.deviceInfo);
      }
    } catch {}
  }

  async function fetchIosDevices() {
    try {
      setIosRefreshing(true);
      const res = await axios.get(`${IOS_API}/devices`);
      setIosDevices(res.data || []);
    } catch {
      setIosDevices([]);
    } finally {
      setIosRefreshing(false);
    }
  }

  async function selectIosDevice(udid: string) {
    setIosSelectedDevice(udid);
    
    if (!udid) {
      setIosDeviceInfo(null);
      setIosConnectionStatus('disconnected');
      return;
    }
    
    try {
      setIosConnectionStatus('checking');
      await axios.post(`${IOS_API}/select`, { udid, connectionType: 'usb' });
      const res = await axios.get(`${IOS_API}/info`);
      setIosDeviceInfo(res.data);
      setIosConnectionStatus('connected');
      setIosConnectionMode('usb');
    } catch (e) {
      console.error('Error selecting iOS device:', e);
      setIosConnectionStatus('disconnected');
      setIosDeviceInfo(null);
    }
  }

  async function connectIosSSH() {
    if (!iosSSHConfig.host) {
      alert('⚠️ Enter SSH host/IP');
      return;
    }

    setIosSSHConnecting(true);
    try {
      const res = await axios.post(`${IOS_API}/ssh/connect`, iosSSHConfig);
      
      if (res.data.success) {
        setIosSSHConnected(true);
        setIosConnectionStatus('connected');
        setIosConnectionMode('ssh');
        setIosDeviceInfo(res.data.deviceInfo);
        
        let msg = `✅ Connected!\n`;
        msg += `User: ${res.data.user || iosSSHConfig.user}\n`;
        msg += `Jailbreak: ${res.data.jailbreakType || 'Unknown'}\n`;
        if (res.data.rootless) msg += `Mode: Rootless\n`;
        if (res.data.hasSudo) msg += `Sudo: Available\n`;
        
        alert(msg);
      } else {
        alert(`❌ Failed: ${res.data.error}`);
      }
    } catch (e: any) {
      alert(`❌ Error: ${e.response?.data?.error || e.message}`);
    } finally {
      setIosSSHConnecting(false);
    }
  }

  async function disconnectIosSSH() {
    try {
      await axios.post(`${IOS_API}/ssh/disconnect`);
      setIosSSHConnected(false);
      setIosConnectionStatus('disconnected');
      setIosDeviceInfo(null);
    } catch {}
  }

  // ==================== ANDROID FUNCTIONS ====================
  async function fetchAdbDevices() {
    try {
      setRefreshing(true);
      const res = await axios.get(`${ADB_API}/devices`);
      setAdbDevices(res.data || []);
    } catch {
      setAdbDevices([]);
    } finally {
      setRefreshing(false);
    }
  }

  async function fetchAdbConfig() {
    try {
      const res = await axios.get(`${ADB_API}/config`);
      if (res.data) {
        setConfig(prev => ({ ...prev, ...res.data }));
        if (res.data.deviceId && res.data.deviceId.includes(':')) {
          const [ip, port] = res.data.deviceId.split(':');
          setWifiIp(ip);
          setWifiPort(port || '5555');
        }
      }
      await fetchAdbDevices();
    } catch {}
  }

  async function checkAdbConnection() {
    if (!config.deviceId) {
      setConnectionStatus('disconnected');
      setDeviceInfo(null);
      return;
    }
    try {
      setConnectionStatus('checking');
      const res = await axios.get(`${ADB_API}/device-info`);
      if (res.data?.connected) {
        setConnectionStatus('connected');
        setDeviceInfo(res.data);
      } else {
        setConnectionStatus('disconnected');
        setDeviceInfo(null);
      }
    } catch {
      setConnectionStatus('disconnected');
      setDeviceInfo(null);
    }
  }

  async function saveAdbConfig() {
    try {
      setSaving(true);
      await axios.post(`${ADB_API}/config`, config);
      alert("✅ Settings saved!");
    } catch {
      alert("❌ Error saving settings");
    } finally {
      setSaving(false);
    }
  }

  async function testAdbConnection() {
    if (!config.deviceId) return alert("⚠️ Select or connect a device first");
    try {
      setTesting(true);
      await axios.post(`${ADB_API}/config`, config);
      const res = await axios.post(`${ADB_API}/connect`);
      if (res.data.connected) {
        await checkAdbConnection();
        alert("✅ Device connected!");
      } else {
        setConnectionStatus('disconnected');
        setDeviceInfo(null);
        alert("❌ Device not responding");
      }
    } catch (e: any) {
      setConnectionStatus('disconnected');
      alert("❌ Connection failed: " + (e.response?.data?.error || e.message));
    } finally {
      setTesting(false);
    }
  }

  async function toggleAdbServer() {
    try {
      const newState = !config.adbRunning;
      setConfig(prev => ({ ...prev, adbRunning: newState }));
      await axios.post(`${ADB_API}/adb-toggle`, { running: newState });
      if (newState) setTimeout(fetchAdbDevices, 1500);
    } catch {
      alert("❌ Failed to toggle ADB");
    }
  }

  async function connectWifi() {
    if (!wifiIp.trim()) return alert("⚠️ Enter device IP address");
    try {
      setConnecting(true);
      const res = await axios.post(`${ADB_API}/wireless-connect`, {
        ip: wifiIp.trim(),
        port: parseInt(wifiPort) || 5555
      });
      if (res.data.success) {
        setConfig(prev => ({ ...prev, deviceId: res.data.deviceId, wireless: true }));
        await fetchAdbDevices();
        await checkAdbConnection();
        alert(`✅ Connected to ${res.data.deviceId}`);
      } else {
        alert("❌ " + (res.data.error || "Connection failed"));
      }
    } catch (e: any) {
      alert("❌ " + (e.response?.data?.error || e.message));
    } finally {
      setConnecting(false);
    }
  }

  async function disconnectWifi() {
    try {
      setConnecting(true);
      await axios.post(`${ADB_API}/wireless-disconnect`, {
        ip: wifiIp.trim(),
        port: parseInt(wifiPort) || 5555
      });
      setConfig(prev => ({ ...prev, deviceId: "", wireless: false }));
      setConnectionStatus('disconnected');
      setDeviceInfo(null);
      await fetchAdbDevices();
      alert("✅ Disconnected");
    } catch (e: any) {
      alert("❌ " + (e.response?.data?.error || e.message));
    } finally {
      setConnecting(false);
    }
  }

  // ==================== RENDER ====================
  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>
        <p className="text-gray-400">Configure device connections</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        <button
          onClick={() => setActiveTab('android')}
          className={`px-6 py-3 rounded-xl font-semibold transition flex items-center gap-2 ${
            activeTab === 'android'
              ? 'bg-emerald-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
          }`}
        >
          <span className="text-xl">🤖</span>
          Android
        </button>
        <button
          onClick={() => setActiveTab('ios')}
          className={`px-6 py-3 rounded-xl font-semibold transition flex items-center gap-2 ${
            activeTab === 'ios'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
          }`}
        >
          <span className="text-xl">🍎</span>
          iOS
        </button>
      </div>

      {/* ==================== ANDROID TAB ==================== */}
      {activeTab === 'android' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            {/* ADB Server Control */}
            <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <span className="text-2xl">⚡</span>
                ADB Server
              </h2>
              <div className="flex items-center justify-between p-4 bg-gray-900/50 rounded-xl border border-gray-800">
                <div>
                  <p className="text-white font-medium">ADB Server Status</p>
                  <p className="text-sm text-gray-500">Start or stop the ADB daemon</p>
                </div>
                <button
                  onClick={toggleAdbServer}
                  className={`px-6 py-2 rounded-xl font-semibold transition ${
                    config.adbRunning 
                      ? "bg-emerald-600 hover:bg-emerald-700" 
                      : "bg-red-600 hover:bg-red-700"
                  } text-white`}
                >
                  {config.adbRunning ? "🟢 Running" : "🔴 Stopped"}
                </button>
              </div>
            </div>

            {/* WiFi ADB Connection */}
            <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <span className="text-2xl">📶</span>
                WiFi ADB Connection
              </h2>
              <div className="space-y-4">
                <div className="p-4 bg-cyan-500/10 border border-cyan-500/30 rounded-xl">
                  <p className="text-sm text-cyan-300 mb-2">
                    <strong>📱 On your Android device:</strong>
                  </p>
                  <ol className="text-xs text-cyan-200/80 space-y-1 list-decimal list-inside">
                    <li>Settings → Developer Options → Wireless Debugging → Enable</li>
                    <li>Tap "Pair device with pairing code" (first time only)</li>
                    <li>Note the IP address shown</li>
                    <li>Enter IP below and click Connect</li>
                  </ol>
                </div>

                <div className="grid grid-cols-3 gap-3">
                  <div className="col-span-2">
                    <label className="block text-sm font-medium text-gray-400 mb-2">Device IP Address</label>
                    <input
                      placeholder="192.168.1.100"
                      value={wifiIp}
                      onChange={e => setWifiIp(e.target.value)}
                      className="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white font-mono focus:border-cyan-500 transition"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-2">Port</label>
                    <input
                      placeholder="5555"
                      value={wifiPort}
                      onChange={e => setWifiPort(e.target.value)}
                      className="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white font-mono focus:border-cyan-500 transition"
                    />
                  </div>
                </div>

                <div className="flex gap-3">
                  <button
                    onClick={connectWifi}
                    disabled={connecting || !wifiIp.trim()}
                    className="flex-1 px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:opacity-90 rounded-xl text-white font-semibold transition disabled:opacity-50 flex items-center justify-center gap-2"
                  >
                    {connecting ? (
                      <>
                        <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                        Connecting...
                      </>
                    ) : (
                      <>📶 Connect WiFi</>
                    )}
                  </button>
                  {config.wireless && config.deviceId && (
                    <button
                      onClick={disconnectWifi}
                      disabled={connecting}
                      className="px-6 py-3 bg-red-600 hover:bg-red-700 rounded-xl text-white font-semibold transition disabled:opacity-50"
                    >
                      Disconnect
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* USB Device Selection */}
            <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <span className="text-2xl">🔌</span>
                USB Device Selection
              </h2>
              <div className="space-y-4">
                <div className="flex gap-2">
                  <select
                    value={config.deviceId}
                    onChange={e => setConfig({ ...config, deviceId: e.target.value, wireless: false })}
                    className="flex-1 p-3 bg-gray-900 border border-gray-700 rounded-xl text-white focus:border-cyan-500 transition"
                  >
                    <option value="">-- Select a device --</option>
                    {adbDevices.map(d => (
                      <option key={d.id} value={d.id}>
                        {d.id} {d.model ? `(${d.model})` : ''} [{d.status}]
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={fetchAdbDevices}
                    disabled={refreshing}
                    className="px-4 py-3 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-xl text-white transition disabled:opacity-50"
                  >
                    {refreshing ? '⏳' : '🔄'}
                  </button>
                </div>

                {adbDevices.length === 0 && (
                  <p className="text-sm text-gray-500 text-center py-2">
                    No devices found. Connect via USB or WiFi.
                  </p>
                )}

                <div className="flex gap-3 pt-2">
                  <button
                    onClick={saveAdbConfig}
                    disabled={saving}
                    className="flex-1 px-6 py-3 bg-gray-700 hover:bg-gray-600 rounded-xl text-white font-semibold transition disabled:opacity-50 flex items-center justify-center gap-2"
                  >
                    {saving ? '⏳' : '💾 Save'}
                  </button>
                  <button
                    onClick={testAdbConnection}
                    disabled={testing || !config.deviceId}
                    className="flex-1 px-6 py-3 bg-emerald-600 hover:bg-emerald-700 rounded-xl text-white font-semibold transition disabled:opacity-50 flex items-center justify-center gap-2"
                  >
                    {testing ? '⏳' : '🔌 Test Connection'}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Android Status Sidebar */}
          <div className="space-y-6">
            <div className={`bg-[#12121a] border rounded-2xl p-6 ${
              connectionStatus === 'connected' ? 'border-emerald-500/50' : 'border-gray-800'
            }`}>
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <span className="text-2xl">📱</span>
                Device Status
              </h3>
              <div className="flex flex-col items-center py-6">
                <div className={`relative w-20 h-36 rounded-2xl border-4 flex items-center justify-center mb-4 ${
                  connectionStatus === 'connected'
                    ? 'border-emerald-500 bg-emerald-500/10'
                    : 'border-gray-600 bg-gray-800/50'
                }`}>
                  <div className="absolute top-2 w-8 h-1 bg-gray-700 rounded-full"></div>
                  {connectionStatus === 'checking' ? (
                    <div className="w-8 h-8 border-3 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
                  ) : connectionStatus === 'connected' ? (
                    <span className="text-3xl text-emerald-400">✓</span>
                  ) : (
                    <span className="text-3xl text-gray-500">?</span>
                  )}
                  {connectionStatus === 'connected' && (
                    <div className="absolute -top-1 -right-1 w-4 h-4 bg-emerald-500 rounded-full border-2 border-[#12121a]">
                      <div className="absolute inset-0 bg-emerald-500 rounded-full animate-ping opacity-75"></div>
                    </div>
                  )}
                </div>
                <div className={`text-lg font-bold ${
                  connectionStatus === 'connected' ? 'text-emerald-400' : 'text-gray-400'
                }`}>
                  {connectionStatus === 'connected' && 'Connected'}
                  {connectionStatus === 'disconnected' && 'Not Connected'}
                  {connectionStatus === 'checking' && 'Checking...'}
                </div>
                {connectionStatus === 'connected' && deviceInfo && (
                  <div className="mt-4 w-full p-3 bg-emerald-500/10 rounded-xl border border-emerald-500/30">
                    <p className="text-sm text-emerald-300 text-center font-mono mb-1">{deviceInfo.id}</p>
                    {deviceInfo.model && (
                      <p className="text-xs text-emerald-400/70 text-center">
                        {deviceInfo.model} • Android {deviceInfo.android_version}
                      </p>
                    )}
                    {deviceInfo.isRooted && (
                      <p className="text-xs text-orange-400 text-center mt-1">🔓 Rooted</p>
                    )}
                  </div>
                )}
              </div>
            </div>

            <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <span className="text-2xl">ℹ️</span>
                Current Config
              </h3>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-400">Device</span>
                  <span className="text-white font-mono text-xs truncate max-w-[120px]">
                    {config.deviceId || 'None'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Mode</span>
                  <span className="text-white">{config.wireless ? '📶 WiFi' : '🔌 USB'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">ADB Server</span>
                  <span className={config.adbRunning ? 'text-emerald-400' : 'text-red-400'}>
                    {config.adbRunning ? '🟢 Running' : '🔴 Stopped'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Devices Found</span>
                  <span className={`font-bold ${adbDevices.length > 0 ? 'text-emerald-400' : 'text-gray-500'}`}>
                    {adbDevices.length}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ==================== iOS TAB ==================== */}
      {activeTab === 'ios' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            
            {/* Connection Mode */}
            <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <span className="text-2xl">🍎</span>
                iOS Connection
              </h2>

              {/* Mode Selector */}
              <div className="flex gap-3 mb-6">
                <button
                  onClick={() => setIosConnectionMode('usb')}
                  className={`flex-1 px-4 py-3 rounded-xl font-semibold transition flex items-center justify-center gap-2 ${
                    iosConnectionMode === 'usb'
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                  }`}
                >
                  🔌 USB (libimobiledevice)
                </button>
                <button
                  onClick={() => setIosConnectionMode('ssh')}
                  className={`flex-1 px-4 py-3 rounded-xl font-semibold transition flex items-center justify-center gap-2 ${
                    iosConnectionMode === 'ssh'
                      ? 'bg-orange-600 text-white'
                      : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                  }`}
                >
                  🔐 SSH (Jailbreak)
                </button>
              </div>

              {/* USB Mode */}
              {iosConnectionMode === 'usb' && (
                <div className="space-y-4">
                  <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-xl">
                    <p className="text-sm text-blue-300">
                      <strong>📱 USB Connection:</strong> Connect iOS device via USB cable and trust the computer.
                    </p>
                  </div>

                  <div className="flex gap-2">
                    <select
                      value={iosSelectedDevice}
                      onChange={e => selectIosDevice(e.target.value)}
                      className="flex-1 p-3 bg-gray-900 border border-gray-700 rounded-xl text-white"
                    >
                      <option value="">-- Select iOS device --</option>
                      {iosDevices.filter(d => d.connectionType === 'usb').map(d => (
                        <option key={d.udid} value={d.udid}>
                          {d.name} ({d.model} - iOS {d.version})
                        </option>
                      ))}
                    </select>
                    <button
                      onClick={fetchIosDevices}
                      disabled={iosRefreshing}
                      className="px-4 py-3 bg-gray-800 hover:bg-gray-700 rounded-xl text-white transition disabled:opacity-50"
                    >
                      {iosRefreshing ? '⏳' : '🔄'}
                    </button>
                  </div>

                  {iosDevices.filter(d => d.connectionType === 'usb').length === 0 && (
                    <p className="text-sm text-gray-500 text-center py-2">
                      No USB devices found. Connect device and trust computer.
                    </p>
                  )}
                </div>
              )}

              {/* SSH Mode */}
              {iosConnectionMode === 'ssh' && (
                <div className="space-y-4">
                  <div className="p-4 bg-orange-500/10 border border-orange-500/30 rounded-xl">
                    <p className="text-sm text-orange-300 mb-2">
                      <strong>🔐 SSH Connection:</strong> Direct connection to jailbroken device (no USB required)
                    </p>
                    <ul className="text-xs text-orange-200/80 space-y-1 list-disc list-inside">
                      <li>Device must have OpenSSH installed</li>
                      <li>Use <code className="bg-gray-800 px-1 rounded">mobile</code> user for rootless jailbreaks</li>
                      <li>Password is your jailbreak password</li>
                    </ul>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div>
                      <label className="block text-xs text-gray-400 mb-1">Host / IP</label>
                      <input
                        value={iosSSHConfig.host}
                        onChange={e => setIosSSHConfig({ ...iosSSHConfig, host: e.target.value })}
                        placeholder="192.168.1.x"
                        disabled={iosSSHConnected}
                        className="w-full p-2 bg-gray-900 border border-gray-700 rounded-lg text-white text-sm disabled:opacity-50"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-gray-400 mb-1">Port</label>
                      <input
                        type="number"
                        value={iosSSHConfig.port}
                        onChange={e => setIosSSHConfig({ ...iosSSHConfig, port: parseInt(e.target.value) || 22 })}
                        placeholder="22"
                        disabled={iosSSHConnected}
                        className="w-full p-2 bg-gray-900 border border-gray-700 rounded-lg text-white text-sm disabled:opacity-50"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-gray-400 mb-1">User</label>
                      <input
                        value={iosSSHConfig.user}
                        onChange={e => setIosSSHConfig({ ...iosSSHConfig, user: e.target.value })}
                        placeholder="mobile"
                        disabled={iosSSHConnected}
                        className="w-full p-2 bg-gray-900 border border-gray-700 rounded-lg text-white text-sm disabled:opacity-50"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-gray-400 mb-1">Password</label>
                      <input
                        type="password"
                        value={iosSSHConfig.password}
                        onChange={e => setIosSSHConfig({ ...iosSSHConfig, password: e.target.value })}
                        placeholder="••••••"
                        disabled={iosSSHConnected}
                        className="w-full p-2 bg-gray-900 border border-gray-700 rounded-lg text-white text-sm disabled:opacity-50"
                      />
                    </div>
                  </div>

                  <div className="flex gap-3">
                    {!iosSSHConnected ? (
                      <button
                        onClick={connectIosSSH}
                        disabled={iosSSHConnecting || !iosSSHConfig.host}
                        className="flex-1 px-6 py-3 bg-orange-600 hover:bg-orange-700 rounded-xl text-white font-semibold transition disabled:opacity-50 flex items-center justify-center gap-2"
                      >
                        {iosSSHConnecting ? (
                          <>
                            <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                            Connecting...
                          </>
                        ) : (
                          '🔗 Connect SSH'
                        )}
                      </button>
                    ) : (
                      <>
                        <div className="flex-1 px-6 py-3 bg-emerald-600 rounded-xl text-white font-semibold flex items-center justify-center gap-2">
                          ✅ Connected to {iosSSHConfig.host}
                        </div>
                        <button
                          onClick={disconnectIosSSH}
                          className="px-6 py-3 bg-red-600 hover:bg-red-700 rounded-xl text-white font-semibold transition"
                        >
                          Disconnect
                        </button>
                      </>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* iOS Status Sidebar */}
          <div className="space-y-6">
            <div className={`bg-[#12121a] border rounded-2xl p-6 ${
              iosConnectionStatus === 'connected' ? 'border-blue-500/50' : 'border-gray-800'
            }`}>
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <span className="text-2xl">📱</span>
                Device Status
              </h3>
              <div className="flex flex-col items-center py-6">
                <div className={`relative w-20 h-36 rounded-3xl border-4 flex items-center justify-center mb-4 ${
                  iosConnectionStatus === 'connected'
                    ? 'border-blue-500 bg-blue-500/10'
                    : 'border-gray-600 bg-gray-800/50'
                }`}>
                  <div className="absolute top-3 w-12 h-3 bg-gray-700 rounded-full"></div>
                  {iosConnectionStatus === 'checking' ? (
                    <div className="w-8 h-8 border-3 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                  ) : iosConnectionStatus === 'connected' ? (
                    <span className="text-3xl">🍎</span>
                  ) : (
                    <span className="text-3xl text-gray-500">?</span>
                  )}
                  {iosConnectionStatus === 'connected' && (
                    <div className="absolute -top-1 -right-1 w-4 h-4 bg-blue-500 rounded-full border-2 border-[#12121a]">
                      <div className="absolute inset-0 bg-blue-500 rounded-full animate-ping opacity-75"></div>
                    </div>
                  )}
                </div>
                <div className={`text-lg font-bold ${
                  iosConnectionStatus === 'connected' ? 'text-blue-400' : 'text-gray-400'
                }`}>
                  {iosConnectionStatus === 'connected' && 'Connected'}
                  {iosConnectionStatus === 'disconnected' && 'Not Connected'}
                  {iosConnectionStatus === 'checking' && 'Checking...'}
                </div>
                {iosConnectionStatus === 'connected' && iosDeviceInfo && (
                  <div className="mt-4 w-full p-3 bg-blue-500/10 rounded-xl border border-blue-500/30">
                    <p className="text-sm text-blue-300 text-center font-medium mb-1">
                      {iosDeviceInfo.name || iosDeviceInfo.hostname || 'iOS Device'}
                    </p>
                    <p className="text-xs text-blue-400/70 text-center">
                      {iosDeviceInfo.model || iosDeviceInfo.architecture} • iOS {iosDeviceInfo.version}
                    </p>
                    {iosDeviceInfo.jailbreakType && (
                      <p className="text-xs text-purple-400 text-center mt-1">
                        {iosDeviceInfo.jailbreakType}
                      </p>
                    )}
                    <p className={`text-xs text-center mt-1 ${
                      iosConnectionMode === 'ssh' ? 'text-orange-400' : 'text-blue-400'
                    }`}>
                      {iosConnectionMode === 'ssh' ? '🔐 SSH' : '🔌 USB'}
                    </p>
                  </div>
                )}
              </div>
            </div>

            <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <span className="text-2xl">ℹ️</span>
                Current Config
              </h3>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-400">Mode</span>
                  <span className={iosConnectionMode === 'ssh' ? 'text-orange-400' : 'text-blue-400'}>
                    {iosConnectionMode === 'ssh' ? '🔐 SSH' : '🔌 USB'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Status</span>
                  <span className={iosConnectionStatus === 'connected' ? 'text-emerald-400' : 'text-gray-500'}>
                    {iosConnectionStatus === 'connected' ? '🟢 Connected' : '⚪ Disconnected'}
                  </span>
                </div>
                {iosConnectionMode === 'ssh' && iosSSHConnected && (
                  <div className="flex justify-between">
                    <span className="text-gray-400">Host</span>
                    <span className="text-white font-mono text-xs">{iosSSHConfig.host}</span>
                  </div>
                )}
                {iosConnectionMode === 'usb' && iosSelectedDevice && (
                  <div className="flex justify-between">
                    <span className="text-gray-400">UDID</span>
                    <span className="text-white font-mono text-xs truncate max-w-[100px]">{iosSelectedDevice}</span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-gray-400">USB Devices</span>
                  <span className={`font-bold ${iosDevices.filter(d => d.connectionType === 'usb').length > 0 ? 'text-blue-400' : 'text-gray-500'}`}>
                    {iosDevices.filter(d => d.connectionType === 'usb').length}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
