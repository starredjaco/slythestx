import { useEffect, useState, useRef } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import AndroidDevices from './Devices/AndroidDevices';
import IOSDevices from './Devices/iOSDevices';

const API = "/api/v1/adb";
const IOS_API = "/api/v1/ios";

interface DeviceInfo {
  id: string;
  status: string;
  model?: string;
  android_version?: string;
  sdk?: string;
  isRooted?: boolean;
}

interface IOSDeviceInfo {
  name?: string;
  hostname?: string;
  model?: string;
  architecture?: string;
  version?: string;
  jailbreakType?: string;
}

export default function Devices() {
  const [mainTab, setMainTab] = useState<"adb" | "ios" | "frida">("adb");

  // Android state
  const [config, setConfig] = useState<any>(null);
  const [deviceInfo, setDeviceInfo] = useState<DeviceInfo | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'checking'>('disconnected');
  const [isRooted, setIsRooted] = useState<boolean>(false);

  // iOS state
  const [iosStatus, setIosStatus] = useState<any>(null);
  const [iosDeviceInfo, setIosDeviceInfo] = useState<IOSDeviceInfo | null>(null);
  const [iosConnectionStatus, setIosConnectionStatus] = useState<'connected' | 'disconnected' | 'checking'>('disconnected');

  const configLoaded = useRef(false);

  useEffect(() => {
    if (!configLoaded.current) {
      configLoaded.current = true;
      loadConfig();
      checkIosConnection();
    }
  }, []);

  useEffect(() => {
    if (config?.deviceId) {
      checkConnection();
    }
  }, [config?.deviceId]);

  // ==================== iOS ====================
  async function checkIosConnection() {
    try {
      setIosConnectionStatus('checking');
      const res = await axios.get(`${IOS_API}/status`);
      setIosStatus(res.data);

      if ((res.data.connectionType === 'ssh' && res.data.jailbroken) || res.data.udid) {
        setIosConnectionStatus('connected');
        setIosDeviceInfo(res.data.deviceInfo);
      } else {
        setIosConnectionStatus('disconnected');
        setIosDeviceInfo(null);
      }
    } catch {
      setIosConnectionStatus('disconnected');
      setIosDeviceInfo(null);
    }
  }

  // ==================== Android ====================
  async function loadConfig() {
    try {
      const res = await axios.get(`${API}/config`);
      setConfig(res.data);
    } catch {
      setConnectionStatus('disconnected');
    }
  }

  async function checkConnection() {
    try {
      setConnectionStatus('checking');
      const res = await axios.get(`${API}/device-info`);

      if (res.data?.connected) {
        setDeviceInfo(res.data);
        setConnectionStatus('connected');
        setIsRooted(res.data.isRooted || false);
      } else {
        setConnectionStatus('disconnected');
        setDeviceInfo(null);
        setIsRooted(false);
      }
    } catch {
      setConnectionStatus('disconnected');
      setDeviceInfo(null);
      setIsRooted(false);
    }
  }

  async function manualRefresh() {
    await checkConnection();
    await checkIosConnection();
  }

  const isAnyDeviceConnected = connectionStatus === 'connected' || iosConnectionStatus === 'connected';
  const connectedPlatform = connectionStatus === 'connected' ? 'android' : iosConnectionStatus === 'connected' ? 'ios' : null;

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Device Management</h1>
        <p className="text-gray-400">ADB & iOS tools and device interaction</p>
      </div>

      {/* Connection Status Bar */}
      <div className={`mb-6 p-4 rounded-xl border flex items-center justify-between ${
        isAnyDeviceConnected
          ? connectedPlatform === 'android'
            ? 'bg-emerald-500/10 border-emerald-500/30'
            : 'bg-blue-500/10 border-blue-500/30'
          : 'bg-red-500/10 border-red-500/30'
      }`}>
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className={`w-3 h-3 rounded-full ${
              isAnyDeviceConnected
                ? connectedPlatform === 'android' ? 'bg-emerald-500' : 'bg-blue-500'
                : 'bg-red-500'
            }`}></div>
            {isAnyDeviceConnected && (
              <div className={`absolute inset-0 w-3 h-3 rounded-full animate-ping ${
                connectedPlatform === 'android' ? 'bg-emerald-500' : 'bg-blue-500'
              }`}></div>
            )}
          </div>

          <div>
            <div className="flex items-center gap-2">
              <p className={`font-semibold ${
                isAnyDeviceConnected
                  ? connectedPlatform === 'android' ? 'text-emerald-400' : 'text-blue-400'
                  : 'text-red-400'
              }`}>
                {isAnyDeviceConnected
                  ? connectedPlatform === 'android'
                    ? '🤖 Android Connected'
                    : '🍎 iOS Connected'
                  : 'No Device Connected'}
              </p>

              {connectedPlatform === 'android' && (
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                  isRooted
                    ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                    : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                }`}>
                  {isRooted ? '🔓 ROOT' : '🔒 NO ROOT'}
                </span>
              )}

              {connectedPlatform === 'ios' && iosStatus && (
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                  iosStatus.connectionType === 'ssh'
                    ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                    : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                }`}>
                  {iosStatus.connectionType === 'ssh' ? '🔐 SSH' : '🔌 USB'}
                </span>
              )}
            </div>

            {connectedPlatform === 'android' && deviceInfo && (
              <p className="text-sm text-gray-400">
                {deviceInfo.id} • {deviceInfo.model || 'Unknown'} • Android {deviceInfo.android_version || '?'}
              </p>
            )}
            {connectedPlatform === 'ios' && iosDeviceInfo && (
              <p className="text-sm text-gray-400">
                {iosDeviceInfo.name || iosDeviceInfo.hostname || 'iOS Device'} •
                {iosDeviceInfo.model || iosDeviceInfo.architecture} • iOS {iosDeviceInfo.version || '?'}
              </p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={manualRefresh}
            className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-white transition"
          >
            🔄 Refresh
          </button>
          <Link
            to="/settings"
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 rounded-lg text-sm text-white transition"
          >
            ⚙️ Configure
          </Link>
        </div>
      </div>

      {/* Main Tabs */}
      <div className="flex gap-3 mb-6">
        <button
          onClick={() => setMainTab("adb")}
          className={`px-6 py-3 rounded-xl font-semibold transition flex items-center gap-2 ${
            mainTab === "adb"
              ? "bg-gradient-to-r from-cyan-500 to-blue-500 text-white"
              : "bg-gray-800 text-gray-400 hover:text-white"
          }`}
        >
          <span className="text-xl">🤖</span>
          Android
          {connectionStatus === 'connected' && <span className="w-2 h-2 bg-emerald-500 rounded-full"></span>}
        </button>

        <button
          onClick={() => setMainTab("ios")}
          className={`px-6 py-3 rounded-xl font-semibold transition flex items-center gap-2 ${
            mainTab === "ios"
              ? "bg-gradient-to-r from-purple-500 to-pink-500 text-white"
              : "bg-gray-800 text-gray-400 hover:text-white"
          }`}
        >
          <span className="text-xl">🍎</span>
          iOS
          {iosConnectionStatus === 'connected' && <span className="w-2 h-2 bg-blue-500 rounded-full"></span>}
        </button>

        <button
          onClick={() => setMainTab("frida")}
          className={`px-6 py-3 rounded-xl font-semibold transition flex items-center gap-2 ${
            mainTab === "frida"
              ? "bg-gradient-to-r from-purple-500 to-pink-500 text-white"
              : "bg-gray-800 text-gray-400 hover:text-white"
          }`}
        >
          <span className="text-xl">🔮</span>
          Frida
        </button>
      </div>

      {/* Android */}
      {mainTab === "adb" && (
        <AndroidDevices
          connectionStatus={connectionStatus}
          deviceInfo={deviceInfo}
          isRooted={isRooted}
          onRefresh={manualRefresh}
        />
      )}

      {/* iOS */}
      {mainTab === "ios" && <IOSDevices />}

      {/* Frida */}
      {mainTab === "frida" && (
        <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-12 text-center">
          <div className="w-24 h-24 bg-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
            <span className="text-5xl">🔮</span>
          </div>
          <h2 className="text-2xl font-bold text-white mb-3">Frida Integration</h2>
          <p className="text-gray-400 max-w-md mx-auto mb-6">Dynamic instrumentation toolkit.</p>
          <div className="inline-block px-4 py-2 bg-purple-500/20 border border-purple-500/30 rounded-xl text-purple-400 text-sm">
            Coming soon
          </div>
        </div>
      )}
    </div>
  );
}
