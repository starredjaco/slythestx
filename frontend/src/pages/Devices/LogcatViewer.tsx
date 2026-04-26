import { useState, useEffect, useRef } from 'react';
import axios from 'axios';

const API = '/api/v1/adb';

interface LogLine {
  text: string;
  level: 'V' | 'D' | 'I' | 'W' | 'E' | 'F';
  tag?: string;
  time?: string;
}

const LOG_COLORS: Record<string, string> = {
  V: 'text-gray-400',      
  D: 'text-cyan-400',      
  I: 'text-green-400',     
  W: 'text-yellow-400',    
  E: 'text-red-400',       
  F: 'text-red-600',     
};

const LOG_BG_COLORS: Record<string, string> = {
  V: '',
  D: '',
  I: '',
  W: 'bg-yellow-500/10',
  E: 'bg-red-500/10',
  F: 'bg-red-500/20',
};

export default function LogcatViewer() {
  const [packages, setPackages] = useState<any[]>([]);
  const [selectedPackage, setSelectedPackage] = useState('');
  const [logLevel, setLogLevel] = useState('V');
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [filter, setFilter] = useState('');
  const [running, setRunning] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [loading, setLoading] = useState(false);
  
  const logsEndRef = useRef<HTMLDivElement>(null);
  const logIndexRef = useRef(0);
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    fetchPackages();
    checkStatus();
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, []);


  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  async function fetchPackages() {
    try {
      const res = await axios.get(`${API}/packages`);
      setPackages(res.data || []);
    } catch (e) {
      console.error('Error fetching packages:', e);
    }
  }

  async function checkStatus() {
    try {
      const res = await axios.get(`${API}/logcat/status`);
      setRunning(res.data.running);
      if (res.data.running) {
        startPolling();
      }
    } catch {}
  }

  function parseLogLine(line: string): LogLine {
    const match = line.match(/^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+([VDIWEF])\/([^:]+):\s*(.*)$/);
    
    if (match) {
      return {
        time: match[1],
        level: match[2] as LogLine['level'],
        tag: match[3],
        text: match[4],
      };
    }
    const levelMatch = line.match(/^\s*([VDIWEF])\//);
    return {
      text: line,
      level: (levelMatch?.[1] as LogLine['level']) || 'V',
    };
  }

  async function startLogcat() {
    if (!selectedPackage) {
      alert('⚠️ Select a package first');
      return;
    }

    setLoading(true);
    try {
      const res = await axios.post(`${API}/logcat/start`, {
        package: selectedPackage,
        level: logLevel,
      });

      if (res.data.success) {
        setRunning(true);
        setLogs([]);
        logIndexRef.current = 0;
        startPolling();
      } else {
        alert(`❌ ${res.data.error || 'Failed to start logcat'}`);
      }
    } catch (e: any) {
      alert(`❌ ${e.response?.data?.error || e.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function stopLogcat() {
    try {
      await axios.post(`${API}/logcat/stop`);
      setRunning(false);
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    } catch (e: any) {
      console.error('Stop error:', e);
    }
  }

  function startPolling() {
    if (pollIntervalRef.current) return;

    pollIntervalRef.current = setInterval(async () => {
      try {
        const res = await axios.get(`${API}/logcat/logs`, {
          params: { since: logIndexRef.current }
        });

        if (res.data.logs.length > 0) {
          const newLogs = res.data.logs.map(parseLogLine);
          setLogs(prev => [...prev, ...newLogs].slice(-1000));
          logIndexRef.current = res.data.newIndex;
        }

        if (!res.data.running) {
          setRunning(false);
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current);
            pollIntervalRef.current = null;
          }
        }
      } catch {}
    }, 500);
  }

  async function clearLogs() {
    try {
      await axios.post(`${API}/logcat/clear`);
      setLogs([]);
      logIndexRef.current = 0;
    } catch {}
  }

  function exportLogs() {
    const content = logs.map(l => 
      `${l.time || ''} ${l.level}/${l.tag || 'unknown'}: ${l.text}`
    ).join('\n');
    
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `logcat_${selectedPackage}_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const filteredLogs = filter
    ? logs.filter(l => 
        l.text.toLowerCase().includes(filter.toLowerCase()) ||
        l.tag?.toLowerCase().includes(filter.toLowerCase())
      )
    : logs;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-[#12121a] border border-gray-800 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <span className="text-2xl">📋</span>
          Logcat Viewer
        </h2>

        {/* Controls */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          {/* Package selector */}
          <div className="md:col-span-2">
            <label className="block text-sm text-gray-400 mb-1">Package</label>
            <select
              value={selectedPackage}
              onChange={e => setSelectedPackage(e.target.value)}
              disabled={running}
              className="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white disabled:opacity-50"
            >
              <option value="">-- Select package --</option>
              {packages.map(p => (
                <option key={p.name} value={p.name}>{p.name}</option>
              ))}
            </select>
          </div>

          {/* Log level */}
          <div>
            <label className="block text-sm text-gray-400 mb-1">Level</label>
            <select
              value={logLevel}
              onChange={e => setLogLevel(e.target.value)}
              disabled={running}
              className="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white disabled:opacity-50"
            >
              <option value="V">Verbose</option>
              <option value="D">Debug</option>
              <option value="I">Info</option>
              <option value="W">Warning</option>
              <option value="E">Error</option>
            </select>
          </div>

          {/* Actions */}
          <div className="flex items-end gap-2">
            {!running ? (
              <button
                onClick={startLogcat}
                disabled={loading || !selectedPackage}
                className="flex-1 px-4 py-3 bg-emerald-600 hover:bg-emerald-700 rounded-xl text-white font-semibold transition disabled:opacity-50"
              >
                {loading ? '⏳' : '▶️'} Start
              </button>
            ) : (
              <button
                onClick={stopLogcat}
                className="flex-1 px-4 py-3 bg-red-600 hover:bg-red-700 rounded-xl text-white font-semibold transition"
              >
                ⏹️ Stop
              </button>
            )}
          </div>
        </div>

        {/* Filter and options */}
        <div className="flex flex-wrap gap-3">
          <input
            type="text"
            placeholder="🔍 Filter logs..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="flex-1 min-w-[200px] p-2 bg-gray-900 border border-gray-700 rounded-lg text-white text-sm"
          />

          <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={e => setAutoScroll(e.target.checked)}
              className="rounded"
            />
            Auto-scroll
          </label>

          <button
            onClick={clearLogs}
            className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-gray-300 transition"
          >
            🗑️ Clear
          </button>

          <button
            onClick={exportLogs}
            disabled={logs.length === 0}
            className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-gray-300 transition disabled:opacity-50"
          >
            💾 Export
          </button>
        </div>
      </div>

      {/* Logs */}
      <div className="bg-[#0d1117] border border-gray-800 rounded-2xl overflow-hidden">
        {/* Status bar */}
        <div className="flex items-center justify-between px-4 py-2 bg-gray-900/50 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <span className={`w-2 h-2 rounded-full ${running ? 'bg-emerald-500 animate-pulse' : 'bg-gray-500'}`} />
            <span className="text-sm text-gray-400">
              {running ? 'Recording...' : 'Stopped'}
            </span>
          </div>
          <span className="text-sm text-gray-500">
            {filteredLogs.length} / {logs.length} lines
          </span>
        </div>

        {/* Log content */}
        <div className="h-[500px] overflow-y-auto font-mono text-xs p-4 space-y-0.5">
          {filteredLogs.length === 0 ? (
            <div className="text-center text-gray-500 py-12">
              {running ? 'Waiting for logs...' : 'No logs yet. Start logcat to capture logs.'}
            </div>
          ) : (
            filteredLogs.map((log, i) => (
              <div
                key={i}
                className={`flex gap-2 py-0.5 px-2 rounded ${LOG_BG_COLORS[log.level] || ''}`}
              >
                {log.time && (
                  <span className="text-gray-600 shrink-0">{log.time}</span>
                )}
                <span className={`shrink-0 font-bold ${LOG_COLORS[log.level]}`}>
                  {log.level}
                </span>
                {log.tag && (
                  <span className="text-purple-400 shrink-0 max-w-[150px] truncate">
                    {log.tag}
                  </span>
                )}
                <span className="text-gray-300 break-all">{log.text}</span>
              </div>
            ))
          )}
          <div ref={logsEndRef} />
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 text-xs text-gray-500">
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded bg-gray-600" /> Verbose
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded bg-cyan-600" /> Debug
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded bg-green-600" /> Info
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded bg-yellow-600" /> Warning
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded bg-red-600" /> Error
        </span>
      </div>
    </div>
  );
}
