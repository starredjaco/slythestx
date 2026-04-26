import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { analysisApi } from '../services/api';

interface Stats {
  total_applications: number;
  android_applications: number;
  ios_applications: number;
  completed_applications: number;
  average_security_score: number;
}

interface RecentScan {
  id: number;
  name: string;
  platform: string;
  technology: string;
  status: string;
  security_score: number | null;
  created_at: string;
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      const [statsRes, scansRes] = await Promise.all([
        analysisApi.getStatistics(),
        analysisApi.listApps({ page: 1, page_size: 5 }),
      ]);
      setStats(statsRes.data);
      setRecentScans(scansRes.data.applications || []);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getScoreColor = (score: number | null) => {
    if (score === null) return 'text-gray-400';
    if (score >= 80) return 'text-emerald-400';
    if (score >= 60) return 'text-yellow-400';
    return 'text-red-400';
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

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Dashboard</h1>
        <p className="text-gray-400">Overview of your mobile security analysis</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
        {/* Total Scans */}
        <div className="bg-[#12121a] rounded-2xl p-6 border border-gray-800 hover:border-cyan-500/50 transition-all">
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-cyan-500/20 rounded-xl flex items-center justify-center">
              <svg className="w-6 h-6 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
              </svg>
            </div>
          </div>
          <p className="text-4xl font-bold text-white mb-1">{stats?.total_applications || 0}</p>
          <p className="text-sm text-gray-400">Total Scans</p>
        </div>

        {/* Android */}
        <div className="bg-[#12121a] rounded-2xl p-6 border border-gray-800 hover:border-green-500/50 transition-all">
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
              <span className="text-2xl">🤖</span>
            </div>
          </div>
          <p className="text-4xl font-bold text-white mb-1">{stats?.android_applications || 0}</p>
          <p className="text-sm text-gray-400">Android Apps</p>
        </div>

        {/* iOS */}
        <div className="bg-[#12121a] rounded-2xl p-6 border border-gray-800 hover:border-blue-500/50 transition-all">
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
              <span className="text-2xl">🍎</span>
            </div>
          </div>
          <p className="text-4xl font-bold text-white mb-1">{stats?.ios_applications || 0}</p>
          <p className="text-sm text-gray-400">iOS Apps</p>
        </div>

        {/* Completed */}
        <div className="bg-[#12121a] rounded-2xl p-6 border border-gray-800 hover:border-emerald-500/50 transition-all">
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-emerald-500/20 rounded-xl flex items-center justify-center">
              <svg className="w-6 h-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
          <p className="text-4xl font-bold text-white mb-1">{stats?.completed_applications || 0}</p>
          <p className="text-sm text-gray-400">Completed</p>
        </div>

        {/* Average Score */}
        <div className="bg-[#12121a] rounded-2xl p-6 border border-gray-800 hover:border-purple-500/50 transition-all">
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center">
              <span className="text-2xl">⭐</span>
            </div>
          </div>
          <p className={`text-4xl font-bold mb-1 ${getScoreColor(stats?.average_security_score || 0)}`}>
            {stats?.average_security_score || 0}
          </p>
          <p className="text-sm text-gray-400">Avg. Score</p>
        </div>
      </div>

	 {/* Recent Scans */}
	<div className="bg-[#12121a] rounded-2xl p-6 border border-gray-800">
	  <div className="flex items-center justify-between mb-4">
	    <h2 className="text-lg font-semibold text-white">Recent Scans</h2>
	    <Link to="/scans" className="text-sm text-cyan-400 hover:text-cyan-300 transition">
	      View all →
	    </Link>
	  </div>

	  <div className="overflow-x-auto">
	    <table className="w-full min-w-[600px]">
	      <thead>
		<tr className="text-left text-sm text-gray-400 border-b border-gray-800">
		  <th className="pb-3 font-medium">Application</th>
		  <th className="pb-3 font-medium">Platform</th>
		  <th className="pb-3 font-medium">Status</th>
		  <th className="pb-3 font-medium text-right">Score</th>
		</tr>
	      </thead>

	      <tbody className="divide-y divide-gray-800">
		{recentScans.length === 0 ? (
		  <tr>
		    <td colSpan={4} className="py-8 text-center text-gray-400">
		      No scans yet. Upload your first application!
		    </td>
		  </tr>
		) : (
		  recentScans.map((scan) => (
		    <tr key={scan.id} className="hover:bg-white/5 transition">
		      <td className="py-4">
		        <Link to={`/scans/${scan.id}`} className="flex items-center gap-3 group min-w-0">
		          <div
		            className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${
		              scan.platform === 'ANDROID'
		                ? 'bg-green-500/20'
		                : 'bg-blue-500/20'
		            }`}
		          >
		            <span className="text-lg">
		              {scan.platform === 'ANDROID' ? '🤖' : '🍎'}
		            </span>
		          </div>

		          <div className="min-w-0">
		            <p className="font-medium text-white group-hover:text-cyan-400 transition truncate">
		              {scan.name}
		            </p>
		            <p className="text-xs text-gray-500 truncate">
		              {scan.technology}
		            </p>
		          </div>
		        </Link>
		      </td>

		      <td className="py-4">
		        <span
		          className={`text-sm ${
		            scan.platform === 'ANDROID'
		              ? 'text-green-400'
		              : 'text-blue-400'
		          }`}
		        >
		          {scan.platform}
		        </span>
		      </td>

		      <td className="py-4">
		        <span
		          className={`px-2.5 py-1 text-xs font-medium rounded-full border ${getStatusBadge(
		            scan.status
		          )}`}
		        >
		          {scan.status}
		        </span>
		      </td>

		      <td className="py-4 text-right">
		        <span
		          className={`text-lg font-bold ${getScoreColor(
		            scan.security_score
		          )}`}
		        >
		          {scan.security_score !== null
		            ? scan.security_score
		            : '—'}
		        </span>
		      </td>
		    </tr>
		  ))
		)}
              </tbody>
            </table>
          </div>
        </div>
    </div>
  );
}
