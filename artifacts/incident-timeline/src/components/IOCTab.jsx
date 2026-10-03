import React, { useState, useEffect } from 'react';
import { apiFetch } from '../api';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Globe, 
  Hash, 
  Server, 
  RefreshCw,
  Save
} from 'lucide-react';

export default function IOCTab() {
  const [iocs, setIocs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [savingKey, setSavingKey] = useState(null);

  const fetchIocs = () => {
    setLoading(true);
    apiFetch('/api/iocs')
      .then(res => res.json())
      .then(data => {
        setIocs(data || []);
        setLoading(false);
      })
      .catch(err => {
        console.error('Failed to load IOCs:', err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchIocs();
  }, []);

  const handleStatusChange = async (val, newStatus) => {
    setSavingKey(val);
    try {
      const res = await apiFetch('/api/iocs/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator_value: val, analyst_status: newStatus })
      });
      if (res.ok) {
        setIocs(prev => prev.map(item => item.indicator_value === val ? { ...item, analyst_status: newStatus } : item));
      }
    } catch (err) {
      console.error('Failed to update IOC status:', err);
    } finally {
      setSavingKey(null);
    }
  };

  const filteredIocs = iocs.filter(ioc => {
    if (search && !ioc.indicator_value.toLowerCase().includes(search.toLowerCase()) && !ioc.detection_rule?.toLowerCase().includes(search.toLowerCase())) {
      return false;
    }
    if (typeFilter && ioc.indicator_type !== typeFilter) {
      return false;
    }
    if (statusFilter && ioc.analyst_status !== statusFilter) {
      return false;
    }
    return true;
  });

  const getStatusBadge = (status) => {
    switch (status) {
      case 'Confirmed Threat':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'False Positive':
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
      default:
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
    }
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'IP Address': return <Globe className="h-4 w-4 text-cyan-400" />;
      case 'SHA256 Hash':
      case 'MD5 Hash': return <Hash className="h-4 w-4 text-purple-400" />;
      case 'Suspicious Port': return <Server className="h-4 w-4 text-amber-400" />;
      default: return <ShieldAlert className="h-4 w-4 text-blue-400" />;
    }
  };

  return (
    <div className="space-y-4">
      
      {/* Header & Filter Controls */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-rose-400" />
            <span>Indicators of Compromise & Evidence Registry</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Rule-derived network indicators, suspicious ports, and artifact hashes. Distinguish observed signals from confirmed threats.
          </p>
        </div>

        <button
          onClick={fetchIocs}
          className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          title="Refresh IOCs"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Filter Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="relative">
          <Search className="h-4 w-4 absolute left-3 top-3 text-slate-400" />
          <input
            type="text"
            placeholder="Search indicator, rule, IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="px-3 py-2 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Indicator Types</option>
          <option value="IP Address">IP Address</option>
          <option value="Suspicious Port">Suspicious Port</option>
          <option value="SHA256 Hash">SHA256 Hash</option>
          <option value="Domain Name">Domain Name</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Analyst Statuses</option>
          <option value="Observed">Observed</option>
          <option value="Confirmed Threat">Confirmed Threat</option>
          <option value="False Positive">False Positive</option>
        </select>
      </div>

      {/* IOC Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-800 bg-[#0d1424] text-slate-400 font-semibold">
              <th className="py-3 px-3.5">Indicator Entity</th>
              <th className="py-3 px-3">Type</th>
              <th className="py-3 px-3">Detection Rule / Context</th>
              <th className="py-3 px-3">Events Count</th>
              <th className="py-3 px-3">First Seen → Last Seen</th>
              <th className="py-3 px-3.5">Analyst Verdict</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
            {loading ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-400 font-sans">
                  Loading indicator registry...
                </td>
              </tr>
            ) : filteredIocs.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-500 font-sans">
                  No indicators match the selected criteria.
                </td>
              </tr>
            ) : (
              filteredIocs.map((ioc) => (
                <tr key={ioc.indicator_value} className="hover:bg-slate-800/30">
                  {/* Indicator Value */}
                  <td className="py-2.5 px-3.5 text-cyan-300 font-bold max-w-[240px] truncate">
                    <div className="flex items-center gap-2">
                      {getTypeIcon(ioc.indicator_type)}
                      <span className="truncate">{ioc.indicator_value}</span>
                    </div>
                  </td>

                  {/* Type */}
                  <td className="py-2.5 px-3 text-slate-300 font-sans text-xs">
                    {ioc.indicator_type}
                  </td>

                  {/* Detection Rule */}
                  <td className="py-2.5 px-3 text-slate-300 font-sans text-xs max-w-[220px] truncate">
                    {ioc.detection_rule || 'Observed Traffic Flow'}
                  </td>

                  {/* Occurrence Count */}
                  <td className="py-2.5 px-3 text-slate-200 font-semibold">
                    <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                      {ioc.occurrence_count} events
                    </span>
                  </td>

                  {/* First Seen -> Last Seen */}
                  <td className="py-2.5 px-3 text-slate-400 text-[10px]">
                    <div>{ioc.first_seen || '—'}</div>
                    <div className="text-slate-500">to {ioc.last_seen || '—'}</div>
                  </td>

                  {/* Analyst Verdict */}
                  <td className="py-2.5 px-3.5 font-sans">
                    <select
                      value={ioc.analyst_status || 'Observed'}
                      onChange={(e) => handleStatusChange(ioc.indicator_value, e.target.value)}
                      disabled={savingKey === ioc.indicator_value}
                      className={`px-2.5 py-1 rounded text-xs font-semibold border focus:outline-none cursor-pointer transition ${getStatusBadge(ioc.analyst_status)}`}
                    >
                      <option value="Observed" className="bg-slate-900 text-amber-300">Observed</option>
                      <option value="Confirmed Threat" className="bg-slate-900 text-rose-300">Confirmed Threat</option>
                      <option value="False Positive" className="bg-slate-900 text-emerald-300">False Positive</option>
                    </select>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

    </div>
  );
}
