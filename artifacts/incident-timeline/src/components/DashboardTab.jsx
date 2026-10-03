import React from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Server, 
  Globe, 
  FolderGit2, 
  Calendar, 
  TrendingUp, 
  Terminal,
  ArrowRight,
  Database,
  Layers,
  CheckCircle2
} from 'lucide-react';

export default function DashboardTab({ metrics, onSelectIncident, onSelectSource, onOpenUpload }) {
  if (!metrics || metrics.total_events === 0) {
    return (
      <div className="py-16 text-center max-w-xl mx-auto">
        <div className="h-16 w-16 mx-auto mb-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
          <Database className="h-8 w-8 text-cyan-400" />
        </div>
        <h2 className="text-xl font-bold text-white mb-2">No Active Security Dataset</h2>
        <p className="text-sm text-slate-400 mb-6 leading-relaxed">
          There are currently no security records loaded in the analytical pipeline. Load the multi-source SOC dataset, the enterprise incident dataset, or upload custom logs to populate the dashboard.
        </p>
        <button
          onClick={onOpenUpload}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-sm shadow-lg shadow-cyan-500/25 transition"
        >
          <Layers className="h-4 w-4" />
          <span>Load Logs or Demo Dataset</span>
        </button>
      </div>
    );
  }

  const sevColors = {
    'Critical': 'bg-rose-500',
    'High': 'bg-amber-500',
    'Medium': 'bg-yellow-500',
    'Low': 'bg-emerald-500',
    'Informational': 'bg-blue-500'
  };

  const sevTextColors = {
    'Critical': 'text-rose-400',
    'High': 'text-amber-400',
    'Medium': 'text-yellow-400',
    'Low': 'text-emerald-400',
    'Informational': 'text-blue-400'
  };

  return (
    <div className="space-y-6">
      
      {/* Time Span Banner */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Calendar className="h-5 w-5" />
          </div>
          <div>
            <span className="text-xs uppercase font-bold tracking-wider text-slate-400">Chronological Coverage</span>
            <div className="font-mono text-sm font-semibold text-slate-100">
              {metrics.time_range?.start || 'N/A'} <span className="text-slate-500 mx-1">→</span> {metrics.time_range?.end || 'N/A'} (UTC)
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
            <span className="text-slate-300 font-medium">Data Pipeline Active</span>
          </div>
          <div className="text-slate-400">
            Storage Engine: <span className="text-cyan-300 font-mono">SQLite (Indexed)</span>
          </div>
        </div>
      </div>

      {/* Top 5 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        
        {/* Total Events */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Total Events</span>
            <Database className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-extrabold text-white font-mono">
            {metrics.total_events?.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Normalized Canonical Records
          </div>
        </div>

        {/* High / Critical Threats */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-rose-950/60 hover:border-rose-900/80 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-rose-300">High / Critical</span>
            <ShieldAlert className="h-4 w-4 text-rose-400" />
          </div>
          <div className="text-2xl font-extrabold text-rose-400 font-mono">
            {((metrics.critical_events || 0) + (metrics.high_events || 0))?.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {metrics.critical_events || 0} Critical · {metrics.high_events || 0} High
          </div>
        </div>

        {/* Log Sources */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Log Sources</span>
            <Server className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-extrabold text-white font-mono">
            {metrics.unique_sources_count}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Multi-Source Integrated
          </div>
        </div>

        {/* Unique IP Entities */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Unique IPs</span>
            <Globe className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-extrabold text-white font-mono">
            {metrics.unique_ips_count}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Source & Target Network Hosts
          </div>
        </div>

        {/* Incident Clusters */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Incidents</span>
            <FolderGit2 className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-extrabold text-amber-300 font-mono">
            {metrics.incidents_count}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Correlated Event Clusters
          </div>
        </div>

      </div>

      {/* Middle Grid: Severity & Source Distributions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Severity Distribution */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
          <h3 className="text-sm font-bold text-white mb-4 flex items-center justify-between">
            <span>Severity Distribution</span>
            <span className="text-xs font-normal text-slate-400">Total: {metrics.total_events}</span>
          </h3>
          <div className="space-y-3">
            {metrics.severity_distribution?.map((sev) => {
              const pct = metrics.total_events > 0 ? ((sev.count / metrics.total_events) * 100).toFixed(1) : 0;
              return (
                <div key={sev.name}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className={`font-semibold ${sevTextColors[sev.name] || 'text-slate-300'}`}>
                      {sev.name}
                    </span>
                    <span className="font-mono text-slate-300">
                      {sev.count.toLocaleString()} <span className="text-slate-500">({pct}%)</span>
                    </span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                    <div 
                      className={`h-full rounded-full ${sevColors[sev.name] || 'bg-cyan-500'}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Source Distribution */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
          <h3 className="text-sm font-bold text-white mb-4 flex items-center justify-between">
            <span>Log Sources Breakdown</span>
            <span className="text-xs font-normal text-slate-400">Distinct: {metrics.unique_sources_count}</span>
          </h3>
          <div className="space-y-3">
            {metrics.source_distribution?.map((src) => {
              const pct = metrics.total_events > 0 ? ((src.count / metrics.total_events) * 100).toFixed(1) : 0;
              return (
                <div 
                  key={src.name}
                  onClick={() => onSelectSource && onSelectSource(src.name)}
                  className="cursor-pointer group"
                >
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-semibold text-slate-200 group-hover:text-cyan-400 transition">
                      {src.name}
                    </span>
                    <span className="font-mono text-slate-300">
                      {src.count.toLocaleString()} <span className="text-slate-500">({pct}%)</span>
                    </span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                    <div 
                      className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 group-hover:from-cyan-400 group-hover:to-blue-400 transition"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

      </div>

      {/* Bottom Grid: Top Interacting IPs & Incident Clusters */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Top Active Incident Clusters */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
          <h3 className="text-sm font-bold text-white mb-4 flex items-center justify-between">
            <span>Primary Incident Clusters</span>
            <span className="text-xs text-slate-400 font-normal">Correlated Investigations</span>
          </h3>
          {metrics.top_incidents?.length > 0 ? (
            <div className="space-y-2.5">
              {metrics.top_incidents.map((inc) => (
                <div 
                  key={inc.correlation_id}
                  onClick={() => onSelectIncident && onSelectIncident(inc.correlation_id)}
                  className="p-3 rounded-lg bg-slate-800/40 hover:bg-slate-800/80 border border-slate-800/80 hover:border-cyan-500/40 cursor-pointer transition flex items-center justify-between group"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-1.5 rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                      <FolderGit2 className="h-4 w-4" />
                    </div>
                    <div>
                      <div className="font-mono text-xs font-semibold text-slate-200 group-hover:text-cyan-400 transition">
                        {inc.correlation_id}
                      </div>
                      <div className="text-[11px] text-slate-400">
                        Max Severity: <span className={sevTextColors[inc.severity] || 'text-slate-300'}>{inc.severity}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {inc.count} events
                    </span>
                    <ArrowRight className="h-4 w-4 text-slate-500 group-hover:text-cyan-400 transition" />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-500 text-center py-8">
              No correlated incident clusters identified.
            </div>
          )}
        </div>

        {/* Top Interacting Network Entities (IPs) */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
          <h3 className="text-sm font-bold text-white mb-4 flex items-center justify-between">
            <span>High-Activity IP Entities</span>
            <span className="text-xs text-slate-400 font-normal">Source & Destination Flows</span>
          </h3>
          {metrics.top_ips?.length > 0 ? (
            <div className="space-y-2.5">
              {metrics.top_ips.map((item) => (
                <div 
                  key={item.ip}
                  className="p-3 rounded-lg bg-slate-800/40 border border-slate-800/80 flex items-center justify-between"
                >
                  <div className="flex items-center gap-2.5">
                    <Globe className="h-4 w-4 text-cyan-400" />
                    <span className="font-mono text-xs text-slate-200 font-semibold">{item.ip}</span>
                  </div>
                  <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    {item.count} occurrences
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-500 text-center py-8">
              No IP addresses recorded in active dataset.
            </div>
          )}
        </div>

      </div>

    </div>
  );
}
