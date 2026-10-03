import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Filter, 
  RotateCcw, 
  ChevronLeft, 
  ChevronRight, 
  ArrowUpDown, 
  ArrowUp, 
  ArrowDown, 
  ExternalLink,
  ShieldAlert,
  Server,
  Terminal,
  Clock,
  Layers,
  FileCode,
  Tag
} from 'lucide-react';

export default function TimelineTab({ 
  onSelectEvent, 
  initialIncident, 
  initialSource 
}) {
  const [events, setEvents] = useState([]);
  const [totalMatched, setTotalMatched] = useState(0);
  const [loading, setLoading] = useState(false);

  // Filters State
  const [search, setSearch] = useState('');
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');
  const [selectedSource, setSelectedSource] = useState(initialSource || '');
  const [selectedSeverity, setSelectedSeverity] = useState('');
  const [ipFilter, setIpFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [correlationFilter, setCorrelationFilter] = useState(initialIncident || '');

  // Pagination & Sorting State
  const [page, setPage] = useState(0);
  const [limit, setLimit] = useState(50);
  const [sortBy, setSortBy] = useState('timestamp');
  const [sortOrder, setSortOrder] = useState('ASC');

  // Sync initial props
  useEffect(() => {
    if (initialIncident) {
      setCorrelationFilter(initialIncident);
      setPage(0);
    }
  }, [initialIncident]);

  useEffect(() => {
    if (initialSource) {
      setSelectedSource(initialSource);
      setPage(0);
    }
  }, [initialSource]);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (search) params.append('search', search);
      if (startTime) params.append('start_time', startTime);
      if (endTime) params.append('end_time', endTime);
      if (selectedSource) params.append('log_sources', selectedSource);
      if (selectedSeverity) params.append('severities', selectedSeverity);
      if (ipFilter) params.append('ip', ipFilter);
      if (userFilter) params.append('username', userFilter);
      if (correlationFilter) params.append('correlation_id', correlationFilter);

      params.append('limit', limit);
      params.append('offset', page * limit);
      params.append('sort_by', sortBy);
      params.append('sort_order', sortOrder);

      const res = await fetch(`/api/events?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events || []);
        setTotalMatched(data.total_matched || 0);
      }
    } catch (err) {
      console.error('Failed to load events:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [
    search, 
    startTime, 
    endTime, 
    selectedSource, 
    selectedSeverity, 
    ipFilter, 
    userFilter, 
    correlationFilter, 
    page, 
    limit, 
    sortBy, 
    sortOrder
  ]);

  const resetFilters = () => {
    setSearch('');
    setStartTime('');
    setEndTime('');
    setSelectedSource('');
    setSelectedSeverity('');
    setIpFilter('');
    setUserFilter('');
    setCorrelationFilter('');
    setSortBy('timestamp');
    setSortOrder('ASC');
    setPage(0);
  };

  const hasActiveFilters = Boolean(
    search || startTime || endTime || selectedSource || selectedSeverity || ipFilter || userFilter || correlationFilter
  );

  const totalPages = Math.ceil(totalMatched / limit) || 1;

  const handleSort = (column) => {
    if (sortBy === column) {
      setSortOrder(sortOrder === 'ASC' ? 'DESC' : 'ASC');
    } else {
      setSortBy(column);
      setSortOrder('ASC');
    }
    setPage(0);
  };

  const getSeverityBadge = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical':
        return <span className="px-2 py-0.5 rounded-full text-[10px] font-extrabold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/40">Critical</span>;
      case 'high':
        return <span className="px-2 py-0.5 rounded-full text-[10px] font-extrabold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40">High</span>;
      case 'medium':
        return <span className="px-2 py-0.5 rounded-full text-[10px] font-extrabold uppercase bg-yellow-500/20 text-yellow-300 border border-yellow-500/40">Medium</span>;
      case 'low':
        return <span className="px-2 py-0.5 rounded-full text-[10px] font-extrabold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">Low</span>;
      default:
        return <span className="px-2 py-0.5 rounded-full text-[10px] font-extrabold uppercase bg-blue-500/20 text-blue-300 border border-blue-500/40">Info</span>;
    }
  };

  const getSourceBadge = (source) => {
    const s = source?.toLowerCase() || '';
    let color = 'bg-slate-800 text-slate-300 border-slate-700';
    if (s.includes('windows')) color = 'bg-blue-900/30 text-blue-300 border-blue-500/30';
    else if (s.includes('firewall')) color = 'bg-purple-900/30 text-purple-300 border-purple-500/30';
    else if (s.includes('linux')) color = 'bg-amber-900/30 text-amber-300 border-amber-500/30';
    else if (s.includes('app')) color = 'bg-emerald-900/30 text-emerald-300 border-emerald-500/30';

    return <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${color}`}>{source || 'Unknown'}</span>;
  };

  return (
    <div className="space-y-4">
      
      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
        
        {/* Top Filter Row: Search & Dropdowns */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          
          {/* Free Text Search */}
          <div className="relative">
            <Search className="h-4 w-4 absolute left-3 top-3 text-slate-400" />
            <input
              type="text"
              placeholder="Search description, host, message..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(0); }}
              className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500 transition"
            />
          </div>

          {/* Log Source Filter */}
          <div>
            <select
              value={selectedSource}
              onChange={(e) => { setSelectedSource(e.target.value); setPage(0); }}
              className="w-full px-3 py-2 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500 transition"
            >
              <option value="">All Log Sources</option>
              <option value="Firewall">Firewall</option>
              <option value="Windows">Windows</option>
              <option value="Linux">Linux</option>
              <option value="Application">Application</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div>
            <select
              value={selectedSeverity}
              onChange={(e) => { setSelectedSeverity(e.target.value); setPage(0); }}
              className="w-full px-3 py-2 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500 transition"
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Informational">Informational</option>
            </select>
          </div>

          {/* Reset Filters Button */}
          <div className="flex items-center gap-2">
            <button
              onClick={resetFilters}
              disabled={!hasActiveFilters}
              className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold border transition ${
                hasActiveFilters
                  ? 'bg-rose-500/10 border-rose-500/30 text-rose-300 hover:bg-rose-500/20 cursor-pointer'
                  : 'bg-slate-800/50 border-slate-800 text-slate-500 cursor-not-allowed'
              }`}
            >
              <RotateCcw className="h-3.5 w-3.5" />
              <span>Reset Filters</span>
            </button>
          </div>

        </div>

        {/* Second Filter Row: Date Range, IP, Username, Correlation ID */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-2 border-t border-slate-800/60">
          
          {/* Start Time */}
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-400 whitespace-nowrap">From:</span>
            <input
              type="text"
              placeholder="YYYY-MM-DD HH:MM:SS"
              value={startTime}
              onChange={(e) => { setStartTime(e.target.value); setPage(0); }}
              className="w-full px-2.5 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* End Time */}
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-400 whitespace-nowrap">To:</span>
            <input
              type="text"
              placeholder="YYYY-MM-DD HH:MM:SS"
              value={endTime}
              onChange={(e) => { setEndTime(e.target.value); setPage(0); }}
              className="w-full px-2.5 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* IP Filter */}
          <div>
            <input
              type="text"
              placeholder="Filter by IP (e.g. 203.0.113.45)"
              value={ipFilter}
              onChange={(e) => { setIpFilter(e.target.value); setPage(0); }}
              className="w-full px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-white placeholder-slate-400 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Incident / Correlation ID Filter */}
          <div>
            <input
              type="text"
              placeholder="Correlation / Incident ID"
              value={correlationFilter}
              onChange={(e) => { setCorrelationFilter(e.target.value); setPage(0); }}
              className="w-full px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-white placeholder-slate-400 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>

        </div>

      </div>

      {/* Results Header: Matched Count & Pagination Info */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-1 text-xs">
        <div className="flex items-center gap-2 text-slate-300">
          <span>Matching Events:</span>
          <span className="font-mono font-bold text-cyan-400 text-sm">
            {totalMatched.toLocaleString()}
          </span>
          {hasActiveFilters && (
            <span className="px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 text-[10px]">
              Filtered Scope
            </span>
          )}
        </div>

        {/* Sort & Page Selector */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-slate-400">
            <span>Rows:</span>
            <select
              value={limit}
              onChange={(e) => { setLimit(Number(e.target.value)); setPage(0); }}
              className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-xs text-slate-200 focus:outline-none"
            >
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={250}>250</option>
            </select>
          </div>

          <div className="flex items-center gap-1 text-slate-400">
            <span>Page {page + 1} of {totalPages}</span>
            <button
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 disabled:cursor-not-allowed border border-slate-700 text-white transition ml-1"
            >
              <ChevronLeft className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
              disabled={page >= totalPages - 1}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 disabled:cursor-not-allowed border border-slate-700 text-white transition"
            >
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Timeline Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-800 bg-[#0d1424] text-slate-400 font-semibold select-none">
              
              <th 
                onClick={() => handleSort('timestamp')}
                className="py-3 px-3.5 cursor-pointer hover:text-cyan-300 transition whitespace-nowrap"
              >
                <div className="flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Timestamp (UTC)</span>
                  {sortBy === 'timestamp' ? (
                    sortOrder === 'ASC' ? <ArrowUp className="h-3 w-3 text-cyan-400" /> : <ArrowDown className="h-3 w-3 text-cyan-400" />
                  ) : <ArrowUpDown className="h-3 w-3 opacity-40" />}
                </div>
              </th>

              <th 
                onClick={() => handleSort('severity')}
                className="py-3 px-3 cursor-pointer hover:text-cyan-300 transition whitespace-nowrap"
              >
                <div className="flex items-center gap-1.5">
                  <span>Severity</span>
                  {sortBy === 'severity' ? (
                    sortOrder === 'ASC' ? <ArrowUp className="h-3 w-3 text-cyan-400" /> : <ArrowDown className="h-3 w-3 text-cyan-400" />
                  ) : <ArrowUpDown className="h-3 w-3 opacity-40" />}
                </div>
              </th>

              <th 
                onClick={() => handleSort('log_source')}
                className="py-3 px-3 cursor-pointer hover:text-cyan-300 transition whitespace-nowrap"
              >
                <div className="flex items-center gap-1.5">
                  <span>Source</span>
                  {sortBy === 'log_source' ? (
                    sortOrder === 'ASC' ? <ArrowUp className="h-3 w-3 text-cyan-400" /> : <ArrowDown className="h-3 w-3 text-cyan-400" />
                  ) : <ArrowUpDown className="h-3 w-3 opacity-40" />}
                </div>
              </th>

              <th className="py-3 px-3 whitespace-nowrap">Event Type / Action</th>
              <th className="py-3 px-3 whitespace-nowrap">Source IP → Destination</th>
              <th className="py-3 px-3 whitespace-nowrap">Host / User</th>
              <th className="py-3 px-3 whitespace-nowrap">Description</th>
              <th className="py-3 px-3 text-right whitespace-nowrap">Inspect</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-800/60">
            {loading ? (
              <tr>
                <td colSpan={8} className="py-12 text-center text-slate-400">
                  <div className="flex items-center justify-center gap-2">
                    <div className="h-4 w-4 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
                    <span>Querying database index...</span>
                  </div>
                </td>
              </tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-16 text-center text-slate-400">
                  <div className="max-w-sm mx-auto space-y-2">
                    <Filter className="h-8 w-8 text-slate-600 mx-auto" />
                    <div className="font-semibold text-slate-300">No Events Found</div>
                    <p className="text-xs text-slate-500">
                      No records match the current filter criteria. Try adjusting date limits or resetting the search filters.
                    </p>
                    {hasActiveFilters && (
                      <button
                        onClick={resetFilters}
                        className="mt-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-semibold border border-slate-700"
                      >
                        Reset All Filters
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              events.map((evt) => (
                <tr
                  key={evt.id}
                  onClick={() => onSelectEvent(evt.id)}
                  className="hover:bg-slate-800/40 cursor-pointer transition group"
                >
                  {/* Timestamp */}
                  <td className="py-2.5 px-3.5 font-mono text-[11px] text-slate-300 whitespace-nowrap">
                    {evt.timestamp || '—'}
                  </td>

                  {/* Severity */}
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    {getSeverityBadge(evt.severity)}
                  </td>

                  {/* Log Source */}
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    {getSourceBadge(evt.log_source)}
                  </td>

                  {/* Event Type & Action */}
                  <td className="py-2.5 px-3 max-w-[160px] truncate">
                    <div className="font-semibold text-slate-200 truncate">{evt.event_type || '—'}</div>
                    <div className="text-[10px] text-slate-400 truncate">{evt.action || '—'}</div>
                  </td>

                  {/* Source IP -> Destination */}
                  <td className="py-2.5 px-3 font-mono text-[11px] whitespace-nowrap">
                    {evt.source_ip || evt.destination_ip ? (
                      <span className="text-slate-300">
                        {evt.source_ip || '—'} 
                        {evt.destination_ip && (
                          <>
                            <span className="text-cyan-500/70 mx-1">→</span>
                            <span className="text-slate-400">{evt.destination_ip}</span>
                          </>
                        )}
                      </span>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>

                  {/* Host / User */}
                  <td className="py-2.5 px-3 text-[11px] max-w-[130px] truncate">
                    <div className="font-semibold text-slate-300 truncate">{evt.hostname || '—'}</div>
                    <div className="text-[10px] text-cyan-400/80 truncate">{evt.username || '—'}</div>
                  </td>

                  {/* Description */}
                  <td className="py-2.5 px-3 text-[11px] text-slate-300 max-w-[320px] truncate">
                    {evt.description || evt.raw_record || '—'}
                  </td>

                  {/* Inspect CTA */}
                  <td className="py-2.5 px-3 text-right">
                    <button
                      onClick={(e) => { e.stopPropagation(); onSelectEvent(evt.id); }}
                      className="p-1 rounded hover:bg-slate-700 text-slate-500 group-hover:text-cyan-400 transition"
                      title="Inspect Event"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                    </button>
                  </td>

                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="flex items-center justify-between text-xs text-slate-400 px-1 pt-1">
        <div>
          Showing {events.length > 0 ? page * limit + 1 : 0} to {Math.min((page + 1) * limit, totalMatched)} of {totalMatched.toLocaleString()} events
        </div>
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setPage(0)}
            disabled={page === 0}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 border border-slate-700 text-white transition"
          >
            First
          </button>
          <button
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 border border-slate-700 text-white transition"
          >
            Prev
          </button>
          <span className="px-2 text-slate-300 font-mono">
            {page + 1} / {totalPages}
          </span>
          <button
            onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 border border-slate-700 text-white transition"
          >
            Next
          </button>
          <button
            onClick={() => setPage(totalPages - 1)}
            disabled={page >= totalPages - 1}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 border border-slate-700 text-white transition"
          >
            Last
          </button>
        </div>
      </div>

    </div>
  );
}
