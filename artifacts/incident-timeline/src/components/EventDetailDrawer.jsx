import React, { useState, useEffect } from 'react';
import { apiFetch } from '../api';
import { 
  X, 
  ShieldAlert, 
  Terminal, 
  FileCode, 
  FolderGit2, 
  Clock, 
  Layers, 
  Tag, 
  ExternalLink,
  Copy,
  Check
} from 'lucide-react';

export default function EventDetailDrawer({ eventId, onClose, onSelectEvent }) {
  const [eventData, setEventData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!eventId) return;
    setLoading(true);
    apiFetch(`/api/events/${eventId}`)
      .then(res => res.json())
      .then(data => {
        setEventData(data);
        setLoading(false);
      })
      .catch(err => {
        console.error('Failed to load event detail:', err);
        setLoading(false);
      });
  }, [eventId]);

  if (!eventId) return null;

  const copyRaw = () => {
    if (eventData?.raw_record) {
      navigator.clipboard.writeText(eventData.raw_record);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const canonicalFields = [
    { label: 'Event ID Unique', key: 'event_id_unique', mono: true },
    { label: 'Timestamp (UTC)', key: 'timestamp', mono: true },
    { label: 'Log Source', key: 'log_source' },
    { label: 'Source Event ID', key: 'event_id', mono: true },
    { label: 'Event Type', key: 'event_type' },
    { label: 'Severity', key: 'severity' },
    { label: 'Action', key: 'action' },
    { label: 'Username', key: 'username', mono: true },
    { label: 'Source IP', key: 'source_ip', mono: true },
    { label: 'Destination IP', key: 'destination_ip', mono: true },
    { label: 'Source Port', key: 'source_port', mono: true },
    { label: 'Destination Port', key: 'destination_port', mono: true },
    { label: 'Protocol', key: 'protocol' },
    { label: 'Hostname', key: 'hostname', mono: true },
    { label: 'Device Type', key: 'device_type' },
    { label: 'Department', key: 'department' },
    { label: 'Country', key: 'country' },
    { label: 'Session ID', key: 'session_id', mono: true },
    { label: 'Correlation ID', key: 'correlation_id', mono: true },
    { label: 'Process Name', key: 'process_name', mono: true },
    { label: 'File Name', key: 'file_name', mono: true },
    { label: 'File Hash', key: 'file_hash', mono: true },
    { label: 'Bytes Sent', key: 'bytes_sent', mono: true },
    { label: 'Bytes Received', key: 'bytes_received', mono: true },
    { label: 'Response Code', key: 'response_code', mono: true },
    { label: 'Status', key: 'status' }
  ];

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end">
      <div 
        className="w-full max-w-2xl bg-[#0d1424] border-l border-slate-800 shadow-2xl h-full flex flex-col transform transition-transform duration-300 ease-in-out"
      >
        {/* Drawer Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <FileCode className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <span>Forensic Event Inspection</span>
                <span className="font-mono text-xs text-cyan-400 font-normal">
                  #{eventData?.id || eventId}
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Canonical Normalized Fields & Raw Evidence Trace
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Drawer Body */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6">
          
          {loading ? (
            <div className="py-24 text-center text-slate-400 flex items-center justify-center gap-2">
              <div className="h-5 w-5 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
              <span>Loading record attributes...</span>
            </div>
          ) : !eventData ? (
            <div className="py-24 text-center text-slate-500">Record not found.</div>
          ) : (
            <>
              {/* Event Description Callout */}
              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Event Description / Message</span>
                <p className="text-sm font-medium text-slate-100 mt-1 leading-relaxed">
                  {eventData.description || '—'}
                </p>
              </div>

              {/* Source Origin Metadata */}
              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs flex flex-wrap items-center justify-between gap-2">
                <div>
                  <span className="text-slate-400">Source File: </span>
                  <span className="font-mono text-cyan-300 font-semibold">{eventData.source_file || 'Direct Load'}</span>
                </div>
                <div>
                  <span className="text-slate-400">Source Row Index: </span>
                  <span className="font-mono text-slate-200">#{eventData.source_row_index || '—'}</span>
                </div>
              </div>

              {/* 27 Canonical Schema Grid */}
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-1.5">
                  <Layers className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Canonical Normalized Attributes</span>
                </h3>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  {canonicalFields.map(f => {
                    const val = eventData[f.key];
                    const isMissing = val === null || val === undefined || val === '';
                    return (
                      <div 
                        key={f.key}
                        className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-800/80 flex flex-col justify-between"
                      >
                        <span className="text-[10px] text-slate-400 font-medium">{f.label}</span>
                        <span className={`text-xs mt-0.5 truncate ${
                          isMissing 
                            ? 'text-slate-600 font-normal italic' 
                            : (f.mono ? 'font-mono text-cyan-200 font-semibold' : 'text-slate-200 font-medium')
                        }`}>
                          {isMissing ? '—' : String(val)}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Raw Record Monospace Callout */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Terminal className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Unaltered Raw Evidence</span>
                  </h3>
                  <button
                    onClick={copyRaw}
                    className="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                  >
                    {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>

                <div className="p-3 rounded-lg bg-[#070b14] border border-slate-800 font-mono text-xs text-cyan-300 break-all leading-relaxed overflow-x-auto select-all">
                  {eventData.raw_record || 'No raw record preserved.'}
                </div>
              </div>

              {/* Correlated Events Section */}
              {eventData.correlated_events?.length > 0 && (
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-1.5">
                    <FolderGit2 className="h-3.5 w-3.5 text-amber-400" />
                    <span>Correlated Evidence ({eventData.correlated_events.length})</span>
                  </h3>

                  <div className="space-y-2">
                    {eventData.correlated_events.map(c => (
                      <div
                        key={c.id}
                        onClick={() => onSelectEvent(c.id)}
                        className="p-2.5 rounded-lg bg-slate-900 hover:bg-slate-800/80 border border-slate-800 cursor-pointer transition flex items-center justify-between text-xs group"
                      >
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[11px] text-cyan-400 font-semibold">{c.timestamp}</span>
                            <span className="px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700 font-medium">
                              {c.log_source}
                            </span>
                            <span className="text-[10px] font-bold text-amber-400">{c.severity}</span>
                          </div>
                          <div className="text-slate-300 font-medium">
                            {c.event_type} {c.action && `· ${c.action}`}
                          </div>
                        </div>

                        <ExternalLink className="h-3.5 w-3.5 text-slate-500 group-hover:text-cyan-400 transition" />
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </>
          )}

        </div>

        {/* Drawer Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between text-xs text-slate-400">
          <div>SOC Forensics Engine v2.0</div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold border border-slate-700 transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
