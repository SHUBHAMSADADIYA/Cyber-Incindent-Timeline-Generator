import React, { useState } from 'react';
import { apiFetch } from '../api';
import { 
  X, 
  Download, 
  FileText, 
  FileSpreadsheet, 
  Code, 
  ShieldCheck, 
  Layers, 
  CheckCircle2 
} from 'lucide-react';

export default function ReportModal({ isOpen, onClose, topIncidents }) {
  if (!isOpen) return null;

  const [format, setFormat] = useState('pdf');
  const [scope, setScope] = useState('all');
  const [selectedIncident, setSelectedIncident] = useState('');
  const [title, setTitle] = useState('Cyber Incident Forensics & Timeline Report');
  const [downloading, setDownloading] = useState(false);

  const handleDownload = async () => {
    setDownloading(true);
    try {
      const payload = {
        scope: scope === 'incident' ? 'incident' : 'all',
        correlation_id: scope === 'incident' ? selectedIncident : null,
        report_title: title,
        include_iocs: true,
        include_notes: true
      };

      const res = await apiFetch(`/api/export/${format}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) throw new Error('Export generation failed');

      // Create download blob
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      
      const contentDisp = res.headers.get('content-disposition');
      let filename = `incident_report.${format}`;
      if (contentDisp && contentDisp.includes('filename=')) {
        filename = contentDisp.split('filename=')[1].replace(/["']/g, '');
      }

      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      onClose();
    } catch (err) {
      console.error('Export download error:', err);
      alert('Failed to generate export file. Please try again.');
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-lg bg-[#0d1424] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Download className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white">Generate Incident Report</h2>
              <p className="text-xs text-slate-400">
                Export forensic deliverables matching reviewed evidence scope
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 text-xs">
          
          {/* Format Selection */}
          <div>
            <label className="block text-slate-400 font-bold uppercase tracking-wider mb-2">
              Export Format
            </label>
            <div className="grid grid-cols-3 gap-3">
              
              <button
                type="button"
                onClick={() => setFormat('pdf')}
                className={`p-3.5 rounded-xl border text-center transition flex flex-col items-center gap-2 ${
                  format === 'pdf'
                    ? 'bg-cyan-500/15 border-cyan-500 text-cyan-300 shadow-md shadow-cyan-500/10'
                    : 'bg-slate-900/80 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <FileText className="h-5 w-5" />
                <span className="font-bold">Executive PDF</span>
              </button>

              <button
                type="button"
                onClick={() => setFormat('csv')}
                className={`p-3.5 rounded-xl border text-center transition flex flex-col items-center gap-2 ${
                  format === 'csv'
                    ? 'bg-cyan-500/15 border-cyan-500 text-cyan-300 shadow-md shadow-cyan-500/10'
                    : 'bg-slate-900/80 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <FileSpreadsheet className="h-5 w-5" />
                <span className="font-bold">Filtered CSV</span>
              </button>

              <button
                type="button"
                onClick={() => setFormat('json')}
                className={`p-3.5 rounded-xl border text-center transition flex flex-col items-center gap-2 ${
                  format === 'json'
                    ? 'bg-cyan-500/15 border-cyan-500 text-cyan-300 shadow-md shadow-cyan-500/10'
                    : 'bg-slate-900/80 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <Code className="h-5 w-5" />
                <span className="font-bold">Evidence JSON</span>
              </button>

            </div>
          </div>

          {/* Scope Selection */}
          <div>
            <label className="block text-slate-400 font-bold uppercase tracking-wider mb-2">
              Report Scope
            </label>
            <div className="space-y-2">
              <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 cursor-pointer hover:bg-slate-800/50">
                <input
                  type="radio"
                  name="scope"
                  checked={scope === 'all'}
                  onChange={() => setScope('all')}
                  className="text-cyan-500 focus:ring-0"
                />
                <span className="text-slate-200 font-medium">Full Active Dataset Scope</span>
              </label>

              <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 cursor-pointer hover:bg-slate-800/50">
                <input
                  type="radio"
                  name="scope"
                  checked={scope === 'incident'}
                  onChange={() => setScope('incident')}
                  className="text-cyan-500 focus:ring-0"
                />
                <span className="text-slate-200 font-medium">Specific Incident Cluster</span>
              </label>
            </div>

            {scope === 'incident' && (
              <div className="mt-2.5">
                <select
                  value={selectedIncident}
                  onChange={(e) => setSelectedIncident(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                >
                  <option value="">Select Incident Correlation ID</option>
                  {topIncidents?.map(inc => (
                    <option key={inc.correlation_id} value={inc.correlation_id}>
                      {inc.correlation_id} ({inc.count} events)
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Report Title */}
          <div>
            <label className="block text-slate-400 font-bold uppercase tracking-wider mb-1.5">
              Report Header Title
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white focus:outline-none focus:border-cyan-500"
            />
          </div>

        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between text-xs">
          <span className="text-slate-500">Ready for stakeholder delivery</span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold border border-slate-700 transition"
            >
              Cancel
            </button>
            <button
              onClick={handleDownload}
              disabled={downloading || (scope === 'incident' && !selectedIncident)}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold shadow-md shadow-cyan-500/20 transition"
            >
              {downloading && <div className="h-3.5 w-3.5 rounded-full border-2 border-white border-t-transparent animate-spin" />}
              <span>{downloading ? 'Compiling File...' : `Download ${format.toUpperCase()}`}</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
