import React, { useState } from 'react';
import { apiFetch } from '../api';
import { 
  X, 
  UploadCloud, 
  FileText, 
  Database, 
  Layers, 
  AlertTriangle, 
  CheckCircle2, 
  Play,
  FileCheck
} from 'lucide-react';

export default function UploadModal({ 
  isOpen, 
  onClose, 
  onUploadSuccess, 
  onRunDemo, 
  onRunEnterprise, 
  onRunTestSuite,
  running 
}) {
  if (!isOpen) return null;

  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);

  const handleFileChange = (e) => {
    if (e.target.files) {
      setFiles(Array.from(e.target.files));
      setErrorMsg(null);
    }
  };

  const handleUploadSubmit = async () => {
    if (files.length === 0) {
      setErrorMsg('Please select at least one file to upload.');
      return;
    }

    setUploading(true);
    setErrorMsg(null);
    setUploadResult(null);

    const formData = new FormData();
    files.forEach(f => formData.append('files', f));

    try {
      const res = await apiFetch('/api/upload', {
        method: 'POST',
        body: formData
      });

      if (!res.ok) {
        if (res.status === 404) {
          throw new Error('Upload API not found. Set VITE_API_BASE_URL to your deployed FastAPI URL in Vercel, then redeploy.');
        }
        throw new Error(`Upload failed with status ${res.status}`);
      }

      const result = await res.json();
      setUploadResult(result);
      if (onUploadSuccess) onUploadSuccess(result);
    } catch (err) {
      setErrorMsg(err.message || 'Failed to process uploaded files.');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-2xl bg-[#0d1424] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <UploadCloud className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white">Ingest Logs & Load Datasets</h2>
              <p className="text-xs text-slate-400">
                Supply multi-source log files or load vetted benchmark datasets
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

        {/* Modal Body */}
        <div className="p-6 space-y-6">
          
          {/* Quick Demo Dataset Options */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-1.5">
              <Play className="h-3.5 w-3.5 text-cyan-400" />
              <span>Instant Benchmark Data (One-Click)</span>
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              
              <button
                onClick={() => { onRunDemo(); onClose(); }}
                disabled={running}
                className="p-3.5 rounded-xl bg-slate-900/80 hover:bg-slate-800/80 border border-cyan-500/30 hover:border-cyan-500 text-left transition group"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-xs text-cyan-300">Multi-Source Logs</span>
                  <Layers className="h-4 w-4 text-cyan-400 group-hover:scale-110 transition" />
                </div>
                <p className="text-[11px] text-slate-400">
                  Firewall CSV, Windows Events, Linux Syslog, Application logs (60 events).
                </p>
              </button>

              <button
                onClick={() => { onRunEnterprise(); onClose(); }}
                disabled={running}
                className="p-3.5 rounded-xl bg-slate-900/80 hover:bg-slate-800/80 border border-blue-500/30 hover:border-blue-500 text-left transition group"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-xs text-blue-300">Enterprise Incident Dataset</span>
                  <Database className="h-4 w-4 text-blue-400 group-hover:scale-110 transition" />
                </div>
                <p className="text-[11px] text-slate-400">
                  Production enterprise incident records from incident_timeline_cleaned.csv with full network topology and correlations.
                </p>
              </button>

              <button
                onClick={() => { onRunTestSuite(); onClose(); }}
                disabled={running}
                className="p-3.5 rounded-xl bg-slate-900/80 hover:bg-slate-800/80 border border-amber-500/30 hover:border-amber-500 text-left transition group"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-xs text-amber-300">Edge-Case Suite</span>
                  <AlertTriangle className="h-4 w-4 text-amber-400 group-hover:scale-110 transition" />
                </div>
                <p className="text-[11px] text-slate-400">
                  Tests malformed dates, exact duplicates, sliding bursts, and error logs.
                </p>
              </button>

            </div>
          </div>

          {/* Custom File Upload Section */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-1.5">
              <UploadCloud className="h-3.5 w-3.5 text-cyan-400" />
              <span>Upload Custom Log Files</span>
            </h3>

            <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500/50 rounded-xl p-6 text-center bg-slate-900/40 transition">
              <input
                type="file"
                multiple
                accept=".csv,.json,.log,.txt"
                onChange={handleFileChange}
                className="hidden"
                id="file-upload"
              />
              <label htmlFor="file-upload" className="cursor-pointer space-y-2 block">
                <UploadCloud className="h-8 w-8 text-cyan-400 mx-auto" />
                <div className="text-xs font-medium text-slate-300">
                  <span className="text-cyan-400 underline underline-offset-2">Browse files</span> or drag and drop
                </div>
                <p className="text-[11px] text-slate-500">
                  Supported formats: CSV (Firewall, Windows, Canonical), Syslog (.log), App logs (.txt), JSON
                </p>
              </label>

              {files.length > 0 && (
                <div className="mt-4 pt-3 border-t border-slate-800 text-left">
                  <span className="text-[11px] font-bold text-slate-400 uppercase">Selected Files ({files.length}):</span>
                  <ul className="mt-1.5 space-y-1 font-mono text-xs text-cyan-300">
                    {files.map((f, i) => (
                      <li key={i} className="flex items-center justify-between">
                        <span>{f.name}</span>
                        <span className="text-slate-500 text-[10px]">{(f.size / 1024).toFixed(1)} KB</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {errorMsg && (
              <div className="mt-3 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
                {errorMsg}
              </div>
            )}

            {uploadResult && (
              <div className="mt-3 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center justify-between">
                <div>
                  ✓ Pipeline completed! {uploadResult.final_events_count} records processed. {uploadResult.duplicates_removed} duplicates removed.
                </div>
              </div>
            )}
          </div>

        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between text-xs">
          <span className="text-slate-500">Preserves original raw logs verbatim</span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold border border-slate-700 transition"
            >
              Cancel
            </button>
            <button
              onClick={handleUploadSubmit}
              disabled={uploading || files.length === 0}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold shadow-md shadow-cyan-500/20 transition"
            >
              {uploading && <div className="h-3.5 w-3.5 rounded-full border-2 border-white border-t-transparent animate-spin" />}
              <span>{uploading ? 'Processing Pipeline...' : 'Process Uploaded Files'}</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
