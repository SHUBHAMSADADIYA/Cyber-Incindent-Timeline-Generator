import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Save, 
  CheckCircle2, 
  User, 
  Clock, 
  FolderGit2, 
  ShieldCheck, 
  AlertTriangle,
  RotateCcw
} from 'lucide-react';

export default function InvestigationTab({ onCaseUpdated }) {
  const [caseId, setCaseId] = useState('CASE-001');
  const [title, setTitle] = useState('');
  const [status, setStatus] = useState('In Progress');
  const [analyst, setAnalyst] = useState('');
  const [notes, setNotes] = useState('');
  const [updatedAt, setUpdatedAt] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const fetchCaseDetails = async () => {
    try {
      const res = await fetch('/api/case');
      if (res.ok) {
        const data = await res.json();
        setCaseId(data.case_id || 'CASE-001');
        setTitle(data.title || 'Multi-Source Cyber Security Incident');
        setStatus(data.status || 'In Progress');
        setAnalyst(data.assigned_analyst || 'SOC Lead Analyst');
        setNotes(data.notes || '');
        setUpdatedAt(data.updated_at || '');
      }
    } catch (err) {
      console.error('Failed to fetch case details:', err);
    }
  };

  useEffect(() => {
    fetchCaseDetails();
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setSaveSuccess(false);

    try {
      const res = await fetch('/api/case', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: caseId,
          title: title,
          status: status,
          assigned_analyst: analyst,
          notes: notes
        })
      });

      if (res.ok) {
        const result = await res.json();
        setUpdatedAt(result.updated_at);
        setSaveSuccess(true);
        if (onCaseUpdated) {
          onCaseUpdated({ case_id: caseId, title, status, assigned_analyst: analyst });
        }
        setTimeout(() => setSaveSuccess(false), 3000);
      }
    } catch (err) {
      console.error('Failed to save case:', err);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      
      {/* Header */}
      <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <FileText className="h-5 w-5 text-cyan-400" />
            <span>Investigation Workspace & Analyst Notebook</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            All case statuses, assigned investigators, and forensic findings persist to the encrypted local database.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {saveSuccess && (
            <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-semibold px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
              <CheckCircle2 className="h-4 w-4" />
              <span>Persisted to Database</span>
            </div>
          )}

          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold shadow-md shadow-cyan-500/20 transition active:scale-95"
          >
            {saving ? (
              <div className="h-3.5 w-3.5 rounded-full border-2 border-white border-t-transparent animate-spin" />
            ) : (
              <Save className="h-4 w-4" />
            )}
            <span>Save Case Notes</span>
          </button>
        </div>
      </div>

      {/* Case Metadata Form */}
      <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <FolderGit2 className="h-4 w-4 text-cyan-400" />
          <span>Case Attributes</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
          
          <div>
            <label className="block text-slate-400 font-medium mb-1">Case Identifier</label>
            <input
              type="text"
              value={caseId}
              disabled
              className="w-full px-3 py-2 rounded-lg bg-slate-800/50 border border-slate-700/80 font-mono text-cyan-300 font-bold focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-slate-400 font-medium mb-1">Investigation Status</label>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-100 font-medium focus:outline-none focus:border-cyan-500"
            >
              <option value="New">New Triage</option>
              <option value="In Progress">In Progress</option>
              <option value="Under Review">Under Review</option>
              <option value="Escalated">Escalated (Tier 3)</option>
              <option value="Closed">Closed / Remediated</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 font-medium mb-1">Assigned Lead Analyst</label>
            <input
              type="text"
              value={analyst}
              onChange={(e) => setAnalyst(e.target.value)}
              placeholder="e.g. John Doe, Senior IR"
              className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-100 focus:outline-none focus:border-cyan-500"
            />
          </div>

        </div>

        <div>
          <label className="block text-slate-400 font-medium mb-1 text-xs">Incident Title / Summary Headline</label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Forensic Notes Editor */}
      <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between text-xs">
          <span className="font-bold uppercase tracking-wider text-slate-400">
            Forensic Findings, Hypothesis & Containment Log
          </span>
          {updatedAt && (
            <span className="text-slate-500 text-[11px] font-mono">
              Last saved: {updatedAt}
            </span>
          )}
        </div>

        <textarea
          rows={12}
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Document timeline evidence, threat actor TTPs, lateral movement paths, compromised host forensics, containment actions, and stakeholder communication..."
          className="w-full p-4 rounded-xl bg-[#090e1a] border border-slate-800 font-mono text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 leading-relaxed resize-y"
        />

        <div className="flex items-center justify-between text-[11px] text-slate-500">
          <span>Markdown notes formatted for executive PDF & JSON report exports</span>
          <span>{notes.length} characters</span>
        </div>
      </div>

    </div>
  );
}
