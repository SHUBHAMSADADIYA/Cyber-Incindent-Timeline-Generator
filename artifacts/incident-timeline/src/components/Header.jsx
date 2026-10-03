import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  UploadCloud, 
  Download, 
  Layers, 
  Clock, 
  FileText, 
  Search, 
  Terminal,
  CheckCircle2,
  RefreshCw
} from 'lucide-react';

export default function Header({ 
  activeTab, 
  setActiveTab, 
  onOpenUpload, 
  onOpenExport, 
  healthStatus, 
  caseDetails,
  onRefresh
}) {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: Activity },
    { id: 'timeline', label: 'Incident Timeline', icon: Clock },
    { id: 'pipeline', label: 'Processing Pipeline', icon: Layers },
    { id: 'iocs', label: 'IOC & Threat Evidence', icon: ShieldAlert },
    { id: 'investigation', label: 'Investigation Case', icon: FileText },
  ];

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'closed': return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
      case 'escalated': return 'bg-rose-500/20 text-rose-300 border-rose-500/30';
      case 'under review': return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
      default: return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
    }
  };

  return (
    <header className="border-b border-slate-800 bg-[#0c1222]/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo & Platform Info */}
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/40">
              <ShieldAlert className="h-6 w-6 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold tracking-tight text-white text-base sm:text-lg">
                  CYBER INCIDENT <span className="text-cyan-400">TIMELINE</span>
                </span>
                <span className="text-[10px] uppercase font-bold tracking-widest px-2 py-0.5 rounded-full bg-slate-800 text-cyan-400 border border-cyan-500/30">
                  v2.0 PRO
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Multi-Source Forensics, Unified Schema & Chronological Synthesis
              </p>
            </div>
          </div>

          {/* Center Case Status Indicator */}
          <div className="hidden lg:flex items-center gap-3 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs">
            <span className="text-slate-400">Active Case:</span>
            <span className="font-mono font-semibold text-slate-200">{caseDetails?.case_id || 'CASE-001'}</span>
            <span className={`px-2 py-0.5 rounded-full border text-[11px] font-medium ${getStatusColor(caseDetails?.status)}`}>
              {caseDetails?.status || 'In Progress'}
            </span>
          </div>

          {/* Right Action Buttons */}
          <div className="flex items-center gap-2 sm:gap-3">
            <button
              onClick={onRefresh}
              title="Refresh Dataset"
              className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition"
            >
              <RefreshCw className="h-4 w-4" />
            </button>

            <button
              onClick={onOpenUpload}
              className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-cyan-500/20 transition active:scale-95"
            >
              <UploadCloud className="h-4 w-4" />
              <span>Ingest / Demo Data</span>
            </button>

            <button
              onClick={onOpenExport}
              className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 hover:text-white text-xs font-semibold transition active:scale-95"
            >
              <Download className="h-4 w-4 text-cyan-400" />
              <span>Export Report</span>
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex space-x-1 sm:space-x-4 overflow-x-auto py-2 border-t border-slate-800/60 scrollbar-none">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition whitespace-nowrap ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                }`}
              >
                <Icon className={`h-4 w-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                {item.label}
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
}
