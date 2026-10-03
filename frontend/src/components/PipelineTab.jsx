import React, { useState, useEffect } from 'react';
import { 
  Layers, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  RefreshCw, 
  FileCode, 
  Database, 
  Play,
  ShieldAlert,
  ArrowRight,
  Filter,
  AlertCircle
} from 'lucide-react';

export default function PipelineTab({ 
  onRunDemo, 
  onRunEnterprise, 
  onRunTestSuite, 
  running 
}) {
  const [pipelineData, setPipelineData] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchPipelineStatus = () => {
    setLoading(true);
    fetch('/api/pipeline/status')
      .then(res => res.json())
      .then(data => {
        setPipelineData(data);
        setLoading(false);
      })
      .catch(err => {
        console.error('Failed to load pipeline status:', err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchPipelineStatus();
  }, [running]);

  const stages = pipelineData?.stages || [];
  const errors = pipelineData?.error_records || pipelineData?.errors || [];
  const totalErrors = pipelineData?.total_errors || 0;

  return (
    <div className="space-y-6">
      
      {/* Pipeline Control Header */}
      <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Layers className="h-5 w-5 text-cyan-400" />
            <span>Consolidated Forensic Pipeline Monitor</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Transparent 8-stage processing engine with row-level validation audit and retention tracking.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 sm:gap-3">
          <button
            onClick={onRunDemo}
            disabled={running}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-xs font-semibold transition active:scale-95 disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5 text-cyan-400" />
            <span>Run Multi-Source Demo</span>
          </button>

          <button
            onClick={onRunEnterprise}
            disabled={running}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/40 text-xs font-semibold transition active:scale-95 disabled:opacity-50"
          >
            <Database className="h-3.5 w-3.5 text-blue-400" />
            <span>Run Enterprise Incident Data</span>
          </button>

          <button
            onClick={onRunTestSuite}
            disabled={running}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/40 text-xs font-semibold transition active:scale-95 disabled:opacity-50"
          >
            <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
            <span>Run Edge-Case Suite</span>
          </button>

          <button
            onClick={fetchPipelineStatus}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
            title="Refresh Status"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Execution Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs text-slate-400 uppercase font-semibold">Active Run ID</div>
          <div className="font-mono text-base font-bold text-cyan-300 mt-1">
            {stages[0]?.run_id || 'RUN-STANDBY'}
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            Deterministic Pipeline Execution
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs text-slate-400 uppercase font-semibold">Flagged Parsing Errors</div>
          <div className="font-mono text-base font-bold text-rose-400 mt-1">
            {totalErrors} Rows Flagged
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            Quarantined Without Data Corruption
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs text-slate-400 uppercase font-semibold">Pipeline Architecture</div>
          <div className="font-mono text-base font-bold text-emerald-400 mt-1">
            Zero Fake AI · 100% Rules
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            Fully Inspectable & Auditable
          </div>
        </div>

      </div>

      {/* Stage-by-Stage Cards */}
      <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center justify-between">
          <span>Pipeline Stages & Execution Metrics</span>
          <span className="text-xs font-normal text-slate-400 font-mono">
            {stages.length} Stages Executed
          </span>
        </h3>

        {stages.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs">
            No pipeline run recorded yet. Click one of the buttons above to run the pipeline.
          </div>
        ) : (
          <div className="space-y-3">
            {stages.map((stg, idx) => (
              <div 
                key={stg.id || idx}
                className="p-3.5 rounded-lg bg-slate-800/40 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div className="flex items-start gap-3">
                  <div className="p-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 mt-0.5">
                    <CheckCircle2 className="h-4 w-4" />
                  </div>
                  <div>
                    <div className="font-bold text-slate-200 text-sm">
                      {stg.stage}
                    </div>
                    <div className="text-slate-400 text-xs mt-0.5">
                      {stg.details}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4 sm:justify-end border-t sm:border-t-0 pt-2 sm:pt-0 border-slate-800/60 font-mono text-[11px]">
                  <div>
                    <span className="text-slate-400">In/Out: </span>
                    <span className="text-slate-200">{stg.input_count} → {stg.output_count}</span>
                  </div>
                  <div className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                    {stg.duration_ms} ms
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    {stg.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Row-Level Parsing Errors Audit Table */}
      <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-rose-400" />
              <span>Row-Level Parsing & Validation Audit Log</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Exact source file, line index, and rejection cause for malformed records.
            </p>
          </div>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-rose-300 border border-rose-900/50">
            {totalErrors} Issues
          </span>
        </div>

        {errors.length === 0 ? (
          <div className="py-8 text-center text-slate-500 text-xs bg-slate-900/40 rounded-lg border border-slate-800/50">
            ✓ No malformed rows or parsing rejections detected in active dataset.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-[#0d1424] text-slate-400 font-semibold">
                  <th className="py-2.5 px-3">File Origin</th>
                  <th className="py-2.5 px-3">Line #</th>
                  <th className="py-2.5 px-3">Rejection Cause</th>
                  <th className="py-2.5 px-3">Raw Log Snippet</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                {errors.map((err, i) => (
                  <tr key={i} className="hover:bg-slate-800/30">
                    <td className="py-2 px-3 text-cyan-300 font-semibold">{err.source_file}</td>
                    <td className="py-2 px-3 text-slate-300">#{err.row_index}</td>
                    <td className="py-2 px-3 text-rose-300">{err.error_reason}</td>
                    <td className="py-2 px-3 text-slate-400 truncate max-w-[300px]">{err.raw_data}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
