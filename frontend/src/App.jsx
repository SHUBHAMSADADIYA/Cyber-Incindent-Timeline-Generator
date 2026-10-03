import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import DashboardTab from './components/DashboardTab';
import TimelineTab from './components/TimelineTab';
import PipelineTab from './components/PipelineTab';
import IOCTab from './components/IOCTab';
import InvestigationTab from './components/InvestigationTab';
import EventDetailDrawer from './components/EventDetailDrawer';
import UploadModal from './components/UploadModal';
import ReportModal from './components/ReportModal';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [metrics, setMetrics] = useState(null);
  const [healthStatus, setHealthStatus] = useState(null);
  const [caseDetails, setCaseDetails] = useState(null);
  
  // Modals & Drawers
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [isExportOpen, setIsExportOpen] = useState(false);

  // Cross-tab drilldowns
  const [initialIncident, setInitialIncident] = useState('');
  const [initialSource, setInitialSource] = useState('');
  const [pipelineRunning, setPipelineRunning] = useState(false);

  const fetchDashboardData = async () => {
    try {
      const res = await fetch('/api/dashboard');
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
      }
    } catch (err) {
      console.error('Failed to fetch dashboard metrics:', err);
    }
  };

  const fetchHealth = async () => {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const data = await res.json();
        setHealthStatus(data);
      }
    } catch (err) {
      console.error('Failed to fetch backend health:', err);
    }
  };

  const fetchCase = async () => {
    try {
      const res = await fetch('/api/case');
      if (res.ok) {
        const data = await res.json();
        setCaseDetails(data);
      }
    } catch (err) {
      console.error('Failed to fetch case details:', err);
    }
  };

  const refreshAll = () => {
    fetchDashboardData();
    fetchHealth();
    fetchCase();
  };

  useEffect(() => {
    refreshAll();
  }, []);

  const handleRunDemo = async () => {
    setPipelineRunning(true);
    try {
      const res = await fetch('/api/pipeline/load-demo', { method: 'POST' });
      if (res.ok) {
        await refreshAll();
        setActiveTab('dashboard');
      }
    } catch (err) {
      console.error('Error running demo:', err);
    } finally {
      setPipelineRunning(false);
    }
  };

  const handleRunEnterprise = async () => {
    setPipelineRunning(true);
    try {
      const res = await fetch('/api/pipeline/load-enterprise', { method: 'POST' });
      if (res.ok) {
        await refreshAll();
        setActiveTab('dashboard');
      }
    } catch (err) {
      console.error('Error running enterprise dataset:', err);
    } finally {
      setPipelineRunning(false);
    }
  };

  const handleRunTestSuite = async () => {
    setPipelineRunning(true);
    try {
      const res = await fetch('/api/pipeline/load-test-suite', { method: 'POST' });
      if (res.ok) {
        await refreshAll();
        setActiveTab('pipeline');
      }
    } catch (err) {
      console.error('Error running test suite:', err);
    } finally {
      setPipelineRunning(false);
    }
  };

  const handleSelectIncident = (corrId) => {
    setInitialIncident(corrId);
    setInitialSource('');
    setActiveTab('timeline');
  };

  const handleSelectSource = (src) => {
    setInitialSource(src);
    setInitialIncident('');
    setActiveTab('timeline');
  };

  return (
    <div className="min-h-screen bg-[#080d1a] text-slate-100 flex flex-col font-sans">
      
      {/* Header Bar */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenUpload={() => setIsUploadOpen(true)}
        onOpenExport={() => setIsExportOpen(true)}
        healthStatus={healthStatus}
        caseDetails={caseDetails}
        onRefresh={refreshAll}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {activeTab === 'dashboard' && (
          <DashboardTab
            metrics={metrics}
            onSelectIncident={handleSelectIncident}
            onSelectSource={handleSelectSource}
            onOpenUpload={() => setIsUploadOpen(true)}
          />
        )}

        {activeTab === 'timeline' && (
          <TimelineTab
            onSelectEvent={(id) => setSelectedEventId(id)}
            initialIncident={initialIncident}
            initialSource={initialSource}
          />
        )}

        {activeTab === 'pipeline' && (
          <PipelineTab
            onRunDemo={handleRunDemo}
            onRunEnterprise={handleRunEnterprise}
            onRunTestSuite={handleRunTestSuite}
            running={pipelineRunning}
          />
        )}

        {activeTab === 'iocs' && (
          <IOCTab />
        )}

        {activeTab === 'investigation' && (
          <InvestigationTab
            onCaseUpdated={(updated) => setCaseDetails(updated)}
          />
        )}

      </main>

      {/* Slide-out Event Detail Drawer */}
      {selectedEventId && (
        <EventDetailDrawer
          eventId={selectedEventId}
          onClose={() => setSelectedEventId(null)}
          onSelectEvent={(id) => setSelectedEventId(id)}
        />
      )}

      {/* Ingest / Load Demo Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadSuccess={() => { refreshAll(); setIsUploadOpen(false); setActiveTab('timeline'); }}
        onRunDemo={handleRunDemo}
        onRunEnterprise={handleRunEnterprise}
        onRunTestSuite={handleRunTestSuite}
        running={pipelineRunning}
      />

      {/* Report Export Modal */}
      <ReportModal
        isOpen={isExportOpen}
        onClose={() => setIsExportOpen(false)}
        topIncidents={metrics?.top_incidents || []}
      />

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#070b16] py-4 text-center text-xs text-slate-500">
        Cyber Incident Timeline Generator & Forensic Hub · Production Engine
      </footer>

    </div>
  );
}
