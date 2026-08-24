import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Binary, 
  FileCode, 
  Cpu, 
  Play, 
  Pause, 
  RotateCcw, 
  Sparkles, 
  Copy, 
  Check, 
  Network, 
  Terminal, 
  Layers, 
  AlertCircle, 
  Database,
  ExternalLink,
  ChevronRight,
  Zap
} from 'lucide-react';
import { MALWARE_SAMPLES } from '../data/samples';
import { MalwareSample, LabSubTab, DynamicEvent, AIAnalysisResult } from '../types';

export const DetectionLab: React.FC = () => {
  const [selectedSampleId, setSelectedSampleId] = useState<string>(MALWARE_SAMPLES[0].id);
  const [activeSubTab, setActiveSubTab] = useState<LabSubTab>('STATIC_ANALYSIS');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Dynamic Sandbox playback state
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(MALWARE_SAMPLES[0].dynamicEvents.length);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);

  // AI Gemini state
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);
  const [aiResult, setAiResult] = useState<AIAnalysisResult | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);

  const currentSample: MalwareSample = MALWARE_SAMPLES.find(s => s.id === selectedSampleId) || MALWARE_SAMPLES[0];

  const handleSelectSample = (sample: MalwareSample) => {
    setSelectedSampleId(sample.id);
    setCurrentStepIndex(sample.dynamicEvents.length);
    setIsPlaying(false);
    setAiResult(null);
    setAiError(null);
  };

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(label);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Step runner for sandbox
  const handlePlayToggle = () => {
    if (isPlaying) {
      setIsPlaying(false);
    } else {
      if (currentStepIndex >= currentSample.dynamicEvents.length) {
        setCurrentStepIndex(1);
      }
      setIsPlaying(true);
    }
  };

  // Sandbox ticker
  React.useEffect(() => {
    let interval: any;
    if (isPlaying) {
      interval = setInterval(() => {
        setCurrentStepIndex(prev => {
          if (prev >= currentSample.dynamicEvents.length) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, 1200);
    }
    return () => clearInterval(interval);
  }, [isPlaying, currentSample.dynamicEvents.length]);

  const handleResetSandbox = () => {
    setIsPlaying(false);
    setCurrentStepIndex(0);
  };

  const handleStepForward = () => {
    if (currentStepIndex < currentSample.dynamicEvents.length) {
      setCurrentStepIndex(prev => prev + 1);
    }
  };

  // Fetch AI Analysis from server
  const handleRunAiAnalysis = async () => {
    setIsAiLoading(true);
    setAiError(null);
    try {
      const response = await fetch('/api/analyze-malware', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sampleName: currentSample.name,
          sampleType: currentSample.category,
          content: currentSample.payloadSnippet,
          staticIndicators: currentSample.imports.map(i => `${i.dll}!${i.functionName} (${i.category})`),
          dynamicBehaviors: currentSample.dynamicEvents.map(e => `[${e.type}] ${e.description}`)
        })
      });

      const data = await response.json();
      if (data.success && data.analysis) {
        setAiResult(data.analysis);
      } else {
        setAiError(data.error || 'Failed to generate AI Threat Assessment');
      }
    } catch (err: any) {
      setAiError(err.message || 'Network error communicating with threat engine');
    } finally {
      setIsAiLoading(false);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-rose-950/80 border border-rose-700/60 text-rose-300">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-orange-950/80 border border-orange-700/60 text-orange-300">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-amber-950/80 border border-amber-700/60 text-amber-300">MEDIUM</span>;
      case 'LOW':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-blue-950/80 border border-blue-700/60 text-blue-300">LOW</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-emerald-950/80 border border-emerald-700/60 text-emerald-300">SAFE</span>;
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Sample Selector Bar */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
            Select Malware / Benign Artifact Sample to Inspect:
          </label>
          <span className="text-xs text-slate-500 font-mono">6 Curated Datasets</span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
          {MALWARE_SAMPLES.map((sample) => {
            const isSelected = selectedSampleId === sample.id;
            return (
              <button
                key={sample.id}
                id={`sample-select-${sample.id}`}
                onClick={() => handleSelectSample(sample)}
                className={`p-3 rounded-xl text-left border transition-all ${
                  isSelected
                    ? 'bg-slate-900 border-cyan-500/70 shadow-md shadow-cyan-950/40 text-cyan-200'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                    sample.severity === 'CRITICAL' ? 'bg-rose-950/90 text-rose-300 border border-rose-800/40' :
                    sample.severity === 'HIGH' ? 'bg-orange-950/90 text-orange-300 border border-orange-800/40' :
                    sample.severity === 'SAFE' ? 'bg-emerald-950/90 text-emerald-300 border border-emerald-800/40' :
                    'bg-slate-800 text-slate-300'
                  }`}>
                    Score: {sample.threatScore}
                  </span>
                </div>
                <h4 className="text-xs font-bold text-slate-200 truncate">{sample.name.split(' ')[0]}</h4>
                <p className="text-[11px] text-slate-400 truncate">{sample.category.replace('_', ' ')}</p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Artifact Header & Threat Score Banner */}
      <div className="rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 border border-slate-800 p-6 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-xl sm:text-2xl font-extrabold text-slate-100">{currentSample.name}</h2>
              {getSeverityBadge(currentSample.severity)}
              <span className="text-xs font-mono text-slate-400 px-2 py-0.5 bg-slate-950 rounded border border-slate-800">
                {currentSample.fileName}
              </span>
            </div>
            <p className="text-xs sm:text-sm text-slate-300 max-w-3xl leading-relaxed">
              {currentSample.description}
            </p>
          </div>

          {/* Threat Metric Card */}
          <div className="flex items-center gap-4 bg-slate-950/80 p-4 rounded-xl border border-slate-800 shrink-0">
            <div>
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">Threat Probability</span>
              <div className="flex items-baseline gap-1.5">
                <span className={`text-3xl font-extrabold font-mono ${
                  currentSample.threatScore > 80 ? 'text-rose-400' : currentSample.threatScore > 40 ? 'text-amber-400' : 'text-emerald-400'
                }`}>
                  {currentSample.threatScore}%
                </span>
                <span className="text-xs font-mono text-slate-500">CVSS {currentSample.cvssScore}</span>
              </div>
            </div>
            <div className="w-12 h-12 rounded-full border-4 border-slate-800 flex items-center justify-center relative">
              <div 
                className={`absolute inset-0 rounded-full border-4 border-transparent ${
                  currentSample.threatScore > 80 ? 'border-t-rose-500 border-r-rose-500' :
                  currentSample.threatScore > 40 ? 'border-t-amber-500' :
                  'border-t-emerald-500'
                }`}
                style={{ transform: `rotate(${(currentSample.threatScore / 100) * 360}deg)` }}
              />
              <span className="text-[10px] font-mono font-bold text-slate-300">{currentSample.threatScore}</span>
            </div>
          </div>
        </div>

        {/* Hashes Row */}
        <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-3 text-xs">
          <span className="font-mono text-slate-400">SHA-256:</span>
          <code className="font-mono text-cyan-300 bg-slate-950 px-2 py-1 rounded border border-slate-800 text-[11px] truncate max-w-xs sm:max-w-md">
            {currentSample.hashes.sha256}
          </code>
          <button
            onClick={() => handleCopy(currentSample.hashes.sha256, 'sha256')}
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            title="Copy SHA-256"
          >
            {copiedHash === 'sha256' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>

          <span className="font-mono text-slate-400 ml-2">Entropy:</span>
          <span className={`font-mono font-bold ${currentSample.overallEntropy > 7.0 ? 'text-rose-400' : 'text-emerald-400'}`}>
            {currentSample.overallEntropy} / 8.0
          </span>
        </div>
      </div>

      {/* Sub-tabs Navigation */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 overflow-x-auto">
        {[
          { id: 'STATIC_ANALYSIS', label: '1. Static & PE Inspection', icon: <FileCode className="w-4 h-4" /> },
          { id: 'DYNAMIC_SANDBOX', label: '2. Dynamic Sandbox Simulator', icon: <ShieldAlert className="w-4 h-4" /> },
          { id: 'YARA_MATCHING', label: '3. YARA Pattern Engine', icon: <Binary className="w-4 h-4" /> },
          { id: 'AI_THREAT_INTEL', label: '4. AI Threat Intelligence', icon: <Sparkles className="w-4 h-4 text-indigo-400" /> }
        ].map((tab) => {
          const isTabActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              id={`subtab-${tab.id.toLowerCase()}`}
              onClick={() => setActiveSubTab(tab.id as LabSubTab)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs sm:text-sm font-semibold transition ${
                isTabActive
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab 1: Static Analysis View */}
      {activeSubTab === 'STATIC_ANALYSIS' && (
        <div className="space-y-6">
          {/* Entropy Distribution Map */}
          <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Binary className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-100">Section Entropy Heatmap</h3>
              </div>
              <span className="text-xs font-mono text-slate-400">Higher (Red) = Encrypted / Packed</span>
            </div>
            <div className="grid grid-cols-6 sm:grid-cols-12 md:grid-cols-16 gap-1.5">
              {currentSample.entropyBlocks.map((val, idx) => (
                <div
                  key={idx}
                  className={`h-10 rounded flex flex-col items-center justify-center text-[10px] font-mono font-bold transition ${
                    val > 7.5 ? 'bg-rose-600 text-white' :
                    val > 6.8 ? 'bg-orange-500 text-slate-950' :
                    val > 5.5 ? 'bg-amber-400 text-slate-950' :
                    'bg-emerald-500 text-slate-950'
                  }`}
                  title={`Block ${idx + 1}: ${val} bits/byte`}
                >
                  <span>{val}</span>
                </div>
              ))}
            </div>
          </div>

          {/* PE Sections Table */}
          <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-100">Portable Executable (PE) Section Headers</h3>
              </div>
              <span className="text-xs font-mono text-slate-400">Architecture: {currentSample.peHeaders.machine}</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                    <th className="pb-2">Section Name</th>
                    <th className="pb-2">Virtual Size</th>
                    <th className="pb-2">Raw Size</th>
                    <th className="pb-2">Entropy</th>
                    <th className="pb-2">Characteristics</th>
                    <th className="pb-2 text-right">Risk Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {currentSample.sections.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-4 text-center text-slate-500">
                        No PE sections (Script or non-PE artifact)
                      </td>
                    </tr>
                  ) : (
                    currentSample.sections.map((sec, i) => (
                      <tr key={i} className="hover:bg-slate-950/50">
                        <td className="py-2.5 font-bold text-slate-200">{sec.name}</td>
                        <td className="py-2.5 text-slate-400">{(sec.virtualSize / 1024).toFixed(1)} KB</td>
                        <td className="py-2.5 text-slate-400">{(sec.rawSize / 1024).toFixed(1)} KB</td>
                        <td className="py-2.5">
                          <span className={`px-1.5 py-0.5 rounded ${sec.entropy > 7.2 ? 'bg-rose-950 text-rose-300 font-bold' : 'text-slate-300'}`}>
                            {sec.entropy}
                          </span>
                        </td>
                        <td className="py-2.5 text-[11px] text-slate-400">{sec.characteristics.join(' | ')}</td>
                        <td className="py-2.5 text-right">
                          {sec.isSuspicious ? (
                            <span className="px-2 py-0.5 rounded bg-rose-950/80 border border-rose-800/50 text-rose-300 font-bold">
                              SUSPICIOUS
                            </span>
                          ) : (
                            <span className="text-slate-500">Normal</span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Suspicious IAT Imports Table */}
          <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 space-y-3">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-rose-400" />
              <h3 className="text-sm font-bold text-slate-100">Suspicious Windows API Imports (IAT)</h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {currentSample.imports.map((imp, idx) => (
                <div key={idx} className="p-3 rounded-xl bg-slate-950 border border-slate-800/90 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-cyan-300">{imp.dll} → {imp.functionName}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {imp.category}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{imp.riskDescription}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Extracted Strings & IOCs */}
          <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 space-y-3">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-bold text-slate-100">Extracted Suspicious Strings & Indicators of Compromise (IOCs)</h3>
            </div>
            <div className="divide-y divide-slate-800/60 font-mono text-xs">
              {currentSample.extractedStrings.map((item, idx) => (
                <div key={idx} className="py-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 overflow-hidden">
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 shrink-0">
                      {item.type}
                    </span>
                    <span className="text-slate-200 truncate">{item.value}</span>
                  </div>
                  <span className={`text-[11px] px-2 py-0.5 rounded self-start sm:self-auto shrink-0 ${
                    item.suspicionScore >= 8 ? 'bg-rose-950 text-rose-300 font-bold' :
                    item.suspicionScore >= 5 ? 'bg-amber-950 text-amber-300' :
                    'text-slate-400'
                  }`}>
                    Suspicion: {item.suspicionScore}/10
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Dynamic Sandbox View */}
      {activeSubTab === 'DYNAMIC_SANDBOX' && (
        <div className="space-y-6">
          {/* Sandbox Controls Bar */}
          <div className="rounded-2xl bg-slate-900 border border-slate-800 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
              <span className="text-sm font-bold text-slate-200">Sandbox Environment: Isolated Windows 11 VM</span>
              <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded">
                Event {Math.min(currentStepIndex, currentSample.dynamicEvents.length)} of {currentSample.dynamicEvents.length}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                id="sandbox-play-btn"
                onClick={handlePlayToggle}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs transition"
              >
                {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                <span>{isPlaying ? 'Pause' : 'Play Simulation'}</span>
              </button>

              <button
                onClick={handleStepForward}
                disabled={currentStepIndex >= currentSample.dynamicEvents.length}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs transition"
              >
                Step +1
              </button>

              <button
                onClick={handleResetSandbox}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                title="Reset Sandbox"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Process Execution Tree */}
            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-bold text-slate-100">Process Spawning Tree</h3>
                </div>
                <span className="text-xs font-mono text-slate-500">Parent → Child Relations</span>
              </div>

              {/* Recursive Process Node View */}
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs space-y-3">
                <div className="flex items-start gap-2 text-rose-400 font-bold">
                  <span className="text-slate-500">[{currentSample.processTree.pid}]</span>
                  <span>{currentSample.processTree.name}</span>
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-800/50">
                    {currentSample.processTree.status}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 pl-4 border-l border-slate-800">
                  cmd: {currentSample.processTree.commandLine}
                </p>

                {currentSample.processTree.children && currentSample.processTree.children.map((child) => (
                  <div key={child.id} className="pl-6 border-l-2 border-slate-800 space-y-2">
                    <div className="flex items-start gap-2 text-amber-300 font-bold">
                      <ChevronRight className="w-3.5 h-3.5 text-slate-500 shrink-0 mt-0.5" />
                      <span className="text-slate-500">[{child.pid}]</span>
                      <span>{child.name}</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800/50">
                        {child.status}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 pl-4">cmd: {child.commandLine}</p>

                    {child.children && child.children.map((gchild) => (
                      <div key={gchild.id} className="pl-6 border-l-2 border-slate-800 space-y-1">
                        <div className="flex items-center gap-2 text-rose-300 font-bold">
                          <ChevronRight className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                          <span className="text-slate-500">[{gchild.pid}]</span>
                          <span>{gchild.name}</span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                            {gchild.status}
                          </span>
                        </div>
                        <p className="text-[10px] text-slate-400 pl-4">cmd: {gchild.commandLine}</p>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </div>

            {/* Event Timeline Stream */}
            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-bold text-slate-100">Behavioral Telemetry Log Stream</h3>
                </div>
                <span className="text-xs font-mono text-slate-400">Sysmon & ETW Hooking</span>
              </div>

              <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1">
                {currentSample.dynamicEvents.slice(0, currentStepIndex).map((evt) => (
                  <div
                    key={evt.step}
                    className="p-3 rounded-xl bg-slate-950 border border-slate-800/90 space-y-1 text-xs transition"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-cyan-400 text-[11px] font-bold">{evt.timestamp}</span>
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-semibold">
                          {evt.type}
                        </span>
                      </div>
                      {getSeverityBadge(evt.severity)}
                    </div>
                    <p className="text-slate-200 leading-snug">{evt.description}</p>
                    <p className="font-mono text-[11px] text-slate-400 truncate">Target: {evt.target}</p>
                  </div>
                ))}

                {currentStepIndex === 0 && (
                  <div className="p-8 text-center text-slate-500 text-xs">
                    Press "Play Simulation" or "Step +1" to start dynamic event replay.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: YARA Rules Matching */}
      {activeSubTab === 'YARA_MATCHING' && (
        <div className="space-y-6">
          <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Binary className="w-5 h-5 text-amber-400" />
                  YARA Rule Matches for {currentSample.name}
                </h3>
                <p className="text-xs text-slate-400">
                  YARA is the industry-standard pattern matching engine for malware classification.
                </p>
              </div>
              <span className="px-3 py-1 rounded-full bg-amber-950/80 border border-amber-800/50 text-xs font-mono text-amber-300 font-bold">
                {currentSample.yaraRules.filter(r => r.matched).length} / {currentSample.yaraRules.length} Rules Triggered
              </span>
            </div>

            <div className="space-y-4">
              {currentSample.yaraRules.map((rule) => (
                <div
                  key={rule.id}
                  className={`rounded-xl border p-5 space-y-3 ${
                    rule.matched
                      ? 'bg-slate-950 border-amber-500/50 shadow-md shadow-amber-950/20'
                      : 'bg-slate-950/60 border-slate-800'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-mono font-bold text-amber-300">rule {rule.name}</span>
                        {rule.matched ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            MATCH DETECTED
                          </span>
                        ) : (
                          <span className="text-xs text-slate-500 font-mono">No Match</span>
                        )}
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5">{rule.meta.description}</p>
                    </div>
                    <div className="text-right text-xs font-mono text-slate-500">
                      Author: {rule.meta.author}
                    </div>
                  </div>

                  {/* Strings Section */}
                  <div>
                    <h5 className="text-[11px] font-mono font-bold uppercase text-slate-400 mb-1.5">
                      Strings & Hex Patterns ($s / $h):
                    </h5>
                    <div className="space-y-1 font-mono text-xs">
                      {rule.strings.map((str) => {
                        const isHit = rule.matchedStrings.includes(str.id);
                        return (
                          <div
                            key={str.id}
                            className={`flex items-center justify-between p-2 rounded ${
                              isHit ? 'bg-amber-950/40 border border-amber-800/40 text-amber-200' : 'bg-slate-900 text-slate-400'
                            }`}
                          >
                            <span>
                              <strong className="text-amber-400">{str.id}</strong> = {str.isHex ? `{ ${str.pattern} }` : `"${str.pattern}"`}
                            </span>
                            {isHit && (
                              <span className="text-[10px] font-bold text-amber-400 uppercase">Matched in Payload</span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Condition */}
                  <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 font-mono text-xs text-slate-300">
                    <span className="text-cyan-400 font-bold">condition:</span> {rule.condition}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: AI Threat Intelligence & Gemini View */}
      {activeSubTab === 'AI_THREAT_INTEL' && (
        <div className="space-y-6">
          {/* Static Explanation Overview */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 space-y-2">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-rose-400">
                1. What This Threat Does
              </h4>
              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                {currentSample.analysisExplanation.whatItDoes}
              </p>
            </div>

            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 space-y-2">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400">
                2. How AMDS Detects It
              </h4>
              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                {currentSample.analysisExplanation.howDetected}
              </p>
            </div>

            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 space-y-2">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-amber-400">
                3. Critical Risk Factors
              </h4>
              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                {currentSample.analysisExplanation.whyDangerous}
              </p>
            </div>
          </div>

          {/* MITRE ATT&CK Matrix */}
          <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-100">MITRE ATT&CK® Enterprise Techniques Mapped</h3>
              </div>
              <span className="text-xs font-mono text-slate-500">Framework v14</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {currentSample.mitreTechniques.map((tech) => (
                <div key={tech.id} className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-cyan-300">{tech.id}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {tech.tactic}
                    </span>
                  </div>
                  <h5 className="text-xs font-semibold text-slate-200">{tech.name}</h5>
                  <p className="text-[11px] text-slate-400">{tech.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Gemini AI Live Deep Threat Assessment Trigger */}
          <div className="rounded-2xl bg-gradient-to-br from-indigo-950/60 via-slate-900 to-slate-950 border border-indigo-700/40 p-6 space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <Sparkles className="w-5 h-5 text-indigo-400" />
                  <h3 className="text-base font-bold text-slate-100">
                    Gemini 3.7 AI Threat Intelligence & Automated Reverse Engineering
                  </h3>
                </div>
                <p className="text-xs text-slate-300 mt-1">
                  Leverage Google Gemini to generate a tailored SOC incident response report and remediation strategy.
                </p>
              </div>

              <button
                id="run-gemini-btn"
                onClick={handleRunAiAnalysis}
                disabled={isAiLoading}
                className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white text-xs font-bold shadow-md shadow-indigo-950/40 transition disabled:opacity-50"
              >
                {isAiLoading ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                    <span>Analyzing Disassembly & Traces...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4" />
                    <span>Run Deep AI Security Assessment</span>
                  </>
                )}
              </button>
            </div>

            {aiError && (
              <div className="p-4 rounded-xl bg-rose-950/80 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{aiError}</span>
              </div>
            )}

            {aiResult && (
              <div className="space-y-4 pt-4 border-t border-indigo-900/50">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">AI Threat Verdict</span>
                    <p className="text-sm font-bold text-rose-400">{aiResult.threatVerdict}</p>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Confidence Score</span>
                    <p className="text-sm font-bold text-cyan-300">{aiResult.confidenceScore}%</p>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Estimated CVSS Score</span>
                    <p className="text-sm font-bold text-amber-400">{aiResult.cvssScore} / 10.0</p>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <h5 className="text-xs font-mono font-bold uppercase text-indigo-300">Executive Summary & Threat Vector</h5>
                  <p className="text-xs text-slate-200 leading-relaxed">{aiResult.summary}</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                    <h5 className="text-xs font-mono font-bold uppercase text-amber-400">Evasion Techniques Detected</h5>
                    <ul className="space-y-1 text-xs text-slate-300">
                      {aiResult.evasionTechniquesDetected.map((tech, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-amber-400">•</span>
                          <span>{tech}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                    <h5 className="text-xs font-mono font-bold uppercase text-emerald-400">Incident Response & Remediation</h5>
                    <ul className="space-y-1 text-xs text-slate-300">
                      {aiResult.remediationSteps.map((step, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-emerald-400 font-bold">✓</span>
                          <span>{step}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {aiResult.deobfuscatedInsight && (
                  <div className="p-4 rounded-xl bg-indigo-950/30 border border-indigo-800/40 text-xs text-indigo-200">
                    <strong className="block font-mono text-indigo-300 mb-1">Deobfuscation & Reverse Engineering Insight:</strong>
                    {aiResult.deobfuscatedInsight}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
