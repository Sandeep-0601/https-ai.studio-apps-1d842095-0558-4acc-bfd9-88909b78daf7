import React from 'react';
import { ShieldCheck, ShieldAlert, Cpu, Code2, BookOpen, Terminal, Sparkles, Layers } from 'lucide-react';
import { ActiveTab } from '../types';

interface HeaderProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
}

export const Header: React.FC<HeaderProps> = ({ activeTab, setActiveTab }) => {
  const tabs: { id: ActiveTab; label: string; icon: React.ReactNode; badge?: string }[] = [
    { id: 'BASICS_GUIDE', label: '1. Architecture & Basics', icon: <BookOpen className="w-4 h-4" /> },
    { id: 'DETECTION_LAB', label: '2. Live Sample Analysis Lab', icon: <ShieldAlert className="w-4 h-4" />, badge: '6 Samples' },
    { id: 'CUSTOM_ANALYZER', label: '3. Custom Code Scanner', icon: <Terminal className="w-4 h-4" />, badge: 'AI Powered' },
    { id: 'EVASION_DEFENSE', label: '4. Evasion vs Defense Lab', icon: <Layers className="w-4 h-4" /> },
    { id: 'PROJECT_BLUEPRINT', label: '5. Build Your Own Project', icon: <Code2 className="w-4 h-4" />, badge: 'Source Code' }
  ];

  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3.5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Brand & Project Identity */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-500/10">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight flex items-center gap-2">
                Advanced Malware Detection System
              </h1>
              <span className="px-2 py-0.5 text-[11px] font-mono font-medium rounded-full bg-cyan-950/80 border border-cyan-700/50 text-cyan-400">
                AMDS v2.5
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Interactive Cybersecurity Engineering & Threat Analysis Platform
            </p>
          </div>
        </div>

        {/* Status Indicators */}
        <div className="flex items-center gap-2 self-end md:self-auto">
          <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="font-mono">Engine: Multi-Vector</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-indigo-950/60 border border-indigo-700/40 text-xs text-indigo-300">
            <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
            <span>Gemini AI 3.7</span>
          </div>
        </div>
      </div>

      {/* Main Navigation Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6">
        <nav className="flex items-center gap-1 overflow-x-auto py-2 scrollbar-none">
          {tabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                id={`tab-${tab.id.toLowerCase()}`}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs sm:text-sm font-medium whitespace-nowrap transition-all duration-150 ${
                  isActive
                    ? 'bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
                {tab.badge && (
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded-full font-mono ${
                      isActive
                        ? 'bg-cyan-500/30 text-cyan-200'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
