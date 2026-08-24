import React, { useState } from 'react';
import { Header } from './components/Header';
import { BasicsGuide } from './components/BasicsGuide';
import { DetectionLab } from './components/DetectionLab';
import { CustomAnalyzer } from './components/CustomAnalyzer';
import { EvasionDefenseLab } from './components/EvasionDefenseLab';
import { ProjectBlueprint } from './components/ProjectBlueprint';
import { ActiveTab } from './types';
import { ShieldCheck, Terminal, Heart } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('BASICS_GUIDE');

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navigation Bar */}
      <Header activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 pt-6 sm:pt-8">
        {activeTab === 'BASICS_GUIDE' && <BasicsGuide />}
        {activeTab === 'DETECTION_LAB' && <DetectionLab />}
        {activeTab === 'CUSTOM_ANALYZER' && <CustomAnalyzer />}
        {activeTab === 'EVASION_DEFENSE' && <EvasionDefenseLab />}
        {activeTab === 'PROJECT_BLUEPRINT' && <ProjectBlueprint />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold text-slate-300">Advanced Malware Detection System (AMDS)</span>
            <span>•</span>
            <span>Cybersecurity Education & Analysis Platform</span>
          </div>
          <div className="flex items-center gap-4 text-slate-400 font-mono text-[11px]">
            <span>Static PE Parser</span>
            <span>•</span>
            <span>Dynamic Sandbox</span>
            <span>•</span>
            <span>YARA Rules</span>
            <span>•</span>
            <span>Gemini AI Threat Intel</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
