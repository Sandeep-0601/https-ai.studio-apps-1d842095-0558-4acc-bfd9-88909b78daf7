import React, { useState } from 'react';
import { 
  Hash, 
  FileCode, 
  ShieldAlert, 
  Cpu, 
  BrainCircuit, 
  ArrowRight, 
  CheckCircle2, 
  AlertTriangle, 
  Info, 
  Activity, 
  Search,
  BookOpen,
  Binary,
  ShieldCheck
} from 'lucide-react';
import { DETECTION_PILLARS, CORE_GLOSSARY } from '../data/basicsContent';

export const BasicsGuide: React.FC = () => {
  const [activePillarIndex, setActivePillarIndex] = useState<number>(0);
  const [entropyInput, setEntropyInput] = useState<string>('Normal text document data with predictable ASCII characters.');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const calculateEntropy = (str: string): number => {
    if (!str || str.length === 0) return 0;
    const freqs: Record<string, number> = {};
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      freqs[char] = (freqs[char] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const char in freqs) {
      const p = freqs[char] / len;
      entropy -= p * Math.log2(p);
    }
    return Number(entropy.toFixed(3));
  };

  const currentEntropy = calculateEntropy(entropyInput);

  const getPillarIcon = (name: string) => {
    switch (name) {
      case 'Hash': return <Hash className="w-5 h-5" />;
      case 'FileCode': return <FileCode className="w-5 h-5" />;
      case 'ShieldAlert': return <ShieldAlert className="w-5 h-5" />;
      case 'Cpu': return <Cpu className="w-5 h-5" />;
      case 'BrainCircuit': return <BrainCircuit className="w-5 h-5" />;
      default: return <Activity className="w-5 h-5" />;
    }
  };

  const filteredGlossary = CORE_GLOSSARY.filter(item => 
    item.term.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.definition.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const activePillar = DETECTION_PILLARS[activePillarIndex];

  return (
    <div className="space-y-8 pb-12">
      {/* Hero Overview */}
      <section className="rounded-2xl bg-gradient-to-b from-slate-900 via-slate-900/90 to-slate-950 border border-slate-800 p-6 sm:p-8">
        <div className="max-w-4xl space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-700/60 text-xs font-mono text-cyan-300">
            <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
            <span>Foundations & Project Architecture</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-slate-100 tracking-tight">
            How Advanced Malware Detection Systems Work
          </h2>
          <p className="text-slate-300 text-sm sm:text-base leading-relaxed">
            A modern, production-grade <strong className="text-cyan-300 font-semibold">Malware Detection System (MDS / EDR)</strong> defends against millions of evolving threats by combining <span className="text-slate-100 underline decoration-cyan-500/50 underline-offset-4">static inspection</span>, <span className="text-slate-100 underline decoration-indigo-500/50 underline-offset-4">dynamic sandboxing</span>, <span className="text-slate-100 underline decoration-amber-500/50 underline-offset-4">behavioral heuristics</span>, and <span className="text-slate-100 underline decoration-emerald-500/50 underline-offset-4">Machine Learning / AI</span>.
          </p>
        </div>

        {/* 5-Step End-to-End Pipeline Visualization */}
        <div className="mt-8 pt-6 border-t border-slate-800/80">
          <h3 className="text-xs uppercase tracking-wider font-mono text-slate-400 font-bold mb-4">
            The 5-Stage Detection & Analysis Pipeline
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            {[
              { num: '01', title: 'Hash Check', desc: 'Instant MD5/SHA256 signature blacklist lookup', icon: <Hash className="w-4 h-4 text-cyan-400" /> },
              { num: '02', title: 'Static PE Parser', desc: 'Imports, Headers, Sections & Shannon Entropy', icon: <FileCode className="w-4 h-4 text-blue-400" /> },
              { num: '03', title: 'YARA Pattern Match', desc: 'Byte sequence & regex string scanning', icon: <Binary className="w-4 h-4 text-amber-400" /> },
              { num: '04', title: 'Dynamic Sandbox', desc: 'Isolated VM execution & process tree tracing', icon: <ShieldAlert className="w-4 h-4 text-rose-400" /> },
              { num: '05', title: 'AI & Heuristic Score', desc: 'ML classification + LLM threat summarization', icon: <BrainCircuit className="w-4 h-4 text-emerald-400" /> }
            ].map((step, idx) => (
              <div
                key={step.num}
                className="rounded-xl bg-slate-950/70 border border-slate-800/90 p-3.5 relative overflow-hidden group hover:border-slate-700 transition"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono font-bold text-slate-400">{step.num}</span>
                  {step.icon}
                </div>
                <h4 className="text-sm font-semibold text-slate-200 mb-1">{step.title}</h4>
                <p className="text-xs text-slate-400 leading-snug">{step.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 5 Pillars Deep-Dive with Interactive Switcher */}
      <section className="space-y-4">
        <div>
          <h3 className="text-xl font-bold text-slate-100">
            The 5 Pillars of Malware Detection
          </h3>
          <p className="text-xs sm:text-sm text-slate-400">
            Click each pillar to examine its internal mechanics, advantages, limitations, and key APIs.
          </p>
        </div>

        {/* Pillar Tabs */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
          {DETECTION_PILLARS.map((pillar, idx) => {
            const isSelected = activePillarIndex === idx;
            return (
              <button
                key={pillar.id}
                id={`pillar-tab-${idx}`}
                onClick={() => setActivePillarIndex(idx)}
                className={`text-left p-3 rounded-xl border transition-all ${
                  isSelected
                    ? 'bg-slate-900 border-cyan-500/60 shadow-md shadow-cyan-950/40 text-cyan-300'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <div className="flex items-center gap-2 mb-1.5">
                  <div className={`p-1.5 rounded-lg ${isSelected ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-400'}`}>
                    {getPillarIcon(pillar.iconName)}
                  </div>
                  <span className="text-xs font-mono font-bold">Pillar 0{idx + 1}</span>
                </div>
                <h4 className="text-xs font-bold text-slate-200 line-clamp-1">{pillar.title.replace(/^\d+\.\s*/, '')}</h4>
              </button>
            );
          })}
        </div>

        {/* Selected Pillar Detailed Card */}
        <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                {getPillarIcon(activePillar.iconName)}
              </div>
              <div>
                <h4 className="text-lg font-bold text-slate-100">{activePillar.title}</h4>
                <p className="text-xs text-slate-400">{activePillar.shortDesc}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              {activePillar.keyToolsAndAPIs.map((tool) => (
                <span key={tool} className="px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 text-[11px] font-mono text-cyan-300">
                  {tool}
                </span>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* How It Works & Real World */}
            <div className="lg:col-span-2 space-y-4">
              <div>
                <h5 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">
                  Operating Principle & Execution Mechanics
                </h5>
                <p className="text-sm text-slate-300 leading-relaxed bg-slate-950/80 p-4 rounded-xl border border-slate-800/80">
                  {activePillar.howItWorks}
                </p>
              </div>

              <div>
                <h5 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">
                  Real-World Industry Scenario
                </h5>
                <div className="flex items-start gap-3 bg-cyan-950/30 border border-cyan-800/40 p-4 rounded-xl text-xs text-slate-300">
                  <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <span>{activePillar.realWorldExample}</span>
                </div>
              </div>
            </div>

            {/* Pros & Cons Matrix */}
            <div className="space-y-4">
              <div className="space-y-2">
                <h5 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  Key Strengths
                </h5>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {activePillar.advantages.map((adv, i) => (
                    <li key={i} className="flex items-start gap-2 bg-slate-950/60 p-2 rounded-lg border border-slate-800/60">
                      <span className="text-emerald-400 font-bold">•</span>
                      <span>{adv}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="space-y-2">
                <h5 className="text-xs font-mono font-bold uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  Critical Limitations / Blindspots
                </h5>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {activePillar.limitations.map((lim, i) => (
                    <li key={i} className="flex items-start gap-2 bg-slate-950/60 p-2 rounded-lg border border-slate-800/60">
                      <span className="text-amber-400 font-bold">•</span>
                      <span>{lim}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Interactive Shannon Entropy Lab & Calculator */}
      <section className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Binary className="w-5 h-5 text-cyan-400" />
              <h3 className="text-lg font-bold text-slate-100">
                Interactive Shannon Entropy Calculator
              </h3>
            </div>
            <p className="text-xs sm:text-sm text-slate-400">
              Entropy measures byte randomness (0.0 to 8.0 bits/byte). Packed/Encrypted malware typically scores <strong className="text-rose-400">&gt; 7.2</strong>.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setEntropyInput('Hello World! Standard text file with common vowels and words.')}
              className="px-2.5 py-1 text-xs rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
            >
              Load Plaintext
            </button>
            <button
              onClick={() => setEntropyInput('k9#mZ$91!xQ&vL*2@pW8~nE%4^rT+yU=0-aB_cD?fG>hJ<kM;oP:qR[sT]uV{wX}yZ')}
              className="px-2.5 py-1 text-xs rounded-lg bg-rose-950/80 border border-rose-800/50 text-rose-300 hover:bg-rose-900/60 transition"
            >
              Load High Entropy / Encrypted
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-3">
            <label className="block text-xs font-mono font-bold text-slate-400">
              Input Byte Stream / Text:
            </label>
            <textarea
              id="entropy-test-input"
              value={entropyInput}
              onChange={(e) => setEntropyInput(e.target.value)}
              rows={4}
              placeholder="Type or paste text to observe real-time Shannon Entropy..."
              className="w-full rounded-xl bg-slate-950 border border-slate-800 p-3 text-xs sm:text-sm font-mono text-slate-200 focus:outline-none focus:border-cyan-500 transition"
            />
          </div>

          <div className="bg-slate-950 p-5 rounded-xl border border-slate-800 flex flex-col justify-between space-y-4">
            <div>
              <span className="text-xs font-mono text-slate-400 block mb-1">Calculated Shannon Entropy:</span>
              <div className="flex items-baseline gap-2">
                <span className={`text-4xl font-extrabold font-mono ${
                  currentEntropy > 7.0 ? 'text-rose-400' : currentEntropy > 5.5 ? 'text-amber-400' : 'text-emerald-400'
                }`}>
                  {currentEntropy}
                </span>
                <span className="text-xs font-mono text-slate-500">/ 8.000 max</span>
              </div>
            </div>

            {/* Gauge Bar */}
            <div>
              <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden flex">
                <div 
                  className={`h-full transition-all duration-300 ${
                    currentEntropy > 7.0 ? 'bg-rose-500' : currentEntropy > 5.5 ? 'bg-amber-500' : 'bg-emerald-500'
                  }`} 
                  style={{ width: `${(currentEntropy / 8.0) * 100}%` }}
                />
              </div>
              <div className="flex justify-between text-[10px] font-mono text-slate-500 mt-1">
                <span>0.0 (Uniform)</span>
                <span>5.5 - 6.5 (Normal Code)</span>
                <span>7.2+ (Packed/Encrypted)</span>
              </div>
            </div>

            <div className="text-xs text-slate-400 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800/80">
              {currentEntropy > 7.0 ? (
                <span className="text-rose-300 font-medium">⚠️ Suspicious: Indicates encrypted shellcode, ransomware payload, or runtime packing (UPX).</span>
              ) : currentEntropy > 5.0 ? (
                <span className="text-emerald-300 font-medium">✓ Normal Range: Typical for compiled C/C++ x86/x64 executable code.</span>
              ) : (
                <span className="text-slate-300">ℹ️ Low Randomness: Highly predictable ASCII text or repetitive zero padding.</span>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Cybersecurity & Malware Glossary */}
      <section className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-lg font-bold text-slate-100">
              Key Terminology & Concepts Glossary
            </h3>
            <p className="text-xs text-slate-400">
              Essential vocabulary every malware analyst and security engineer must know.
            </p>
          </div>
          <div className="relative w-full sm:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              id="glossary-search"
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search terms (e.g., IAT, C2)..."
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {filteredGlossary.map((item) => (
            <div key={item.term} className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition space-y-1.5">
              <h4 className="text-sm font-bold text-cyan-300 font-mono flex items-center justify-between">
                <span>{item.term}</span>
                <span className="text-[10px] text-slate-500 uppercase font-sans">Cyber Term</span>
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed">{item.definition}</p>
              {item.formula && (
                <code className="text-[11px] font-mono text-emerald-400 bg-slate-950 px-2 py-1 rounded block border border-slate-800/80 mt-2">
                  {item.formula}
                </code>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};
