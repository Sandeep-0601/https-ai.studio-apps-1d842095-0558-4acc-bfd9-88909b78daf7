export interface DetectionPillar {
  id: string;
  title: string;
  shortDesc: string;
  iconName: string;
  howItWorks: string;
  advantages: string[];
  limitations: string[];
  keyToolsAndAPIs: string[];
  realWorldExample: string;
}

export const DETECTION_PILLARS: DetectionPillar[] = [
  {
    id: 'signature-detection',
    title: '1. Signature & Hash Matching',
    shortDesc: 'Exact match detection using cryptographic hashes (MD5, SHA-256) and YARA byte rules.',
    iconName: 'Hash',
    howItWorks: 'Calculates the cryptographic checksum of a file or scans for unique sequences of bytes. If the hash matches a known malicious database (like VirusTotal or threat feeds), it is instantly flagged.',
    advantages: [
      'Extremely fast (O(1) database lookup).',
      'Near-zero false positive rate on known samples.',
      'Low CPU/RAM resource footprint.'
    ],
    limitations: [
      'Easily bypassed: changing a single bit (e.g. adding 1 byte of junk data) changes the entire SHA-256 hash.',
      'Completely blind to zero-day (never-before-seen) malware.'
    ],
    keyToolsAndAPIs: ['SHA-256', 'SSDEEP (Fuzzy Hashing)', 'YARA Rules', 'VirusTotal API'],
    realWorldExample: 'Known WannaCry binaries matching SHA-256 ed01ebf8333... are blocked before execution.'
  },
  {
    id: 'static-analysis',
    title: '2. Static Analysis & PE Headers',
    shortDesc: 'Inspecting executable file structure, headers, imported functions, and entropy without executing code.',
    iconName: 'FileCode',
    howItWorks: 'Parses the Portable Executable (PE) or ELF file format. Examines the Import Address Table (IAT) for dangerous APIs (VirtualAlloc, WriteProcessMemory), inspects section names, and measures Shannon Entropy to detect packing/encryption.',
    advantages: [
      'Safe: Analyzes file without triggering potentially destructive execution.',
      'Identifies malicious capabilities before payload detonation.',
      'High throughput: can scan thousands of files per minute.'
    ],
    limitations: [
      'Cannot analyze code obfuscated with runtime packers or runtime API resolution (LoadLibrary + GetProcAddress).',
      'May produce false positives on protected commercial software (DRMs).'
    ],
    keyToolsAndAPIs: ['pefile (Python)', 'Capa (Mandiant)', 'PE-bear', 'Ghidra / IDA Pro'],
    realWorldExample: 'A file with 7.9+ entropy and imports for CreateRemoteThread + CryptEncrypt is flagged as packed ransomware.'
  },
  {
    id: 'dynamic-sandbox',
    title: '3. Dynamic Sandbox Execution',
    shortDesc: 'Running the binary in a secure, isolated virtual environment to monitor runtime behavior.',
    iconName: 'ShieldAlert',
    howItWorks: 'Executes the sample inside a virtual machine or container. Hooks Windows API calls, watches process creation trees, records file system and registry changes, and captures outbound network traffic.',
    advantages: [
      'Unpacks runtime-obfuscated malware automatically as it executes in memory.',
      'Captures real-time Command & Control (C2) domains and dropped files.',
      'Defeats static code obfuscation.'
    ],
    limitations: [
      'Resource intensive: requires 2-5 minutes per sample.',
      'Evasive malware uses Anti-VM techniques (checking CPU cores, mouse movements, or sleep delays) to stay dormant.'
    ],
    keyToolsAndAPIs: ['Cuckoo Sandbox', 'ANY.RUN', 'CAPE Sandbox', 'Sysmon', 'Procmon'],
    realWorldExample: 'Watching a Word macro spawn PowerShell.exe, which attempts to connect to a suspicious Russian IP.'
  },
  {
    id: 'heuristic-behavioral',
    title: '4. Behavioral & Heuristic Detection',
    shortDesc: 'Identifying suspicious sequences of actions regardless of whether the file signature is known.',
    iconName: 'Cpu',
    howItWorks: 'Instead of matching exact signatures, it monitors behavioral rules and triggers: e.g., "If process deletes volume shadow copies AND rapidly modifies 100+ files with high entropy -> Verdict = Ransomware".',
    advantages: [
      'Detects brand-new zero-day attacks and fileless malware.',
      'Monitors living-off-the-land binaries (PowerShell, Certutil, WMI).'
    ],
    limitations: [
      'Requires fine-tuning to prevent false alarms on developer tools or backup software.',
      'Requires continuous kernel-level or EDR agent telemetry.'
    ],
    keyToolsAndAPIs: ['Microsoft Defender AMSI', 'ETW (Event Tracing for Windows)', 'CrowdStrike Falcon', 'Sigma Rules'],
    realWorldExample: 'Blocking an unmanaged script that attempts to inject code into svchost.exe.'
  },
  {
    id: 'ai-ml-intelligence',
    title: '5. Machine Learning & AI Classification',
    shortDesc: 'Using trained neural networks, Random Forests, and LLMs to classify binary feature vectors and explain threats.',
    iconName: 'BrainCircuit',
    howItWorks: 'Extracts hundreds of numerical features (section sizes, byte entropy, n-grams, opcode frequencies) and feeds them into ML models (XGBoost / LightGBM) trained on datasets like EMBER. LLMs (Gemini) synthesize raw disassembly into actionable security briefings.',
    advantages: [
      'Generalizes beyond static rules to catch subtle variants.',
      'Translates complex assembly & API traces into plain-English remediation guides.',
      'Automates triage for SOC analysts.'
    ],
    limitations: [
      'Susceptible to adversarial ML poisoning or evasion (e.g. byte-padding).',
      'Requires high-quality balanced datasets.'
    ],
    keyToolsAndAPIs: ['EMBER Dataset', 'Scikit-learn', 'LightGBM / XGBoost', 'Google Gemini 3.7 API'],
    realWorldExample: 'An ML model scores an unknown binary with 94.2% malware probability based on abnormal PE header structure.'
  }
];

export const CORE_GLOSSARY = [
  {
    term: 'Shannon Entropy',
    definition: 'A mathematical measure of randomness in a byte stream (0.0 to 8.0). Normal compiled code is ~5.5-6.5; encrypted payloads or compressed packers (like UPX) score 7.2 to 8.0.',
    formula: 'H(X) = -sum( P(x_i) * log2(P(x_i)) )'
  },
  {
    term: 'PE Header (Portable Executable)',
    definition: 'The standard executable file format for Windows (.exe, .dll, .sys). Contains DOS header, COFF header, Optional header, Section tables (.text, .data, .rsrc), and the Import Address Table.'
  },
  {
    term: 'Import Address Table (IAT)',
    definition: 'A lookup table of external DLL functions (APIs) the program calls. Suspicious imports (e.g. VirtualAllocEx + CreateRemoteThread) reveal code injection capabilities.'
  },
  {
    term: 'YARA Rules',
    definition: 'The industry-standard rule language for pattern matching on malware strings, hex byte sequences, and logical conditions used by antivirus and threat hunters worldwide.'
  },
  {
    term: 'C2 (Command & Control)',
    definition: 'Attacker-controlled servers that malware contacts to receive commands, download secondary payloads, or exfiltrate stolen credentials and files.'
  },
  {
    term: 'Process Hollowing / Injection',
    definition: 'A stealth evasion technique where malware spawns a legitimate process (like svchost.exe), unmaps its memory, and writes malicious shellcode inside to deceive task managers and basic scanners.'
  },
  {
    term: 'AMSI (Antimalware Scan Interface)',
    definition: 'A Windows interface that allows applications like PowerShell and Office macros to submit scripts to installed antivirus software in cleartext right before execution, defeating obfuscation.'
  },
  {
    term: 'IOC (Indicator of Compromise)',
    definition: 'Forensic artifacts observed on a network or operating system that indicate an intrusion (e.g. file hashes, malicious IP addresses, domain names, registry keys).'
  }
];
