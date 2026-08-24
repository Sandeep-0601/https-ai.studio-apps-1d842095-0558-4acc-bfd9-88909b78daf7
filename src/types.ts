export type SeverityLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type MalwareCategory = 
  | 'RANSOMWARE'
  | 'TROJAN'
  | 'SPYWARE_KEYLOGGER'
  | 'WORM_BOTNET'
  | 'FILELESS_DROPPER'
  | 'BENIGN_UTILITY';

export interface HashSignatures {
  md5: string;
  sha1: string;
  sha256: string;
  ssdeep: string;
}

export interface PESection {
  name: string;
  virtualSize: number;
  rawSize: number;
  entropy: number;
  characteristics: string[];
  isSuspicious: boolean;
}

export interface SuspiciousImport {
  dll: string;
  functionName: string;
  category: 'INJECTION' | 'EVASION' | 'PERSISTENCE' | 'NETWORK' | 'CRYPTO' | 'SPYWARE' | 'SYSTEM';
  riskDescription: string;
}

export interface ExtractedString {
  value: string;
  type: 'IP_ADDRESS' | 'URL' | 'REGISTRY' | 'COMMAND' | 'FILE_PATH' | 'BASE64' | 'MUTEX';
  suspicionScore: number; // 0-10
}

export interface DynamicEvent {
  step: number;
  timestamp: string;
  type: 'PROCESS_SPAWN' | 'FILE_WRITE' | 'FILE_DELETE' | 'REGISTRY_WRITE' | 'NETWORK_DNS' | 'NETWORK_TCP' | 'MEMORY_INJECT' | 'CRYPTO_OP';
  description: string;
  target: string;
  severity: SeverityLevel;
}

export interface ProcessNode {
  id: string;
  name: string;
  pid: number;
  ppid?: number;
  commandLine: string;
  status: 'RUNNING' | 'TERMINATED' | 'INJECTED' | 'MALICIOUS';
  children?: ProcessNode[];
}

export interface YaraRule {
  id: string;
  name: string;
  meta: {
    author: string;
    description: string;
    threatFamily: string;
    confidence: string;
  };
  strings: {
    id: string;
    pattern: string;
    isHex?: boolean;
  }[];
  condition: string;
  matched: boolean;
  matchedStrings: string[];
}

export interface MitreTechnique {
  id: string;
  tactic: string;
  name: string;
  description: string;
  observedInSample: boolean;
}

export interface AIAnalysisResult {
  threatVerdict: string;
  confidenceScore: number;
  familyClassification: string;
  cvssScore: number;
  summary: string;
  attackVectors: string[];
  mitreTechniques: { id: string; name: string; description: string }[];
  evasionTechniquesDetected: string[];
  remediationSteps: string[];
  deobfuscatedInsight: string;
}

export interface MalwareSample {
  id: string;
  name: string;
  fileName: string;
  fileSizeFormatted: string;
  category: MalwareCategory;
  threatVerdict: string;
  threatScore: number; // 0 - 100
  cvssScore: number; // 0.0 - 10.0
  severity: SeverityLevel;
  description: string;
  hashes: HashSignatures;
  overallEntropy: number;
  entropyBlocks: number[];
  peHeaders: {
    machine: string;
    numberOfSections: number;
    timeDateStamp: string;
    subsystem: string;
    entryPoint: string;
    imageSize: string;
  };
  sections: PESection[];
  imports: SuspiciousImport[];
  extractedStrings: ExtractedString[];
  dynamicEvents: DynamicEvent[];
  processTree: ProcessNode;
  yaraRules: YaraRule[];
  mitreTechniques: MitreTechnique[];
  payloadSnippet: string;
  analysisExplanation: {
    whatItDoes: string;
    howDetected: string;
    whyDangerous: string;
  };
}

export type ActiveTab = 
  | 'BASICS_GUIDE' 
  | 'DETECTION_LAB' 
  | 'CUSTOM_ANALYZER' 
  | 'EVASION_DEFENSE' 
  | 'PROJECT_BLUEPRINT';

export type LabSubTab = 
  | 'STATIC_ANALYSIS' 
  | 'DYNAMIC_SANDBOX' 
  | 'YARA_MATCHING' 
  | 'AI_THREAT_INTEL';
