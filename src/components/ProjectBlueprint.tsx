import React, { useState } from 'react';
import { 
  Code2, 
  Database, 
  BrainCircuit, 
  Binary, 
  Terminal, 
  Copy, 
  Check, 
  ExternalLink, 
  Cpu, 
  CheckCircle2, 
  Layers 
} from 'lucide-react';

const CODE_TEMPLATES = {
  featureExtractor: `# extract_pe_features.py
import pefile
import math
import hashlib
import json
import sys

def calculate_entropy(data):
    """Calculates Shannon Entropy (0.0 to 8.0) of a byte array."""
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    occ = {}
    for byte in data:
        occ[byte] = occ.get(byte, 0) + 1
    for count in occ.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_features(file_path):
    """Parses PE file and extracts numerical feature vector for ML model."""
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"[-] Error reading PE header: {e}")
        return None

    with open(file_path, "rb") as f:
        content = f.read()

    features = {
        "md5": hashlib.md5(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
        "file_size": len(content),
        "overall_entropy": calculate_entropy(content),
        "num_sections": len(pe.sections),
        "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "image_base": pe.OPTIONAL_HEADER.ImageBase,
        "section_entropies": [],
        "suspicious_apis_count": 0,
        "has_rwx_section": 0
    }

    # Extract section properties
    for section in pe.sections:
        s_entropy = calculate_entropy(section.get_data())
        features["section_entropies"].append({
            "name": section.Name.decode('utf-8', errors='ignore').strip('\\x00'),
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": s_entropy
        })
        # Check for RWX memory (Read, Write, Execute) -> high risk
        characteristics = section.Characteristics
        if (characteristics & 0x20000000) and (characteristics & 0x80000000):
            features["has_rwx_section"] = 1

    # Suspicious Windows API Import Check
    DANGEROUS_APIS = {
        "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", 
        "CreateRemoteThread", "SetWindowsHookExA", "CryptEncrypt",
        "InternetOpenUrlA", "IsDebuggerPresent", "AmsiScanBuffer"
    }

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name and imp.name.decode('utf-8', errors='ignore') in DANGEROUS_APIS:
                    features["suspicious_apis_count"] += 1

    return features

if __name__ == "__main__":
    if len(sys.argv) > 1:
        res = extract_features(sys.argv[1])
        print(json.dumps(res, indent=2))`,

  trainModel: `# train_malware_classifier.py
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
import joblib

# Example dataset structure (e.g. derived from EMBER or custom extracts)
# Columns: [file_size, overall_entropy, num_sections, has_rwx, suspicious_apis, label (0=benign, 1=malware)]

def train():
    print("[*] Loading extracted PE feature dataset...")
    # Simulated feature matrix
    np.random.seed(42)
    n_samples = 5000
    
    # Benign samples: normal entropy (5.0-6.5), 0-1 suspicious APIs
    benign = np.column_stack([
        np.random.normal(200000, 50000, n_samples // 2),
        np.random.normal(5.8, 0.4, n_samples // 2),
        np.random.randint(3, 6, n_samples // 2),
        np.zeros(n_samples // 2),
        np.random.poisson(0.2, n_samples // 2),
        np.zeros(n_samples // 2)
    ])
    
    # Malware samples: higher entropy (>7.0), multiple suspicious APIs, RWX sections
    malware = np.column_stack([
        np.random.normal(600000, 200000, n_samples // 2),
        np.random.normal(7.4, 0.5, n_samples // 2),
        np.random.randint(4, 9, n_samples // 2),
        np.random.choice([0, 1], n_samples // 2, p=[0.3, 0.7]),
        np.random.poisson(3.5, n_samples // 2),
        np.ones(n_samples // 2)
    ])

    data = np.vstack([benign, malware])
    X = data[:, :-1]
    y = data[:, -1]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print(f"[*] Training Random Forest Classifier on {len(X_train)} samples...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    print("\\n[+] Model Evaluation Results:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malware"]))
    print(f"ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}")
    
    # Save trained model to disk
    joblib.dump(clf, "malware_detector_rf.pkl")
    print("[+] Model saved to malware_detector_rf.pkl")

if __name__ == "__main__":
    train()`,

  yaraScanner: `# yara_scanner.py
import yara
import sys
import os

YARA_RULES = """
rule Ransomware_ShadowCopy_Delete {
    meta:
        description = "Detects attempts to delete shadow copies"
        author = "AMDS"
    strings:
        $vss = "vssadmin" nocase
        $del = "Delete Shadows" nocase
        $all = "/All /Quiet" nocase
    condition:
        $vss and ($del or $all)
}

rule Process_Injection_APIs {
    meta:
        description = "Detects process injection API combination"
    strings:
        $a1 = "VirtualAllocEx"
        $a2 = "WriteProcessMemory"
        $a3 = "CreateRemoteThread"
    condition:
        all of them
}
"""

def scan_file(file_path):
    rules = yara.compile(source=YARA_RULES)
    matches = rules.match(file_path)
    print(f"[*] Scanning {file_path} with YARA rules...")
    if matches:
        print(f"[!] MALWARE DETECTED: {len(matches)} rule(s) matched!")
        for match in matches:
            print(f"    - Match: {match.rule}")
    else:
        print("[+] Clean: No YARA signature hits.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        scan_file(sys.argv[1])`
};

export const ProjectBlueprint: React.FC = () => {
  const [activeCodeTab, setActiveCodeTab] = useState<'featureExtractor' | 'trainModel' | 'yaraScanner'>('featureExtractor');
  const [copiedCode, setCopiedCode] = useState<boolean>(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(CODE_TEMPLATES[activeCodeTab]);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Overview Card */}
      <div className="rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 border border-slate-800 p-6 space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-700/60 text-xs font-mono text-cyan-300">
          <Code2 className="w-3.5 h-3.5" />
          <span>Complete Project Implementation Blueprint</span>
        </div>
        <h2 className="text-2xl font-extrabold text-slate-100">
          How to Build a Real Machine Learning Malware Detection Project
        </h2>
        <p className="text-slate-300 text-xs sm:text-sm max-w-3xl leading-relaxed">
          Step-by-step roadmap, dataset recommendations, feature extraction algorithms, and starter code templates for college, research, or enterprise security portfolio projects.
        </p>
      </div>

      {/* 4-Phase Roadmap */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          {
            phase: 'Phase 1',
            title: 'Dataset Acquisition',
            desc: 'Collect balanced benign (System32) and malware samples (EMBER, VirusShare, MalShare).',
            icon: <Database className="w-5 h-5 text-cyan-400" />
          },
          {
            phase: 'Phase 2',
            title: 'Feature Engineering',
            desc: 'Extract PE headers, Shannon Entropy, IAT APIs, byte n-grams using Python pefile.',
            icon: <Layers className="w-5 h-5 text-blue-400" />
          },
          {
            phase: 'Phase 3',
            title: 'Model Training',
            desc: 'Train Random Forest / LightGBM classifiers with 100+ decision trees to reach >98% accuracy.',
            icon: <BrainCircuit className="w-5 h-5 text-indigo-400" />
          },
          {
            phase: 'Phase 4',
            title: 'YARA & AI Triage',
            desc: 'Combine ML probability with YARA signature matching and LLM threat explanation.',
            icon: <Terminal className="w-5 h-5 text-emerald-400" />
          }
        ].map((item, idx) => (
          <div key={idx} className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono font-bold text-slate-500 uppercase">{item.phase}</span>
              {item.icon}
            </div>
            <h4 className="text-sm font-bold text-slate-100">{item.title}</h4>
            <p className="text-xs text-slate-400 leading-snug">{item.desc}</p>
          </div>
        ))}
      </div>

      {/* Recommended Datasets Table */}
      <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4">
        <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
          <Database className="w-4 h-4 text-cyan-400" />
          Recommended Open Datasets for Training & Benchmarking
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
            <span className="font-bold text-cyan-300 font-mono">1. EMBER Dataset</span>
            <p className="text-slate-400">1.1 million scanned PE files with pre-extracted feature vectors, published by Endgame/Elastic.</p>
            <span className="text-[10px] font-mono text-slate-500 block">Format: JSON / Vector Array</span>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
            <span className="font-bold text-cyan-300 font-mono">2. SOREL-20M</span>
            <p className="text-slate-400">Sophos-ReversingLabs 20 million sample dataset with malware labels and disassemblies.</p>
            <span className="text-[10px] font-mono text-slate-500 block">Format: PyTorch / Parquet</span>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
            <span className="font-bold text-cyan-300 font-mono">3. VirusShare / MalShare</span>
            <p className="text-slate-400">Live corpus of real malware binaries (Trojan, Ransomware, Worms) for researchers.</p>
            <span className="text-[10px] font-mono text-slate-500 block">Format: Raw Binaries (Zip-Encrypted)</span>
          </div>
        </div>
      </div>

      {/* Copy-Ready Python Starter Source Code */}
      <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Copy-Ready Python Starter Implementation
            </h3>
            <p className="text-xs text-slate-400">
              Run these scripts on any system with <code className="text-cyan-300 font-mono">pip install pefile scikit-learn yara-python</code>.
            </p>
          </div>

          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition self-start sm:self-auto"
          >
            {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedCode ? 'Copied to Clipboard' : 'Copy Script'}</span>
          </button>
        </div>

        {/* Code Tabs */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
          {[
            { id: 'featureExtractor', label: '1. extract_pe_features.py' },
            { id: 'trainModel', label: '2. train_malware_classifier.py' },
            { id: 'yaraScanner', label: '3. yara_scanner.py' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveCodeTab(tab.id as any)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
                activeCodeTab === tab.id
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-950'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Code View */}
        <div className="relative">
          <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 overflow-x-auto leading-relaxed max-h-[480px]">
            {CODE_TEMPLATES[activeCodeTab]}
          </pre>
        </div>
      </div>
    </div>
  );
};
