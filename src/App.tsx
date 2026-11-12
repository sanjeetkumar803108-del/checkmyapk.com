import React, { useState, useRef } from 'react';
import {
  Shield,
  Search,
  AlertTriangle,
  Download,
  Sparkles,
  ArrowRight,
  RefreshCw,
  Terminal,
  Cpu,
  Layers,
  Activity,
  FileCode2,
  Wrench,
  Copy,
  Check,
  Code2,
  Smartphone,
  Globe,
  UploadCloud,
  ShieldCheck,
  Lock,
  Zap,
  Binary,
  Server,
  Radio,
  FileJson,
  FileText,
  Info,
  X,
  TrendingUp,
  CheckCircle2
} from 'lucide-react';
import { CyberBackground } from './components/CyberBackground';
import { ScoreGauge } from './components/ScoreGauge';
import { FindingCard } from './components/FindingCard';
import { LiveTerminalLogs } from './components/LiveTerminalLogs';

interface ExportedComp {
  componentType: 'activity' | 'service' | 'receiver' | 'provider';
  name: string;
  explicitlyExported: boolean;
  implicitViaIntentFilter: boolean;
  permission: string | null;
  isLauncher: boolean;
  hasDeepLink: boolean;
  risky: boolean;
}

interface SecurityReport {
  targetUrl: string;
  scanTimestamp: string;
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'F';
  riskLevel: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  summaryCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info?: number;
    pass: number;
  };
  findings: any[];
  aiExecutiveSummary?: string;
  isApkAudit?: boolean;
  isDemoPreview?: boolean;
  apkMeta?: {
    fileName: string;
    sizeMb: string;
    sha256?: string;
    obfuscationStatus?: string;
    packageName: string;
    versionName?: string;
    versionCode?: number;
    targetSdkVersion: number;
    minSdkVersion: number;
    frameworkDetected: string;
    architectures: string[];
    permissions: string[];
    dexCount: number;
    totalFiles: number;
    exportedComponents?: {
      totalExported: number;
      unprotectedCount: number;
      activities: ExportedComp[];
      services: ExportedComp[];
      receivers: ExportedComp[];
      providers: ExportedComp[];
    };
    trackers?: string[];
    sdks?: string[];
    discoveredEndpoints?: string[];
    baasUrls?: string[];
    probedApis?: Array<{
      url: string;
      status: number | string;
      latencyMs: number;
      cors: string;
      hsts: boolean;
      reachable: boolean;
    }>;
    dexBytecodeGraph?: {
      dexCount: number;
      totalClasses: number;
      appClasses: number;
      methodsAnalyzed: number;
      instructionsScanned: number;
      durationMs: number;
      interproceduralPathsCount?: number;
      pinningSignals?: string[];
      taintPaths: Array<{
        source: string;
        sink: string;
        methodSignature: string;
        detail: string;
        severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
        owaspRef: string;
        hopCount?: number;
        callChain?: string[];
      }>;
      callGraphHotspots: Array<{
        callerMethod: string;
        calleeSignature: string;
        category: string;
      }>;
    };
    nativeElfSummary?: {
      totalSoFiles: number;
      uniqueLibrariesCount: number;
      appLibrariesCount: number;
      hardeningWeakCount: number;
      nativeStringsScannedKb: number;
      libraries: Array<{
        fileName: string;
        baseName: string;
        abi: string;
        sizeBytes: number;
        archBits: 32 | 64;
        isThirdPartyRuntime: boolean;
        pie: boolean;
        nx: boolean;
        stackCanary: boolean;
        relro: 'FULL' | 'PARTIAL' | 'NONE';
      }>;
    };
    pinningStatus?: {
      active: boolean;
      signals: string[];
    };
  };
  webDeepSurface?: {
    discoveredRoutes: string[];
    apiEndpoints: string[];
    openApiSpecs: Array<{ url: string; title?: string; pathsCount: number }>;
    graphqlEndpoints: Array<{ url: string; introspectionEnabled: boolean; typesCount?: number }>;
    domSinks: Array<{
      type: string;
      severity: 'HIGH' | 'MEDIUM';
      fileUrl: string;
      snippet: string;
      taintedByInput: boolean;
    }>;
    jwtAudits: Array<{
      source: string;
      alg: string;
      hasExp: boolean;
      expired: boolean;
      claims: string[];
      issues: string[];
    }>;
    robotsDisallowed: string[];
    sitemapCount: number;
    authAudit?: {
      enabled: boolean;
      authKind: string;
      targetStatus: number;
      protectedApiChecks: Array<{
        url: string;
        authStatus: number | string;
        unauthStatus: number | string;
      }>;
    };
  };
  domainVerification?: {
    verified: boolean;
    method: string | null;
    token: string;
    burstProfile: string;
  };
  networkPosture?: {
    corsReflection: 'Reflected (Critical)' | 'Reflected (High)' | 'Strict';
    tlsProtocol: string | null;
    certDaysRemaining: number | null;
    certIssuer: string | null;
    spfPresent: boolean | null;
    dmarcPolicy: string | null;
    securityTxtPresent: boolean;
    missingSriCount: number;
    outdatedLibraries: string[];
  };
  telemetry?: {
    latencyMs?: number;
    totalBytesScanned: number;
    totalLinesInspected: number;
    scriptsCount: number;
    detectedTech: string[];
    durationSeconds: string;
    realTimeLogs: Array<{ time: string; msg: string }>;
  };
}

export default function App() {
  const [scanMode, setScanMode] = useState<'web' | 'apk'>('apk');
  const [url, setUrl] = useState('');
  const [showWebAuthOptions, setShowWebAuthOptions] = useState(false);
  const [webAuthHeader, setWebAuthHeader] = useState('');
  const [webAuthCookie, setWebAuthCookie] = useState('');
  const [apkFile, setApkFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'vulns' | 'pass'>('all');
  const [activeStepMessage, setActiveStepMessage] = useState('Initiating automated security probe...');
  const [showLogsModal, setShowLogsModal] = useState(false);
  const [showTrustModal, setShowTrustModal] = useState<'privacy' | 'methodology' | null>(null);
  const [hashCopied, setHashCopied] = useState(false);
  const [scoreDelta, setScoreDelta] = useState<{
    previousScore: number;
    delta: number;
    fixedIssues: string[];
    newIssues: string[];
  } | null>(null);
  const [domainChallenge, setDomainChallenge] = useState<{
    host: string;
    token: string;
    txtRecord: string;
    metaTag: string;
  } | null>(null);
  const [masterTab, setMasterTab] = useState<'vercel' | 'nextjs' | 'express'>('vercel');
  const [masterCopied, setMasterCopied] = useState(false);
  const [mdCopied, setMdCopied] = useState(false);

  const updateScanHistory = (targetKey: string, score: number, findingsList: any[] = []) => {
    try {
      const raw = localStorage.getItem('checkmyapk_history');
      const map: Record<string, { score: number; at: string; findingTypes?: string[] }> = raw ? JSON.parse(raw) : {};
      const prev = map[targetKey];
      const currentTypes = Array.from(
        new Set(
          findingsList
            .filter((f) => f && f.severity !== 'PASS' && f.severity !== 'INFO' && typeof f.type === 'string')
            .map((f) => `${f.severity}:${f.type}`)
        )
      ).slice(0, 60);

      if (prev && typeof prev.score === 'number') {
        const prevTypes = Array.isArray(prev.findingTypes) ? prev.findingTypes : [];
        const prevSet = new Set(prevTypes);
        const curSet = new Set(currentTypes);
        const fixedIssues = prevTypes.filter((t) => !curSet.has(t)).map((t) => t.replace(/^[^:]+:/, ''));
        const newIssues = currentTypes.filter((t) => !prevSet.has(t)).map((t) => t.replace(/^[^:]+:/, ''));
        setScoreDelta({
          previousScore: prev.score,
          delta: score - prev.score,
          fixedIssues,
          newIssues
        });
      } else {
        setScoreDelta(null);
      }
      map[targetKey] = { score, at: new Date().toISOString(), findingTypes: currentTypes };
      localStorage.setItem('checkmyapk_history', JSON.stringify(map));
    } catch (e) {
      setScoreDelta(null);
    }
  };

  const handleLoadDomainChallenge = async () => {
    const clean = url.trim();
    if (!clean) {
      setError('Enter your website URL above first to generate a domain ownership token.');
      return;
    }
    try {
      const r = await fetch(`/api/domain-verify/challenge?targetUrl=${encodeURIComponent(clean)}`);
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || 'Could not generate challenge');
      setDomainChallenge(d);
      setError(null);
    } catch (err: any) {
      setError(err?.message || 'Could not generate domain challenge.');
    }
  };

  const handleOpenSampleDemo = () => {
    setError(null);
    setScoreDelta(null);
    setReport({
      targetUrl: 'com.demo.payvault',
      scanTimestamp: new Date().toISOString(),
      score: 62,
      grade: 'C',
      riskLevel: 'HIGH',
      isApkAudit: true,
      isDemoPreview: true,
      summaryCounts: { critical: 1, high: 1, medium: 2, low: 0, pass: 5 },
      aiExecutiveSummary:
        '1. 📱 SAMPLE DEMO REPORT — PAYVAULT TEST APK: This interactive showcase illustrates how CheckMyAPK catches unprotected IPC receivers, hardcoded cleartext endpoints, and exposed cloud endpoints.\n2. 🚨 PRIMARY EXPOSURE: Unencrypted HTTP endpoint and unprotected exported receiver found.\n3. ⚡ ACTION: Drop your own real .apk file above to run a live 4-stage RAM-only audit.',
      apkMeta: {
        fileName: 'sample-payvault-demo.apk',
        sizeMb: '14.2',
        sha256: 'demo0000showcase9f2a81c4b5d6e7f809a1b2c3d4e5f60718293a4b5c6d7e8',
        obfuscationStatus: 'Unobfuscated Symbols',
        packageName: 'com.demo.payvault',
        versionName: '2.4.0',
        versionCode: 24,
        targetSdkVersion: 35,
        minSdkVersion: 24,
        frameworkDetected: 'Native Android (Java/Kotlin)',
        architectures: ['arm64-v8a', 'armeabi-v7a'],
        permissions: ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE', 'android.permission.CAMERA'],
        dexCount: 2,
        totalFiles: 1420,
        exportedComponents: {
          totalExported: 4,
          unprotectedCount: 1,
          activities: [
            { componentType: 'activity', name: 'com.demo.payvault.MainActivity', explicitlyExported: true, implicitViaIntentFilter: false, permission: null, isLauncher: true, hasDeepLink: false, risky: false }
          ],
          services: [
            { componentType: 'service', name: 'com.demo.payvault.SyncWorkerService', explicitlyExported: true, implicitViaIntentFilter: false, permission: 'android.permission.BIND_JOB_SERVICE', isLauncher: false, hasDeepLink: false, risky: false }
          ],
          receivers: [
            { componentType: 'receiver', name: 'com.demo.payvault.WalletTransferReceiver', explicitlyExported: true, implicitViaIntentFilter: false, permission: null, isLauncher: false, hasDeepLink: false, risky: true }
          ],
          providers: []
        },
        trackers: ['Firebase Analytics'],
        sdks: ['OkHttp3 Client', 'Retrofit2 REST', 'Firebase Cloud Messaging'],
        probedApis: [
          { url: 'https://api.example.com/v1/status', status: 200, latencyMs: 142, cors: 'Restricted', hsts: true, reachable: true }
        ]
      },
      findings: [
        {
          category: 'Manifest & IPC Surface',
          type: 'Unprotected Exported Services/Receivers/Providers (1)',
          severity: 'HIGH',
          owaspRef: 'MASVS-PLATFORM-1',
          proof: 'Exported without android:permission: [receiver] com.demo.payvault.WalletTransferReceiver',
          description: 'Sample Demo Finding: Exported broadcast receivers without permission limits can be spoofed by rogue apps.',
          remediation: 'Set android:exported="false" or add a signature-level android:permission.'
        },
        {
          category: 'Secrets & Cryptography',
          type: 'Hardcoded API Secret in APK (Sample Gemini Key)',
          severity: 'CRITICAL',
          owaspRef: 'MASVS-CRYPTO-1',
          proof: 'Sample Demo Proof: Pattern "AIzaSyDemo...x9Qa" detected inside classes.dex',
          description: 'Sample Demo Finding: API secrets inside compiled DEX can be extracted in seconds via JADX.',
          remediation: 'Move sensitive API keys to a backend proxy.'
        },
        {
          category: 'Manifest Security',
          type: 'Debug Mode Disabled (Non-Debuggable)',
          severity: 'PASS',
          owaspRef: 'MASVS-RESILIENCE-1',
          proof: 'android:debuggable is false in release manifest.',
          description: 'App blocks external debugger attachment.',
          remediation: 'Keep debuggable false in release builds.'
        }
      ],
      telemetry: {
        totalLinesInspected: 1420,
        totalBytesScanned: 14889779,
        scriptsCount: 2,
        detectedTech: ['Native Android (Java/Kotlin)', 'arm64-v8a', 'OkHttp3 Client', 'Retrofit2 REST'],
        durationSeconds: '0.00 (Demo)',
        realTimeLogs: [
          { time: '[+0.00s]', msg: 'Loaded interactive Sample Demo Preview report (simulated showcase data).' }
        ]
      }
    });
    setFilter('vulns');
  };

  const handleExportJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const urlObj = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = urlObj;
    const safeName = (report.apkMeta?.packageName || report.targetUrl).replace(/[^a-zA-Z0-9.-]/g, '_');
    a.download = `checkmyapk-${safeName}-report.json`;
    a.click();
    URL.revokeObjectURL(urlObj);
  };

  const buildMarkdownReport = (r: SecurityReport) => {
    const targetName = r.isApkAudit ? r.apkMeta?.packageName || r.targetUrl : r.targetUrl;
    const lines = [
      `# CheckMyAPK.com Security Audit Report`,
      `- **Target:** ${targetName}`,
      `- **Score:** ${r.score}/100 (Grade ${r.grade} • ${r.riskLevel} RISK)`,
      `- **Timestamp:** ${r.scanTimestamp}`,
      ...(r.apkMeta?.sha256 ? [`- **APK SHA-256:** \`${r.apkMeta.sha256}\``] : []),
      ...(r.apkMeta?.obfuscationStatus ? [`- **Obfuscation:** ${r.apkMeta.obfuscationStatus}`] : []),
      ...(r.networkPosture
        ? [
            `- **Network & Supply-Chain:** CORS Reflection=${r.networkPosture.corsReflection} | TLS=${r.networkPosture.tlsProtocol || 'N/A'} (${r.networkPosture.certDaysRemaining ?? 'N/A'}d left) | DMARC=${r.networkPosture.dmarcPolicy || 'none'} | Missing SRI=${r.networkPosture.missingSriCount}`
          ]
        : []),
      ``,
      `## AI Security Brief`,
      r.aiExecutiveSummary || 'N/A',
      ``,
      `## Findings (${r.findings.length})`,
      ...r.findings.map((f) =>
        `### [${f.severity}] ${f.type}${f.owaspRef ? ` (${f.owaspRef})` : ''}\n- **Proof:** \`${f.proof}\`\n- **Impact:** ${f.description}\n- **Fix:** ${f.remediation}\n`
      )
    ];
    return { targetName, text: lines.join('\n') };
  };

  const handleExportMarkdown = () => {
    if (!report) return;
    const { targetName, text } = buildMarkdownReport(report);
    const blob = new Blob([text], { type: 'text/markdown' });
    const urlObj = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = urlObj;
    const safeName = targetName.replace(/[^a-zA-Z0-9.-]/g, '_');
    a.download = `checkmyapk-${safeName}-report.md`;
    a.click();
    URL.revokeObjectURL(urlObj);
  };

  const handleCopyMarkdown = () => {
    if (!report) return;
    const { text } = buildMarkdownReport(report);
    navigator.clipboard.writeText(text);
    setMdCopied(true);
    setTimeout(() => setMdCopied(false), 2000);
  };

  const masterCodes = {
    vercel: {
      filename: 'vercel.json',
      desc: 'Create or update vercel.json in your root project directory:',
      code: `{\n  "headers": [\n    {\n      "source": "/(.*)",\n      "headers": [\n        { "key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; connect-src 'self' https:;" },\n        { "key": "X-Frame-Options", "value": "DENY" },\n        { "key": "X-Content-Type-Options", "value": "nosniff" },\n        { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" },\n        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" }\n      ]\n    }\n  ]\n}`
    },
    nextjs: {
      filename: 'next.config.js',
      desc: 'Add this security headers block inside next.config.js:',
      code: `/** @type {import('next').NextConfig} */\nconst nextConfig = {\n  async headers() {\n    return [\n      {\n        source: '/(.*)',\n        headers: [\n          { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:;" },\n          { key: 'X-Frame-Options', value: 'DENY' },\n          { key: 'X-Content-Type-Options', value: 'nosniff' },\n          { key: 'Strict-Transport-Security', value: "max-age=31536000; includeSubDomains; preload" }\n        ]\n      }\n    ];\n  }\n};\nmodule.exports = nextConfig;`
    },
    express: {
      filename: 'server.js',
      desc: 'Add helmet and express-rate-limit in your Express app:',
      code: `// npm install helmet express-rate-limit\nconst express = require('express');\nconst helmet = require('helmet');\nconst rateLimit = require('express-rate-limit');\n\nconst app = express();\n\n// 1. One line fixes CSP, HSTS, X-Frame-Options & MIME sniffing:\napp.use(helmet());\n\n// 2. Protect from Denial-of-Wallet rate limit attacks:\napp.use('/api/', rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 100,\n  message: { error: 'Too many requests, slow down.' }\n}));`
    }
  };

  const handleCopyMaster = (code: string) => {
    navigator.clipboard.writeText(code);
    setMasterCopied(true);
    setTimeout(() => setMasterCopied(false), 2000);
  };

  // 🌐 Scan Web Target
  const handleScanWeb = async (targetToScan?: string) => {
    const finalUrl = (targetToScan || url).trim();
    if (!finalUrl) return;

    setUrl(finalUrl);
    setLoading(true);
    setError(null);
    setReport(null);

    const steps = [
      'Resolving target DNS & establishing secure TLS socket...',
      'Crawling HTML document tree and extracting script bundles...',
      'Mapping robots.txt, sitemap.xml, OpenAPI specs & GraphQL endpoints...',
      'Scanning JS bundles for leaked secrets & Static DOM XSS sinks...',
      'Auditing JWT claims, HTTP Security Headers & CORS origin policies...',
      'Testing Firebase / Supabase rules & passive API route error leaks...',
      'Sending 15-request burst to test Denial-of-Wallet rate limits...',
      'Invoking Gemini Neural Engine for custom architectural threat synthesis...'
    ];

    let stepIdx = 0;
    const stepInterval = setInterval(() => {
      stepIdx++;
      if (stepIdx < steps.length) {
        setActiveStepMessage(steps[stepIdx]);
      }
    }, 800);

    try {
      const payload: Record<string, string> = { targetUrl: finalUrl };
      if (webAuthHeader.trim()) payload.authHeader = webAuthHeader.trim();
      if (webAuthCookie.trim()) payload.authCookie = webAuthCookie.trim();

      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      clearInterval(stepInterval);

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `HTTP error ${res.status}`);
      }

      const data = await res.json();
      setReport(data);
      updateScanHistory(`web:${data.targetUrl}`, data.score, data.findings);
      const hasVulns = data.findings?.some((f: any) => f.severity !== 'PASS');
      setFilter(hasVulns ? 'vulns' : 'all');
      setLoading(false);
    } catch (err: any) {
      clearInterval(stepInterval);
      setError(err.message || 'Web scan failed.');
      setLoading(false);
    }
  };

  // 📱 Scan APK File Upload (Async Worker Queue + Live Telemetry Polling)
  const handleScanApk = async (fileToScan?: File) => {
    const selectedFile = fileToScan || apkFile;
    if (!selectedFile) {
      setError('Please select or drop an Android .apk file to begin.');
      return;
    }

    setLoading(true);
    setError(null);
    setReport(null);
    setActiveStepMessage('Uploading APK & queuing Dalvik Bytecode CFG worker...');

    try {
      const formData = new FormData();
      formData.append('apk', selectedFile);

      const enqueueRes = await fetch('/api/jobs/scan-apk', {
        method: 'POST',
        body: formData
      });

      if (!enqueueRes.ok) {
        const errJson = await enqueueRes.json().catch(() => ({}));
        throw new Error(errJson.error || `Server error queuing APK audit (${enqueueRes.status})`);
      }

      const { jobId, streamUrl } = await enqueueRes.json();
      const deadline = Date.now() + 180000;

      const finishWithJob = (job: any) => {
        const data = job.result;
        setReport(data);
        updateScanHistory(`apk:${data.apkMeta?.packageName || selectedFile.name}`, data.score, data.findings);
        const hasVulns = data.findings?.some((f: any) => f.severity !== 'PASS');
        setFilter(hasVulns ? 'vulns' : 'all');
        setLoading(false);
      };

      // Prefer real-time Server-Sent Events (zero redundant polling), with 1000ms poll fallback
      const sseCompleted = await new Promise<boolean>((resolve, reject) => {
        if (typeof EventSource === 'undefined') {
          resolve(false);
          return;
        }
        let settled = false;
        const es = new EventSource(streamUrl || `/api/jobs/${jobId}/stream`);
        es.onmessage = (evt) => {
          try {
            const job = JSON.parse(evt.data);
            if (job.currentStage) {
              setActiveStepMessage(`[${job.progress ?? 0}%] ${job.currentStage}`);
            }
            if (job.status === 'completed' && job.result) {
              settled = true;
              es.close();
              finishWithJob(job);
              resolve(true);
            } else if (job.status === 'failed') {
              settled = true;
              es.close();
              reject(new Error(job.error || 'APK audit job failed.'));
            }
          } catch {}
        };
        es.onerror = () => {
          es.close();
          if (!settled) resolve(false);
        };
      });

      if (sseCompleted) return;

      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 1000));
        const pollRes = await fetch(`/api/jobs/${jobId}`);
        if (!pollRes.ok) {
          throw new Error(`Lost connection to audit job ${jobId}`);
        }
        const job = await pollRes.json();
        if (job.currentStage) {
          setActiveStepMessage(`[${job.progress ?? 0}%] ${job.currentStage}`);
        }
        if (job.status === 'completed' && job.result) {
          finishWithJob(job);
          return;
        }
        if (job.status === 'failed') {
          throw new Error(job.error || 'APK audit job failed.');
        }
      }

      throw new Error('APK deep audit exceeded timeout window.');
    } catch (err: any) {
      setError(err.message || 'APK audit failed.');
      setLoading(false);
    }
  };

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith('.apk')) {
        setApkFile(file);
        setError(null);
      } else {
        setError('Please upload a valid Android package file (.apk).');
      }
    }
  };

  const filteredFindings =
    report?.findings.filter((f) => {
      if (filter === 'vulns') return f.severity !== 'PASS' && f.severity !== 'INFO';
      if (filter === 'pass') return f.severity === 'PASS' || f.severity === 'INFO';
      return true;
    }) || [];

  return (
    <div className="min-h-screen text-slate-100 flex flex-col font-sans relative overflow-x-hidden">
      {/* ── Interactive 3D Arrow-Key Cyber Matrix Canvas ── */}
      <CyberBackground accentMode={scanMode} />

      {/* ── Ultra-Sleek Glassmorphism Navbar ── */}
      <header className="px-4 sm:px-8 py-3.5 border-b border-white/[0.08] bg-[#04060c]/75 backdrop-blur-xl sticky top-0 z-50 flex items-center justify-between no-print">
        <div
          onClick={() => {
            setReport(null);
            setError(null);
          }}
          className="flex items-center gap-3 cursor-pointer group"
        >
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-400/30 flex items-center justify-center text-cyan-300 cyber-glow-cyan group-hover:scale-105 transition-transform">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-lg font-extrabold tracking-tight text-white">
                CheckMy<span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-emerald-400">APK</span>
              </span>
              <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-cyan-500/15 border border-cyan-400/30 text-cyan-300 tracking-wider">
                .COM
              </span>
            </div>
            <p className="text-[10px] font-semibold text-slate-400 tracking-wider uppercase leading-none mt-0.5 hidden sm:block">
              Enterprise APK & Web Security Suite
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/25 text-[11px] font-bold text-emerald-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Engine v4.5 Online</span>
          </div>

          <button
            onClick={() => setShowTrustModal('methodology')}
            className="hidden sm:flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold bg-white/[0.04] hover:bg-white/[0.1] text-slate-300 border border-white/10 transition-all cursor-pointer"
          >
            <Info className="w-3.5 h-3.5 text-cyan-400" />
            <span>How It Works</span>
          </button>

          {report && (
            <>
              <button
                onClick={handleExportJson}
                title="Download JSON Security Telemetry"
                className="px-3 py-2 rounded-xl text-xs font-bold bg-white/[0.06] hover:bg-white/[0.12] text-slate-200 border border-white/10 transition-all hidden sm:flex items-center gap-1.5 cursor-pointer"
              >
                <FileJson className="w-3.5 h-3.5 text-amber-400" />
                <span>JSON</span>
              </button>
              <button
                onClick={handleExportMarkdown}
                title="Download Markdown Issue Report"
                className="px-3 py-2 rounded-xl text-xs font-bold bg-white/[0.06] hover:bg-white/[0.12] text-slate-200 border border-white/10 transition-all hidden sm:flex items-center gap-1.5 cursor-pointer"
              >
                <FileText className="w-3.5 h-3.5 text-purple-400" />
                <span>MD</span>
              </button>
              <button
                onClick={handleCopyMarkdown}
                title="Copy Markdown Summary for GitHub PR / Slack"
                className="px-3 py-2 rounded-xl text-xs font-bold bg-white/[0.06] hover:bg-white/[0.12] text-slate-200 border border-white/10 transition-all hidden md:flex items-center gap-1.5 cursor-pointer"
              >
                {mdCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-300" />}
                <span>{mdCopied ? 'Copied!' : 'Copy PR'}</span>
              </button>
            </>
          )}

          <button
            onClick={() => window.print()}
            disabled={!report}
            className="px-4 py-2 rounded-xl text-xs font-bold bg-white/[0.06] hover:bg-white/[0.12] text-slate-100 border border-white/10 transition-all disabled:opacity-30 disabled:pointer-events-none flex items-center gap-2 cursor-pointer shadow-sm"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export PDF</span>
          </button>
        </div>
      </header>

      {/* ── Main Interactive Workspace ── */}
      <main className="flex-1 max-w-5xl mx-auto w-full p-4 sm:p-8 flex flex-col gap-10 relative z-10">
        {/* ── Hero & Command Center ── */}
        {!report && !loading && (
          <div className="flex flex-col items-center text-center pt-4 sm:pt-8 pb-6 space-y-8">
            {/* Top Status Badge */}
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full glass-card border border-cyan-400/25 text-cyan-300 text-xs font-bold shadow-lg">
              <Sparkles className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
              <span>AI-Powered OWASP MASVS & Web Penetration Tester</span>
            </div>

            {/* Headline */}
            <div className="max-w-3xl space-y-4">
              <h1 className="text-4xl sm:text-6xl font-black tracking-tight text-white leading-[1.1]">
                Audit Your APK & Web App Before{' '}
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-purple-400 to-emerald-400 animate-gradient-text">
                  Hackers Do.
                </span>
              </h1>
              <p className="text-sm sm:text-base text-slate-300/90 max-w-2xl mx-auto leading-relaxed font-medium">
                Drop any Android <code className="text-purple-300 bg-purple-500/10 px-1.5 py-0.5 rounded">.apk</code> or live website URL to detect leaked API keys, debug backdoors, cleartext MITM flaws, and Denial-of-Wallet gaps in seconds.
              </p>
            </div>

            {/* ── Glassmorphic Command Center Panel ── */}
            <div className="w-full max-w-2xl glass-panel rounded-3xl p-4 sm:p-6 shadow-2xl border border-white/10 relative overflow-hidden">
              {/* Mode Switcher Tabs */}
              <div className="flex items-center p-1.5 bg-[#050811]/90 border border-white/10 rounded-2xl mb-5 shadow-inner">
                <button
                  type="button"
                  onClick={() => {
                    setScanMode('apk');
                    setError(null);
                  }}
                  className={`flex-1 py-2.5 px-4 rounded-xl text-xs sm:text-sm font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer ${
                    scanMode === 'apk'
                      ? 'bg-gradient-to-r from-purple-600 to-indigo-600 text-white cyber-glow-purple'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Smartphone className="w-4 h-4" />
                  <span>Android APK Audit</span>
                  <span className="text-[9px] font-black uppercase px-1.5 py-0.5 rounded bg-white/15 hidden sm:inline">
                    .APK
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setScanMode('web');
                    setError(null);
                  }}
                  className={`flex-1 py-2.5 px-4 rounded-xl text-xs sm:text-sm font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer ${
                    scanMode === 'web'
                      ? 'bg-gradient-to-r from-cyan-500 to-emerald-500 text-slate-950 cyber-glow-cyan'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Globe className="w-4 h-4" />
                  <span>Website & API Audit</span>
                  <span className="text-[9px] font-black uppercase px-1.5 py-0.5 rounded bg-black/15 hidden sm:inline">
                    URL
                  </span>
                </button>
              </div>

              {/* APK MODE */}
              {scanMode === 'apk' && (
                <div className="space-y-4">
                  <input
                    type="file"
                    ref={fileInputRef}
                    accept=".apk"
                    className="hidden"
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        setApkFile(e.target.files[0]);
                        setError(null);
                      }
                    }}
                  />

                  <div
                    onDragOver={(e) => {
                      e.preventDefault();
                      setIsDragging(true);
                    }}
                    onDragLeave={() => setIsDragging(false)}
                    onDrop={handleFileDrop}
                    onClick={() => fileInputRef.current?.click()}
                    className={`relative p-8 sm:p-10 rounded-2xl border-2 border-dashed transition-all cursor-pointer flex flex-col items-center justify-center gap-3 text-center overflow-hidden group ${
                      isDragging
                        ? 'border-purple-400 bg-purple-950/30 scale-[1.01]'
                        : apkFile
                        ? 'border-emerald-400/50 bg-emerald-950/15'
                        : 'border-white/15 bg-[#060913]/80 hover:border-purple-400/50 hover:bg-purple-950/10'
                    }`}
                  >
                    {/* Animated holographic scanner beam */}
                    <div className="absolute inset-x-0 top-0 h-16 bg-gradient-to-b from-purple-500/0 via-purple-400/15 to-purple-500/0 pointer-events-none animate-scan-beam" />

                    <div
                      className={`w-16 h-16 rounded-2xl flex items-center justify-center transition-transform group-hover:scale-105 ${
                        apkFile
                          ? 'bg-emerald-500/15 border border-emerald-400/40 text-emerald-400'
                          : 'bg-purple-500/15 border border-purple-400/30 text-purple-400'
                      }`}
                    >
                      {apkFile ? <ShieldCheck className="w-8 h-8" /> : <UploadCloud className="w-8 h-8" />}
                    </div>

                    <div className="relative z-10">
                      <h3 className="text-base font-extrabold text-white mb-1">
                        {apkFile ? apkFile.name : 'Drop Your Android .APK File Here'}
                      </h3>
                      <p className="text-xs text-slate-400 font-medium">
                        {apkFile
                          ? `${(apkFile.size / 1024 / 1024).toFixed(2)} MB • Ready for Dalvik DEX & Manifest Decompilation`
                          : 'Click to browse or drag & drop • Supports up to 100MB • Zero server storage'}
                      </p>
                    </div>
                  </div>

                  <button
                    type="button"
                    disabled={!apkFile}
                    onClick={() => handleScanApk()}
                    className="w-full py-3.5 px-6 rounded-xl bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-600 hover:brightness-110 text-white font-black text-sm flex items-center justify-center gap-2.5 transition-all disabled:opacity-40 disabled:pointer-events-none cursor-pointer shadow-xl shadow-purple-600/25 active:scale-[0.99]"
                  >
                    <Binary className="w-4 h-4" />
                    <span>Launch Deep APK Reverse-Engineering Audit</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>

                  <div className="flex flex-wrap items-center justify-between gap-2 pt-1 text-[11px] text-slate-400">
                    <button
                      type="button"
                      onClick={handleOpenSampleDemo}
                      className="inline-flex items-center gap-1.5 text-cyan-300 hover:text-cyan-200 font-bold bg-cyan-500/10 hover:bg-cyan-500/20 px-3 py-1.5 rounded-xl border border-cyan-500/25 transition-all cursor-pointer"
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>Preview Sample APK Report</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowTrustModal('privacy')}
                      className="inline-flex items-center gap-1.5 text-emerald-300/90 hover:text-emerald-200 font-semibold cursor-pointer"
                    >
                      <Lock className="w-3.5 h-3.5" />
                      <span>RAM-Only • Zero Disk Storage Guarantee</span>
                    </button>
                  </div>
                </div>
              )}

              {/* WEB MODE */}
              {scanMode === 'web' && (
                <div className="space-y-4">
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      handleScanWeb();
                    }}
                    className="w-full flex flex-col sm:flex-row gap-2.5 bg-[#050811]/90 p-2 rounded-2xl border border-white/10 focus-within:border-cyan-400/60 transition-all shadow-inner"
                  >
                    <div className="flex items-center gap-2.5 px-3 flex-1">
                      <Search className="w-5 h-5 text-cyan-400 shrink-0" />
                      <input
                        type="text"
                        placeholder="https://your-website.com"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        className="w-full bg-transparent text-sm font-semibold text-white placeholder-slate-500 focus:outline-none py-1.5"
                      />
                    </div>
                    <button
                      type="submit"
                      className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-400 to-emerald-400 hover:brightness-110 text-slate-950 font-black text-sm flex items-center justify-center gap-2 transition-all active:scale-95 cyber-glow-cyan shrink-0 cursor-pointer"
                    >
                      <span>Audit Target</span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </form>

                  {/* Optional Authenticated API & JWT Audit */}
                  <div className="text-left">
                    <button
                      type="button"
                      onClick={() => setShowWebAuthOptions(!showWebAuthOptions)}
                      className="text-[11px] font-bold text-cyan-300 hover:text-cyan-200 inline-flex items-center gap-1.5 cursor-pointer"
                    >
                      <Lock className="w-3.5 h-3.5" />
                      <span>
                        {showWebAuthOptions
                          ? 'Hide Authenticated API & JWT Audit Inputs'
                          : '+ Optional: Audit With Bearer JWT or Session Cookie (Same-Origin Only)'}
                      </span>
                    </button>

                    {showWebAuthOptions && (
                      <div className="mt-2.5 p-3.5 rounded-2xl bg-[#050811]/90 border border-cyan-500/25 space-y-2.5">
                        <div className="text-[10px] text-slate-400">
                          Credentials are forwarded strictly to the target&apos;s own origin for safe read-only checks (JWT decode + auth control verification) and are never logged or stored.
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          <input
                            type="password"
                            autoComplete="off"
                            placeholder="Bearer <JWT_TOKEN> (optional)"
                            value={webAuthHeader}
                            onChange={(e) => setWebAuthHeader(e.target.value)}
                            className="w-full px-3 py-2 rounded-xl bg-black/50 border border-white/10 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400/50 font-mono"
                          />
                          <input
                            type="password"
                            autoComplete="off"
                            placeholder="Cookie: session=... (optional)"
                            value={webAuthCookie}
                            onChange={(e) => setWebAuthCookie(e.target.value)}
                            className="w-full px-3 py-2 rounded-xl bg-black/50 border border-white/10 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400/50 font-mono"
                          />
                        </div>
                      </div>
                    )}
                    <div className="mt-2 flex items-center justify-between flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={handleLoadDomainChallenge}
                        className="text-[11px] font-bold text-emerald-300 hover:text-emerald-200 inline-flex items-center gap-1.5 cursor-pointer"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Verify Domain Ownership (Unlock Full 15-Request Rate Burst)</span>
                      </button>
                      <span className="text-[10px] text-slate-500">
                        Unverified public targets use a safe 4-request gentle profile
                      </span>
                    </div>

                    {domainChallenge && (
                      <div className="mt-2 p-3 rounded-2xl bg-[#050811]/90 border border-emerald-500/25 text-[10px] font-mono space-y-1.5 text-slate-300">
                        <div className="text-emerald-300 font-bold">
                          Add either TXT record or HTML Meta Tag to verify &quot;{domainChallenge.host}&quot;:
                        </div>
                        <div className="p-1.5 rounded bg-black/60 break-all select-all text-cyan-300">
                          DNS TXT: {domainChallenge.txtRecord}
                        </div>
                        <div className="p-1.5 rounded bg-black/60 break-all select-all text-emerald-300">
                          HTML Meta: {domainChallenge.metaTag}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Quick Test Targets */}
                  <div className="flex items-center gap-2 text-xs text-slate-400 flex-wrap justify-center pt-1">
                    <span className="font-bold text-slate-500">Quick Targets:</span>
                    <button
                      type="button"
                      onClick={() => handleScanWeb('http://localhost:3000')}
                      className="px-3 py-1.5 rounded-xl bg-white/[0.04] hover:bg-cyan-500/15 border border-white/10 hover:border-cyan-400/40 text-cyan-300 font-bold transition-all text-xs cursor-pointer"
                    >
                      localhost:3000
                    </button>
                    <button
                      type="button"
                      onClick={() => handleScanWeb('https://salowtech.com')}
                      className="px-3 py-1.5 rounded-xl bg-white/[0.04] hover:bg-white/10 border border-white/10 text-slate-300 font-semibold transition-all text-xs cursor-pointer"
                    >
                      salowtech.com
                    </button>
                  </div>
                </div>
              )}

              {error && (
                <div className="mt-4 p-3.5 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-200 text-xs font-bold flex items-center gap-2.5 text-left">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                  <span>{error}</span>
                </div>
              )}
            </div>

            {/* Keyboard Arrow Interaction Pill */}
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/[0.03] border border-white/10 text-[11px] font-semibold text-slate-400">
              <span>⌨️ Pro Tip: Use keyboard</span>
              <span className="px-1.5 py-0.5 rounded bg-white/10 text-cyan-300 font-mono text-[10px] font-bold">
                ↑ ↓ ← →
              </span>
              <span>arrow keys to pilot the live 3D cyber background!</span>
            </div>

            {/* ── Enterprise Feature Bento Grid ── */}
            <div className="w-full pt-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-left">
                <div className="glass-card p-5 rounded-2xl border border-white/10 hover:border-purple-400/40 transition-all group">
                  <div className="w-10 h-10 rounded-xl bg-purple-500/15 border border-purple-400/30 flex items-center justify-center text-purple-400 mb-3 group-hover:scale-110 transition-transform">
                    <Binary className="w-5 h-5" />
                  </div>
                  <h3 className="text-sm font-extrabold text-white mb-1">Dalvik DEX Scanner</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Decompiles APK bytecode and AndroidBinaryXML to expose hardcoded keys, debug flags & insecure manifests.
                  </p>
                </div>

                <div className="glass-card p-5 rounded-2xl border border-white/10 hover:border-cyan-400/40 transition-all group">
                  <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-400/30 flex items-center justify-center text-cyan-400 mb-3 group-hover:scale-110 transition-transform">
                    <Zap className="w-5 h-5" />
                  </div>
                  <h3 className="text-sm font-extrabold text-white mb-1">Denial-of-Wallet Probe</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Fires rapid burst payloads at live API endpoints to verify rate limiting before bots drain your AI credits.
                  </p>
                </div>

                <div className="glass-card p-5 rounded-2xl border border-white/10 hover:border-emerald-400/40 transition-all group">
                  <div className="w-10 h-10 rounded-xl bg-emerald-500/15 border border-emerald-400/30 flex items-center justify-center text-emerald-400 mb-3 group-hover:scale-110 transition-transform">
                    <Sparkles className="w-5 h-5" />
                  </div>
                  <h3 className="text-sm font-extrabold text-white mb-1">AI Code Fix Doctor</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Not just alerts — gives copy-paste patches for Gradle, AndroidManifest, Vercel, Next.js & Express in simple Hinglish/English.
                  </p>
                </div>

                <div className="glass-card p-5 rounded-2xl border border-white/10 hover:border-amber-400/40 transition-all group">
                  <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-400/30 flex items-center justify-center text-amber-400 mb-3 group-hover:scale-110 transition-transform">
                    <Lock className="w-5 h-5" />
                  </div>
                  <h3 className="text-sm font-extrabold text-white mb-1">Play Store Ready</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Aligns directly with MobSF & OWASP MASVS standards so your Android app passes Google Play reviews cleanly.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Live Scanning Theater ── */}
        {loading && (
          <div className="flex flex-col items-center justify-center max-w-2xl mx-auto my-auto w-full py-12 gap-6">
            <div className="relative">
              <div
                className={`w-20 h-20 rounded-3xl flex items-center justify-center border shadow-2xl ${
                  scanMode === 'apk'
                    ? 'bg-purple-500/15 border-purple-400/40 text-purple-300 cyber-glow-purple'
                    : 'bg-cyan-500/15 border-cyan-400/40 text-cyan-300 cyber-glow-cyan'
                }`}
              >
                <RefreshCw className="w-9 h-9 animate-spin" />
              </div>
            </div>

            <div className="flex flex-col items-center gap-2 text-center">
              <h2 className="text-2xl font-black text-white tracking-tight">
                {scanMode === 'apk' ? 'Decompiling & Auditing APK Binary...' : 'Running Live Penetration Probes...'}
              </h2>
              <p className="text-xs text-cyan-300 font-mono animate-pulse">
                ❯ {activeStepMessage}
              </p>
            </div>

            <LiveTerminalLogs
              targetUrl={scanMode === 'apk' ? apkFile?.name || 'Android Package' : url}
              isApkMode={scanMode === 'apk'}
            />
          </div>
        )}

        {/* ── Executive Report Dashboard ── */}
        {report && (
          <div className="flex flex-col gap-6 pb-10">
            {report.isDemoPreview && (
              <div className="p-3.5 rounded-2xl bg-amber-500/15 border border-amber-400/35 text-amber-200 text-xs font-bold flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-amber-300 shrink-0" />
                  <span>
                    SAMPLE DEMO PREVIEW — Interactive showcase showing how CheckMyAPK reports vulnerable test APKs. Upload your own `.apk` for a real audit.
                  </span>
                </div>
                <button
                  onClick={() => setReport(null)}
                  className="px-3 py-1 rounded-lg bg-amber-400 text-slate-950 font-black text-[11px] hover:brightness-110 cursor-pointer shrink-0"
                >
                  Scan Real APK
                </button>
              </div>
            )}

            {/* Target Header Bar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 glass-panel p-5 rounded-3xl">
              <div className="flex items-center gap-3.5">
                <div
                  className={`w-12 h-12 rounded-2xl flex items-center justify-center shrink-0 ${
                    report.isApkAudit
                      ? 'bg-purple-500/15 border border-purple-400/40 text-purple-300 cyber-glow-purple'
                      : 'bg-cyan-500/15 border border-cyan-400/40 text-cyan-300 cyber-glow-cyan'
                  }`}
                >
                  {report.isApkAudit ? <Smartphone className="w-6 h-6" /> : <Shield className="w-6 h-6" />}
                </div>
                <div>
                  <span className="text-[10px] font-black uppercase tracking-widest text-slate-400 block">
                    {report.isApkAudit ? 'Android APK Audit Target' : 'Web Security Audit Target'}
                  </span>
                  <div className="text-base font-black text-white flex items-center gap-2 flex-wrap">
                    <span>{report.isApkAudit ? report.apkMeta?.packageName || report.targetUrl : report.targetUrl}</span>
                    {report.isApkAudit && report.apkMeta && (
                      <span className="text-[11px] font-bold text-purple-200 bg-purple-500/20 border border-purple-400/30 px-2.5 py-0.5 rounded-full">
                        {report.apkMeta.fileName} • {report.apkMeta.sizeMb} MB
                        {report.apkMeta.versionName ? ` • v${report.apkMeta.versionName}` : ''}
                      </span>
                    )}
                    {scoreDelta && (
                      <span
                        className={`text-[10px] font-black px-2 py-0.5 rounded-full border inline-flex items-center gap-1 ${
                          scoreDelta.delta >= 0
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                            : 'bg-rose-500/15 text-rose-300 border-rose-400/30'
                        }`}
                      >
                        <TrendingUp className="w-3 h-3" />
                        {scoreDelta.delta > 0
                          ? `+${scoreDelta.delta} pts vs prev (${scoreDelta.previousScore}→${report.score})`
                          : scoreDelta.delta < 0
                          ? `${scoreDelta.delta} pts vs prev (${scoreDelta.previousScore}→${report.score})`
                          : `Consistent (${report.score}/100)`}
                        {(scoreDelta.fixedIssues.length > 0 || scoreDelta.newIssues.length > 0) &&
                          ` • ${scoreDelta.fixedIssues.length} Fixed • ${scoreDelta.newIssues.length} New`}
                      </span>
                    )}
                    {!report.isApkAudit && report.domainVerification && (
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                          report.domainVerification.verified
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                            : 'bg-white/[0.05] text-slate-300 border-white/10'
                        }`}
                      >
                        {report.domainVerification.verified
                          ? `Verified Owner (${report.domainVerification.method})`
                          : `Safe Mode (${report.domainVerification.burstProfile})`}
                      </span>
                    )}
                  </div>
                  {scoreDelta && scoreDelta.fixedIssues.length > 0 && (
                    <div className="mt-1 text-[10px] text-emerald-300 font-semibold">
                      Resolved since last scan: {scoreDelta.fixedIssues.slice(0, 3).join(' • ')}
                      {scoreDelta.fixedIssues.length > 3 ? ` (+${scoreDelta.fixedIssues.length - 3} more)` : ''}
                    </div>
                  )}
                  {report.isApkAudit && report.apkMeta?.sha256 && (
                    <div className="flex items-center gap-2 flex-wrap mt-1.5 text-[10px] font-mono text-slate-400">
                      <button
                        type="button"
                        onClick={() => {
                          navigator.clipboard.writeText(report.apkMeta!.sha256!);
                          setHashCopied(true);
                          setTimeout(() => setHashCopied(false), 1800);
                        }}
                        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-cyan-300 cursor-pointer"
                        title="Click to copy full SHA-256 fingerprint"
                      >
                        <span>SHA-256: {report.apkMeta.sha256.slice(0, 16)}...</span>
                        {hashCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                      {report.apkMeta.obfuscationStatus && (
                        <span className="px-2 py-0.5 rounded-md bg-white/[0.04] border border-white/10 text-slate-300">
                          Code: {report.apkMeta.obfuscationStatus}
                        </span>
                      )}
                      {report.telemetry?.durationSeconds && (
                        <span className="px-2 py-0.5 rounded-md bg-emerald-500/10 border border-emerald-500/20 text-emerald-300">
                          {report.telemetry.durationSeconds}s
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-2.5 no-print">
                {report.telemetry?.realTimeLogs && (
                  <button
                    onClick={() => setShowLogsModal(true)}
                    className="px-4 py-2 rounded-xl text-xs font-bold bg-white/[0.06] hover:bg-white/[0.12] text-cyan-300 border border-white/10 transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                    Logs ({report.telemetry.realTimeLogs.length})
                  </button>
                )}
                <button
                  onClick={() => {
                    setReport(null);
                    setApkFile(null);
                  }}
                  className="px-4 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-cyan-500/20 to-purple-500/20 hover:from-cyan-500/30 hover:to-purple-500/30 text-white border border-white/15 transition-all flex items-center justify-center gap-1.5 cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  New Audit
                </button>
              </div>
            </div>

            {/* Technical Telemetry Row */}
            {report.telemetry && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {report.isApkAudit && report.apkMeta ? (
                    <>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <Cpu className="w-5 h-5 text-purple-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">Framework</span>
                          <span className="text-xs font-extrabold text-white">{report.apkMeta.frameworkDetected}</span>
                        </div>
                      </div>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <Smartphone className="w-5 h-5 text-cyan-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">SDK Level</span>
                          <span className="text-xs font-extrabold text-white">
                            Target {report.apkMeta.targetSdkVersion} (Min {report.apkMeta.minSdkVersion})
                          </span>
                        </div>
                      </div>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <Layers className="w-5 h-5 text-amber-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">Bytecode</span>
                          <span className="text-xs font-extrabold text-white">{report.apkMeta.dexCount} DEX Archives</span>
                        </div>
                      </div>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <FileCode2 className="w-5 h-5 text-emerald-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">Permissions</span>
                          <span className="text-xs font-extrabold text-white">{report.apkMeta.permissions.length} Declared</span>
                        </div>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <Activity className="w-5 h-5 text-cyan-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">Latency</span>
                          <span className="text-xs font-extrabold text-white">{report.telemetry.latencyMs || 0} ms</span>
                        </div>
                      </div>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <FileCode2 className="w-5 h-5 text-emerald-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">Inspected</span>
                          <span className="text-xs font-extrabold text-white">
                            {report.telemetry.totalLinesInspected.toLocaleString()} lines ({(report.telemetry.totalBytesScanned / 1024).toFixed(0)} KB)
                          </span>
                        </div>
                      </div>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <Layers className="w-5 h-5 text-amber-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">JS Bundles</span>
                          <span className="text-xs font-extrabold text-white">{report.telemetry.scriptsCount} Chunks</span>
                        </div>
                      </div>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <Cpu className="w-5 h-5 text-purple-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">Stack</span>
                          <div className="flex gap-1 flex-wrap mt-0.5">
                            {report.telemetry.detectedTech.map((t, idx) => (
                              <span key={idx} className="text-[10px] font-bold bg-cyan-500/15 text-cyan-300 px-1.5 py-0.5 rounded">
                                {t}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </>
                  )}
                </div>

                {/* Web Deep Surface: Multi-Route, OpenAPI, GraphQL, DOM XSS Sinks & JWT */}
                {!report.isApkAudit && report.webDeepSurface && (
                  <div className="glass-card p-5 rounded-2xl border border-cyan-500/25 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Globe className="w-4 h-4 text-cyan-400" />
                        <h3 className="text-xs font-black uppercase tracking-wider text-white">
                          Stage 2.5: Web Attack Surface, DOM XSS Sinks &amp; API/JWT Audit
                        </h3>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
                        <span className="px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 font-bold">
                          {report.webDeepSurface.discoveredRoutes.length} Routes • {report.webDeepSurface.apiEndpoints.length} APIs
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded-full font-black border ${
                            report.webDeepSurface.domSinks.length > 0
                              ? 'bg-rose-500/15 text-rose-300 border-rose-400/30'
                              : 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                          }`}
                        >
                          {report.webDeepSurface.domSinks.length} DOM Sink(s)
                        </span>
                        {report.webDeepSurface.graphqlEndpoints.length > 0 && (
                          <span
                            className={`px-2 py-0.5 rounded-full font-bold border ${
                              report.webDeepSurface.graphqlEndpoints.some((g) => g.introspectionEnabled)
                                ? 'bg-amber-500/15 text-amber-300 border-amber-400/30'
                                : 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                            }`}
                          >
                            GraphQL:{' '}
                            {report.webDeepSurface.graphqlEndpoints.some((g) => g.introspectionEnabled)
                              ? 'Introspection Open'
                              : 'Protected'}
                          </span>
                        )}
                        {report.webDeepSurface.jwtAudits.length > 0 && (
                          <span className="px-2 py-0.5 rounded-full bg-purple-500/15 text-purple-300 border border-purple-400/30 font-bold">
                            JWT Audited: {report.webDeepSurface.jwtAudits.length}
                          </span>
                        )}
                        {report.webDeepSurface.authAudit?.enabled && (
                          <span className="px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-400/30 font-bold">
                            Auth: {report.webDeepSurface.authAudit.authKind} (HTTP {report.webDeepSurface.authAudit.targetStatus})
                          </span>
                        )}
                        {report.networkPosture && (
                          <>
                            <span
                              className={`px-2 py-0.5 rounded-full font-bold border ${
                                report.networkPosture.corsReflection === 'Strict'
                                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                                  : 'bg-rose-500/15 text-rose-300 border-rose-400/30'
                              }`}
                            >
                              CORS Probe: {report.networkPosture.corsReflection}
                            </span>
                            {report.networkPosture.tlsProtocol && (
                              <span className="px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 font-bold">
                                {report.networkPosture.tlsProtocol}
                                {report.networkPosture.certDaysRemaining !== null
                                  ? ` (${report.networkPosture.certDaysRemaining}d cert)`
                                  : ''}
                              </span>
                            )}
                            {report.networkPosture.spfPresent !== null && (
                              <span
                                className={`px-2 py-0.5 rounded-full font-bold border ${
                                  report.networkPosture.spfPresent &&
                                  (report.networkPosture.dmarcPolicy === 'reject' ||
                                    report.networkPosture.dmarcPolicy === 'quarantine')
                                    ? 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                                    : 'bg-amber-500/15 text-amber-300 border-amber-400/30'
                                }`}
                              >
                                SPF:{report.networkPosture.spfPresent ? 'Yes' : 'No'} • DMARC:{report.networkPosture.dmarcPolicy || 'none'}
                              </span>
                            )}
                          </>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 text-[11px] font-mono">
                      {/* Routes & OpenAPI */}
                      <div className="p-3 rounded-xl bg-[#050811]/80 border border-white/5 space-y-1.5">
                        <div className="text-[10px] font-black uppercase text-cyan-300">
                          Routes, Sitemap &amp; OpenAPI ({report.webDeepSurface.openApiSpecs.length} Spec)
                        </div>
                        <div className="max-h-28 overflow-y-auto space-y-1 pr-1 text-slate-300">
                          {report.webDeepSurface.openApiSpecs.map((sp, i) => (
                            <div key={i} className="text-amber-300 truncate" title={sp.url}>
                              OpenAPI: {sp.url.replace(/^https?:\/\/[^/]+/, '')} ({sp.pathsCount} paths)
                            </div>
                          ))}
                          {report.webDeepSurface.apiEndpoints.slice(0, 6).map((ep, i) => (
                            <div key={`ep-${i}`} className="text-emerald-300 truncate" title={ep}>
                              API: {ep}
                            </div>
                          ))}
                          {report.webDeepSurface.discoveredRoutes.slice(0, 5).map((rt, i) => (
                            <div key={`rt-${i}`} className="text-slate-400 truncate" title={rt}>
                              Route: {rt}
                            </div>
                          ))}
                          {report.webDeepSurface.apiEndpoints.length === 0 &&
                            report.webDeepSurface.discoveredRoutes.length === 0 &&
                            report.webDeepSurface.openApiSpecs.length === 0 && (
                              <div className="text-slate-500">No extra routes or OpenAPI docs exposed.</div>
                            )}
                        </div>
                      </div>

                      {/* Static DOM XSS Sinks */}
                      <div className="p-3 rounded-xl bg-[#050811]/80 border border-white/5 space-y-1.5">
                        <div className="text-[10px] font-black uppercase text-rose-300">
                          Static DOM XSS Sinks ({report.webDeepSurface.domSinks.length})
                        </div>
                        <div className="max-h-28 overflow-y-auto space-y-1.5 pr-1">
                          {report.webDeepSurface.domSinks.length > 0 ? (
                            report.webDeepSurface.domSinks.slice(0, 6).map((sink, i) => (
                              <div key={i} className="p-1.5 rounded bg-rose-500/10 border border-rose-500/20">
                                <div className="flex items-center justify-between gap-1 text-[10px]">
                                  <span className="font-bold text-rose-300">{sink.type}</span>
                                  {sink.taintedByInput && (
                                    <span className="px-1 rounded bg-rose-500/30 text-white text-[9px]">INPUT TAINT</span>
                                  )}
                                </div>
                                <div className="text-slate-300 text-[10px] truncate" title={sink.snippet}>
                                  {sink.snippet}
                                </div>
                              </div>
                            ))
                          ) : (
                            <div className="text-emerald-300">0 unsafe eval / innerHTML / postMessage sinks matched.</div>
                          )}
                        </div>
                      </div>

                      {/* JWT & Auth Control Checks */}
                      <div className="p-3 rounded-xl bg-[#050811]/80 border border-white/5 space-y-1.5">
                        <div className="text-[10px] font-black uppercase text-purple-300">
                          JWT &amp; Auth Session Audit ({report.webDeepSurface.jwtAudits.length})
                        </div>
                        <div className="max-h-28 overflow-y-auto space-y-1.5 pr-1">
                          {report.webDeepSurface.jwtAudits.map((jt, i) => (
                            <div key={i} className="p-1.5 rounded bg-purple-500/10 border border-purple-500/20 space-y-0.5">
                              <div className="flex items-center justify-between text-[10px]">
                                <span className="text-purple-200 font-bold">alg: {jt.alg}</span>
                                <span className={jt.hasExp ? 'text-emerald-300' : 'text-amber-300'}>
                                  {jt.hasExp ? (jt.expired ? 'Expired exp' : 'Valid exp') : 'No exp'}
                                </span>
                              </div>
                              <div className="text-[10px] text-slate-400 truncate">
                                Claims: {jt.claims.join(', ')}
                              </div>
                              {jt.issues.length > 0 && (
                                <div className="text-[10px] text-rose-300 truncate">{jt.issues.join(' • ')}</div>
                              )}
                            </div>
                          ))}
                          {report.webDeepSurface.authAudit?.protectedApiChecks.slice(0, 4).map((chk, i) => (
                            <div key={`chk-${i}`} className="text-[10px] text-slate-300 flex justify-between gap-2">
                              <span className="truncate">{chk.url}</span>
                              <span className="shrink-0 text-cyan-300">
                                {chk.authStatus} vs {chk.unauthStatus}
                              </span>
                            </div>
                          ))}
                          {report.webDeepSurface.jwtAudits.length === 0 &&
                            (!report.webDeepSurface.authAudit ||
                              report.webDeepSurface.authAudit.protectedApiChecks.length === 0) && (
                              <div className="text-slate-500">
                                No client JWTs found. Attach an optional Bearer JWT above to audit session claims &amp; protected routes.
                              </div>
                            )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Ostorlab-Level APK Intelligence Bento Modules */}
                {report.isApkAudit && report.apkMeta && (
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    {/* 1. Exported Components Surface */}
                    {report.apkMeta.exportedComponents && (
                      <div className="glass-card p-5 rounded-2xl border border-white/10 space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Shield className="w-4 h-4 text-cyan-400" />
                            <h3 className="text-xs font-black uppercase tracking-wider text-white">
                              Exported IPC Surface
                            </h3>
                          </div>
                          <span
                            className={`text-[10px] font-black px-2 py-0.5 rounded-full border ${
                              report.apkMeta.exportedComponents.unprotectedCount > 0
                                ? 'bg-amber-500/15 text-amber-300 border-amber-400/30'
                                : 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                            }`}
                          >
                            {report.apkMeta.exportedComponents.unprotectedCount > 0
                              ? `${report.apkMeta.exportedComponents.unprotectedCount} Unprotected`
                              : `${report.apkMeta.exportedComponents.totalExported} Audited`}
                          </span>
                        </div>

                        <div className="grid grid-cols-4 gap-1.5 text-center">
                          {[
                            { label: 'Activities', count: report.apkMeta.exportedComponents.activities.length },
                            { label: 'Services', count: report.apkMeta.exportedComponents.services.length },
                            { label: 'Receivers', count: report.apkMeta.exportedComponents.receivers.length },
                            { label: 'Providers', count: report.apkMeta.exportedComponents.providers.length }
                          ].map((box, idx) => (
                            <div key={idx} className="p-2 rounded-xl bg-[#050811]/80 border border-white/5">
                              <span className="text-sm font-black text-white block">{box.count}</span>
                              <span className="text-[9px] font-bold uppercase text-slate-400">{box.label}</span>
                            </div>
                          ))}
                        </div>

                        <div className="space-y-1.5 max-h-28 overflow-y-auto pr-1 text-[11px] font-mono">
                          {[
                            ...report.apkMeta.exportedComponents.activities,
                            ...report.apkMeta.exportedComponents.services,
                            ...report.apkMeta.exportedComponents.receivers,
                            ...report.apkMeta.exportedComponents.providers
                          ].slice(0, 8).map((c, idx) => (
                            <div
                              key={idx}
                              className="flex items-center justify-between gap-2 px-2.5 py-1 rounded-lg bg-[#050811]/70 border border-white/5"
                            >
                              <span className="truncate text-slate-300" title={c.name}>
                                <span className="text-cyan-400">[{c.componentType[0].toUpperCase()}]</span>{' '}
                                {c.name.split('.').slice(-2).join('.')}
                              </span>
                              <span
                                className={`text-[9px] font-bold px-1.5 py-0.5 rounded shrink-0 ${
                                  c.risky
                                    ? 'bg-rose-500/20 text-rose-300'
                                    : c.isLauncher
                                    ? 'bg-cyan-500/20 text-cyan-300'
                                    : 'bg-emerald-500/15 text-emerald-300'
                                }`}
                              >
                                {c.risky ? 'UNPROTECTED' : c.isLauncher ? 'LAUNCHER' : 'GUARDED'}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* 2. Trackers & 3rd-Party SDKs */}
                    <div className="glass-card p-5 rounded-2xl border border-white/10 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Radio className="w-4 h-4 text-purple-400" />
                          <h3 className="text-xs font-black uppercase tracking-wider text-white">
                            Trackers & Embedded SDKs
                          </h3>
                        </div>
                        <span className="text-[10px] font-black px-2 py-0.5 rounded-full bg-purple-500/15 text-purple-300 border border-purple-400/30">
                          {(report.apkMeta.trackers?.length || 0) + (report.apkMeta.sdks?.length || 0)} Detected
                        </span>
                      </div>

                      <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                        <div>
                          <span className="text-[10px] font-bold uppercase text-amber-300 block mb-1">
                            Analytics & Ad Trackers ({report.apkMeta.trackers?.length || 0})
                          </span>
                          <div className="flex flex-wrap gap-1.5">
                            {report.apkMeta.trackers && report.apkMeta.trackers.length > 0 ? (
                              report.apkMeta.trackers.map((t, idx) => (
                                <span
                                  key={idx}
                                  className="text-[10px] font-bold px-2 py-0.5 rounded-lg bg-amber-500/15 text-amber-200 border border-amber-400/25"
                                >
                                  {t}
                                </span>
                              ))
                            ) : (
                              <span className="text-[11px] text-slate-500">No ad/analytics trackers detected</span>
                            )}
                          </div>
                        </div>

                        <div>
                          <span className="text-[10px] font-bold uppercase text-cyan-300 block mb-1">
                            Core & Payment SDKs ({report.apkMeta.sdks?.length || 0})
                          </span>
                          <div className="flex flex-wrap gap-1.5">
                            {report.apkMeta.sdks && report.apkMeta.sdks.length > 0 ? (
                              report.apkMeta.sdks.map((s, idx) => (
                                <span
                                  key={idx}
                                  className="text-[10px] font-bold px-2 py-0.5 rounded-lg bg-cyan-500/15 text-cyan-200 border border-cyan-400/25"
                                >
                                  {s}
                                </span>
                              ))
                            ) : (
                              <span className="text-[11px] text-slate-500">Zero external SDK footprints found</span>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* 3. Stage 3 Extracted Backend APIs */}
                    <div className="glass-card p-5 rounded-2xl border border-white/10 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Server className="w-4 h-4 text-emerald-400" />
                          <h3 className="text-xs font-black uppercase tracking-wider text-white">
                            Stage 3: Backend APIs
                          </h3>
                        </div>
                        <span className="text-[10px] font-black px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-400/30">
                          {report.apkMeta.probedApis?.length || 0} Live Probed
                        </span>
                      </div>

                      <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1 text-[11px] font-mono">
                        {report.apkMeta.probedApis && report.apkMeta.probedApis.length > 0 ? (
                          report.apkMeta.probedApis.map((api, idx) => (
                            <div
                              key={idx}
                              className="p-2 rounded-xl bg-[#050811]/80 border border-white/5 space-y-1"
                            >
                              <div className="flex items-center justify-between gap-2">
                                <span className="truncate text-cyan-300 font-semibold" title={api.url}>
                                  {api.url.replace(/^https?:\/\//, '')}
                                </span>
                                <span
                                  className={`text-[9px] font-black px-1.5 py-0.5 rounded shrink-0 ${
                                    api.reachable
                                      ? 'bg-emerald-500/20 text-emerald-300'
                                      : 'bg-slate-500/20 text-slate-300'
                                  }`}
                                >
                                  {api.reachable ? `HTTP ${api.status} • ${api.latencyMs}ms` : String(api.status)}
                                </span>
                              </div>
                              <div className="flex items-center gap-2 text-[9px] text-slate-400">
                                <span>HSTS: {api.hsts ? 'Yes' : 'No'}</span>
                                <span>•</span>
                                <span className="truncate">CORS: {api.cors}</span>
                              </div>
                            </div>
                          ))
                        ) : (
                          <div className="p-3 rounded-xl bg-[#050811]/60 border border-white/5 text-slate-400 text-[11px]">
                            No custom external API origins were hardcoded in DEX/JS bundles.
                          </div>
                        )}
                        {report.apkMeta.baasUrls && report.apkMeta.baasUrls.length > 0 && (
                          <div className="pt-1 flex flex-wrap gap-1">
                            {report.apkMeta.baasUrls.map((b, idx) => (
                              <span key={idx} className="text-[9px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 truncate max-w-full">
                                BaaS: {b.replace('https://', '')}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* 4. Stage 2.5: Dalvik Bytecode Control-Flow, Cross-Method Taint & Native ELF Inspection */}
                {report.isApkAudit && report.apkMeta?.dexBytecodeGraph && (
                  <div className="glass-card p-5 rounded-2xl border border-purple-500/25 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Binary className="w-4 h-4 text-purple-400" />
                        <h3 className="text-xs font-black uppercase tracking-wider text-white">
                          Stage 2.5: Dalvik Bytecode CFG &amp; Cross-Method Taint Graph
                        </h3>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
                        <span className="px-2 py-0.5 rounded-full bg-purple-500/15 text-purple-300 border border-purple-400/30 font-bold">
                          {report.apkMeta.dexBytecodeGraph.methodsAnalyzed.toLocaleString()} Methods • {report.apkMeta.dexBytecodeGraph.instructionsScanned.toLocaleString()} Opcodes ({report.apkMeta.dexBytecodeGraph.durationMs}ms)
                        </span>
                        {report.apkMeta.pinningStatus && (
                          <span
                            className={`px-2 py-0.5 rounded-full font-bold border ${
                              report.apkMeta.pinningStatus.active
                                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                                : 'bg-amber-500/15 text-amber-300 border-amber-400/30'
                            }`}
                          >
                            {report.apkMeta.pinningStatus.active ? 'SSL Pinning: Active' : 'SSL Pinning: Not Detected'}
                          </span>
                        )}
                        <span
                          className={`px-2 py-0.5 rounded-full font-black border ${
                            report.apkMeta.dexBytecodeGraph.taintPaths.length > 0
                              ? 'bg-rose-500/15 text-rose-300 border-rose-400/30'
                              : 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                          }`}
                        >
                          {report.apkMeta.dexBytecodeGraph.taintPaths.length > 0
                            ? `${report.apkMeta.dexBytecodeGraph.taintPaths.length} Taint Flow(s)${
                                (report.apkMeta.dexBytecodeGraph.interproceduralPathsCount || 0) > 0
                                  ? ` (${report.apkMeta.dexBytecodeGraph.interproceduralPathsCount} Multi-Hop)`
                                  : ''
                              }`
                            : '0 Taint Leaks'}
                        </span>
                      </div>
                    </div>

                    {report.apkMeta.dexBytecodeGraph.taintPaths.length > 0 && (
                      <div className="space-y-1.5">
                        {report.apkMeta.dexBytecodeGraph.taintPaths.slice(0, 6).map((tp, idx) => (
                          <div key={idx} className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/25 text-[11px] font-mono">
                            <div className="flex items-center justify-between gap-2 text-rose-300 font-bold">
                              <span>
                                {tp.source} ➔ {tp.sink}
                                {tp.hopCount && tp.hopCount >= 2 ? ` (${tp.hopCount}-Hop Chain)` : ''}
                              </span>
                              <span className="text-[9px] px-1.5 py-0.5 rounded bg-rose-500/20">{tp.owaspRef}</span>
                            </div>
                            <div className="text-slate-300 mt-1 break-all">
                              {tp.callChain && tp.callChain.length >= 2 ? tp.callChain.join(' ➔ ') : tp.methodSignature}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {report.apkMeta.dexBytecodeGraph.callGraphHotspots.length > 0 && (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 pt-1 max-h-36 overflow-y-auto pr-1">
                        {report.apkMeta.dexBytecodeGraph.callGraphHotspots.slice(0, 9).map((edge, idx) => (
                          <div key={idx} className="p-2 rounded-xl bg-[#050811]/80 border border-white/5 text-[10px] font-mono space-y-0.5">
                            <span className="text-[9px] font-black uppercase text-cyan-300">{edge.category}</span>
                            <div className="text-slate-300 truncate" title={edge.callerMethod}>{edge.callerMethod}</div>
                            <div className="text-purple-300 truncate" title={edge.calleeSignature}>↳ {edge.calleeSignature}</div>
                          </div>
                        ))}
                      </div>
                    )}

                    {report.apkMeta.nativeElfSummary && report.apkMeta.nativeElfSummary.uniqueLibrariesCount > 0 && (
                      <div className="pt-2 border-t border-white/10 space-y-2">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="text-[11px] font-black uppercase tracking-wider text-cyan-300">
                            Native ELF (.so) Binary Matrix ({report.apkMeta.nativeElfSummary.uniqueLibrariesCount} Unique • {report.apkMeta.nativeElfSummary.appLibrariesCount} App Libs • {report.apkMeta.nativeElfSummary.nativeStringsScannedKb} KB Strings)
                          </span>
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                              report.apkMeta.nativeElfSummary.hardeningWeakCount > 0
                                ? 'bg-amber-500/15 text-amber-300 border-amber-400/30'
                                : 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                            }`}
                          >
                            {report.apkMeta.nativeElfSummary.hardeningWeakCount > 0
                              ? `${report.apkMeta.nativeElfSummary.hardeningWeakCount} Weak Binary Flag(s)`
                              : 'PIE / NX / RELRO Hardened'}
                          </span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-32 overflow-y-auto pr-1 text-[10px] font-mono">
                          {report.apkMeta.nativeElfSummary.libraries.slice(0, 9).map((lib, idx) => (
                            <div key={idx} className="p-2 rounded-xl bg-[#050811]/80 border border-white/5 flex flex-col gap-1">
                              <div className="flex items-center justify-between gap-2">
                                <span className="truncate font-bold text-slate-200" title={lib.fileName}>{lib.baseName}</span>
                                <span className="text-[9px] text-slate-400 shrink-0">{lib.archBits}b {lib.abi}</span>
                              </div>
                              <div className="flex flex-wrap gap-1 text-[9px]">
                                <span className={`px-1.5 rounded ${lib.pie ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/20 text-rose-300'}`}>PIE</span>
                                <span className={`px-1.5 rounded ${lib.nx ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/20 text-rose-300'}`}>NX</span>
                                <span className={`px-1.5 rounded ${lib.stackCanary ? 'bg-emerald-500/15 text-emerald-300' : 'bg-amber-500/15 text-amber-300'}`}>Canary</span>
                                <span className={`px-1.5 rounded ${lib.relro !== 'NONE' ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/20 text-rose-300'}`}>RELRO:{lib.relro}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="mt-2 flex items-center justify-between flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={handleLoadDomainChallenge}
                        className="text-[11px] font-bold text-emerald-300 hover:text-emerald-200 inline-flex items-center gap-1.5 cursor-pointer"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Verify Domain Ownership (Unlock Full 15-Request Rate Burst)</span>
                      </button>
                      <span className="text-[10px] text-slate-500">
                        Unverified public targets use a safe 4-request gentle profile
                      </span>
                    </div>

                    {domainChallenge && (
                      <div className="mt-2 p-3 rounded-2xl bg-[#050811]/90 border border-emerald-500/25 text-[10px] font-mono space-y-1.5 text-slate-300">
                        <div className="text-emerald-300 font-bold">
                          Add either TXT record or HTML Meta Tag to verify &quot;{domainChallenge.host}&quot;:
                        </div>
                        <div className="p-1.5 rounded bg-black/60 break-all select-all text-cyan-300">
                          DNS TXT: {domainChallenge.txtRecord}
                        </div>
                        <div className="p-1.5 rounded bg-black/60 break-all select-all text-emerald-300">
                          HTML Meta: {domainChallenge.metaTag}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Scorecard Overview Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <ScoreGauge score={report.score} grade={report.grade} riskLevel={report.riskLevel} />

              <div className="md:col-span-2 grid grid-cols-2 sm:grid-cols-5 gap-3 glass-panel p-5 rounded-3xl">
                <div className="p-3 rounded-2xl bg-rose-500/10 border border-rose-500/25 text-center flex flex-col items-center justify-center">
                  <span className="text-3xl font-black text-rose-400">{report.summaryCounts.critical}</span>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-rose-300 mt-1">Critical</span>
                </div>
                <div className="p-3 rounded-2xl bg-orange-500/10 border border-orange-500/25 text-center flex flex-col items-center justify-center">
                  <span className="text-3xl font-black text-orange-400">{report.summaryCounts.high}</span>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-orange-300 mt-1">High Risk</span>
                </div>
                <div className="p-3 rounded-2xl bg-amber-500/10 border border-amber-500/25 text-center flex flex-col items-center justify-center">
                  <span className="text-3xl font-black text-amber-400">{report.summaryCounts.medium}</span>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-amber-300 mt-1">Medium</span>
                </div>
                <div className="p-3 rounded-2xl bg-blue-500/10 border border-blue-500/25 text-center flex flex-col items-center justify-center">
                  <span className="text-3xl font-black text-blue-400">{report.summaryCounts.low}</span>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-blue-300 mt-1">Low Risk</span>
                </div>
                <div className="p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/25 text-center flex flex-col items-center justify-center">
                  <span className="text-3xl font-black text-emerald-400">{report.summaryCounts.pass}</span>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-300 mt-1">Passed</span>
                </div>

                {report.aiExecutiveSummary && (
                  <div className="col-span-2 sm:col-span-5 mt-2 p-4 rounded-2xl bg-[#050811]/90 border border-cyan-500/25 text-xs shadow-inner">
                    <div className="flex items-center gap-1.5 text-cyan-400 font-black mb-2">
                      <Sparkles className="w-4 h-4" />
                      <span>
                        {report.isApkAudit
                          ? 'CheckMyAPK Neural Mobile Penetration Brief:'
                          : 'CheckMyAPK Neural Web Security Synthesis:'}
                      </span>
                    </div>
                    <div className="text-slate-300 whitespace-pre-line leading-relaxed text-[12px] font-medium">
                      {report.aiExecutiveSummary}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* 🛠️ Master Remediation Playbook (Web Only) */}
            {!report.isApkAudit && report.findings.filter((f) => f.severity !== 'PASS' && f.severity !== 'INFO').length > 0 && (
              <div className="glass-panel border-emerald-500/30 rounded-3xl p-5 space-y-4 shadow-xl">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
                      <Wrench className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-sm font-black text-white flex items-center gap-2 flex-wrap">
                        <span>60-Second Master Fix: Resolve All Headers in 1 File</span>
                        <span className="text-[10px] font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/25 px-2 py-0.5 rounded-full">
                          Recommended
                        </span>
                      </h3>
                      <p className="text-xs text-slate-400">
                        Paste this single configuration snippet into your repository to harden all web headers instantly:
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-1 bg-[#050811] p-1 rounded-xl border border-white/10 text-xs shrink-0">
                    {(['vercel', 'nextjs', 'express'] as const).map((tab) => (
                      <button
                        key={tab}
                        onClick={() => setMasterTab(tab)}
                        className={`px-3 py-1.5 rounded-lg font-bold transition-all cursor-pointer ${
                          masterTab === tab ? 'bg-emerald-500 text-slate-950' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        {tab === 'vercel' ? 'Vercel' : tab === 'nextjs' ? 'Next.js' : 'Node/Express'}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="rounded-2xl border border-white/10 bg-[#050811] overflow-hidden text-xs">
                  <div className="flex items-center justify-between px-4 py-2.5 bg-white/[0.04] border-b border-white/10">
                    <div className="flex items-center gap-2 text-slate-300 font-mono text-[11px]">
                      <Code2 className="w-4 h-4 text-emerald-400" />
                      <span>{masterCodes[masterTab].filename}</span>
                    </div>
                    <button
                      onClick={() => handleCopyMaster(masterCodes[masterTab].code)}
                      className="flex items-center gap-1.5 text-xs font-bold text-emerald-300 hover:text-emerald-200 transition-colors bg-emerald-500/15 px-3 py-1 rounded-lg border border-emerald-500/30 cursor-pointer"
                    >
                      {masterCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      {masterCopied ? 'Copied!' : 'Copy Config'}
                    </button>
                  </div>
                  <pre className="p-4 text-[11px] font-mono text-emerald-300 overflow-x-auto leading-relaxed select-all max-h-48">
                    {masterCodes[masterTab].code}
                  </pre>
                </div>
              </div>
            )}

            {/* Findings Filter Bar */}
            <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-3">
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={() => setFilter('vulns')}
                  className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    filter === 'vulns'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                      : 'text-slate-400 hover:text-slate-200 bg-white/[0.03] border border-white/5'
                  }`}
                >
                  Vulnerabilities ({report.findings.filter((f) => f.severity !== 'PASS' && f.severity !== 'INFO').length})
                </button>
                <button
                  onClick={() => setFilter('pass')}
                  className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    filter === 'pass'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'text-slate-400 hover:text-slate-200 bg-white/[0.03] border border-white/5'
                  }`}
                >
                  Passed Checks ({report.summaryCounts.pass})
                </button>
                <button
                  onClick={() => setFilter('all')}
                  className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    filter === 'all'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-slate-200 bg-white/[0.03] border border-white/5'
                  }`}
                >
                  All Items ({report.findings.length})
                </button>
              </div>
            </div>

            {/* Findings List */}
            <div className="flex flex-col gap-3">
              {filteredFindings.length === 0 ? (
                <div className="p-10 text-center glass-card rounded-2xl text-slate-400 text-xs font-medium">
                  No security findings match this filter. Switch to "All Items" or "Passed Checks" to view full audit telemetry!
                </div>
              ) : (
                filteredFindings.map((finding, idx) => (
                  <FindingCard
                    key={idx}
                    finding={finding}
                    detectedTech={report.telemetry?.detectedTech}
                    targetUrl={report.targetUrl}
                    defaultExpanded={idx < 2}
                  />
                ))
              )}
            </div>
          </div>
        )}
      </main>

      {/* ── Inspection Logs Modal ── */}
      {showLogsModal && report?.telemetry?.realTimeLogs && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 no-print">
          <div className="glass-panel rounded-3xl max-w-2xl w-full max-h-[80vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-4 border-b border-white/10 flex items-center justify-between bg-[#080c17]">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-extrabold text-white">Full Engine Telemetry Log</h3>
              </div>
              <button
                onClick={() => setShowLogsModal(false)}
                className="text-xs px-3 py-1 bg-white/10 hover:bg-white/20 text-white font-bold rounded-lg cursor-pointer transition-colors"
              >
                Close
              </button>
            </div>
            <div className="p-5 font-mono text-xs text-slate-300 space-y-2.5 overflow-y-auto max-h-[60vh] bg-[#04060c]">
              {report.telemetry.realTimeLogs.map((item, idx) => (
                <div key={idx} className="flex gap-2.5 leading-relaxed">
                  <span className="text-cyan-400 shrink-0 font-bold">{item.time}</span>
                  <span>{item.msg}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Privacy / Methodology Trust Modal ── */}
      {showTrustModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 no-print">
          <div className="glass-panel rounded-3xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden border border-white/15">
            <div className="p-4 border-b border-white/10 flex items-center justify-between bg-[#080c17]">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-black text-white">
                  {showTrustModal === 'privacy'
                    ? 'Zero-Retention Privacy & Authorized Security Policy'
                    : '4-Stage CheckMyAPK Audit Methodology'}
                </h3>
              </div>
              <button
                onClick={() => setShowTrustModal(null)}
                className="p-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-6 space-y-4 text-xs text-slate-300 overflow-y-auto leading-relaxed">
              {showTrustModal === 'privacy' ? (
                <>
                  <div className="p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/25 space-y-1.5">
                    <h4 className="font-black text-emerald-300 flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4" />
                      100% RAM-Only Sandbox (Zero Disk Retention)
                    </h4>
                    <p>
                      Uploaded <code className="text-white">.apk</code> files are processed strictly in volatile server memory using Multer memory buffers. CheckMyAPK never writes your APK binary to permanent disk storage, never shares source builds, and immediately discards memory buffers once your report returns.
                    </p>
                  </div>
                  <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 space-y-1.5">
                    <h4 className="font-black text-white">Cryptographic Integrity (SHA-256)</h4>
                    <p>
                      Every APK audit generates the binary&apos;s SHA-256 fingerprint so you can prove which exact release build passed verification.
                    </p>
                  </div>
                  <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 space-y-1.5">
                    <h4 className="font-black text-amber-300">Authorized Use Only</h4>
                    <p>
                      Only audit mobile apps and web endpoints that you own or have explicit permission to evaluate. Automated SSRF guards block private network probes in production environments.
                    </p>
                  </div>
                </>
              ) : (
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="p-3.5 rounded-2xl bg-[#050811]/80 border border-white/10">
                      <strong className="text-cyan-300 block mb-1">Stage 1: Binary Manifest & IPC</strong>
                      Parses AndroidBinaryXML (<code className="text-white">AndroidManifest.xml</code> + <code className="text-white">network_security_config</code>) to check debuggable flags, backup rules, SDK targets, and exported Activities/Services/Receivers/Providers.
                    </div>
                    <div className="p-3.5 rounded-2xl bg-[#050811]/80 border border-white/10">
                      <strong className="text-purple-300 block mb-1">Stage 2: DEX, Resources & Secrets</strong>
                      Scans <code className="text-white">classes*.dex</code>, <code className="text-white">resources.arsc</code> &amp; JS assets for hardcoded API keys, SSL TrustAll bypasses, ECB/DES weak crypto, WebView exposure, R8 obfuscation, and embedded trackers/SDKs.
                    </div>
                    <div className="p-3.5 rounded-2xl bg-[#050811]/80 border border-white/10">
                      <strong className="text-emerald-300 block mb-1">Stage 3: Auto Backend API Probes</strong>
                      Extracts backend API &amp; Firebase/Supabase URLs from APK binaries and actively checks live TLS/HSTS, CORS credentials policy, and open anonymous DB reads.
                    </div>
                    <div className="p-3.5 rounded-2xl bg-[#050811]/80 border border-white/10">
                      <strong className="text-amber-300 block mb-1">Web &amp; API Suite</strong>
                      Inspects live JS chunks + HTML for leaked keys, <code className="text-white">.env</code>/<code className="text-white">.git</code>/<code className="text-white">.js.map</code> exposures, CSP/HSTS/Cookie flags, Firebase/Supabase rules, and burst rate limits.
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Premium Footer ── */}
      <footer className="py-6 px-6 border-t border-white/[0.06] bg-[#04060c]/60 backdrop-blur-md text-center text-xs text-slate-400 relative z-10 no-print">
        <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <span className="font-bold text-slate-300">
            CheckMyAPK<span className="text-cyan-400">.com</span> — AI App &amp; Web Security Scanner
          </span>
          <div className="flex items-center gap-4 text-[11px] font-semibold">
            <button
              type="button"
              onClick={() => setShowTrustModal('privacy')}
              className="text-emerald-300/90 hover:text-emerald-200 cursor-pointer"
            >
              Zero-Retention Privacy
            </button>
            <button
              type="button"
              onClick={() => setShowTrustModal('methodology')}
              className="text-cyan-300/90 hover:text-cyan-200 cursor-pointer"
            >
              4-Stage Methodology
            </button>
            <span className="text-slate-500 hidden md:inline">OWASP Top 10 • OWASP MASVS v2</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
