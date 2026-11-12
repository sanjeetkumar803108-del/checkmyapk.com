import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import axios from 'axios';
import multer from 'multer';
import { scanForLeakedKeys, scanSensitiveWebArtifacts } from './server/scanner/keyScanner.ts';
import { scanSecurityHeaders } from './server/scanner/headerScanner.ts';
import { probeDatabaseSecurity } from './server/scanner/dbProbe.ts';
import { probeRateLimiting } from './server/scanner/rateLimitProbe.ts';
import { computeSecurityScore } from './server/scanner/scoreCalculator.ts';
import { 
  generateAiSecuritySummary, 
  generateVulnerabilityDeepFix, 
  generateAiMobileAssessment 
} from './server/scanner/aiAdvisor.ts';
import { scanApkBuffer } from './server/scanner/apkScanner.ts';
import {
  createScanJob,
  getScanJob,
  pushScanJobProgress,
  completeScanJob,
  failScanJob
} from './server/scanner/jobQueue.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.disable('x-powered-by');
const PORT = process.env.PORT || 5000;
const IS_PROD = process.env.NODE_ENV === 'production' || process.argv.includes('--prod');

app.use(cors());
app.use(express.json());

// Configure Multer for in-memory APK uploads up to 100MB
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 }
});

// Helper to extract script URLs from HTML
function extractScriptUrls(html: string, baseUrl: string): string[] {
  const urls: string[] = [];
  const scriptRegex = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let match;

  while ((match = scriptRegex.exec(html)) !== null) {
    const rawSrc = match[1];
    try {
      const resolved = new URL(rawSrc, baseUrl).href;
      urls.push(resolved);
    } catch (e) {}
  }

  // Also check for modern Vite/Webpack modulepreload links
  const preloadRegex = /<link\b[^>]*\brel\s*=\s*["']modulepreload["'][^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>/gi;
  while ((match = preloadRegex.exec(html)) !== null) {
    const rawHref = match[1];
    try {
      const resolved = new URL(rawHref, baseUrl).href;
      if (!urls.includes(resolved)) urls.push(resolved);
    } catch (e) {}
  }

  return urls;
}

// Technology signature detection
function detectTechnologies(html: string, headers: Record<string, any>): string[] {
  const tech: string[] = [];
  const lowerHtml = html.toLowerCase();

  if (lowerHtml.includes('react') || lowerHtml.includes('__react') || lowerHtml.includes('react-dom')) tech.push('React');
  if (lowerHtml.includes('__next_data__') || lowerHtml.includes('/_next/')) tech.push('Next.js');
  if (lowerHtml.includes('vite') || lowerHtml.includes('/@vite')) tech.push('Vite');
  if (lowerHtml.includes('firebaseio.com') || lowerHtml.includes('firebaseapp.com') || lowerHtml.includes('firebase')) tech.push('Firebase');
  if (lowerHtml.includes('supabase.co')) tech.push('Supabase');
  if (lowerHtml.includes('tailwind') || lowerHtml.includes('tailwindcss')) tech.push('Tailwind CSS');
  if (lowerHtml.includes('katex')) tech.push('KaTeX Math');
  if (headers['server']) tech.push(`Server: ${headers['server']}`);
  if (headers['cf-ray']) tech.push('Cloudflare Edge CDN');

  return Array.from(new Set(tech));
}

// 🛡️ MAIN SCANNER API ENDPOINT
app.post('/api/scan', async (req, res) => {
  const startTime = Date.now();
  const realTimeLogs: Array<{ time: string; msg: string }> = [];

  const log = (msg: string) => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
    realTimeLogs.push({ time: `[+${elapsed}s]`, msg });
    console.log(`[SecureAppAI +${elapsed}s] ${msg}`);
  };

  let { targetUrl } = req.body;

  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ error: 'Please provide a valid target URL.' });
  }

  targetUrl = targetUrl.trim();
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = `https://${targetUrl}`;
  }

  log(`Target identified: ${targetUrl}`);

  try {
    const parsedUrl = new URL(targetUrl);
    const hostLower = parsedUrl.hostname.toLowerCase();

    // Production SSRF Protection Guard
    const isMetadataHost = hostLower === '169.254.169.254' || hostLower === 'metadata.google.internal' || hostLower.endsWith('.internal');
    const isPrivateIp =
      hostLower === 'localhost' ||
      hostLower === '127.0.0.1' ||
      hostLower === '::1' ||
      hostLower === '0.0.0.0' ||
      hostLower.startsWith('10.') ||
      hostLower.startsWith('192.168.') ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(hostLower);

    if (isMetadataHost || (IS_PROD && isPrivateIp)) {
      return res.status(400).json({ error: 'Scanning internal, loopback, or cloud metadata addresses is disabled for security.' });
    }

    log(`Connecting to ${parsedUrl.hostname} over ${parsedUrl.protocol}...`);

    // Step 1: Network Handshake & Fetch HTML + Headers
    const fetchStart = Date.now();
    let initialRes;
    try {
      initialRes = await axios.get(targetUrl, {
        timeout: 9000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 CheckMyAPK-Auditor/1.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        },
        maxRedirects: 5,
        validateStatus: () => true
      });
    } catch (fetchErr: any) {
      log(`Connection failed: ${fetchErr.message}`);
      return res.status(400).json({ 
        error: `Could not connect to ${targetUrl}. Please ensure the server is online. (${fetchErr.message})` 
      });
    }

    const latencyMs = Date.now() - fetchStart;
    log(`HTTP handshake complete: HTTP ${initialRes.status} in ${latencyMs}ms`);

    const html = typeof initialRes.data === 'string' ? initialRes.data : '';
    const headers = initialRes.headers;

    // Step 2: Extract JavaScript bundles
    const scriptUrls = extractScriptUrls(html, targetUrl);
    log(`Discovered ${scriptUrls.length} JavaScript bundles & module chunks to audit`);

    // Step 3: Run key hunter, sensitive artifact checks (.env/.git/.js.map), headers & rate-limit probes
    log(`Executing Secret Hunter & Sensitive Artifact (.env/.git/.js.map) probes...`);
    log(`Probing HTTP Security Headers, Cookies & CORS policies...`);
    log(`Firing 15-request burst to test Denial-of-Wallet rate limits...`);

    const [keyResult, artifactFindings, headerFindings, rateLimitFinding] = await Promise.all([
      scanForLeakedKeys(scriptUrls),
      scanSensitiveWebArtifacts(targetUrl, scriptUrls),
      Promise.resolve(scanSecurityHeaders(headers)),
      probeRateLimiting(targetUrl)
    ]);

    // Step 3b: Now feed extracted JS bundle text + HTML into DB probe & tech fingerprint!
    log(`Probing extracted client scripts for Firebase/Supabase DB rules & Auth tokens...`);
    const dbFindings = await probeDatabaseSecurity(html, keyResult.collectedScriptContent);
    const detectedTech = detectTechnologies(`${html}\n${keyResult.collectedScriptContent.slice(0, 120000)}`, headers);
    log(`Fingerprinted technologies: ${detectedTech.join(', ') || 'Standard Web Stack'}`);

    const transportFindings: any[] = [];
    if (parsedUrl.protocol === 'http:' && !isPrivateIp) {
      transportFindings.push({
        category: 'Transport Encryption (TLS)',
        type: 'Unencrypted HTTP Website Transport',
        severity: 'HIGH',
        proof: `Site responded directly over cleartext ${targetUrl} without HTTPS enforcement.`,
        description: 'Traffic sent over HTTP can be intercepted or altered by attackers on public Wi-Fi or local networks.',
        remediation: 'Enable SSL/TLS certificate (Let\'s Encrypt/Cloudflare) and force 301 redirects from http:// to https://.',
        owaspRef: 'OWASP-A02'
      });
    }

    log(`Inspected ${keyResult.totalLinesInspected} lines of code (${(keyResult.totalBytesScanned / 1024).toFixed(1)} KB)`);
    log(`Found ${keyResult.findings.length + artifactFindings.length} leaked secret/artifact alerts, ${headerFindings.filter(h => h.severity !== 'PASS').length} header flags`);

    // Aggregate Findings
    const allFindings = [
      ...transportFindings,
      ...keyResult.findings.map(f => ({ ...f, category: 'API Keys & Secrets', owaspRef: f.owaspRef || 'OWASP-A02' })),
      ...artifactFindings.map(f => ({ ...f, category: 'Exposed Source Maps & Configs', owaspRef: f.owaspRef || 'OWASP-A05' })),
      ...headerFindings.map(f => ({ ...f, category: 'Security Headers & CORS', owaspRef: f.owaspRef || 'OWASP-A05' })),
      ...dbFindings.map(f => ({ ...f, category: 'Database & Cloud Rules', owaspRef: f.owaspRef || 'OWASP-A01' })),
      { ...rateLimitFinding, category: 'Rate Limiting & Cost Protection', owaspRef: rateLimitFinding.owaspRef || 'OWASP-API04' }
    ];

    // Step 4: Mathematical Scoring
    log(`Computing formal vulnerability deduction score...`);
    const finalReport = computeSecurityScore(targetUrl, allFindings);

    // Step 5: Gemini 3.8 Flash Neural Security Analysis
    log(`Invoking Gemini 3.8 Flash Neural Engine for custom threat synthesis...`);
    const aiSummary = await generateAiSecuritySummary(
      targetUrl, 
      allFindings, 
      {
        serverHeader: headers['server'] ? String(headers['server']) : undefined,
        scriptsCount: scriptUrls.length,
        detectedTech
      }
    );
    finalReport.aiExecutiveSummary = aiSummary;

    const totalDuration = ((Date.now() - startTime) / 1000).toFixed(2);
    log(`Audit successfully concluded in ${totalDuration}s. Final Grade: ${finalReport.grade} (${finalReport.score}/100)`);

    // Attach deep telemetry
    const enrichedResponse = {
      ...finalReport,
      telemetry: {
        latencyMs,
        totalBytesScanned: keyResult.totalBytesScanned,
        totalLinesInspected: keyResult.totalLinesInspected,
        scriptsCount: scriptUrls.length,
        detectedTech,
        durationSeconds: totalDuration,
        realTimeLogs
      }
    };

    return res.json(enrichedResponse);

  } catch (err: any) {
    console.error('[SecureAppAI] Scan error:', err);
    return res.status(500).json({ error: err.message || 'An unexpected error occurred during security audit.' });
  }
});

// 🤖 ON-DEMAND AI VULNERABILITY FIX DOCTOR
app.post('/api/explain-vulnerability', async (req, res) => {
  try {
    const { finding, detectedTech = [], targetUrl = '', framework } = req.body;
    if (!finding || !finding.type) {
      return res.status(400).json({ error: 'Finding payload is required.' });
    }

    console.log(`[AI Fix Doctor] Generating deep remediation guide for "${finding.type}"...`);
    const deepFix = await generateVulnerabilityDeepFix(
      finding,
      Array.isArray(detectedTech) ? detectedTech : [detectedTech],
      targetUrl,
      framework
    );

    return res.json(deepFix);
  } catch (err: any) {
    console.error('[AI Fix Doctor] Error:', err);
    return res.status(500).json({ error: err.message || 'Failed to generate AI fix guide.' });
  }
});

function validateApkUpload(req: express.Request): { error?: string; buffer?: Buffer; fileName?: string } {
  if (!req.file || !req.file.buffer) {
    return { error: 'Please select an Android .apk file to upload.' };
  }
  // Verify ZIP/APK local file header magic bytes ('PK' = 0x50 0x4B) before unzipping
  if (req.file.buffer.length < 4 || req.file.buffer[0] !== 0x50 || req.file.buffer[1] !== 0x4b) {
    return { error: 'Invalid APK container: uploaded file is not a valid ZIP/APK archive.' };
  }
  return {
    buffer: req.file.buffer,
    fileName: req.file.originalname || 'application.apk'
  };
}

async function runApkAuditPipeline(
  apkBuffer: Buffer,
  fileName: string,
  onProgress?: (progress: number, stage: string, timeLabel: string) => void
) {
  const startTime = Date.now();
  const realTimeLogs: Array<{ time: string; msg: string }> = [];

  const log = (msg: string, progress = 15) => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
    const timeLabel = `[+${elapsed}s]`;
    realTimeLogs.push({ time: timeLabel, msg });
    console.log(`[ApkAudit +${elapsed}s] ${msg}`);
    onProgress?.(progress, msg, timeLabel);
  };

  const sizeMb = (apkBuffer.length / 1024 / 1024).toFixed(1);
  log(`APK received: ${fileName} (${sizeMb} MB)`, 15);
  log(`Decompressing APK zip container, AndroidBinaryXML & DEX bytecode...`, 30);

  const apkScanResult = await scanApkBuffer(apkBuffer, fileName);

  log(`Package identified: ${apkScanResult.packageName} v${apkScanResult.versionName || '1.0'} (Target SDK: ${apkScanResult.targetSdkVersion})`, 45);
  log(`Framework fingerprinted: ${apkScanResult.frameworkDetected} • Inspected ${apkScanResult.permissions.length} permissions & ${apkScanResult.exportedComponents?.totalExported || 0} exported IPC components`, 55);

  if (apkScanResult.dexBytecodeGraph) {
    const cfg = apkScanResult.dexBytecodeGraph;
    const crossHops = cfg.interproceduralPathsCount || 0;
    log(
      `Stage 2.5 Bytecode CFG: Disassembled ${cfg.methodsAnalyzed.toLocaleString()} methods (${cfg.instructionsScanned.toLocaleString()} Dalvik opcodes) in ${cfg.durationMs}ms — ${cfg.taintPaths.length} taint flow(s) (${crossHops} cross-method)`,
      68
    );
  }
  if (apkScanResult.nativeElfSummary && apkScanResult.nativeElfSummary.uniqueLibrariesCount > 0) {
    const elf = apkScanResult.nativeElfSummary;
    log(
      `Native ELF (.so) Audit: Checked ${elf.uniqueLibrariesCount} binaries (${elf.appLibrariesCount} app libs, ${elf.nativeStringsScannedKb} KB native strings; pinning=${apkScanResult.pinningStatus?.active ? 'ACTIVE' : 'NONE'})`,
      73
    );
  }

  // ── Stage 3: Auto-Extracted Backend API & BaaS Live Probing ──
  const allApkFindings: any[] = [...apkScanResult.findings];
  const baasTargets = apkScanResult.baasUrls || [];
  const customApiTargets = (apkScanResult.discoveredEndpoints || []).slice(0, 3);
  const probedApis: Array<{
    url: string;
    status: number | string;
    latencyMs: number;
    cors: string;
    hsts: boolean;
    reachable: boolean;
  }> = [];

  if (baasTargets.length > 0 || customApiTargets.length > 0) {
    log(`Stage 3 Active Probe: Auditing ${baasTargets.length} BaaS & ${customApiTargets.length} extracted backend endpoints...`, 78);

    const dbProbePromise = baasTargets.length > 0
      ? probeDatabaseSecurity('', baasTargets.join('\n')).catch(() => [])
      : Promise.resolve([]);

    const apiProbePromises = customApiTargets.map(async (apiUrl) => {
      const probeStart = Date.now();
      try {
        const apiRes = await axios.get(apiUrl, {
          timeout: 3500,
          validateStatus: () => true,
          headers: { 'User-Agent': 'CheckMyAPK-Stage3-Auditor/1.0' }
        });
        const latencyMs = Date.now() - probeStart;
        const headerFindings = scanSecurityHeaders(apiRes.headers || {});
        const corsOrigin = String(apiRes.headers?.['access-control-allow-origin'] || 'Restricted');
        const hsts = Boolean(apiRes.headers?.['strict-transport-security']);

        for (const hf of headerFindings) {
          if (hf.type.includes('Critical Insecure CORS')) {
            allApkFindings.push({
              category: 'Backend API & Cloud DB (Stage 3)',
              type: `Extracted Backend API Misconfiguration: ${hf.type}`,
              severity: 'HIGH',
              proof: `Target ${apiUrl} returned ${hf.proof}`,
              description: hf.description,
              remediation: hf.remediation,
              owaspRef: hf.owaspRef || 'OWASP-API08'
            });
          }
        }

        probedApis.push({
          url: apiUrl,
          status: apiRes.status,
          latencyMs,
          cors: corsOrigin,
          hsts,
          reachable: true
        });
      } catch (probeErr: any) {
        probedApis.push({
          url: apiUrl,
          status: probeErr?.code === 'ECONNABORTED' ? 'Timeout' : 'Unreachable',
          latencyMs: Date.now() - probeStart,
          cors: 'N/A',
          hsts: false,
          reachable: false
        });
      }
    });

    const [dbResults] = await Promise.all([dbProbePromise, ...apiProbePromises]);
    for (const df of dbResults) {
      allApkFindings.push({
        category: 'Backend API & Cloud DB (Stage 3)',
        type: df.type,
        severity: df.severity === 'INFO' ? 'LOW' : df.severity,
        proof: df.proof,
        description: df.description,
        remediation: df.remediation,
        owaspRef: df.owaspRef || 'OWASP-A01'
      });
    }

    const reachableCount = probedApis.filter(p => p.reachable).length;
    if (reachableCount > 0 && !allApkFindings.some(f => f.category === 'Backend API & Cloud DB (Stage 3)' && (f.severity === 'CRITICAL' || f.severity === 'HIGH'))) {
      allApkFindings.push({
        category: 'Backend API & Cloud DB (Stage 3)',
        type: `Live Extracted Backend APIs Audited (${reachableCount} Reachable)`,
        severity: 'PASS',
        proof: `Verified ${reachableCount}/${probedApis.length} extracted backend targets (${probedApis.filter(p => p.reachable).map(p => `${p.url} -> HTTP ${p.status}`).join(', ')}) with zero open DB or CORS credential leaks.`,
        description: 'Extracted backend API endpoints responded over HTTPS without permissive credentialed CORS wildcards or open anonymous BaaS reads.',
        remediation: 'Maintain strict per-route JWT authentication and WAF throttling on all mobile backend API endpoints.',
        owaspRef: 'OWASP-API01'
      });
    }
  }

  log(`Found ${allApkFindings.filter(f => f.severity === 'CRITICAL').length} Critical, ${allApkFindings.filter(f => f.severity === 'HIGH').length} High findings — calculating OWASP MASVS score...`, 88);
  const finalReport = computeSecurityScore(apkScanResult.packageName, allApkFindings);

  log(`Generating OWASP MASVS v2 & Bytecode Remediation Assessment...`, 94);
  const aiMobileSummary = await generateAiMobileAssessment(
    {
      packageName: apkScanResult.packageName,
      frameworkDetected: apkScanResult.frameworkDetected,
      targetSdkVersion: apkScanResult.targetSdkVersion,
      dexCount: apkScanResult.dexCount,
      fileSizeMb: sizeMb,
      architectures: apkScanResult.architectures,
      permissionsCount: apkScanResult.permissions.length,
      obfuscationStatus: apkScanResult.obfuscationStatus,
      exportedTotal: apkScanResult.exportedComponents?.totalExported || 0,
      unprotectedIpc: apkScanResult.exportedComponents?.unprotectedCount || 0,
      trackers: apkScanResult.trackers || [],
      sdks: apkScanResult.sdks || [],
      probedApisCount: probedApis.length
    },
    allApkFindings
  );
  finalReport.aiExecutiveSummary = aiMobileSummary;

  const totalDuration = ((Date.now() - startTime) / 1000).toFixed(2);
  log(`Mobile audit completed in ${totalDuration}s. Final Grade: ${finalReport.grade} (${finalReport.score}/100)`, 99);

  return {
    ...finalReport,
    isApkAudit: true,
    apkMeta: {
      fileName,
      sizeMb,
      sha256: apkScanResult.sha256,
      obfuscationStatus: apkScanResult.obfuscationStatus,
      packageName: apkScanResult.packageName,
      versionName: apkScanResult.versionName,
      versionCode: apkScanResult.versionCode,
      targetSdkVersion: apkScanResult.targetSdkVersion,
      minSdkVersion: apkScanResult.minSdkVersion,
      frameworkDetected: apkScanResult.frameworkDetected,
      architectures: apkScanResult.architectures,
      permissions: apkScanResult.permissions,
      dexCount: apkScanResult.dexCount,
      totalFiles: apkScanResult.telemetry.totalFiles,
      exportedComponents: apkScanResult.exportedComponents,
      trackers: apkScanResult.trackers || [],
      sdks: apkScanResult.sdks || [],
      discoveredEndpoints: apkScanResult.discoveredEndpoints || [],
      baasUrls: apkScanResult.baasUrls || [],
      probedApis,
      dexDeepAudit: apkScanResult.dexDeepAudit,
      dexBytecodeGraph: apkScanResult.dexBytecodeGraph,
      nativeElfSummary: apkScanResult.nativeElfSummary,
      pinningStatus: apkScanResult.pinningStatus
    },
    telemetry: {
      totalLinesInspected: apkScanResult.telemetry.totalFiles,
      totalBytesScanned: apkBuffer.length,
      scriptsCount: apkScanResult.dexCount,
      detectedTech: [
        apkScanResult.frameworkDetected,
        ...apkScanResult.architectures,
        ...(apkScanResult.sdks || []).slice(0, 4)
      ],
      durationSeconds: totalDuration,
      realTimeLogs
    }
  };
}

// 📱 MOBILE APK DEEP SECURITY AUDIT ENDPOINT (Sync Direct Response)
app.post('/api/scan-apk', upload.single('apk'), async (req, res) => {
  const checked = validateApkUpload(req);
  if (checked.error || !checked.buffer) {
    return res.status(400).json({ error: checked.error });
  }
  try {
    const result = await runApkAuditPipeline(checked.buffer, checked.fileName!);
    return res.json(result);
  } catch (err: any) {
    console.error('[ApkAudit] Scan error:', err);
    return res.status(500).json({ error: err.message || 'Failed to parse and audit APK file.' });
  }
});

// ⚙️ ASYNC WORKER QUEUE ENDPOINT (Non-blocking APK Deep Audit + Job Polling)
app.post('/api/jobs/scan-apk', upload.single('apk'), (req, res) => {
  const checked = validateApkUpload(req);
  if (checked.error || !checked.buffer) {
    return res.status(400).json({ error: checked.error });
  }

  const job = createScanJob('apk', checked.fileName!);
  const apkBuffer = checked.buffer;
  const fileName = checked.fileName!;

  // Run pipeline asynchronously in background without blocking HTTP worker thread
  setImmediate(async () => {
    try {
      const report = await runApkAuditPipeline(apkBuffer, fileName, (progress, stage, timeLabel) => {
        pushScanJobProgress(job.id, progress, stage, timeLabel);
      });
      completeScanJob(job.id, report);
    } catch (err: any) {
      console.error(`[AsyncJob ${job.id}] Failed:`, err);
      failScanJob(job.id, err?.message || 'Async APK audit failed.');
    }
  });

  return res.status(202).json({
    jobId: job.id,
    status: job.status,
    progress: job.progress,
    pollUrl: `/api/jobs/${job.id}`
  });
});

app.get('/api/jobs/:jobId', (req, res) => {
  const job = getScanJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: 'Audit job not found or expired.' });
  }
  return res.json(job);
});

// Start Server
async function startServer() {
  if (!IS_PROD) {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(Number(PORT), '0.0.0.0', () => {
    console.log(`\n======================================================`);
    console.log(`🛡️  CheckMyAPK.com Scanner is live on: http://localhost:${PORT}`);
    console.log(`======================================================\n`);
  });
}

startServer();
