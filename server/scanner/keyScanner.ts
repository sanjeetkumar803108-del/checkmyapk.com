import axios from 'axios';
import { AUDIT_HTTPS_AGENT } from './securityGuard.ts';

export interface LeakedKeyFinding {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  fileUrl: string;
  proof: string;
  description: string;
  remediation: string;
  owaspRef?: string;
}

export interface KeyScanResult {
  findings: LeakedKeyFinding[];
  totalBytesScanned: number;
  totalLinesInspected: number;
  scannedScripts: string[];
  collectedScriptContent: string;
  collectedScripts: Array<{ url: string; content: string }>;
}

const SECRET_PATTERNS = [
  {
    name: 'OpenAI Secret Key',
    regex: /sk-(?:proj-)?[a-zA-Z0-9_-]{32,}/g,
    severity: 'CRITICAL' as const,
    description: 'A private OpenAI secret key was discovered exposed in public client JavaScript bundles.',
    remediation: 'Never use OpenAI keys on the frontend. Move all AI completions to a backend proxy server (Node.js/Next.js/Python) and protect it with user authentication.'
  },
  {
    name: 'Anthropic Claude Key',
    regex: /sk-ant-api[a-zA-Z0-9_-]{32,}/g,
    severity: 'CRITICAL' as const,
    description: 'An Anthropic Claude secret API key is exposed in the frontend assets.',
    remediation: 'Immediately rotate this key in your Anthropic Console and migrate all API calls to a secure backend endpoint.'
  },
  {
    name: 'Stripe Live Secret Key',
    regex: /sk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'CRITICAL' as const,
    description: 'Live Stripe secret key found in client bundle. Attackers can refund payments or access customer data.',
    remediation: 'Rotate this Stripe key immediately in the Stripe Dashboard. Client apps should only ever use the publishable key (pk_live_...).'
  },
  {
    name: 'AWS Access Key ID',
    regex: /AKIA[0-9A-Z]{16}/g,
    severity: 'CRITICAL' as const,
    description: 'Amazon Web Services (AWS) Access Key ID discovered in frontend code.',
    remediation: 'Revoke this credential immediately in AWS IAM and use AWS Cognito or backend IAM roles instead.'
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /ghp_[0-9a-zA-Z]{36}/g,
    severity: 'CRITICAL' as const,
    description: 'Personal GitHub Access Token exposed in client assets.',
    remediation: 'Revoke this token immediately on GitHub Settings -> Developer settings -> Personal access tokens.'
  },
  {
    name: 'Google Gemini / Cloud API Key',
    regex: /AIza[0-9A-Za-z-_]{35}/g,
    severity: 'HIGH' as const,
    description: 'Google AI / Cloud API Key identified in public client JavaScript bundle.',
    remediation: 'Move Gemini/Cloud API keys strictly to backend process.env proxies. If this key is exclusively a Firebase Web Client config identifier, restrict it in Google Cloud Console by HTTP Referrer and allowed APIs.'
  },
  {
    name: 'Private Cryptographic Key Block (PEM)',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'CRITICAL' as const,
    description: 'A raw cryptographic private key header was found inside public client-side assets.',
    remediation: 'Remove private keys immediately from frontend builds, rotate compromised keypairs, and sign tokens strictly server-side.'
  },
  {
    name: 'Hardcoded MongoDB Credentials URI',
    regex: /mongodb(?:\+srv)?:\/\/[a-zA-Z0-9._-]+:[^@\s"'`]+@[a-zA-Z0-9.-]+/g,
    severity: 'CRITICAL' as const,
    description: 'Database connection string with embedded username and password found in client-side code.',
    remediation: 'Rotate database user password immediately and move database connections strictly to backend API routes.'
  }
];

function compactDisplayUrl(rawUrl: string, maxLen = 110): string {
  if (rawUrl.length <= maxLen) return rawUrl;
  return `${rawUrl.slice(0, maxLen - 3)}...`;
}

export async function probeGeminiKeyLive(apiKey: string): Promise<boolean> {
  try {
    const resp = await axios.get(`https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(apiKey)}`, {
      timeout: 2200,
      validateStatus: () => true
    });
    return resp.status === 200;
  } catch {
    return false;
  }
}

export async function scanForLeakedKeys(scriptUrls: string[]): Promise<KeyScanResult> {
  const findings: LeakedKeyFinding[] = [];
  const checkedKeys = new Set<string>();
  const scannedScripts: string[] = [];
  let totalBytesScanned = 0;
  let totalLinesInspected = 0;
  const scriptChunks: string[] = [];
  const collectedScripts: Array<{ url: string; content: string }> = [];
  let collectedBytes = 0;
  const MAX_COLLECTED_BYTES = 2 * 1024 * 1024;

  const googleClientKeys: Array<{
    key: string;
    masked: string;
    url: string;
    isFirebase: boolean;
    hasGeminiContext: boolean;
  }> = [];

  await Promise.all(
    scriptUrls.slice(0, 20).map(async (url) => {
      try {
        const resp = await axios.get(url, {
          timeout: 5500,
          httpsAgent: AUDIT_HTTPS_AGENT,
          maxContentLength: 10 * 1024 * 1024,
          headers: { 'User-Agent': 'CheckMyAPK-Auditor/1.0 (+https://checkmyapk.com)' }
        });

        const content = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);
        totalBytesScanned += content.length;
        totalLinesInspected += content.split('\n').length;
        scannedScripts.push(url);

        if (collectedBytes < MAX_COLLECTED_BYTES) {
          const slice = content.slice(0, MAX_COLLECTED_BYTES - collectedBytes);
          scriptChunks.push(slice);
          collectedScripts.push({ url, content: slice });
          collectedBytes += slice.length;
        }

        for (const pat of SECRET_PATTERNS) {
          const regex = new RegExp(pat.regex.source, pat.regex.flags);
          for (const matchArr of content.matchAll(regex)) {
            const m = matchArr[0];
            const matchIdx = matchArr.index ?? 0;
            if (checkedKeys.has(m)) continue;
            checkedKeys.add(m);

            const maskedProof = m.length > 14
              ? `${m.slice(0, 8)}...${m.slice(-4)}`
              : `${m.slice(0, 4)}...`;

            if (pat.name.includes('Google Gemini / Cloud')) {
              const ctx = content.slice(Math.max(0, matchIdx - 240), matchIdx + 240);
              const isFirebase = /(?:firebaseapp\.com|authDomain|storageBucket|messagingSenderId|firebaseio\.com|firebasedatabase\.app)/i.test(ctx);
              const hasGeminiContext = /(?:generativelanguage\.googleapis\.com|@google\/genai|GoogleGenerativeAI|gemini-(?:1|2|3)|generateContent)/i.test(ctx);
              googleClientKeys.push({
                key: m,
                masked: maskedProof,
                url,
                isFirebase,
                hasGeminiContext
              });
              continue;
            }

            findings.push({
              type: pat.name,
              severity: pat.severity,
              fileUrl: url,
              proof: `Detected in ${compactDisplayUrl(url)} -> ${maskedProof}`,
              description: pat.description,
              remediation: pat.remediation,
              owaspRef: 'OWASP-A02'
            });
          }
        }
      } catch (e: any) {
        // Ignore individual unreachable scripts
      }
    })
  );

  // Classify & group AIza... keys with optional safe read-only Gemini models.list check
  if (googleClientKeys.length > 0) {
    let liveProbeCount = 0;
    const liveGeminiHits: typeof googleClientKeys = [];
    const standardClientHits: typeof googleClientKeys = [];

    for (const item of googleClientKeys) {
      let isLiveGemini = false;
      if ((item.hasGeminiContext || !item.isFirebase) && liveProbeCount < 2) {
        liveProbeCount++;
        isLiveGemini = await probeGeminiKeyLive(item.key);
      }

      if (isLiveGemini) {
        liveGeminiHits.push(item);
      } else if (item.hasGeminiContext) {
        findings.push({
          type: 'Google Gemini / AI API Key Pattern in Client Bundle',
          severity: 'HIGH',
          fileUrl: item.url,
          proof: `Detected in ${compactDisplayUrl(item.url)} -> ${item.masked} (Generative AI SDK context nearby)`,
          description: 'An AIza... key referenced near Generative AI SDK patterns was found in frontend code.',
          remediation: 'Move Gemini SDK calls strictly to a backend proxy using process.env and restrict this key in Google Cloud Console.',
          owaspRef: 'OWASP-A02'
        });
      } else {
        standardClientHits.push(item);
      }
    }

    if (liveGeminiHits.length > 0) {
      findings.push({
        type: 'Live Unrestricted Gemini AI Key Exposed in Client Bundle',
        severity: 'CRITICAL',
        fileUrl: liveGeminiHits[0].url,
        proof: `Verified HTTP 200 on generativelanguage.googleapis.com/v1beta/models for ${liveGeminiHits.map(k => k.masked).join(', ')} (${compactDisplayUrl(liveGeminiHits[0].url)})`,
        description: 'Live verification confirmed this client-exposed AIza key has active unrestricted access to Gemini / Generative Language APIs, enabling quota hijacking and unexpected billing.',
        remediation: 'Revoke/rotate this API key immediately in Google Cloud Console, move Gemini calls to your backend server, and apply API + HTTP Referrer restrictions.',
        owaspRef: 'OWASP-A02'
      });
    }

    if (standardClientHits.length > 0) {
      const anyFirebase = standardClientHits.some(k => k.isFirebase);
      const uniqueBundles = Array.from(new Set(standardClientHits.map(k => compactDisplayUrl(k.url, 80))));
      findings.push({
        type: anyFirebase
          ? 'Firebase Client API Key Detected (Verify GCP Key Restrictions)'
          : 'Google Public Client API Key Detected (Verify Referrer & API Restrictions)',
        severity: 'LOW',
        fileUrl: standardClientHits[0].url,
        proof: `Grouped ${standardClientHits.length} public client key(s) (${standardClientHits.map(k => k.masked).slice(0, 3).join(', ')}) across ${uniqueBundles.length} bundle(s): ${uniqueBundles[0]}`,
        description: 'Google Maps, Firebase, and Search web SDK AIza... keys are designed to be shipped publicly in client bundles, provided HTTP Referrer and API-scope restrictions are enabled in Google Cloud Console.',
        remediation: 'Open Google Cloud Console -> Credentials -> Edit API Key -> Enable HTTP Referrer restrictions for your production domain and restrict APIs strictly to the required client service (never Generative Language API).',
        owaspRef: 'OWASP-A05'
      });
    }
  }

  return {
    findings,
    totalBytesScanned,
    totalLinesInspected,
    scannedScripts,
    collectedScriptContent: scriptChunks.join('\n'),
    collectedScripts
  };
}

export async function scanSensitiveWebArtifacts(baseUrl: string, scriptUrls: string[]): Promise<LeakedKeyFinding[]> {
  const findings: LeakedKeyFinding[] = [];
  let origin = '';
  try {
    origin = new URL(baseUrl).origin;
  } catch (e) {
    return findings;
  }

  const probeTargets: Array<{ url: string; check: 'env' | 'git' }> = [
    { url: `${origin}/.env`, check: 'env' },
    { url: `${origin}/.git/HEAD`, check: 'git' }
  ];

  const candidateMaps = scriptUrls
    .filter(u => u.endsWith('.js') && u.startsWith(origin))
    .slice(0, 2)
    .map(u => `${u}.map`);

  await Promise.all([
    ...probeTargets.map(async ({ url, check }) => {
      try {
        const res = await axios.get(url, {
          timeout: 3500,
          httpsAgent: AUDIT_HTTPS_AGENT,
          maxContentLength: 256 * 1024,
          validateStatus: () => true,
          headers: { 'User-Agent': 'CheckMyAPK-Auditor/1.0 (+https://checkmyapk.com)' }
        });
        if (res.status !== 200 || typeof res.data !== 'string') return;
        const body = res.data.trim();
        const isHtmlFallback = body.startsWith('<!') || body.toLowerCase().startsWith('<html');
        if (isHtmlFallback) return;

        if (check === 'env' && /^[A-Z0-9_]{2,}=[^\r\n]+/m.test(body)) {
          findings.push({
            type: 'Publicly Exposed .env Configuration File',
            severity: 'CRITICAL',
            fileUrl: url,
            proof: `GET ${url} returned HTTP 200 containing environment key-value assignments.`,
            description: 'Your server exposes its raw .env secrets file directly over HTTP, allowing anyone to read database passwords, API keys, and signing secrets.',
            remediation: 'Block access to dotfiles (.env, .git) in Nginx/Apache/Vercel config and rotate all exposed secrets immediately.',
            owaspRef: 'OWASP-A05'
          });
        } else if (check === 'git' && body.startsWith('ref: refs/')) {
          findings.push({
            type: 'Publicly Exposed .git Repository Directory',
            severity: 'CRITICAL',
            fileUrl: url,
            proof: `GET ${url} returned HTTP 200 with "${body.slice(0, 40)}"`,
            description: 'Your entire application source code and commit history can be reconstructed by downloading the exposed .git directory.',
            remediation: 'Deny all external HTTP access to /.git/* paths on your web server and remove .git from public web root.',
            owaspRef: 'OWASP-A05'
          });
        }
      } catch (e) {}
    }),
    ...candidateMaps.map(async (mapUrl) => {
      try {
        const res = await axios.get(mapUrl, {
          timeout: 3500,
          httpsAgent: AUDIT_HTTPS_AGENT,
          maxContentLength: 512 * 1024,
          validateStatus: () => true,
          headers: { 'User-Agent': 'CheckMyAPK-Auditor/1.0 (+https://checkmyapk.com)' }
        });
        if (res.status !== 200) return;
        const raw = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
        if (raw.includes('"mappings"') && raw.includes('"sources"')) {
          findings.push({
            type: 'Public JavaScript Source Map (.js.map) Exposed',
            severity: 'MEDIUM',
            fileUrl: mapUrl,
            proof: `GET ${mapUrl} returned HTTP 200 revealing original unminified TypeScript/React sources.`,
            description: 'Production source maps expose original variable names, internal routes, comments, and client logic cleanly to reverse engineers.',
            remediation: 'Set build.sourcemap = false (Vite) or productionBrowserSourceMaps: false (Next.js) in production builds.',
            owaspRef: 'OWASP-A05'
          });
        }
      } catch (e) {}
    })
  ]);

  return findings;
}
