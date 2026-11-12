import axios from 'axios';

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

export async function scanForLeakedKeys(scriptUrls: string[]): Promise<KeyScanResult> {
  const findings: LeakedKeyFinding[] = [];
  const checkedKeys = new Set<string>();
  const scannedScripts: string[] = [];
  let totalBytesScanned = 0;
  let totalLinesInspected = 0;
  const scriptChunks: string[] = [];
  let collectedBytes = 0;
  const MAX_COLLECTED_BYTES = 2 * 1024 * 1024;

  await Promise.all(
    scriptUrls.slice(0, 20).map(async (url) => {
      try {
        const resp = await axios.get(url, {
          timeout: 5500,
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

            let findingName = pat.name;
            let findingSeverity: LeakedKeyFinding['severity'] = pat.severity;
            let findingDesc = pat.description;
            let findingRem = pat.remediation;
            let findingOwasp = 'OWASP-A02';

            if (pat.name.includes('Google Gemini / Cloud')) {
              const ctx = content.slice(Math.max(0, matchIdx - 220), matchIdx + 220);
              const isFirebaseClientCfg = /(?:firebaseapp\.com|authDomain|storageBucket|messagingSenderId|firebaseio\.com|firebasedatabase\.app)/i.test(ctx);
              if (isFirebaseClientCfg) {
                findingName = 'Firebase Client API Key Detected (Verify GCP Key Restrictions)';
                findingSeverity = 'LOW';
                findingOwasp = 'OWASP-A05';
                findingDesc = 'Firebase Client SDK web apiKey is public by design, but if left unrestricted in Google Cloud Console, attackers can bill Generative AI / Cloud APIs against this key.';
                findingRem = 'Open Google Cloud Console -> Credentials -> API Key -> Add HTTP Referrer restriction for your domain and restrict APIs strictly to Firebase/Identity Toolkit (exclude Generative Language API).';
              }
            }

            findings.push({
              type: findingName,
              severity: findingSeverity,
              fileUrl: url,
              proof: `Detected in ${url} -> ${maskedProof}`,
              description: findingDesc,
              remediation: findingRem,
              owaspRef: findingOwasp
            });
          }
        }
      } catch (e: any) {
        // Ignore individual unreachable scripts
      }
    })
  );

  return {
    findings,
    totalBytesScanned,
    totalLinesInspected,
    scannedScripts,
    collectedScriptContent: scriptChunks.join('\n')
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
