import { GoogleGenAI } from '@google/genai';
import crypto from 'crypto';

const aiResponseCache = new Map<string, string>();
let cooldownKey = '';
let geminiCooldownUntil = 0;

function getCacheKey(prefix: string, payload: unknown): string {
  const hash = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex').slice(0, 24);
  return `${prefix}:${hash}`;
}

function setAiCache(key: string, val: string) {
  if (aiResponseCache.size >= 150) {
    const oldest = aiResponseCache.keys().next().value;
    if (oldest) aiResponseCache.delete(oldest);
  }
  aiResponseCache.set(key, val);
}

async function generateWithFastTimeout(
  ai: GoogleGenAI,
  contents: string,
  config?: any,
  cacheKey?: string,
  apiKey?: string
): Promise<string | null> {
  if (cacheKey && aiResponseCache.has(cacheKey)) {
    return aiResponseCache.get(cacheKey)!;
  }
  if (apiKey && cooldownKey === apiKey && Date.now() < geminiCooldownUntil) {
    return null;
  }

  const models = ['gemini-3.8-flash'];
  for (const modelName of models) {
    try {
      const response = await Promise.race([
        ai.models.generateContent({
          model: modelName,
          contents,
          ...(config ? { config } : {})
        }),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(`${modelName} timed out after 7s`)), 7000)
        )
      ]);
      if (response && response.text) {
        const text = response.text.trim();
        if (cacheKey) setAiCache(cacheKey, text);
        return text;
      }
    } catch (err: any) {
      const msg = String(err?.message || err);
      if (apiKey && (msg.includes('429') || msg.includes('RESOURCE_EXHAUSTED'))) {
        cooldownKey = apiKey;
        geminiCooldownUntil = Date.now() + 60_000;
        console.warn(`[AI Advisor] ${modelName} quota exhausted (429); activating 60s deterministic fallback mode.`);
      } else {
        console.warn(`[AI Advisor] ${modelName} skipped:`, msg.slice(0, 220));
      }
    }
  }
  return null;
}

function buildDeterministicWebSummary(
  targetUrl: string,
  findings: any[],
  meta: { serverHeader?: string; scriptsCount: number; detectedTech: string[] }
): string {
  const vulns = findings.filter(f => f.severity !== 'PASS');
  const criticals = vulns.filter(f => f.severity === 'CRITICAL');
  const highs = vulns.filter(f => f.severity === 'HIGH');
  const topVuln = criticals[0] || highs[0] || vulns[0];
  const stackLabel = meta.detectedTech.length > 0 ? meta.detectedTech.join(', ') : 'Custom Web App';

  if (vulns.length === 0) {
    return `1. 🛡️ THREAT LANDSCAPE: ${targetUrl} (${stackLabel}) passed all ${findings.length} automated web security probes across ${meta.scriptsCount} JS bundles with zero critical or high exposures.\n2. 🚨 PRIMARY ATTACK VECTOR: Client-side bundle inspection and HTTP header enforcement look hardened; remain vigilant on authenticated server API endpoints.\n3. ⚡ 24-HOUR REMEDIATION ROADMAP: Keep CSP policies strict without 'unsafe-eval', and audit backend API routes individually for IDOR/BOLA authorization.`;
  }

  return `1. 🛡️ THREAT LANDSCAPE: ${targetUrl} (${stackLabel}${meta.serverHeader ? `, ${meta.serverHeader}` : ''}) exposed ${vulns.length} security issues (${criticals.length} Critical, ${highs.length} High) across ${meta.scriptsCount} audited JS bundles.\n2. 🚨 PRIMARY ATTACK VECTOR: Highest priority weakness is "${topVuln.type}" (${topVuln.severity}) — ${topVuln.description}\n3. ⚡ 24-HOUR REMEDIATION ROADMAP: (1) Resolve "${topVuln.type}" immediately using the copy-paste config below; (2) Apply the 60-Second Master Security Headers block (${vulns.slice(0, 3).map(v => v.type).join(', ')}); (3) Re-run CheckMyAPK to confirm score uplift.`;
}

function buildDeterministicMobileSummary(
  meta: {
    packageName: string;
    frameworkDetected: string;
    targetSdkVersion?: number;
    dexCount: number;
    fileSizeMb: string;
    architectures: string[];
    permissionsCount: number;
    obfuscationStatus?: string;
    exportedTotal?: number;
    unprotectedIpc?: number;
    trackers?: string[];
    probedApisCount?: number;
  },
  findings: any[]
): string {
  const vulns = findings.filter(f => f.severity !== 'PASS');
  const topVuln =
    vulns.find(f => f.severity === 'CRITICAL') ||
    vulns.find(f => f.severity === 'HIGH') ||
    vulns[0];

  const trackerNote =
    meta.trackers && meta.trackers.length > 0
      ? `Embedded trackers (${meta.trackers.slice(0, 3).join(', ')}) were fingerprinted.`
      : 'Minimal ad/tracking footprint detected.';

  if (!topVuln) {
    return `1. 📱 REVERSE-ENGINEERING RESILIENCE: ${meta.packageName} (${meta.frameworkDetected}, Target SDK ${meta.targetSdkVersion || 34}, Obfuscation: ${meta.obfuscationStatus || 'Checked'}) passed all static DEX, Manifest IPC (${meta.exportedTotal || 0} exported), and Stage 3 API (${meta.probedApisCount || 0} endpoints) checks cleanly. ${trackerNote}\n2. 🚨 CRITICAL THREAT EXPOSURE: No high-risk client secret leaks, debuggable flags, or cleartext traffic gaps found.\n3. ⚡ ANDROID STUDIO REMEDIATION ROADMAP: Maintain minifyEnabled true in build.gradle release builds, add OkHttp CertificatePinner for sensitive APIs, and verify Play Console Data Safety matches SDK behavior.`;
  }

  return `1. 📱 REVERSE-ENGINEERING RESILIENCE: Audited ${meta.packageName} (${meta.frameworkDetected}, ${meta.dexCount} DEX / ${meta.fileSizeMb} MB, ${meta.obfuscationStatus || 'Binary Audited'}). Inspected ${meta.exportedTotal || 0} exported IPC components (${meta.unprotectedIpc || 0} unprotected) and ${meta.probedApisCount || 0} live backend endpoints. ${trackerNote}\n2. 🚨 CRITICAL THREAT EXPOSURE: Primary risk is "${topVuln.type}" (${topVuln.severity}) — ${topVuln.description}\n3. ⚡ ANDROID STUDIO REMEDIATION ROADMAP: (1) ${topVuln.remediation} (2) Re-build signed release APK/AAB; (3) Re-upload to CheckMyAPK to verify Stage 3 + DEX resolution.`;
}

function buildDeterministicDeepFix(finding: any, techStack: string, targetUrl: string): {
  simpleExplanation: string;
  dangerScenario: string;
  steps: string[];
  beforeCode?: string;
  codeBlock: { filename: string; language: string; code: string };
  verifyCommand: string;
  source: 'gemini' | 'deterministic';
} {
  const t = String(finding.type || '');
  const isFirebaseClientKey = t.includes('Firebase Client API Key');
  const isAndroid =
    t.includes('APK') ||
    t.includes('debuggable') ||
    t.includes('Cleartext') ||
    t.includes('Backup') ||
    t.includes('WebView') ||
    t.includes('Exported') ||
    t.includes('SSL') ||
    t.includes('Certificate Pinning') ||
    t.includes('Encryption') ||
    t.includes('Keystore') ||
    t.includes('Target SDK') ||
    t.includes('Obfuscation') ||
    t.includes('network_security_config') ||
    t.includes('CA Certificates') ||
    t.includes('resources.arsc') ||
    t.includes('Native Library') ||
    t.includes('Native ELF') ||
    t.includes('Cross-Method') ||
    t.includes('Play Console') ||
    t.includes('Tapjacking');

  if (isFirebaseClientKey) {
    const isApkTarget = techStack.toLowerCase().includes('android') || techStack.toLowerCase().includes('capacitor');
    return {
      simpleExplanation: `Yeh warning "${t}" dikhati hai ki aapke ${isApkTarget ? 'Android/Capacitor APK' : 'frontend bundle'} me Firebase Client API Key (${finding.proof || 'AIza...'}) maujood hai. Firebase Auth ke liye client key public rehna normal hai, lekin agar Google Cloud Console me ispar API restrictions na hon toh koi bhi is key se paid Gemini/GCP APIs use kar sakta hai.`,
      dangerScenario: 'Attacker JS bundle ya APK assets se AIza... key nikaal kar Google Generative Language API ya unconstrained GCP quotas par aapke billing account se requests chala sakta hai.',
      steps: [
        'Step 1: Google Cloud Console -> APIs & Services -> Credentials open karein aur is API Key par click karein.',
        isApkTarget
          ? 'Step 2: Application restrictions me "Android apps" select karke apna Package Name + SHA-1 fingerprint add karein.'
          : 'Step 2: Application restrictions me "Websites (HTTP referrers)" me sirf apna production domain (e.g. https://yourdomain.com/*) whitelist karein.',
        'Step 3: API restrictions me sirf Firebase / Identity Toolkit APIs allow karein aur Generative Language (Gemini) API ko uncheck rakhein.'
      ],
      codeBlock: {
        filename: 'Google Cloud Console -> API Key Restrictions (Checklist)',
        language: 'bash',
        code: isApkTarget
          ? `# 1. Application restriction: Android apps\n#    Package: com.yourapp.id\n#    SHA-1: <Release Keystore SHA-1>\n# 2. API restrictions: ONLY Firebase Installations, Identity Toolkit, Token Service\n# 3. NEVER enable Generative Language API on public mobile/web AIza keys!`
          : `# 1. Application restriction: Websites (HTTP referrers)\n#    Allowed: https://your-domain.vercel.app/*\n# 2. API restrictions: ONLY Identity Toolkit & Firebase APIs\n# 3. Move all Gemini / AI SDK calls strictly to backend process.env!`
      },
      verifyCommand: 'Check Google Cloud Console -> Credentials -> Ensure "Key restrictions: Active"',
      source: 'deterministic'
    };
  }

  if (isAndroid) {
    let filename = 'android/app/build.gradle / AndroidManifest.xml';
    let language = 'xml';
    let beforeCode = `<application\n    android:debuggable="true"\n    android:allowBackup="true"\n    android:usesCleartextTraffic="true" />`;
    let code = `<!-- Update AndroidManifest.xml / build.gradle -->\n<application\n    android:debuggable="false"\n    android:allowBackup="false"\n    android:usesCleartextTraffic="false" />`;
    let explanation = `Yeh mobile vulnerability "${t}" aapke Android APK configuration ya compiled bytecode me kamzori dikhati hai (${finding.proof || 'Manifest/DEX check'}).`;
    let danger = finding.description || 'Malicious apps ya attackers device ya network par is weakness ka galat fayda utha sakte hain.';
    let steps = [
      `Step 1: Apne Android project me ${filename} open karein.`,
      'Step 2: Neeche diya production-hardened configuration apply karein aur clean release build compile karein.',
      'Step 3: Naya .apk file CheckMyAPK.com par dobara upload karke score improvement verify karein.'
    ];

    if (t.includes('WebView') || t.includes('capacitor')) {
      filename = 'capacitor.config.ts (or capacitor.config.json)';
      language = 'json';
      beforeCode = `{\n  "server": { "cleartext": true },\n  "android": { "allowMixedContent": true, "webContentsDebuggingEnabled": true }\n}`;
      explanation = `Aapke Capacitor/Hybrid APK config me "${t}" detect hua hai (${finding.proof || 'cleartext=true'}). Jab server.cleartext true hota hai toh Capacitor CLI sync ke waqt plugins manifest me android:usesCleartextTraffic="true" inject karta hai aur unencrypted HTTP traffic allow ho sakta hai.`;
      danger = 'Public Wi-Fi, hotspot, ya compromised router par baitha attacker Man-in-the-Middle (MitM) attack karke plain HTTP network traffic sniff kar sakta hai ya WebView me malicious JavaScript inject kar sakta hai.';
      steps = [
        'Step 1: Apne root project me capacitor.config.ts (ya capacitor.config.json) open karein — existing appId, appName, webDir aur plugins ko DELETE na karein.',
        'Step 2: Sirf server.cleartext ko false aur android security flags ko niche dikhaye anusaar merge/update karein.',
        'Step 3: "npm run build && npx cap sync android" chalayein taaki plugins manifest se usesCleartextTraffic="true" hat jaye, phir release APK dubara build karein.'
      ];
      code = `// Merge into your EXISTING capacitor.config.ts / .json (keep appId, webDir & plugins!)\n{\n  "server": {\n    "cleartext": false,\n    "androidScheme": "https"\n  },\n  "android": {\n    "allowMixedContent": false,\n    "webContentsDebuggingEnabled": false\n  }\n}`;
    } else if (t.includes('Certificate Pinning')) {
      filename = 'res/xml/network_security_config.xml';
      explanation = `App me SSL/TLS Certificate Pinning active nahi dikh rahi hai (${finding.proof || 'no pin-set / CertificatePinner'}).`;
      code = `<domain-config cleartextTrafficPermitted="false">\n  <domain includeSubdomains="true">api.yourapp.com</domain>\n  <pin-set expiration="2027-12-31">\n    <pin digest="SHA-256">PRIMARY_SPKI_BASE64_HASH=</pin>\n    <pin digest="SHA-256">BACKUP_SPKI_BASE64_HASH=</pin>\n  </pin-set>\n</domain-config>`;
    } else if (t.includes('Cleartext') || t.includes('CA Certificates') || t.includes('network_security_config') || t.includes('SSL')) {
      filename = 'res/xml/network_security_config.xml';
      explanation = `Network transport flaw "${t}" (${finding.proof || 'TLS/Cleartext config'}) aapke app ke HTTPS/TLS guarantees ko kamzor karta hai.`;
      danger = 'Public Wi-Fi par Man-in-the-Middle (MitM) attacker network packets intercept karke user session tokens, API responses, ya credentials padh/badal sakta hai.';
    } else if (t.includes('Exported')) {
      filename = 'AndroidManifest.xml';
      explanation = `IPC exposure "${t}" (${finding.proof || 'exported=true'}) bina permission guard ke internal components ko bahar expose karta hai.`;
      steps = [
        'Step 1: AndroidManifest.xml me flagged Activity/Service/Receiver/Provider dhoondhein.',
        'Step 2: Internal components par android:exported="false" ya signature-level android:permission lagayein.',
        'Step 3: Release APK recompile karke CheckMyAPK.com par dubara scan karein.'
      ];
      code = `<service android:name=".InternalService" android:exported="false" />\n<receiver android:name=".InternalReceiver" android:exported="false" />`;
    } else if (t.includes('Encryption')) {
      filename = 'CryptoHelper.kt';
      language = 'kotlin';
      explanation = `Weak cryptographic algorithm "${t}" (${finding.proof || 'AES/ECB or DES'}) bytecode me paya gaya hai, jisse encrypted data patterns leak ho sakte hain.`;
      code = `val cipher = Cipher.getInstance("AES/GCM/NoPadding")\nval iv = ByteArray(12).also { SecureRandom().nextBytes(it) }\ncipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))`;
    } else if (t.includes('Obfuscation')) {
      filename = 'android/app/build.gradle';
      language = 'groovy';
      explanation = `Release binary me ProGuard/R8 obfuscation missing dikh raha hai (${finding.proof || 'unminified classes'}), jisse JADX-GUI me code seedhe readable milta hai.`;
      code = `buildTypes {\n  release {\n    minifyEnabled true\n    shrinkResources true\n    proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'\n  }\n}`;
    } else if (t.includes('Native Library') || t.includes('Native ELF')) {
      filename = 'app/src/main/cpp/CMakeLists.txt';
      language = 'cmake';
      explanation = `Compiled C/C++ native shared library (.so) me binary hardening flags missing mile hain (${finding.proof || 'PIE/NX/RELRO/Canary'}).`;
      code = `set(CMAKE_C_FLAGS "\${CMAKE_C_FLAGS} -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2")\nset(CMAKE_CXX_FLAGS "\${CMAKE_CXX_FLAGS} -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2")\nset(CMAKE_SHARED_LINKER_FLAGS "\${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,noexecstack -Wl,-z,relro,-z,now")`;
    } else if (t.includes('Secret') || t.includes('resources.arsc')) {
      explanation = `Compiled APK ke andar sensitive secret (${finding.proof || 'DEX/resources.arsc'}) mila hai jise JADX-GUI ya apktool se seconds me extract kiya ja sakta hai.`;
    }

    return {
      simpleExplanation: explanation,
      dangerScenario: danger,
      steps,
      beforeCode,
      codeBlock: { filename, language, code },
      verifyCommand: 'npx cap sync android && ./gradlew assembleRelease',
      source: 'deterministic'
    };
  }

  // Finding-aware Web fallbacks
  let webFilename = techStack.toLowerCase().includes('next') ? 'next.config.js' : 'vercel.json';
  let webLang = techStack.toLowerCase().includes('next') ? 'javascript' : 'json';
  let webBefore = `// Missing X-Content-Type-Options, X-Frame-Options, HSTS headers in HTTP response`;
  let webCode = `{\n  "headers": [\n    {\n      "source": "/(.*)",\n      "headers": [\n        { "key": "X-Content-Type-Options", "value": "nosniff" },\n        { "key": "X-Frame-Options", "value": "SAMEORIGIN" },\n        { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" },\n        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" }\n      ]\n    }\n  ]\n}`;
  let verifyCmd = `curl -I ${targetUrl}`;

  if (t.includes('DOM XSS') || t.includes('Unsafe Dynamic Code Execution')) {
    webFilename = 'src/components/SafeRender.tsx (DOMPurify + No eval)';
    webLang = 'typescript';
    webBefore = `<div dangerouslySetInnerHTML={{ __html: untrustedHtml }} /> // or element.innerHTML = untrustedHtml;`;
    webCode = `import DOMPurify from 'dompurify';\n\n// Never pass raw strings into innerHTML, eval(), or unguarded dangerouslySetInnerHTML:\nconst cleanHtml = DOMPurify.sanitize(untrustedHtml);\nreturn <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;`;
  } else if (t.includes('postMessage')) {
    webFilename = 'src/utils/postMessageBridge.ts';
    webLang = 'typescript';
    webBefore = `window.addEventListener('message', (event) => handleSafePayload(event.data));\ntargetWindow.postMessage(payload, '*');`;
    webCode = `// 1. Validate exact origin on message listeners:\nwindow.addEventListener('message', (event) => {\n  if (event.origin !== 'https://app.yourdomain.com') return;\n  handleSafePayload(event.data);\n});\n\n// 2. Specify exact targetOrigin instead of wildcard '*':\ntargetWindow.postMessage(payload, 'https://app.yourdomain.com');`;
  } else if (t.includes('GraphQL')) {
    webFilename = 'server/graphql.ts (Disable Production Introspection)';
    webLang = 'typescript';
    webBefore = `const server = new ApolloServer({ typeDefs, resolvers, introspection: true });`;
    webCode = `const server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: process.env.NODE_ENV !== 'production'\n});`;
  } else if (t.includes('OpenAPI') || t.includes('Swagger')) {
    webFilename = 'server.ts (Gate Swagger UI / OpenAPI JSON)';
    webLang = 'typescript';
    webBefore = `app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(openApiSpec));`;
    webCode = `if (process.env.NODE_ENV !== 'production') {\n  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(openApiSpec));\n}\n// Or protect /openapi.json behind admin auth middleware!`;
  } else if (t.includes('JWT') && !t.includes('LocalStorage')) {
    webFilename = 'server/auth/jwtVerifier.ts';
    webLang = 'typescript';
    webBefore = `const token = jwt.sign({ id: user.id, password: user.password }, SECRET);\nconst decoded = jwt.decode(token); // trusts alg: "none"`;
    webCode = `import jwt from 'jsonwebtoken';\n\n// 1. Sign with short TTL & zero PII:\nconst token = jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET!, {\n  algorithm: 'HS256',\n  expiresIn: '15m'\n});\n\n// 2. Reject "alg: none" strictly by pinning algorithms:\nconst decoded = jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] });`;
  } else if (t.includes('Stack Trace') || t.includes('Unauthenticated API Endpoint')) {
    webFilename = 'server/middleware/apiSecurity.ts';
    webLang = 'typescript';
    webCode = `// Require auth middleware on user/admin routes and sanitize error output:\napp.get('/api/users', requireAuth, async (req, res) => {\n  res.json({ users: safePublicDtos }); // Never expose passwordHash/secrets\n});\n\napp.use((err, req, res, next) => {\n  console.error(err);\n  res.status(500).json({ error: 'Internal server error' });\n});`;
  } else if (t.includes('.env') || t.includes('.git')) {
    webFilename = 'nginx.conf / hosting dashboard';
    webLang = 'bash';
    webCode = `# Block dotfiles (.env, .git) on Nginx/Apache and rotate all leaked credentials immediately!\nlocation ~ /\\. {\n  deny all;\n  return 404;\n}`;
    verifyCmd = `curl -i ${targetUrl.replace(/\/$/, '')}/.env`;
  } else if (t.includes('Source Map') || t.includes('.js.map')) {
    webFilename = 'vite.config.ts / next.config.js';
    webLang = 'javascript';
    webCode = `// Vite:\nexport default defineConfig({ build: { sourcemap: false } });\n// Next.js:\nmodule.exports = { productionBrowserSourceMaps: false };`;
  } else if (t.includes('Cookie') || t.includes('LocalStorage')) {
    webFilename = 'server.ts (Session Cookie Policy)';
    webLang = 'typescript';
    webCode = `res.cookie('session', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict',\n  maxAge: 7 * 24 * 60 * 60 * 1000\n});`;
  } else if (t.includes('Firebase') || t.includes('Supabase') || t.includes('Database')) {
    webFilename = t.includes('Supabase') ? 'supabase-rls.sql' : 'firestore.rules';
    webLang = t.includes('Supabase') ? 'sql' : 'javascript';
    webCode = t.includes('Supabase')
      ? `ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "Owner only" ON your_table FOR ALL USING (auth.uid() = user_id);`
      : `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /users/{userId} { allow read, write: if request.auth != null && request.auth.uid == userId; }\n  }\n}`;
  } else if (t.includes('CORS')) {
    webFilename = 'server.ts (CORS Whitelist)';
    webLang = 'typescript';
    webCode = `const ALLOWED = new Set(['https://yourdomain.com']);\napp.use(cors({ origin: (o, cb) => cb(null, !o || ALLOWED.has(o)), credentials: true }));`;
  } else if (t.includes('Key') || t.includes('Secret') || t.includes('MongoDB') || t.includes('Private Cryptographic')) {
    webFilename = '.env + Backend API Proxy';
    webLang = 'typescript';
    webCode = `// Move raw API keys/secrets strictly to backend process.env and rotate exposed keys immediately!\napp.post('/api/proxy', async (req, res) => {\n  const key = process.env.PRIVATE_API_KEY;\n  // forward securely from server\n});`;
  } else if (t.includes('Rate Limit')) {
    webFilename = 'server.ts (express-rate-limit)';
    webLang = 'typescript';
    webCode = `import rateLimit from 'express-rate-limit';\napp.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));`;
  }

  return {
    simpleExplanation: `Yeh web vulnerability "${t}" aapke ${techStack} application server response ya frontend bundle me detect hui hai (${finding.proof || 'HTTP probe'}).`,
    dangerScenario: finding.description || 'Attackers missing defense headers, leaked files, ya permissive policies ka fayda utha kar XSS, clickjacking, ya credential theft kar sakte hain.',
    steps: [
      `Step 1: Apne project (${techStack}) me ${webFilename} open karein.`,
      'Step 2: Neeche diya hardened snippet apply karein (aur agar koi key/file leak hui hai toh secret rotate karein).',
      'Step 3: Production deploy karein aur CheckMyAPK.com ya verify command se re-test karein.'
    ],
    beforeCode: webBefore,
    codeBlock: { filename: webFilename, language: webLang, code: webCode },
    verifyCommand: verifyCmd,
    source: 'deterministic'
  };
}

export interface AiAuditSummary {
  executiveSummary: string;
  threatLevel: string;
  topAttackVector: string;
  actionablePlan: string[];
}

export async function generateAiSecuritySummary(
  targetUrl: string, 
  findings: any[],
  meta: { serverHeader?: string; scriptsCount: number; detectedTech: string[] }
): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return buildDeterministicWebSummary(targetUrl, findings, meta);
  }

  try {
    const ai = new GoogleGenAI({ apiKey });
    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = findings.filter(f => f.severity === 'HIGH').length;
    const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
    const passedCount = findings.filter(f => f.severity === 'PASS').length;
    const prioritizedFindings = [...findings.filter(f => f.severity !== 'PASS'), ...findings.filter(f => f.severity === 'PASS')].slice(0, 12);

    const prompt = `You are a Principal Cybersecurity Architect & Penetration Tester conducting a rigorous vulnerability audit on an application.
Target: ${targetUrl}
Detected Tech Stack: ${meta.detectedTech.length > 0 ? meta.detectedTech.join(', ') : 'Custom Web App'}
Server Signature: ${meta.serverHeader || 'Hidden / Custom'}
Audited JavaScript Bundles: ${meta.scriptsCount}
Vulnerability Telemetry:
- Critical Vulnerabilities: ${criticalCount}
- High-Risk Vulnerabilities: ${highCount}
- Medium-Risk Vulnerabilities: ${mediumCount}
- Verified Defenses (Passed): ${passedCount}

Findings Details:
${JSON.stringify(prioritizedFindings, null, 2)}

Write a deeply specific, highly professional, non-generic Security Posture Assessment (130-160 words).
Structure your response into 3 crisp sections:
1. 🛡️ THREAT LANDSCAPE: Direct assessment of ${targetUrl}'s exposure based on the detected stack and findings. Mention specific technologies or files found.
2. 🚨 PRIMARY ATTACK VECTOR: Explain the exact way an attacker would exploit the weakest link found in this audit.
3. ⚡ 24-HOUR REMEDIATION ROADMAP: Give 2-3 precise engineering tasks the development team must execute immediately.

Avoid generic placeholder phrases. Speak directly to the engineering team of this application.`;

    const cacheKey = getCacheKey('web', { targetUrl, prioritizedFindings: prioritizedFindings.map(f => `${f.type}:${f.severity}`) });
    const aiText = await generateWithFastTimeout(ai, prompt, undefined, cacheKey, apiKey);
    return aiText || buildDeterministicWebSummary(targetUrl, findings, meta);
  } catch (err: any) {
    console.error('[AI Advisor] Gemini generation failed:', err.message);
    return buildDeterministicWebSummary(targetUrl, findings, meta);
  }
}

/**
 * 🤖 Deep AI Vulnerability Doctor:
 * Generates an in-depth, beginner-friendly explanation and exact copy-paste code fix
 * for any specific vulnerability found during testing.
 */
export async function generateVulnerabilityDeepFix(
  finding: any,
  detectedTech: string[],
  targetUrl: string,
  userFramework?: string
): Promise<{
  simpleExplanation: string;
  dangerScenario: string;
  steps: string[];
  beforeCode?: string;
  codeBlock: { filename: string; language: string; code: string };
  verifyCommand: string;
  source: 'gemini' | 'deterministic';
}> {
  const apiKey = process.env.GEMINI_API_KEY;
  const techStack = userFramework || (detectedTech.length > 0 ? detectedTech.join(', ') : 'React / Node.js / Vercel');

  if (!apiKey) {
    return buildDeterministicDeepFix(finding, techStack, targetUrl);
  }

  const cacheKey = getCacheKey('fix', { type: finding.type, techStack, targetUrl });
  try {
    const ai = new GoogleGenAI({ apiKey });
    const prompt = `You are an elite Cybersecurity Engineer and DevSecOps mentor helping a developer fix a security vulnerability.
Target URL: ${targetUrl}
Detected Tech Stack: ${techStack}
Vulnerability Title: ${finding.type}
Severity: ${finding.severity}
Finding Proof / Trigger: ${finding.proof || 'N/A'}
Description: ${finding.description || 'N/A'}

Explain this in crystal-clear, developer-friendly language (Hinglish/English mix that Indian developers love, simple and practical).
Your response MUST be strict valid JSON matching this schema:
{
  "simpleExplanation": "2-3 sentences in simple Hinglish explaining what this flaw actually is and why it happened.",
  "dangerScenario": "2-3 sentences explaining exactly how a hacker or malicious user can exploit this weakness in real life.",
  "steps": [
    "Step 1: Open [exact file, e.g. vercel.json, next.config.js, AndroidManifest.xml, or server.ts]",
    "Step 2: Add or replace the code shown below",
    "Step 3: Deploy/build the updated app and verify"
  ],
  "beforeCode": "Short 1-4 line example of the insecure/vulnerable pattern before the fix.",
  "codeBlock": {
    "filename": "Exact file name (e.g. vercel.json, AndroidManifest.xml, capacitor.config.json, server.js)",
    "language": "json | javascript | typescript | xml | kotlin | groovy | bash",
    "code": "Ready-to-copy, production-ready code snippet fixing this exact vulnerability for ${techStack}."
  },
  "verifyCommand": "Terminal command (e.g. curl -I https://... or ./gradlew assembleRelease) to verify that the fix is working."
}

Do NOT wrap with markdown quotes other than standard JSON.`;

    const rawJson = await generateWithFastTimeout(ai, prompt, { responseMimeType: 'application/json' }, cacheKey, apiKey);
    if (!rawJson) {
      return buildDeterministicDeepFix(finding, techStack, targetUrl);
    }
    const parsed = JSON.parse(rawJson);
    const fallback = buildDeterministicDeepFix(finding, techStack, targetUrl);
    return {
      simpleExplanation: parsed.simpleExplanation || fallback.simpleExplanation,
      dangerScenario: parsed.dangerScenario || fallback.dangerScenario,
      steps: parsed.steps || fallback.steps,
      beforeCode: parsed.beforeCode || fallback.beforeCode,
      codeBlock: parsed.codeBlock || fallback.codeBlock,
      verifyCommand: parsed.verifyCommand || fallback.verifyCommand,
      source: 'gemini'
    };
  } catch (err: any) {
    console.error('[AI Advisor] Deep Fix generation failed:', err.message);
    return buildDeterministicDeepFix(finding, techStack, targetUrl);
  }
}

/**
 * 📱 Mobile APK Penetration Testing Threat Assessment:
 * Evaluates binary protections, reverse-engineering vectors, and MASVS compliance.
 */
export async function generateAiMobileAssessment(
  meta: {
    packageName: string;
    frameworkDetected: string;
    targetSdkVersion?: number;
    dexCount: number;
    fileSizeMb: string;
    architectures: string[];
    permissionsCount: number;
    obfuscationStatus?: string;
    exportedTotal?: number;
    unprotectedIpc?: number;
    trackers?: string[];
    sdks?: string[];
    probedApisCount?: number;
  },
  findings: any[]
): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return buildDeterministicMobileSummary(meta, findings);
  }

  try {
    const ai = new GoogleGenAI({ apiKey });
    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = findings.filter(f => f.severity === 'HIGH').length;
    const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
    const prioritizedFindings = [...findings.filter(f => f.severity !== 'PASS'), ...findings.filter(f => f.severity === 'PASS')].slice(0, 10);

    const prompt = `You are a Senior Mobile Penetration Tester & Reverse Engineer conducting an OWASP MASVS v2 security audit on an Android APK.
Target Package: ${meta.packageName}
Mobile Framework: ${meta.frameworkDetected}
Target SDK: ${meta.targetSdkVersion || 34}
Dalvik DEX Files: ${meta.dexCount} (${meta.fileSizeMb} MB)
Obfuscation Status: ${meta.obfuscationStatus || 'Checked'}
Native ABIs: ${meta.architectures.join(', ') || 'Pure Java/Kotlin'}
Declared Permissions: ${meta.permissionsCount}
Exported IPC Components: ${meta.exportedTotal || 0} (${meta.unprotectedIpc || 0} unprotected)
Trackers: ${(meta.trackers || []).join(', ') || 'None'}
Embedded SDKs: ${(meta.sdks || []).join(', ') || 'None'}
Stage 3 Probed Backend Endpoints: ${meta.probedApisCount || 0}

Vulnerability Findings:
- Critical Findings: ${criticalCount}
- High-Risk Findings: ${highCount}
- Medium-Risk Findings: ${mediumCount}
Details:
${JSON.stringify(prioritizedFindings, null, 2)}

Write an executive-level Mobile Application Security Posture (140-170 words).
Structure your response into 3 crisp sections:
1. 📱 REVERSE-ENGINEERING RESILIENCE: Assess how vulnerable this APK is if an attacker decompiles it using JADX-GUI, Apktool, or attaches Frida. Mention the framework (${meta.frameworkDetected}), obfuscation status, and specific components/trackers found.
2. 🚨 CRITICAL THREAT EXPOSURE: Explain the exact way an attacker can exploit the worst vulnerability detected (e.g. WebView cleartext, exported component, hardcoded keys, or Stage 3 backend exposure).
3. ⚡ ANDROID STUDIO REMEDIATION ROADMAP: Give 2-3 precise code adjustments in AndroidManifest.xml, capacitor.config.json, or build.gradle for the engineering team.

Avoid generic boilerplate phrases. Speak directly to the Android development team.`;

    const cacheKey = getCacheKey('mobile', {
      packageName: meta.packageName,
      findings: prioritizedFindings.map(f => `${f.type}:${f.severity}`)
    });
    const mobileText = await generateWithFastTimeout(ai, prompt, undefined, cacheKey, apiKey);
    return mobileText || buildDeterministicMobileSummary(meta, findings);
  } catch (err: any) {
    console.error('[AI Advisor] Mobile Gemini generation failed:', err.message);
    return buildDeterministicMobileSummary(meta, findings);
  }
}

