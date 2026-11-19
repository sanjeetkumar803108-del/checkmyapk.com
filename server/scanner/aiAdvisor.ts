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

  const models = ['gemini-3.8-flash', 'gemini-3.7-flash', 'gemini-3.5-flash'];
  let sawQuotaExhausted = false;
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
      if (msg.includes('429') || msg.includes('RESOURCE_EXHAUSTED')) {
        sawQuotaExhausted = true;
        console.warn(`[AI Advisor] ${modelName} quota exhausted (429); trying fallback model...`);
      } else {
        console.warn(`[AI Advisor] ${modelName} skipped:`, msg.slice(0, 220));
      }
    }
  }
  if (apiKey && sawQuotaExhausted) {
    cooldownKey = apiKey;
    geminiCooldownUntil = Date.now() + 60_000;
    console.warn(`[AI Advisor] All Gemini models hit quota limits (429); activating 60s deterministic fallback mode.`);
  }
  return null;
}

export interface CompoundAttackChain {
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  summary: string;
  components: string[];
}

export function detectCompoundAttackChains(findings: any[], isApk: boolean): CompoundAttackChain[] {
  const vulns = findings.filter((f) => f && f.severity !== 'PASS' && f.severity !== 'INFO');
  const titles = vulns.map((f) => String(f.type || '').toLowerCase());
  const hasAny = (rx: RegExp) => titles.some((t) => rx.test(t));
  const matchTitles = (rx: RegExp) =>
    vulns.filter((f) => rx.test(String(f.type || ''))).map((f) => String(f.type)).slice(0, 2);

  const chains: CompoundAttackChain[] = [];

  if (!isApk) {
    const hasXssVector = hasAny(/dom xss|unsafe dynamic code|unencoded query reflection|postmessage/i);
    const hasNoCsp = hasAny(/missing content-security-policy/i);
    const hasClientToken = hasAny(/localstorage|no httponly|hardcoded jwt/i);
    if (hasXssVector && (hasNoCsp || hasClientToken)) {
      chains.push({
        title: 'Client Session Hijack & Account Takeover Chain',
        severity: 'CRITICAL',
        components: [
          ...matchTitles(/dom xss|unsafe dynamic code|unencoded query reflection|postmessage/i),
          ...matchTitles(/missing content-security-policy|localstorage|no httponly/i),
        ].slice(0, 3),
        summary:
          'Missing Content-Security-Policy or client-readable auth storage combined with unguarded DOM sinks / unencoded reflection allows script injection flaws to steal active user sessions directly.',
      });
    }

    const hasCors = hasAny(/cors origin reflection|permissive cors/i);
    const hasApiOrAuth = hasAny(/unauthenticated api|graphql|openapi|jwt|no active rate limit/i);
    if (hasCors && hasApiOrAuth) {
      chains.push({
        title: 'Cross-Origin API & Data Exfiltration Chain',
        severity: 'CRITICAL',
        components: [
          ...matchTitles(/cors origin reflection|permissive cors/i),
          ...matchTitles(/unauthenticated api|graphql|openapi|jwt|no active rate limit/i),
        ].slice(0, 3),
        summary:
          'Permissive cross-origin headers paired with exposed API schemas, weak JWT claims, or missing rate limits allow external malicious origins to query backend endpoints with user credentials.',
      });
    }

    const hasInfraExpose = hasAny(/\.env|\.git|actuator|publicly listable.*bucket|firebase.*readable|supabase.*exposed/i);
    const hasSecrets = hasAny(/key|secret|mongodb|private cryptographic/i);
    if (hasInfraExpose || (hasSecrets && vulns.filter((v) => v.severity === 'CRITICAL').length >= 1)) {
      if (hasInfraExpose && hasSecrets) {
        chains.push({
          title: 'Cloud Storage & Exposed Credential Pivot Chain',
          severity: 'CRITICAL',
          components: [
            ...matchTitles(/\.env|\.git|actuator|publicly listable.*bucket|firebase|supabase/i),
            ...matchTitles(/key|secret|mongodb/i),
          ].slice(0, 3),
          summary:
            'Exposed environment/storage infrastructure alongside client-accessible credentials enables direct unauthorized access to cloud buckets, databases, or billed third-party APIs.',
        });
      }
    }

    const hasCve = hasAny(/known vulnerable library|outdated .* library/i);
    const hasNoSri = hasAny(/missing subresource integrity/i);
    if (hasCve && hasNoSri) {
      chains.push({
        title: 'Frontend Supply-Chain Dependency Exposure Chain',
        severity: 'HIGH',
        components: [...matchTitles(/known vulnerable library|outdated .* library/i), ...matchTitles(/subresource integrity/i)].slice(0, 3),
        summary:
          'Known vulnerable client libraries served alongside unpinned external CDN scripts without Subresource Integrity expand frontend script-tampering risk.',
      });
    }
  } else {
    const hasNetworkIntercept = hasAny(/cleartext|trustmanager|hostnameverifier|ssl error|ssl \/ tls certificate validation bypass/i);
    const hasNoPinning = hasAny(/no ssl \/ tls certificate pinning/i);
    const hasApiSecrets = hasAny(/secret|api key|gemini|token|cleartext http urls/i);
    if (hasNetworkIntercept && (hasNoPinning || hasApiSecrets)) {
      chains.push({
        title: 'Zero-Resistance MitM Traffic & Credential Interception Chain',
        severity: 'CRITICAL',
        components: [
          ...matchTitles(/cleartext|trustmanager|hostnameverifier|ssl error|validation bypass/i),
          ...matchTitles(/certificate pinning|secret|api key/i),
        ].slice(0, 3),
        summary:
          'Cleartext traffic or disabled certificate verification combined with absent certificate pinning lets on-path Wi-Fi attackers intercept auth headers and API payloads cleanly.',
      });
    }

    const hasIpc = hasAny(/exported|deep link hijacking/i);
    const hasWebViewOrTaint = hasAny(/webview|cross-method|taint|javascript bridge|allowuniversalaccess/i);
    if (hasIpc && hasWebViewOrTaint) {
      chains.push({
        title: 'IPC Intent / Deep-Link Hijack to WebView / Native Sink Chain',
        severity: 'CRITICAL',
        components: [...matchTitles(/exported|deep link hijacking/i), ...matchTitles(/webview|cross-method|taint|javascript bridge/i)].slice(0, 3),
        summary:
          'Unprotected exported activities/deep links paired with unguarded WebView bridges or Intent taint flows let co-resident malicious apps route untrusted URIs directly into privileged sinks.',
      });
    }

    const hasUnobfuscated = hasAny(/obfuscation not detected|debuggable/i);
    const hasCryptoOrSecret = hasAny(/secret|api key|secretkeyspec|ivparameterspec|weak cipher/i);
    if (hasUnobfuscated && hasCryptoOrSecret) {
      chains.push({
        title: 'Rapid Decompilation Secret & Cipher Key Recovery Chain',
        severity: 'HIGH',
        components: [...matchTitles(/obfuscation|debuggable/i), ...matchTitles(/secret|api key|secretkeyspec|weak cipher/i)].slice(0, 3),
        summary:
          'Readable release symbols (missing R8/ProGuard) allow attackers using JADX to locate hardcoded secrets, static encryption keys, or weak cipher routines within seconds.',
      });
    }

    const hasBackupOrLog = hasAny(/allowbackup|sensitive data logged|biometricprompt.*without cryptoobject/i);
    if (hasBackupOrLog && vulns.length >= 2 && hasAny(/allowbackup/i) && hasAny(/sensitive data logged|biometricprompt/i)) {
      chains.push({
        title: 'Local Device Data Extraction & Auth Bypass Chain',
        severity: 'HIGH',
        components: matchTitles(/allowbackup|sensitive data logged|biometricprompt/i).slice(0, 3),
        summary:
          'Enabled ADB backups alongside sensitive debug logs or event-only biometric prompts increase local credential exposure on stolen or USB-debugged devices.',
      });
    }
  }

  return chains.slice(0, 3);
}

function buildDeterministicWebSummary(
  targetUrl: string,
  findings: any[],
  meta: { serverHeader?: string; scriptsCount: number; detectedTech: string[] }
): string {
  const vulns = findings.filter(f => f.severity !== 'PASS' && f.severity !== 'INFO');
  const criticals = vulns.filter(f => f.severity === 'CRITICAL');
  const highs = vulns.filter(f => f.severity === 'HIGH');
  const topVuln = criticals[0] || highs[0] || vulns[0];
  const stackLabel = meta.detectedTech.length > 0 ? meta.detectedTech.join(', ') : 'Custom Web App';
  const uniqueTopTypes = Array.from(new Set(vulns.map(v => String(v.type)))).slice(0, 3);
  const chains = detectCompoundAttackChains(findings, false);

  if (vulns.length === 0) {
    return `1. 🛡️ THREAT LANDSCAPE: ${targetUrl} (${stackLabel}) passed all ${findings.length} automated web security probes across ${meta.scriptsCount} JS bundles with zero critical or high exposures.\n2. 🚨 PRIMARY ATTACK VECTOR: Client-side bundle inspection and HTTP header enforcement look hardened; remain vigilant on authenticated server API endpoints.\n3. ⚡ 24-HOUR REMEDIATION ROADMAP: Keep CSP policies strict without 'unsafe-eval', and audit backend API routes individually for IDOR/BOLA authorization.`;
  }

  const serverIncluded =
    Boolean(meta.serverHeader) &&
    stackLabel.toLowerCase().includes(String(meta.serverHeader).toLowerCase());
  const stackSummary = `${stackLabel}${meta.serverHeader && !serverIncluded ? `, ${meta.serverHeader}` : ''}`;
  const chainText = chains[0]
    ? `Compound risk — ${chains[0].title}: ${chains[0].summary}`
    : `Highest priority weakness is "${topVuln.type}" (${topVuln.severity}) — ${topVuln.description}`;

  return `1. 🛡️ THREAT LANDSCAPE: ${targetUrl} (${stackSummary}) exposed ${vulns.length} security issue(s) (${criticals.length} Critical, ${highs.length} High) across ${meta.scriptsCount} audited JS bundles.\n2. 🚨 PRIMARY ATTACK VECTOR: ${chainText}\n3. ⚡ 24-HOUR REMEDIATION ROADMAP: (1) Resolve "${topVuln.type}" immediately using the recommended patch; (2) Address top priorities (${uniqueTopTypes.join(', ')}); (3) Re-run CheckMyAPK to confirm score uplift.`;
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
  const vulns = findings.filter(f => f.severity !== 'PASS' && f.severity !== 'INFO');
  const topVuln =
    vulns.find(f => f.severity === 'CRITICAL') ||
    vulns.find(f => f.severity === 'HIGH') ||
    vulns[0];
  const chains = detectCompoundAttackChains(findings, true);

  const trackerNote =
    meta.trackers && meta.trackers.length > 0
      ? `Embedded trackers (${meta.trackers.slice(0, 3).join(', ')}) were fingerprinted.`
      : 'Minimal ad/tracking footprint detected.';

  if (!topVuln) {
    return `1. 📱 REVERSE-ENGINEERING RESILIENCE: ${meta.packageName} (${meta.frameworkDetected}, Target SDK ${meta.targetSdkVersion || 34}, Obfuscation: ${meta.obfuscationStatus || 'Checked'}) passed all static DEX, Manifest IPC (${meta.exportedTotal || 0} exported), and Stage 3 API (${meta.probedApisCount || 0} endpoints) checks cleanly. ${trackerNote}\n2. 🚨 CRITICAL THREAT EXPOSURE: No high-risk client secret leaks, debuggable flags, or cleartext traffic gaps found.\n3. ⚡ ANDROID STUDIO REMEDIATION ROADMAP: Maintain minifyEnabled true in build.gradle release builds, add OkHttp CertificatePinner for sensitive APIs, and verify Play Console Data Safety matches SDK behavior.`;
  }

  const chainText = chains[0]
    ? `Chained risk — ${chains[0].title}: ${chains[0].summary}`
    : `Primary risk is "${topVuln.type}" (${topVuln.severity}) — ${topVuln.description}`;

  return `1. 📱 REVERSE-ENGINEERING RESILIENCE: Audited ${meta.packageName} (${meta.frameworkDetected}, ${meta.dexCount} DEX / ${meta.fileSizeMb} MB, ${meta.obfuscationStatus || 'Binary Audited'}). Inspected ${meta.exportedTotal || 0} exported IPC components (${meta.unprotectedIpc || 0} unprotected) and ${meta.probedApisCount || 0} live backend endpoints. ${trackerNote}\n2. 🚨 CRITICAL THREAT EXPOSURE: ${chainText}\n3. ⚡ ANDROID STUDIO REMEDIATION ROADMAP: (1) ${topVuln.remediation} (2) Re-build signed release APK/AAB; (3) Re-upload to CheckMyAPK to verify Stage 3 + DEX resolution.`;
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
    t.includes('AAB') ||
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
    t.includes('Tapjacking') ||
    t.includes('FLAG_SECURE') ||
    t.includes('BiometricPrompt') ||
    t.includes('Logcat') ||
    t.includes('Deep Link') ||
    t.includes('assetlinks.json');

  if (isFirebaseClientKey) {
    const isApkTarget = techStack.toLowerCase().includes('android') || techStack.toLowerCase().includes('capacitor');
    return {
      simpleExplanation: `• This warning (${t}) indicates that a Firebase Client API Key (${finding.proof || 'AIza...'}) is embedded in your ${isApkTarget ? 'Android/Capacitor APK' : 'frontend bundle'}.\n• While Firebase client keys are intentionally public for Authentication, leaving them unrestricted in Google Cloud Console exposes paid GCP and Gemini quotas.`,
      dangerScenario: `• An attacker can extract the AIza... key from your ${isApkTarget ? 'APK assets' : 'JS bundle'} within seconds.\n• If Generative Language or other APIs are enabled without application restrictions, the attacker can run requests billed directly to your Google Cloud account.`,
      steps: [
        'Open Google Cloud Console -> APIs & Services -> Credentials and select this API key.',
        isApkTarget
          ? 'Under Application restrictions, select "Android apps" and add your Package Name + Release SHA-1 fingerprint.'
          : 'Under Application restrictions, select "Websites (HTTP referrers)" and allow only your production domain (e.g., https://yourdomain.com/*).',
        'Under API restrictions, permit only Firebase / Identity Toolkit APIs and ensure Generative Language (Gemini) API is unchecked.'
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
    let explanation = `• This mobile finding (${t}) indicates a security weakness in your Android APK configuration or compiled bytecode.\n• Evidence detected: ${finding.proof || 'Manifest/DEX check'}.`;
    let danger = `• ${finding.description || 'Malicious apps or network attackers can exploit this configuration to intercept traffic or access app internals.'}\n• Left unpatched, this increases reverse-engineering and data-exposure risk on end-user devices.`;
    let steps = [
      `Open ${filename} in your Android project.`,
      'Apply the production-hardened configuration below and compile a clean release build.',
      'Re-upload the signed release .apk to CheckMyAPK.com to verify the score improvement.'
    ];

    if (t.includes('WebView') || t.includes('capacitor')) {
      filename = 'capacitor.config.ts (or capacitor.config.json)';
      language = 'json';
      beforeCode = `{\n  "server": { "cleartext": true },\n  "android": { "allowMixedContent": true, "webContentsDebuggingEnabled": true }\n}`;
      explanation = `• Your Capacitor/Hybrid APK configuration enables "${t}" (${finding.proof || 'cleartext=true'}).\n• When server.cleartext is true, Capacitor injects android:usesCleartextTraffic="true" during sync and allows unencrypted HTTP traffic.`;
      danger = `• An attacker on public Wi-Fi, a hotspot, or a compromised router can perform a Man-in-the-Middle (MitM) attack.\n• Plaintext HTTP traffic can be sniffed or modified to inject malicious JavaScript into the WebView.`;
      steps = [
        'Open capacitor.config.ts (or capacitor.config.json) in your project root — keep your existing appId, appName, webDir, and plugins intact.',
        'Set server.cleartext to false and update the android security flags as shown below.',
        'Run "npm run build && npx cap sync android" to remove usesCleartextTraffic="true" from the merged manifest, then rebuild the release APK.'
      ];
      code = `// Merge into your EXISTING capacitor.config.ts / .json (keep appId, webDir & plugins!)\n{\n  "server": {\n    "cleartext": false,\n    "androidScheme": "https"\n  },\n  "android": {\n    "allowMixedContent": false,\n    "webContentsDebuggingEnabled": false\n  }\n}`;
    } else if (t.includes('Certificate Pinning')) {
      filename = 'res/xml/network_security_config.xml';
      explanation = `• SSL/TLS Certificate Pinning is not enforced in the application (${finding.proof || 'no pin-set / CertificatePinner'}).\n• Without pinning, any trusted or rogue root CA installed on the device can intercept HTTPS requests.`;
      code = `<domain-config cleartextTrafficPermitted="false">\n  <domain includeSubdomains="true">api.yourapp.com</domain>\n  <pin-set expiration="2027-12-31">\n    <pin digest="SHA-256">PRIMARY_SPKI_BASE64_HASH=</pin>\n    <pin digest="SHA-256">BACKUP_SPKI_BASE64_HASH=</pin>\n  </pin-set>\n</domain-config>`;
    } else if (t.includes('Cleartext') || t.includes('CA Certificates') || t.includes('network_security_config') || t.includes('SSL')) {
      filename = 'res/xml/network_security_config.xml';
      explanation = `• The network transport issue "${t}" (${finding.proof || 'TLS/Cleartext config'}) weakens HTTPS/TLS guarantees in your app.\n• Unencrypted traffic or user-trusted CAs allow interception of sensitive API payloads.`;
      danger = `• A Man-in-the-Middle (MitM) attacker on public Wi-Fi can intercept or alter session tokens, API responses, and user credentials in transit.\n• User-installed proxy CAs can decrypt HTTPS traffic without triggering SSL errors.`;
    } else if (t.includes('Exported')) {
      filename = 'AndroidManifest.xml';
      explanation = `• The IPC exposure "${t}" (${finding.proof || 'exported=true'}) exposes internal Android components without a permission guard.\n• Third-party apps on the same device can invoke these components directly.`;
      steps = [
        'Locate the flagged Activity, Service, Receiver, or Provider in AndroidManifest.xml.',
        'Set android:exported="false" on internal components, or require a signature-level android:permission.',
        'Rebuild the release APK and re-scan it on CheckMyAPK.com to confirm resolution.'
      ];
      code = `<service android:name=".InternalService" android:exported="false" />\n<receiver android:name=".InternalReceiver" android:exported="false" />`;
    } else if (t.includes('Encryption')) {
      filename = 'CryptoHelper.kt';
      language = 'kotlin';
      explanation = `• A weak symmetric cipher mode "${t}" (${finding.proof || 'AES/ECB or DES'}) was detected in compiled bytecode.\n• Deterministic ECB blocks or legacy DES ciphers can leak plaintext patterns.`;
      code = `val cipher = Cipher.getInstance("AES/GCM/NoPadding")\nval iv = ByteArray(12).also { SecureRandom().nextBytes(it) }\ncipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))`;
    } else if (t.includes('Obfuscation')) {
      filename = 'android/app/build.gradle';
      language = 'groovy';
      explanation = `• ProGuard/R8 code obfuscation appears disabled in the release binary (${finding.proof || 'unminified classes'}).\n• Decompiling the APK with JADX-GUI exposes readable class, method, and variable names.`;
      code = `buildTypes {\n  release {\n    minifyEnabled true\n    shrinkResources true\n    proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'\n  }\n}`;
    } else if (t.includes('Native Library') || t.includes('Native ELF')) {
      filename = 'app/src/main/cpp/CMakeLists.txt';
      language = 'cmake';
      explanation = `• Compiled C/C++ native shared libraries (.so) are missing binary hardening flags (${finding.proof || 'PIE/NX/RELRO/Canary'}).\n• Missing exploit mitigations make memory-corruption bugs easier to weaponize.`;
      code = `set(CMAKE_C_FLAGS "\${CMAKE_C_FLAGS} -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2")\nset(CMAKE_CXX_FLAGS "\${CMAKE_CXX_FLAGS} -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2")\nset(CMAKE_SHARED_LINKER_FLAGS "\${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,noexecstack -Wl,-z,relro,-z,now")`;
    } else if (t.includes('FLAG_SECURE')) {
      filename = 'MainActivity.kt';
      language = 'kotlin';
      beforeCode = `override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState) }`;
      explanation = `• WindowManager.LayoutParams.FLAG_SECURE was not detected in compiled bytecode.\n• Sensitive screens can be screenshotted, screen-recorded, or exposed inside Android Recents task thumbnails.`;
      code = `override fun onCreate(savedInstanceState: Bundle?) {\n  super.onCreate(savedInstanceState)\n  window.setFlags(\n    WindowManager.LayoutParams.FLAG_SECURE,\n    WindowManager.LayoutParams.FLAG_SECURE\n  )\n}`;
    } else if (t.includes('BiometricPrompt')) {
      filename = 'BiometricAuthHelper.kt';
      language = 'kotlin';
      beforeCode = `biometricPrompt.authenticate(promptInfo) // Event-only check without CryptoObject`;
      explanation = `• Event-only BiometricPrompt authentication validates an in-memory callback rather than unlocking an AndroidKeyStore key.\n• Rooted devices can hook authentication callbacks if hardware CryptoObject cryptographic binding is missing.`;
      code = `val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")\n// Configure setUserAuthenticationRequired(true) on KeyGenParameterSpec,\n// then unlock a Cipher bound via CryptoObject:\nbiometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))`;
    } else if (t.includes('Logcat')) {
      filename = 'proguard-rules.pro';
      language = 'bash';
      beforeCode = `Log.d("AUTH_DEBUG", "JWT=" + token)`;
      explanation = `• Sensitive credential or token debug logs remain active inside release Dalvik bytecode.\n• USB debugging or privileged log readers can capture logged session identifiers.`;
      code = `# Strip all verbose/debug/info Log calls in release R8/ProGuard builds:\n-assumenosideeffects class android.util.Log {\n    public static boolean isLoggable(java.lang.String, int);\n    public static int v(...);\n    public static int d(...);\n    public static int i(...);\n}`;
    } else if (t.includes('Deep Link') || t.includes('assetlinks.json')) {
      filename = 'https://yourdomain.com/.well-known/assetlinks.json';
      language = 'json';
      beforeCode = `<intent-filter android:autoVerify="true"><data android:scheme="https" android:host="yourdomain.com"/></intent-filter> <!-- without matching /.well-known/assetlinks.json -->`;
      explanation = `• Declared HTTPS deep link hosts in AndroidManifest.xml failed verification against /.well-known/assetlinks.json.\n• Unverified App Links let rival installed apps intercept deep link URLs and hijack OAuth callbacks or payment returns.`;
      code = `[\n  {\n    "relation": ["delegate_permission/common.handle_all_urls"],\n    "target": {\n      "namespace": "android_app",\n      "package_name": "com.yourapp.package",\n      "sha256_cert_fingerprints": ["YOUR:RELEASE:SIGNING:CERT:SHA256:HEX"]\n    }\n  }\n]`;
    } else if (t.includes('Secret') || t.includes('resources.arsc')) {
      explanation = `• A sensitive secret (${finding.proof || 'DEX/resources.arsc'}) is embedded inside the compiled APK.\n• Attackers can extract hardcoded strings from APK archives in seconds using JADX-GUI or apktool.`;
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
  } else if (t.includes('Dynamic CORS Origin Reflection') || t.includes('CORS')) {
    webFilename = 'server.ts (Explicit CORS Origin Allowlist)';
    webLang = 'typescript';
    webBefore = `app.use(cors({ origin: true, credentials: true })); // Reflects ANY attacker Origin header!`;
    webCode = `const ALLOWED_ORIGINS = new Set(['https://yourdomain.com', 'https://app.yourdomain.com']);\napp.use(cors({\n  origin: (origin, cb) => cb(null, !origin || ALLOWED_ORIGINS.has(origin)),\n  credentials: true\n}));`;
    verifyCmd = `curl -I -H "Origin: https://evil-attacker.example" ${targetUrl}`;
  } else if (t.includes('SSL/TLS Certificate') || t.includes('TLS Protocol')) {
    webFilename = '/etc/nginx/sites-available/ssl.conf';
    webLang = 'bash';
    webBefore = `ssl_protocols TLSv1 TLSv1.1 TLSv1.2;`;
    webCode = `ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\n# Renew / verify automated certbot certificate:\nsudo certbot renew --nginx`;
    verifyCmd = `openssl s_client -connect ${targetUrl.replace(/^https?:\/\//, '').split('/')[0]}:443 -tls1_3`;
  } else if (t.includes('SPF') || t.includes('DMARC')) {
    webFilename = 'DNS TXT Records (Cloudflare / Route53)';
    webLang = 'bash';
    webBefore = `# Missing SPF and DMARC TXT records -> domain can be spoofed in phishing emails`;
    webCode = `# 1. Root domain TXT record (SPF):\nTXT  @       "v=spf1 -all"\n# 2. _dmarc subdomain TXT record (DMARC enforcement):\nTXT  _dmarc  "v=DMARC1; p=quarantine; adkim=s; aspf=s; rua=mailto:security@yourdomain.com"`;
    verifyCmd = `nslookup -type=TXT _dmarc.${targetUrl.replace(/^https?:\/\//, '').split('/')[0]}`;
  } else if (t.includes('Subresource Integrity') || t.includes('Outdated')) {
    webFilename = 'index.html / package.json (SRI + Dependency Upgrade)';
    webLang = 'javascript';
    webBefore = `<script src="https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js"></script>`;
    webCode = `<!-- 1. Upgrade library to latest patched version & pin SRI integrity hash: -->\n<script\n  src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"\n  integrity="sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs"\n  crossorigin="anonymous"></script>`;
    verifyCmd = `npm audit --production`;
  } else if (t.includes('Key') || t.includes('Secret') || t.includes('MongoDB') || t.includes('Private Cryptographic')) {
    webFilename = '.env + Backend API Proxy';
    webLang = 'typescript';
    webCode = `// Move raw API keys/secrets strictly to backend process.env and rotate exposed keys immediately!\napp.post('/api/proxy', async (req, res) => {\n  const key = process.env.PRIVATE_API_KEY;\n  // forward securely from server\n});`;
  } else if (t.includes('Rate Limit')) {
    webFilename = 'server.ts (express-rate-limit)';
    webLang = 'typescript';
    webCode = `import rateLimit from 'express-rate-limit';\napp.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));`;
  } else if (t.includes('Publicly Listable') && t.includes('Bucket')) {
    webFilename = 'Cloud Storage Bucket IAM / Public Access Policy';
    webLang = 'json';
    webBefore = `"Principal": "*", "Action": "s3:ListBucket" // Public directory listing enabled`;
    webCode = `{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Deny",\n      "Principal": "*",\n      "Action": "s3:ListBucket",\n      "Resource": "arn:aws:s3:::YOUR_BUCKET_NAME",\n      "Condition": { "StringNotEquals": { "aws:PrincipalAccount": "YOUR_ACCOUNT_ID" } }\n    }\n  ]\n}\n// Enable Block Public Access -> BlockPublicAcls & BlockPublicPolicy = true`;
    verifyCmd = `curl -I "${finding.proof?.match(/https?:\/\/\S+/)?.[0] || targetUrl}"`;
  } else if (t.includes('Known Vulnerable Library')) {
    webFilename = 'package.json / build.gradle';
    webLang = 'json';
    webCode = `// Upgrade vulnerable dependency flagged by OSV.dev:\n// ${finding.remediation || 'Upgrade package to latest patched version'}\nnpm audit fix && npm audit --production`;
    verifyCmd = `npm audit --production`;
  } else if (t.includes('Open Redirect')) {
    webFilename = 'server/routes/redirect.ts';
    webLang = 'typescript';
    webBefore = `return res.redirect(req.query.next); // Blindly accepts external https:// URLs`;
    webCode = `const ALLOWED_PATHS = /^\\/[a-zA-Z0-9_\\-/?=&%]*$/;\nconst nextUrl = String(req.query.next || '/');\nconst safeDest = ALLOWED_PATHS.test(nextUrl) && !nextUrl.startsWith('//') ? nextUrl : '/';\nreturn res.redirect(safeDest);`;
  } else if (t.includes('X-Forwarded-Host')) {
    webFilename = 'nginx.conf / express trust proxy';
    webLang = 'typescript';
    webBefore = `const host = req.headers['x-forwarded-host'] || req.headers.host;`;
    webCode = `// Restrict trusted reverse proxies so external X-Forwarded-Host headers are ignored:\napp.set('trust proxy', 1);\nconst CANONICAL_HOST = 'yourdomain.com';\nconst safeOrigin = \`https://\${CANONICAL_HOST}\`;`;
  } else if (t.includes('Unencoded Query Reflection')) {
    webFilename = 'server/views/template.tsx';
    webLang = 'typescript';
    webBefore = `res.send(\`<p>Search: \${req.query.q}</p>\`); // Unescaped output`;
    webCode = `// Encode all dynamic query values before rendering HTML & keep strict CSP:\nconst escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));\nres.send(\`<p>Search: \${escapeHtml(String(req.query.q || ''))}</p>\`);`;
  } else if (t.includes('TRACE Method')) {
    webFilename = 'nginx.conf / httpd.conf';
    webLang = 'bash';
    webCode = `# Disable HTTP TRACE in Apache:\nTraceEnable Off\n\n# Or block TRACE in Nginx server block:\nif ($request_method = TRACE) { return 405; }`;
    verifyCmd = `curl -i -X TRACE ${targetUrl}`;
  } else if (t.includes('Diagnostics Endpoint')) {
    webFilename = 'application.properties / reverse-proxy.conf';
    webLang = 'bash';
    webCode = `# Restrict Spring Actuator & Metrics strictly to internal localhost/VPC management ports:\nmanagement.endpoints.web.exposure.include=health\nmanagement.server.address=127.0.0.1`;
  }

  return {
    simpleExplanation: `• This web vulnerability (${t}) was detected in your ${techStack} server response or frontend bundle.\n• Evidence detected: ${finding.proof || 'HTTP probe'}.`,
    dangerScenario: `• ${finding.description || 'Attackers can exploit missing security headers, leaked files, or permissive policies to perform XSS, clickjacking, or credential theft.'}\n• Unpatched exposure increases the risk of automated scraping and client-side session hijacking.`,
    steps: [
      `Open ${webFilename} in your ${techStack} project.`,
      'Apply the hardened configuration snippet shown below (and rotate any leaked API keys or secrets immediately).',
      'Deploy to production and verify with CheckMyAPK.com or the verification command below.'
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
    const attackChains = detectCompoundAttackChains(findings, false);

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
${attackChains.length > 0 ? `\nCorrelated Compound Attack Chains Detected:\n${JSON.stringify(attackChains, null, 2)}` : ''}

Findings Details:
${JSON.stringify(prioritizedFindings, null, 2)}

Write a deeply specific, highly professional, non-generic Security Posture Assessment (130-165 words).
Structure your response into 3 crisp sections:
1. 🛡️ THREAT LANDSCAPE: Direct assessment of ${targetUrl}'s exposure based on the detected stack and findings. Mention specific technologies, CVEs, buckets, or files found.
2. 🚨 PRIMARY ATTACK VECTOR: Explain the exact way vulnerabilities chain together (if any compound chain exists above, highlight that attack path!) or how the weakest link exposes the app.
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

  const cacheKey = getCacheKey('fix', { type: finding.type, proof: finding.proof || '', techStack, targetUrl });
  try {
    const ai = new GoogleGenAI({ apiKey });
    const prompt = `You are an elite Cybersecurity Engineer and DevSecOps mentor helping a developer fix a security vulnerability.
Target URL: ${targetUrl}
Detected Tech Stack: ${techStack}
Vulnerability Title: ${finding.type}
Severity: ${finding.severity}
Finding Proof / Trigger: ${finding.proof || 'N/A'}
Description: ${finding.description || 'N/A'}

IMPORTANT: Respond strictly in clear, professional English (no Hinglish or non-English words). Format explanations cleanly point-wise.
Your response MUST be strict valid JSON matching this schema:
{
  "simpleExplanation": "2-3 concise bullet points separated by \\n (each starting with '• ') explaining what this flaw is and why it occurred.",
  "dangerScenario": "2-3 concise bullet points separated by \\n (each starting with '• ') explaining exactly how an attacker can exploit this weakness in practice.",
  "steps": [
    "Open [exact file, e.g. vercel.json, next.config.js, AndroidManifest.xml, or server.ts].",
    "Add or replace the configuration/code shown below.",
    "Deploy or rebuild the updated application and run the verification command."
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
    const attackChains = detectCompoundAttackChains(findings, true);

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
${attackChains.length > 0 ? `\nCorrelated Mobile Attack Chains Detected:\n${JSON.stringify(attackChains, null, 2)}\n` : ''}
Details:
${JSON.stringify(prioritizedFindings, null, 2)}

Write an executive-level Mobile Application Security Posture (140-170 words).
Structure your response into 3 crisp sections:
1. 📱 REVERSE-ENGINEERING RESILIENCE: Assess how vulnerable this APK is if an attacker decompiles it using JADX-GUI, Apktool, or attaches Frida. Mention the framework (${meta.frameworkDetected}), obfuscation status, and specific components/trackers/CVEs found.
2. 🚨 CRITICAL THREAT EXPOSURE: Explain how multiple findings chain together (if any compound chain is listed above) or how an attacker exploits the highest risk detected.
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

