import React, { useState } from 'react';
import { 
  CheckCircle2, 
  Copy, 
  Check, 
  ShieldAlert, 
  ChevronDown, 
  ChevronUp, 
  Sparkles, 
  Terminal, 
  Code2, 
  Loader2, 
  AlertTriangle,
  Lightbulb,
  FileCode,
  Smartphone,
  Lock,
  ArrowRight
} from 'lucide-react';

export interface FindingProps {
  category: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'PASS';
  proof: string;
  description: string;
  remediation: string;
  owaspRef?: string;
}

interface FindingCardProps {
  finding: FindingProps;
  detectedTech?: string[];
  targetUrl?: string;
  defaultExpanded?: boolean;
  canUseAiFixDoctor?: boolean;
  onRequestUpgrade?: () => void;
}

function getPlayComplianceTag(finding: FindingProps): string | null {
  if (finding.severity === 'PASS' || finding.severity === 'INFO') return null;
  const ref = String(finding.owaspRef || '');
  const t = String(finding.type || '');
  if (t.includes('Play Console') || t.includes('Target SDK') || t.includes('Tapjacking')) {
    return 'Play Policy: App & Permissions';
  }
  if (ref.startsWith('MASVS-NETWORK') || t.includes('Cleartext') || t.includes('SSL') || t.includes('Pinning') || t.includes('WebView')) {
    return 'Play Data Safety: Transit TLS';
  }
  if (ref.startsWith('MASVS-CRYPTO') || ref.startsWith('MASVS-STORAGE') || t.includes('Secret') || t.includes('allowBackup')) {
    return 'Play Data Safety: Crypto & Keys';
  }
  if (ref.startsWith('MASVS-')) {
    return 'Play Policy: Device & Network';
  }
  if (ref.startsWith('OWASP-API')) {
    return 'OWASP API Top 10';
  }
  return null;
}

function getConfidenceTag(finding: FindingProps): {
  label: 'Confirmed' | 'Heuristic • Verify Context';
  style: string;
  tooltip: string;
} {
  const txt = `${finding.category || ''} ${finding.type || ''} ${finding.proof || ''}`;
  const isHeuristic =
    /verify referrer|heuristic|potential|dom xss sink|postmessage|pattern|hardcoded|obfuscation/i.test(txt) &&
    !/live.*200|verified via|expired|self-signed|returned http|missing .*header|cors|tls|spf|dmarc|apk|manifest|elf|signing/i.test(txt);

  if (isHeuristic) {
    return {
      label: 'Heuristic • Verify Context',
      style: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
      tooltip:
        'Static pattern match: verify upstream sanitizers, origin checks, or API/referrer restrictions manually.'
    };
  }

  return {
    label: 'Confirmed',
    style: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
    tooltip:
      'Deterministically verified from live HTTP/TLS/DNS telemetry, read-only API probe, or manifest/bytecode metadata.'
  };
}

// Built-in framework specific fixes for instant copy-pasting (Web + Mobile APK)
function getPreconfiguredFixes(type: string, targetUrl: string): Record<string, { filename: string; code: string }> {
  // ── Android Mobile APK Fixes ──
  if (type.includes('debuggable') || type.includes('Debug Mode')) {
    return {
      gradle: {
        filename: 'android/app/build.gradle',
        code: `android {\n    buildTypes {\n        release {\n            debuggable false\n            minifyEnabled true\n            shrinkResources true\n            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'\n        }\n    }\n}`
      },
      manifest: {
        filename: 'AndroidManifest.xml (Remove Hardcoded Attribute)',
        code: `<!-- Remove android:debuggable completely from AndroidManifest.xml -->\n<!-- Android Gradle automatically sets debuggable=false for release builds -->\n<application\n    android:icon="@mipmap/ic_launcher"\n    android:allowBackup="false">`
      }
    };
  }

  if (type.includes('Cleartext') || type.includes('usesCleartextTraffic')) {
    return {
      manifest: {
        filename: 'AndroidManifest.xml',
        code: `<application\n    android:usesCleartextTraffic="false"\n    android:networkSecurityConfig="@xml/network_security_config"\n    ... >`
      },
      xml: {
        filename: 'res/xml/network_security_config.xml',
        code: `<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n    <!-- Enforce strict HTTPS encryption for all network traffic -->\n    <base-config cleartextTrafficPermitted="false">\n        <trust-anchors>\n            <certificates src="system" />\n        </trust-anchors>\n    </base-config>\n</network-security-config>`
      }
    };
  }

  if (type.includes('allowBackup') || type.includes('Backup')) {
    return {
      manifest: {
        filename: 'AndroidManifest.xml',
        code: `<!-- Block adb backup & cloud backup of private SQLite DBs and auth tokens (Android 11 & 12+) -->\n<application\n    android:allowBackup="false"\n    android:fullBackupContent="false"\n    android:dataExtractionRules="@xml/data_extraction_rules">`
      }
    };
  }

  if (type.includes('Target SDK')) {
    return {
      gradle: {
        filename: 'android/app/build.gradle (AGP 8+)',
        code: `android {\n    compileSdk 35\n    defaultConfig {\n        minSdk 24\n        targetSdk 35 // Android 15+ Play Store compliant\n    }\n}`
      }
    };
  }

  if (type.includes('Debug Certificate') || type.includes('Keystore')) {
    return {
      studio: {
        filename: 'Android Studio -> Release Signing',
        code: `// 1. In Android Studio: Click Build -> Generate Signed Bundle / APK\n// 2. Choose 'Android App Bundle' or 'APK'\n// 3. Select your release keystore (.jks) file and enter your password\n// 4. Set Build Variant to 'release'\n// Never distribute APKs signed with debug.keystore!`
      }
    };
  }

  if (type.includes('SYSTEM_ALERT_WINDOW') || type.includes('Tapjacking')) {
    return {
      manifest: {
        filename: 'AndroidManifest.xml',
        code: `<!-- Remove SYSTEM_ALERT_WINDOW from AndroidManifest.xml unless strictly required for floating overlays -->\n<!-- Delete: <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" /> -->`
      },
      kotlin: {
        filename: 'MainActivity.kt (Block Overlay Tapjacking)',
        code: `// Reject touch events when another app draws an overlay above sensitive screens:\noverride fun onCreate(savedInstanceState: Bundle?) {\n    super.onCreate(savedInstanceState)\n    window.decorView.filterTouchesWhenObscured = true\n}`
      }
    };
  }

  if (type.includes('Hardcoded API Secret in APK')) {
    return {
      proxy: {
        filename: 'Backend Proxy Pattern (Android Architecture)',
        code: `// Never compile raw API keys into Dalvik DEX or assets!\n// Store keys on your secure server backend (e.g. https://api.yourapp.com/chat)\n// In Android/Capacitor/Flutter: Call your own backend endpoint instead of OpenAI/Gemini directly.`
      }
    };
  }

  if (type.includes('Unprotected Exported') || type.includes('Exported Component')) {
    return {
      manifest: {
        filename: 'AndroidManifest.xml',
        code: `<!-- Restrict internal Activities, Services, Receivers, and Providers -->\n<service\n    android:name=".InternalSyncService"\n    android:exported="false" />\n\n<!-- Or require a signature-level permission if IPC sharing is required -->\n<permission\n    android:name="\${applicationId}.permission.INTERNAL_IPC"\n    android:protectionLevel="signature" />`
      }
    };
  }

  if (type.includes('Native Library Missing Binary Protections') || type.includes('Native ELF')) {
    return {
      cmake: {
        filename: 'app/src/main/cpp/CMakeLists.txt (NDK Hardening)',
        code: `# Enforce Stack Canary, Non-Executable Stack (NX), PIE, and Full RELRO:\nset(CMAKE_C_FLAGS "\${CMAKE_C_FLAGS} -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2")\nset(CMAKE_CXX_FLAGS "\${CMAKE_CXX_FLAGS} -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2")\nset(CMAKE_SHARED_LINKER_FLAGS "\${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,noexecstack -Wl,-z,relro,-z,now")`
      }
    };
  }

  if (type.includes('Certificate Pinning')) {
    return {
      xml: {
        filename: 'res/xml/network_security_config.xml',
        code: `<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n  <domain-config cleartextTrafficPermitted="false">\n    <domain includeSubdomains="true">api.yourapp.com</domain>\n    <pin-set expiration="2027-12-31">\n      <pin digest="SHA-256">PRIMARY_SPKI_BASE64_HASH=</pin>\n      <pin digest="SHA-256">BACKUP_SPKI_BASE64_HASH=</pin>\n    </pin-set>\n  </domain-config>\n</network-security-config>`
      },
      okhttp: {
        filename: 'NetworkClient.kt (OkHttp CertificatePinner)',
        code: `val pinner = CertificatePinner.Builder()\n    .add("api.yourapp.com", "sha256/PRIMARY_SPKI_BASE64_HASH=")\n    .add("api.yourapp.com", "sha256/BACKUP_SPKI_BASE64_HASH=")\n    .build()\n\nval client = OkHttpClient.Builder()\n    .certificatePinner(pinner)\n    .build()`
      }
    };
  }

  if (type.includes('Play Console Restricted Policy Permissions')) {
    return {
      manifest: {
        filename: 'AndroidManifest.xml (<queries> Instead of QUERY_ALL_PACKAGES)',
        code: `<!-- Remove broad QUERY_ALL_PACKAGES / REQUEST_INSTALL_PACKAGES unless strictly core -->\n<!-- Use targeted package visibility instead: -->\n<queries>\n  <intent>\n    <action android:name="android.intent.action.VIEW" />\n    <data android:scheme="https" />\n  </intent>\n</queries>`
      }
    };
  }

  if (
    type.includes('SSL / TLS Certificate Validation Bypass') ||
    type.includes('X509TrustManager') ||
    type.includes('HostnameVerifier') ||
    type.includes('SslErrorHandler')
  ) {
    return {
      okhttp: {
        filename: 'NetworkClient.kt / WebViewClient (Strict TLS)',
        code: `// Remove TrustAllCerts, AllowAllHostnameVerifier & handler.proceed()!\nval pinner = CertificatePinner.Builder()\n    .add("api.yourapp.com", "sha256/YOUR_SPKI_PIN_HASH=")\n    .build()\nval client = OkHttpClient.Builder().certificatePinner(pinner).build()`
      }
    };
  }

  if (
    type.includes('Weak Symmetric Encryption') ||
    type.includes('Weak Cipher Mode Verified') ||
    type.includes('Hardcoded Symmetric Key') ||
    type.includes('IvParameterSpec')
  ) {
    return {
      crypto: {
        filename: 'CryptoHelper.kt (AndroidKeyStore + AES-GCM)',
        code: `// Use AndroidKeyStore + AES/GCM/NoPadding + fresh random 12-byte IV:\nval cipher = Cipher.getInstance("AES/GCM/NoPadding")\nval iv = ByteArray(12).also { SecureRandom().nextBytes(it) }\ncipher.init(Cipher.ENCRYPT_MODE, secretKeyFromAndroidKeyStore, GCMParameterSpec(128, iv))`
      }
    };
  }

  if (type.includes('Tainted WebView') || type.includes('WebView Universal') || type.includes('WebView JavaScript Bridge')) {
    return {
      kotlin: {
        filename: 'WebViewActivity.kt (Origin Allowlist + Safe Settings)',
        code: `val uri = Uri.parse(incomingUrl)\nrequire(uri.scheme == "https" && uri.host == "yourdomain.com") { "Blocked untrusted origin" }\nwebView.settings.apply {\n  allowFileAccess = false\n  allowFileAccessFromFileURLs = false\n  allowUniversalAccessFromFileURLs = false\n}\nwebView.loadUrl(uri.toString())`
      }
    };
  }

  if (type.includes('Local SQLite Injection')) {
    return {
      kotlin: {
        filename: 'DatabaseHelper.kt (Parameterized Query)',
        code: `// Never concatenate Intent/URI strings into SQL!\nval cursor = db.rawQuery("SELECT * FROM items WHERE id = ?", arrayOf(safeItemId))`
      }
    };
  }

  if (type.includes('Intent Redirection') || type.includes('PendingIntent')) {
    return {
      kotlin: {
        filename: 'IntentSecurity.kt (Immutable PendingIntent & Explicit Target)',
        code: `// Always pass PendingIntent.FLAG_IMMUTABLE and pin forwarded component package:\nval pi = PendingIntent.getActivity(context, reqCode, intent, PendingIntent.FLAG_IMMUTABLE)\n\n// Before forwarding nested Intent:\nval comp = nestedIntent.component\nrequire(comp == null || comp.packageName == context.packageName) { "Blocked external hijack" }`
      }
    };
  }

  if (type.includes('WebView / Hybrid Bridge')) {
    return {
      capacitor: {
        filename: 'capacitor.config.ts / json (Merge Inside Existing Config)',
        code: `// Merge into your existing config — keep appId, webDir, and plugins intact,\n// then run: npx cap sync android && rebuild release APK\n{\n  "server": {\n    "cleartext": false,\n    "androidScheme": "https"\n  },\n  "android": {\n    "allowMixedContent": false,\n    "webContentsDebuggingEnabled": false\n  }\n}`
      }
    };
  }

  if (type.includes('Hardcoded Cleartext HTTP URLs')) {
    return {
      https: {
        filename: 'AndroidManifest.xml + API Constants',
        code: `// Upgrade all hardcoded http:// URLs to https:// in source & config.\n// Enforce HTTPS platform-wide in AndroidManifest.xml:\n<application android:usesCleartextTraffic="false" ... />`
      }
    };
  }

  if (type.includes('Obfuscation') || type.includes('ProGuard')) {
    return {
      gradle: {
        filename: 'android/app/build.gradle',
        code: `android {\n  buildTypes {\n    release {\n      minifyEnabled true\n      shrinkResources true\n      proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'\n    }\n  }\n}`
      }
    };
  }

  if (type.includes('CA Certificates Trusted') || type.includes('network_security_config')) {
    return {
      xml: {
        filename: 'res/xml/network_security_config.xml',
        code: `<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n  <base-config cleartextTrafficPermitted="false">\n    <trust-anchors><certificates src="system" /></trust-anchors>\n  </base-config>\n  <!-- Only trust user CAs inside debug builds -->\n  <debug-overrides>\n    <trust-anchors><certificates src="user" /></trust-anchors>\n  </debug-overrides>\n</network-security-config>`
      }
    };
  }

  if (type.includes('.env Configuration') || type.includes('.git Repository')) {
    return {
      nginx: {
        filename: 'nginx.conf / .htaccess',
        code: `# Block all hidden dotfiles & .git metadata in production\nlocation ~ /\\. {\n  deny all;\n  return 404;\n}`
      },
      vercel: {
        filename: 'Deployment Security Checklist',
        code: `// 1. Delete public /.env and /.git from server root.\n// 2. Rotate EVERY API key and DB password listed in that file immediately.\n// 3. Configure secrets strictly in platform Environment Variables UI.`
      }
    };
  }

  if (type.includes('Source Map') || type.includes('.js.map')) {
    return {
      vite: {
        filename: 'vite.config.ts / next.config.js',
        code: `// In vite.config.ts:\nexport default defineConfig({\n  build: { sourcemap: false }\n});\n\n// In next.config.js:\nmodule.exports = { productionBrowserSourceMaps: false };`
      }
    };
  }

  if (type.includes('Session Cookie') || type.includes('Set-Cookie')) {
    return {
      express: {
        filename: 'server.ts (Auth Cookie Policy)',
        code: `res.cookie('session', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'lax',\n  maxAge: 7 * 24 * 60 * 60 * 1000\n});`
      }
    };
  }

  if (type.includes('Firebase Client API Key')) {
    return {
      gcp: {
        filename: 'Google Cloud Console -> Credentials -> Browser / Android API Key',
        code: `// Firebase Client API Keys are public by design, so lock down the key in GCP:\n// 1. Application restrictions:\n//    - Web apps: HTTP referrers -> https://your-domain.com/*\n//    - Android APKs: Package name + release SHA-1 certificate fingerprint\n// 2. API restrictions -> Restrict key ONLY to:\n//    - Identity Toolkit API\n//    - Token Service API / Firebase Installations API\n//    (CRITICAL: NEVER allow Generative Language / Gemini API on a Firebase client key!)\n// 3. Enforce Firebase App Check + strict Firestore/RTDB Security Rules.`
      }
    };
  }

  if (type.includes('DOM XSS') || type.includes('Unsafe Dynamic Code Execution')) {
    return {
      react: {
        filename: 'SafeHtmlRenderer.tsx (DOMPurify + Safe React)',
        code: `import DOMPurify from 'dompurify';\n\n// Replace innerHTML / eval() / raw __html with sanitized JSX rendering:\nconst cleanHtml = DOMPurify.sanitize(userContent);\nreturn <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;`
      }
    };
  }

  if (type.includes('postMessage')) {
    return {
      bridge: {
        filename: 'windowMessageHandler.ts (Strict Origin Guard)',
        code: `window.addEventListener('message', (event) => {\n  if (event.origin !== 'https://app.yourdomain.com') return;\n  processVerifiedMessage(event.data);\n});\n\n// Specify exact origin instead of '*':\npopupWindow.postMessage(payload, 'https://app.yourdomain.com');`
      }
    };
  }

  if (type.includes('GraphQL')) {
    return {
      apollo: {
        filename: 'graphqlServer.ts (Disable Prod Introspection)',
        code: `const server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: process.env.NODE_ENV !== 'production'\n});`
      }
    };
  }

  if (type.includes('OpenAPI') || type.includes('Swagger')) {
    return {
      express: {
        filename: 'server.ts (Restrict Swagger / OpenAPI JSON)',
        code: `// Disable or require admin authentication before serving /openapi.json or /swagger.json:\nif (process.env.NODE_ENV !== 'production') {\n  app.get('/openapi.json', (_req, res) => res.json(openApiSpec));\n}`
      }
    };
  }

  if (type.includes('Verbose Server Stack Trace') || type.includes('Unauthenticated API Endpoint')) {
    return {
      express: {
        filename: 'server/middleware/errorAndAuth.ts',
        code: `// 1. Protect API routes & whitelist safe DTO fields:\napp.get('/api/users', requireAuth, (req, res) => {\n  res.json(users.map(({ id, displayName }) => ({ id, displayName })));\n});\n\n// 2. Mask stack traces in production:\napp.use((err, _req, res, _next) => {\n  console.error(err);\n  res.status(500).json({ error: 'Internal server error' });\n});`
      }
    };
  }

  if (type.includes('JWT') && !type.includes('LocalStorage')) {
    return {
      jwt: {
        filename: 'auth/jwtVerify.ts (Strict Alg Pinning & Short Exp)',
        code: `import jwt from 'jsonwebtoken';\n\n// 1. Always enforce short expiry and zero PII in claims:\nconst token = jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET!, {\n  algorithm: 'HS256',\n  expiresIn: '15m'\n});\n\n// 2. Never accept alg: "none" — explicitly pin algorithms:\nconst payload = jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] });`
      }
    };
  }

  if (type.includes('LocalStorage') || type.includes('JWT')) {
    return {
      cookie: {
        filename: 'server/auth.ts (HttpOnly Session Cookie Pattern)',
        code: `// Avoid: localStorage.setItem('token', jwt) -> readable by any XSS script!\n// Instead issue HttpOnly + Secure cookies from your backend:\nres.cookie('__Host-session', sessionToken, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict',\n  path: '/',\n  maxAge: 7 * 24 * 60 * 60 * 1000\n});`
      }
    };
  }

  if (type.includes('CORS')) {
    return {
      express: {
        filename: 'server.ts (Strict CORS Allowlist)',
        code: `const ALLOWED_ORIGINS = new Set(['https://yourdomain.com']);\napp.use(cors({\n  origin: (origin, cb) => cb(null, !origin || ALLOWED_ORIGINS.has(origin)),\n  credentials: true\n}));`
      },
      nginx: {
        filename: '/etc/nginx/conf.d/cors.conf',
        code: `# Reject untrusted origins instead of reflecting $http_origin blindly:\nif ($http_origin ~* "^https://(www\\.)?yourdomain\\.com$") {\n  add_header Access-Control-Allow-Origin "$http_origin" always;\n  add_header Access-Control-Allow-Credentials "true" always;\n  add_header Vary "Origin" always;\n}`
      }
    };
  }

  if (type.includes('SPF') || type.includes('DMARC') || type.includes('security.txt')) {
    return {
      dns: {
        filename: 'DNS TXT Records + /.well-known/security.txt',
        code: `# DNS TXT Records:\n@        TXT  "v=spf1 -all"\n_dmarc   TXT  "v=DMARC1; p=quarantine; rua=mailto:security@yourdomain.com"\n\n# /.well-known/security.txt:\nContact: mailto:security@yourdomain.com\nExpires: 2027-12-31T23:59:59.000Z`
      }
    };
  }

  if (type.includes('Subresource Integrity') || type.includes('Outdated')) {
    return {
      html: {
        filename: 'index.html / package.json',
        code: `<!-- Always attach integrity + crossorigin on external static CDN scripts & upgrade outdated libs: -->\n<script\n  src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"\n  integrity="sha384-..."\n  crossorigin="anonymous"\n></script>\n\n# Run in terminal:\nnpm audit fix`
      }
    };
  }

  // ── Web Vulnerabilities Fixes ──
  const isCsp = type.includes('Content-Security-Policy');
  const isHsts = type.includes('Strict-Transport-Security');
  const isClickjack = type.includes('Clickjacking') || type.includes('X-Frame-Options');
  const isRateLimit = type.includes('Rate Limiting');
  const isKey = type.includes('Key') || type.includes('Secret');
  const isDb = type.includes('Firebase') || type.includes('Database');

  if (isCsp) {
    return {
      vercel: {
        filename: 'vercel.json',
        code: `{\n  "headers": [\n    {\n      "source": "/(.*)",\n      "headers": [\n        {\n          "key": "Content-Security-Policy",\n          "value": "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; connect-src 'self' https:;"\n        }\n      ]\n    }\n  ]\n}`
      },
      nextjs: {
        filename: 'next.config.js',
        code: `module.exports = {\n  async headers() {\n    return [\n      {\n        source: '/(.*)',\n        headers: [\n          {\n            key: 'Content-Security-Policy',\n            value: "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:;"\n          }\n        ]\n      }\n    ];\n  }\n};`
      },
      express: {
        filename: 'server.js (Node.js)',
        code: `// npm install helmet\nconst helmet = require('helmet');\n\napp.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: ["'self'"],\n    scriptSrc: ["'self'", "'unsafe-inline'", "https:"],\n    styleSrc: ["'self'", "'unsafe-inline'", "https:"]\n  }\n}));`
      },
      nginx: {
        filename: '/etc/nginx/sites-available/default',
        code: `add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:;" always;`
      }
    };
  }

  if (isHsts) {
    return {
      vercel: {
        filename: 'vercel.json',
        code: `{\n  "headers": [\n    {\n      "source": "/(.*)",\n      "headers": [\n        {\n          "key": "Strict-Transport-Security",\n          "value": "max-age=31536000; includeSubDomains; preload"\n        }\n      ]\n    }\n  ]\n}`
      },
      nextjs: {
        filename: 'next.config.js',
        code: `// inside async headers() in next.config.js:\n{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' }`
      },
      express: {
        filename: 'server.js',
        code: `// npm install helmet\nconst helmet = require('helmet');\napp.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));`
      },
      nginx: {
        filename: 'nginx.conf',
        code: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`
      }
    };
  }

  if (isClickjack) {
    return {
      vercel: {
        filename: 'vercel.json',
        code: `{\n  "headers": [\n    {\n      "source": "/(.*)",\n      "headers": [\n        {\n          "key": "X-Frame-Options",\n          "value": "DENY"\n        }\n      ]\n    }\n  ]\n}`
      },
      nextjs: {
        filename: 'next.config.js',
        code: `{ key: 'X-Frame-Options', value: 'DENY' }`
      },
      express: {
        filename: 'server.js',
        code: `const helmet = require('helmet');\napp.use(helmet.frameguard({ action: 'deny' }));`
      },
      nginx: {
        filename: 'nginx.conf',
        code: `add_header X-Frame-Options "DENY" always;`
      }
    };
  }

  if (isRateLimit) {
    return {
      express: {
        filename: 'server.js',
        code: `// npm install express-rate-limit\nconst rateLimit = require('express-rate-limit');\n\nconst apiLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 100,\n  standardHeaders: true,\n  legacyHeaders: false,\n  message: { error: 'Too many requests. Please wait a few minutes before trying again.' }\n});\n\napp.use('/api/', apiLimiter);`
      },
      nextjs: {
        filename: 'middleware.ts (Upstash Rate Limiting)',
        code: `import { Ratelimit } from '@upstash/ratelimit';\nimport { Redis } from '@upstash/redis';\nimport { NextRequest, NextResponse } from 'next/server';\n\nconst ratelimit = new Ratelimit({\n  redis: Redis.fromEnv(),\n  limiter: Ratelimit.slidingWindow(20, '1 m'),\n});\n\nexport async function middleware(request: NextRequest) {\n  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? '127.0.0.1';\n  const { success } = await ratelimit.limit(ip);\n  if (!success) return new NextResponse('Rate limit exceeded', { status: 429 });\n  return NextResponse.next();\n}`
      },
      nginx: {
        filename: 'nginx.conf',
        code: `limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;\n\nlocation /api/ {\n  limit_req zone=one burst=20 nodelay;\n  proxy_pass http://backend;\n}`
      },
      vercel: {
        filename: 'vercel.json (Edge Middleware / WAF)',
        code: `// Enable Vercel Attack Challenge Mode in Dashboard:\n// Project Settings -> Security -> Attack Challenge Mode -> Enabled`
      }
    };
  }

  if (isKey) {
    return {
      express: {
        filename: '.env & server.ts (Backend Proxy Pattern)',
        code: `// 1. In .env:\nAPI_SECRET_KEY=sk_your_private_key\n\n// 2. In server.ts (DO NOT expose key in client bundles):\napp.post('/api/secure-action', async (req, res) => {\n  const apiKey = process.env.API_SECRET_KEY;\n  const response = await fetch('https://api.external.com', {\n    method: 'POST',\n    headers: {\n      'Authorization': \`Bearer \${apiKey}\`,\n      'Content-Type': 'application/json'\n    },\n    body: JSON.stringify(req.body)\n  });\n  res.status(response.status).json(await response.json());\n});`
      },
      nextjs: {
        filename: 'app/api/route.ts (Serverless Route)',
        code: `// Server-side only (never prefix with NEXT_PUBLIC_)\nconst SECRET_KEY = process.env.GEMINI_API_KEY;\n\nexport async function POST(req: Request) {\n  // Safe server execution\n  return Response.json({ success: true });\n}`
      },
      vercel: {
        filename: 'Project Settings -> Environment Variables',
        code: `// Add your secret keys directly in the Vercel Dashboard.\n// Mark them as "Server Only" so they never leak to the client browser.`
      }
    };
  }

  if (isDb) {
    return {
      firebase: {
        filename: 'firestore.rules',
        code: `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /users/{userId} {\n      allow read, write: if request.auth != null && request.auth.uid == userId;\n    }\n    match /{document=**} {\n      allow read, write: if false;\n    }\n  }\n}`
      },
      express: {
        filename: 'database.rules.json (Realtime DB)',
        code: `{\n  "rules": {\n    "users": {\n      "$uid": {\n        ".read": "$uid === auth.uid",\n        ".write": "$uid === auth.uid"\n      }\n    },\n    ".read": false,\n    ".write": false\n  }\n}`
      }
    };
  }

  // Default Master Security Config
  return {
    vercel: {
      filename: 'vercel.json (Master Headers Fix)',
      code: `{\n  "headers": [\n    {\n      "source": "/(.*)",\n      "headers": [\n        { "key": "X-Content-Type-Options", "value": "nosniff" },\n        { "key": "X-Frame-Options", "value": "DENY" },\n        { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" },\n        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" }\n      ]\n    }\n  ]\n}`
    },
    nextjs: {
      filename: 'next.config.js',
      code: `module.exports = {\n  async headers() {\n    return [\n      {\n        source: '/(.*)',\n        headers: [\n          { key: 'X-Content-Type-Options', value: 'nosniff' },\n          { key: 'X-Frame-Options', value: 'DENY' },\n          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }\n        ]\n      }\n    ];\n  }\n};`
    },
    express: {
      filename: 'server.js',
      code: `const helmet = require('helmet');\napp.use(helmet());`
    },
    nginx: {
      filename: 'nginx.conf',
      code: `add_header X-Content-Type-Options "nosniff" always;\nadd_header X-Frame-Options "DENY" always;\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`
    }
  };
}

export const FindingCard: React.FC<FindingCardProps> = ({ 
  finding, 
  detectedTech = [], 
  targetUrl = '',
  defaultExpanded = false,
  canUseAiFixDoctor = true,
  onRequestUpgrade
}) => {
  const isPass = finding.severity === 'PASS' || finding.severity === 'INFO';
  const [expanded, setExpanded] = useState(defaultExpanded || (!isPass && finding.severity === 'CRITICAL'));
  const [copied, setCopied] = useState(false);

  const preconfigured = getPreconfiguredFixes(finding.type, targetUrl);
  const availableTabs = Object.keys(preconfigured);
  const [activeTab, setActiveTab] = useState<string>(availableTabs[0] || 'vercel');

  // AI Deep Fix Doctor state
  const [loadingAiFix, setLoadingAiFix] = useState(false);
  const [aiFixData, setAiFixData] = useState<any>(null);
  const [aiFixError, setAiFixError] = useState<string | null>(null);

  let badgeStyle = 'bg-rose-500/15 text-rose-400 border-rose-500/30';
  let leftAccent = 'border-l-rose-500';
  if (finding.severity === 'HIGH') {
    badgeStyle = 'bg-orange-500/15 text-orange-400 border-orange-500/30';
    leftAccent = 'border-l-orange-500';
  }
  if (finding.severity === 'MEDIUM') {
    badgeStyle = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    leftAccent = 'border-l-amber-500';
  }
  if (finding.severity === 'LOW') {
    badgeStyle = 'bg-blue-500/15 text-blue-400 border-blue-500/30';
    leftAccent = 'border-l-blue-500';
  }
  if (finding.severity === 'INFO') {
    badgeStyle = 'bg-slate-500/15 text-slate-300 border-slate-500/30';
    leftAccent = 'border-l-slate-400';
  }
  if (finding.severity === 'PASS') {
    badgeStyle = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
    leftAccent = 'border-l-emerald-500';
  }

  const currentSnippet = (preconfigured as any)[activeTab] || Object.values(preconfigured)[0] || {
    filename: 'config',
    code: '// Review finding remediation guidance'
  };

  const getTabLabel = (tabKey: string) => {
    switch (tabKey) {
      case 'vercel': return 'Vercel';
      case 'nextjs': return 'Next.js';
      case 'express': return 'Node/Express';
      case 'nginx': return 'Nginx';
      case 'gradle': return 'build.gradle';
      case 'manifest': return 'AndroidManifest.xml';
      case 'xml': return 'network_security.xml';
      case 'studio': return 'Android Studio';
      case 'proxy': return 'Backend Proxy';
      case 'capacitor': return 'Capacitor';
      case 'okhttp': return 'OkHttp Pinning';
      case 'crypto': return 'Android Keystore';
      case 'https': return 'HTTPS / API';
      case 'vite': return 'Vite / Env';
      case 'firebase': return 'Firestore Rules';
      case 'gcp': return 'GCP Console';
      case 'cookie': return 'HttpOnly Cookie';
      case 'kotlin': return 'Kotlin / Android';
      default: return tabKey.toUpperCase();
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // 🤖 Trigger On-Demand AI Fix Doctor
  const handleAskAiDoctor = async () => {
    if (aiFixData) return;
    setLoadingAiFix(true);
    setAiFixError(null);

    try {
      const res = await fetch('/api/explain-vulnerability', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding,
          detectedTech,
          targetUrl,
          framework: activeTab
        })
      });

      if (!res.ok) {
        throw new Error(`Failed to generate AI fix (${res.statusText})`);
      }

      const data = await res.json();
      setAiFixData(data);
    } catch (err: any) {
      setAiFixError(err.message || 'Could not connect to Gemini AI Fix Doctor.');
    } finally {
      setLoadingAiFix(false);
    }
  };

  return (
    <div className={`wb-surface rounded-xl border-l-[3px] ${leftAccent} transition-all overflow-hidden print:break-inside-avoid ${
      isPass ? 'hover:border-emerald-500/30' : 'hover:border-white/20'
    }`}>
      {/* ── Main Header ── */}
      <div
        onClick={() => setExpanded(!expanded)}
        className="wb-spec-row px-4 sm:px-5 py-4 flex items-start justify-between gap-3 cursor-pointer select-none transition-colors"
      >
        <div className="flex items-start gap-3 min-w-0">
          <div className="mt-0.5 shrink-0">
            {isPass ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <ShieldAlert className={`w-4 h-4 ${finding.severity === 'CRITICAL' ? 'text-rose-400' : finding.severity === 'HIGH' ? 'text-amber-400' : 'text-cyan-400'}`} />
            )}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5 flex-wrap mb-1.5">
              <span className={`font-mono text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded border ${badgeStyle}`}>
                {finding.severity}
              </span>
              {finding.owaspRef && (
                <span className="font-mono text-[10px] font-medium px-1.5 py-0.5 rounded wb-spec-code">
                  {finding.owaspRef}
                </span>
              )}
              {(() => {
                const policyTag = getPlayComplianceTag(finding);
                return policyTag ? (
                  <span className="font-mono text-[10px] font-medium px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/25">
                    {policyTag}
                  </span>
                ) : null;
              })()}
              {!isPass && (() => {
                const conf = getConfidenceTag(finding);
                return (
                  <span
                    title={conf.tooltip}
                    className={`font-mono text-[10px] font-medium px-1.5 py-0.5 rounded border ${conf.style}`}
                  >
                    {conf.label}
                  </span>
                );
              })()}
              <span className="text-[11px] text-slate-400 ml-0.5">
                {finding.category}
              </span>
            </div>
            <h4 className="text-[13.5px] font-display font-semibold tracking-[-0.01em] text-white leading-snug">
              {finding.type}
            </h4>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0 no-print">
          {!isPass && (
            <span className="font-mono text-[10px] font-medium text-emerald-400 bg-emerald-500/10 border border-emerald-500/25 px-2 py-0.5 rounded hidden sm:inline-flex items-center gap-1">
              <Code2 className="w-3 h-3" />
              Patch Ready
            </span>
          )}
          <button
            type="button"
            aria-label={expanded ? 'Collapse finding' : 'Expand finding'}
            className="text-slate-400 p-1 hover:text-white shrink-0 cursor-pointer"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* ── Expanded Deep Breakdown ── */}
      {expanded && (
        <div className="px-4 sm:px-5 pb-5 pt-4 space-y-4 text-xs border-t border-white/10 wb-surface-muted border-x-0 border-b-0">

          {/* 1. Risk & Impact */}
          <div className="space-y-1.5">
            <span className="font-mono text-[10px] font-semibold uppercase text-slate-400 tracking-[0.12em] flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              Risk &amp; Impact
            </span>
            <p className="text-slate-300 leading-relaxed wb-surface p-3 rounded-lg">
              {finding.description}
            </p>
          </div>

          {/* 2. Artifact Evidence */}
          {finding.proof && (
            <div className="space-y-1.5">
              <span className="font-mono text-[10px] font-semibold uppercase text-slate-400 tracking-[0.12em] flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                Artifact Evidence
              </span>
              <div className="wb-ide-evidence border border-white/10 rounded-lg p-3 font-mono text-[11px] text-cyan-400 break-all select-all">
                {finding.proof}
              </div>
            </div>
          )}

          {/* 3. Remediation Patch (Locked vs Unlocked) */}
          {!isPass && !canUseAiFixDoctor && (
            <div className="p-4 rounded-xl wb-surface border-amber-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="text-xs font-display font-semibold text-amber-400 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5" />
                  <span>Copy-Paste Code Patches &amp; AI Fix Doctor</span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  {finding.remediation} Upgrade to <strong className="text-white">Pro Security</strong> for ready-to-paste code patches and Gemini remediation.
                </p>
              </div>
              {onRequestUpgrade && (
                <button
                  type="button"
                  onClick={onRequestUpgrade}
                  className="wb-emerald-btn h-9 px-3.5 rounded-md font-semibold text-[11px] inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
                >
                  <span>Unlock Fix Code</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          )}

          {!isPass && canUseAiFixDoctor && (
            <div className="space-y-3 wb-surface p-4 rounded-xl">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="font-mono text-[10.5px] font-semibold uppercase text-emerald-400 tracking-[0.12em] flex items-center gap-1.5">
                  <Lightbulb className="w-3.5 h-3.5 text-emerald-400" />
                  Recommended Code Patch
                </span>

                {/* Dynamic Framework Selector Tabs */}
                {availableTabs.length > 1 && (
                  <div className="inline-flex items-center gap-1 wb-surface-muted p-1 rounded-md text-[10px] font-mono flex-wrap no-print">
                    {availableTabs.map((t) => (
                      <button
                        key={t}
                        type="button"
                        onClick={() => setActiveTab(t)}
                        className={`px-2 py-0.5 rounded font-medium transition-colors cursor-pointer ${
                          activeTab === t ? 'bg-emerald-500/20 text-emerald-400 font-semibold' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        {getTabLabel(t)}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Code Snippet Box */}
              <div className="relative rounded-lg border border-white/10 wb-surface-muted overflow-hidden print:break-inside-avoid">
                <div className="wb-ide-chrome flex items-center justify-between px-3 py-2 border-b border-white/10 text-[11px]">
                  <div className="flex items-center gap-1.5 text-slate-300 font-mono truncate">
                    <FileCode className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span className="truncate">{currentSnippet.filename}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleCopy(currentSnippet.code)}
                    className={`no-print inline-flex items-center gap-1 text-[10px] font-mono font-medium transition-colors px-2.5 py-1 rounded border cursor-pointer shrink-0 ${
                      copied
                        ? 'bg-emerald-500/15 border-emerald-500/35 text-emerald-400'
                        : 'bg-white/[0.05] hover:bg-white/[0.1] border-white/10 text-slate-300 hover:text-white'
                    }`}
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copied ? 'Copied' : 'Copy Code'}
                  </button>
                </div>
                <pre className="p-3.5 text-[11px] font-mono text-emerald-300 overflow-x-auto leading-relaxed select-all">
                  {currentSnippet.code}
                </pre>
              </div>

              {/* On-Demand AI Fix Doctor */}
              <div className={`pt-2 border-t border-white/10 ${!aiFixData ? 'no-print' : ''}`}>
                {!aiFixData && !loadingAiFix && (
                  <button
                    type="button"
                    onClick={handleAskAiDoctor}
                    className="w-full py-2.5 px-3 rounded-lg text-xs font-medium bg-emerald-500/[0.08] hover:bg-emerald-500/[0.14] text-emerald-400 border border-emerald-500/25 flex items-center justify-center gap-2 transition-colors cursor-pointer"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Ask Gemini AI: Explain &amp; Generate Custom Fix</span>
                  </button>
                )}

                {loadingAiFix && (
                  <div className="p-3 rounded-lg wb-surface-muted border border-emerald-500/30 flex items-center justify-center gap-2 text-emerald-400 text-xs font-medium animate-pulse">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Drafting custom remediation patch...</span>
                  </div>
                )}

                {aiFixError && (
                  <div className="p-2.5 text-xs text-rose-400 bg-rose-500/10 border border-rose-500/25 rounded-lg">
                    {aiFixError}
                  </div>
                )}

                {aiFixData && (
                  <div className="p-3.5 rounded-lg wb-surface-muted border border-emerald-500/25 space-y-3">
                    <div className="flex items-center gap-2 text-emerald-400 font-mono font-semibold text-[11px] uppercase tracking-wider">
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>
                        {aiFixData.source === 'deterministic'
                          ? 'Deterministic Remediation Rulebook'
                          : 'Gemini AI Deep Remediation'}
                      </span>
                    </div>

                    <div className="space-y-2.5 text-slate-300 text-[11.5px] leading-relaxed">
                      <div>
                        <strong className="text-white block mb-0.5">Root Cause:</strong>
                        <p>{aiFixData.simpleExplanation}</p>
                      </div>

                      <div>
                        <strong className="text-rose-400 block mb-0.5">Attack Scenario:</strong>
                        <p className="text-slate-300">{aiFixData.dangerScenario}</p>
                      </div>

                      {aiFixData.steps && (
                        <div>
                          <strong className="text-emerald-400 block mb-1">Action Steps:</strong>
                          <ul className="list-disc pl-4 space-y-0.5 text-slate-300">
                            {aiFixData.steps.map((st: string, idx: number) => (
                              <li key={idx}>{st}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {aiFixData.codeBlock && (
                        <div className="mt-2 space-y-2">
                          {aiFixData.beforeCode && (
                            <div className="rounded-lg border border-rose-500/25 overflow-hidden">
                              <div className="px-2.5 py-1 wb-diff-del border-b border-rose-500/20 font-mono text-[10px] font-semibold">
                                - Vulnerable Pattern
                              </div>
                              <pre className="p-2.5 wb-diff-del font-mono text-[10.5px] overflow-x-auto select-all">
                                {aiFixData.beforeCode}
                              </pre>
                            </div>
                          )}
                          <div className="rounded-lg border border-emerald-500/30 overflow-hidden wb-surface">
                            <div className="flex items-center justify-between px-2.5 py-1.5 wb-ide-chrome border-b border-white/10 font-mono text-[10px] text-slate-300">
                              <span>
                                + Secure Patch: <strong className="text-emerald-400">{aiFixData.codeBlock.filename}</strong>
                              </span>
                              <button
                                type="button"
                                onClick={() => handleCopy(aiFixData.codeBlock.code)}
                                className="text-emerald-400 hover:underline font-semibold inline-flex items-center gap-1 cursor-pointer"
                              >
                                <Copy className="w-3 h-3" />
                                Copy Fix
                              </button>
                            </div>
                            <pre className="p-2.5 text-emerald-300 font-mono text-[10.5px] overflow-x-auto select-all">
                              {aiFixData.codeBlock.code}
                            </pre>
                          </div>
                          {aiFixData.verifyCommand && (
                            <div className="px-2.5 py-1.5 rounded-lg wb-ide-evidence border border-white/10 text-[10px] font-mono text-slate-400">
                              Verify: <span className="text-cyan-400">{aiFixData.verifyCommand}</span>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Passed Check Confirmation */}
          {isPass && (
            <div className="bg-emerald-500/[0.06] border border-emerald-500/25 rounded-lg p-3">
              <span className="font-mono text-[10px] font-semibold uppercase text-emerald-400 tracking-[0.12em] block mb-1">
                Defense Verified
              </span>
              <p className="text-slate-300 text-xs leading-relaxed">
                {finding.remediation}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
