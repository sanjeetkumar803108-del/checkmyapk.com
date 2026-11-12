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
  Smartphone
} from 'lucide-react';

export interface FindingProps {
  category: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'PASS';
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
}

// Built-in framework specific fixes for instant copy-pasting (Web + Mobile APK)
function getPreconfiguredFixes(type: string, targetUrl: string): Record<string, { filename: string; code: string }> {
  // ── Android Mobile APK Fixes ──
  if (type.includes('debuggable') || type.includes('Debug Mode')) {
    return {
      gradle: {
        filename: 'android/app/build.gradle',
        code: `android {\n    buildTypes {\n        release {\n            debuggable false\n            minifyEnabled true\n            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'\n        }\n    }\n}`
      },
      manifest: {
        filename: 'AndroidManifest.xml',
        code: `<!-- Ensure android:debuggable is false or omitted in release builds -->\n<application\n    android:debuggable="false"\n    android:icon="@mipmap/ic_launcher"\n    ... >`
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
        code: `<!-- Disallow extraction of SQLite databases and private auth tokens via adb backup -->\n<application\n    android:allowBackup="false"\n    android:fullBackupContent="false"\n    ... >`
      }
    };
  }

  if (type.includes('Target SDK')) {
    return {
      gradle: {
        filename: 'android/app/build.gradle',
        code: `android {\n    compileSdkVersion 35\n    defaultConfig {\n        minSdkVersion 24\n        targetSdkVersion 35 // Android 15+ Play Store compliant\n    }\n}`
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
        code: `<!-- Remove SYSTEM_ALERT_WINDOW from manifest unless strictly needed for floating PIP -->\n<!-- Delete this line: <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" /> -->\n\n// In Activity: Enable filterTouchesWhenObscured to block overlay tapjacking:\nview.setFilterTouchesWhenObscured(true);`
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

  if (type.includes('LocalStorage') || type.includes('JWT')) {
    return {
      cookie: {
        filename: 'server/auth.ts (HttpOnly Session Cookie Pattern)',
        code: `// Avoid: localStorage.setItem('token', jwt) -> readable by any XSS script!\n// Instead issue HttpOnly + Secure cookies from your backend:\nres.cookie('__Host-session', sessionToken, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict',\n  path: '/',\n  maxAge: 7 * 24 * 60 * 60 * 1000\n});`
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
        code: `import { Ratelimit } from '@upstash/ratelimit';\nimport { Redis } from '@upstash/redis';\nimport { NextResponse } from 'next/server';\n\nconst ratelimit = new Ratelimit({\n  redis: Redis.fromEnv(),\n  limiter: Ratelimit.slidingWindow(20, '1 m'),\n});\n\nexport async function middleware(request) {\n  const ip = request.ip ?? '127.0.0.1';\n  const { success } = await ratelimit.limit(ip);\n  if (!success) return new NextResponse('Rate limit exceeded', { status: 429 });\n  return NextResponse.next();\n}`
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
        code: `// 1. In .env:\nAPI_SECRET_KEY=sk_your_private_key\n\n// 2. In server.ts (DO NOT expose key in client bundles):\napp.post('/api/secure-action', async (req, res) => {\n  const apiKey = process.env.API_SECRET_KEY;\n  const response = await fetch('https://api.external.com', {\n    headers: { 'Authorization': \`Bearer \${apiKey}\` },\n    body: JSON.stringify(req.body)\n  });\n  res.json(await response.json());\n});`
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
  defaultExpanded = false
}) => {
  const isPass = finding.severity === 'PASS';
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
    <div className={`rounded-2xl border border-l-4 ${leftAccent} transition-all overflow-hidden glass-card ${
      isPass ? 'border-white/5 hover:border-emerald-500/30' : 'border-white/10 hover:border-cyan-500/30 shadow-lg'
    }`}>
      {/* ── Main Header ── */}
      <div 
        onClick={() => setExpanded(!expanded)} 
        className="p-4 sm:p-5 flex items-start justify-between gap-3 cursor-pointer select-none hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex items-start gap-3">
          <div className="mt-0.5 shrink-0">
            {isPass ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            ) : (
              <ShieldAlert className={`w-5 h-5 ${finding.severity === 'CRITICAL' ? 'text-rose-500' : 'text-orange-400'}`} />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className={`text-[10px] uppercase font-black px-2 py-0.5 rounded-md border ${badgeStyle}`}>
                {finding.severity}
              </span>
              {finding.owaspRef && (
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-md bg-cyan-500/10 text-cyan-300 border border-cyan-500/25">
                  {finding.owaspRef}
                </span>
              )}
              <span className="text-[11px] font-bold text-slate-400">
                {finding.category}
              </span>
            </div>
            <h4 className="text-sm font-bold text-slate-100 leading-snug">
              {finding.type}
            </h4>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {!isPass && (
            <span className="text-[10px] font-bold text-cyan-400 bg-cyan-950/40 border border-cyan-800/50 px-2 py-1 rounded-lg hidden sm:flex items-center gap-1">
              <Code2 className="w-3 h-3" />
              Fix Available
            </span>
          )}
          <button className="text-slate-400 p-1 hover:text-slate-200 shrink-0">
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* ── Expanded Deep Breakdown ── */}
      {expanded && (
        <div className="p-4 pt-0 space-y-4 text-xs border-t border-[#1a1f2e] mt-1 bg-[#0b0d14]/60">
          
          {/* 1. Threat & Real-World Risk */}
          <div className="pt-3">
            <span className="text-[10px] font-black uppercase text-slate-400 tracking-wider flex items-center gap-1.5 mb-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              Khatra & Impact (Why This is Dangerous):
            </span>
            <p className="text-slate-300 leading-relaxed font-normal bg-[#10131d] p-3 rounded-xl border border-[#1d2233]">
              {finding.description}
            </p>
          </div>

          {/* 2. Proof of Vulnerability */}
          {finding.proof && (
            <div>
              <span className="text-[10px] font-black uppercase text-slate-400 tracking-wider flex items-center gap-1.5 mb-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                Proof of Vulnerability (Exact Artifact Evidence):
              </span>
              <div className="bg-[#07090e] border border-[#1a1f2c] rounded-xl p-3 font-mono text-[11px] text-cyan-300 break-all select-all">
                {finding.proof}
              </div>
            </div>
          )}

          {/* 3. STEP-BY-STEP FIX & CODE (If Vulnerability) */}
          {!isPass && (
            <div className="space-y-3 bg-[#0d1017] p-4 rounded-2xl border border-cyan-500/20">
              
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="text-[11px] font-black uppercase text-emerald-400 tracking-wider flex items-center gap-1.5">
                  <Lightbulb className="w-4 h-4 text-emerald-400" />
                  Step-by-Step Code Solution:
                </span>

                {/* Dynamic Framework Selector Tabs */}
                {availableTabs.length > 1 && (
                  <div className="flex items-center gap-1 bg-[#141824] p-1 rounded-xl border border-[#22293d] text-[10px] flex-wrap">
                    {availableTabs.map((t) => (
                      <button
                        key={t}
                        onClick={() => setActiveTab(t)}
                        className={`px-2 py-0.5 rounded-lg font-bold transition-all cursor-pointer ${
                          activeTab === t ? 'bg-cyan-500 text-black' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        {getTabLabel(t)}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Code Snippet Box */}
              <div className="relative rounded-xl border border-[#1e2538] bg-[#07090e] overflow-hidden">
                <div className="flex items-center justify-between px-3 py-1.5 bg-[#121622] border-b border-[#1e2538] text-[11px]">
                  <div className="flex items-center gap-1.5 text-slate-300 font-mono">
                    <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                    <span>{currentSnippet.filename}</span>
                  </div>
                  <button
                    onClick={() => handleCopy(currentSnippet.code)}
                    className="flex items-center gap-1 text-[10px] font-bold text-cyan-300 hover:text-cyan-200 transition-colors bg-cyan-950/60 px-2.5 py-1 rounded-lg border border-cyan-800/40 cursor-pointer"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copied ? 'Copied to Clipboard!' : 'Copy Code'}
                  </button>
                </div>
                <pre className="p-3 text-[11px] font-mono text-emerald-300 overflow-x-auto leading-relaxed select-all">
                  {currentSnippet.code}
                </pre>
              </div>

              {/* 🤖 On-Demand AI Fix Doctor (Gemini 3.8 Flash) */}
              <div className="pt-2 border-t border-[#1a1f2e]">
                {!aiFixData && !loadingAiFix && (
                  <button
                    onClick={handleAskAiDoctor}
                    className="w-full py-2.5 px-3 rounded-xl text-xs font-bold bg-gradient-to-r from-cyan-950/80 via-blue-950/80 to-purple-950/80 hover:from-cyan-900/80 hover:to-purple-900/80 text-cyan-300 border border-cyan-500/30 flex items-center justify-center gap-2 transition-all cursor-pointer shadow-lg hover:shadow-cyan-500/10"
                  >
                    <Sparkles className="w-4 h-4 text-cyan-400" />
                    <span>Ask Gemini 3.8 Flash: Explain & Write Custom Fix in Simple Hindi/English</span>
                  </button>
                )}

                {loadingAiFix && (
                  <div className="p-3 rounded-xl bg-[#090b12] border border-cyan-500/30 flex items-center justify-center gap-2 text-cyan-300 text-xs font-bold animate-pulse">
                    <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                    <span>Gemini 3.8 Flash Neural Engine is analyzing the APK & drafting remediation...</span>
                  </div>
                )}

                {aiFixError && (
                  <div className="p-2.5 text-xs text-rose-300 bg-rose-950/30 border border-rose-800/40 rounded-xl">
                    {aiFixError}
                  </div>
                )}

                {/* AI Fix Doctor Results */}
                {aiFixData && (
                  <div className="p-3.5 rounded-xl bg-[#090c14] border border-cyan-500/30 space-y-3">
                    <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs">
                      <Sparkles className="w-4 h-4 text-cyan-400" />
                      <span>
                        {aiFixData.source === 'deterministic'
                          ? 'Deterministic Security Rulebook (AI Quota Fallback):'
                          : 'Gemini 3.8 Flash Deep Remediation Report:'}
                      </span>
                    </div>

                    <div className="space-y-2 text-slate-300 text-[11px] leading-relaxed">
                      <div>
                        <strong className="text-white block mb-0.5">📌 Asal Kaami Kya Hai (Simple Explanation):</strong>
                        <p>{aiFixData.simpleExplanation}</p>
                      </div>

                      <div>
                        <strong className="text-rose-400 block mb-0.5">🚨 Hacker Attack Scenario (Live Danger):</strong>
                        <p className="text-rose-200/90">{aiFixData.dangerScenario}</p>
                      </div>

                      {aiFixData.steps && (
                        <div>
                          <strong className="text-emerald-400 block mb-1">🛠️ Step-by-Step Action Plan:</strong>
                          <ul className="list-disc pl-4 space-y-0.5 text-emerald-200/90">
                            {aiFixData.steps.map((st: string, idx: number) => (
                              <li key={idx}>{st}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {aiFixData.codeBlock && (
                        <div className="mt-2">
                          <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
                            <span>File: <strong className="text-cyan-300">{aiFixData.codeBlock.filename}</strong></span>
                            <button
                              onClick={() => handleCopy(aiFixData.codeBlock.code)}
                              className="text-cyan-400 hover:text-cyan-300 font-bold flex items-center gap-1"
                            >
                              <Copy className="w-3 h-3" />
                              Copy AI Code
                            </button>
                          </div>
                          <pre className="p-2.5 rounded-lg bg-black border border-cyan-900/40 text-emerald-300 font-mono text-[10px] overflow-x-auto select-all">
                            {aiFixData.codeBlock.code}
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>

            </div>
          )}

          {/* If Pass */}
          {isPass && (
            <div className="bg-emerald-950/20 border border-emerald-900/40 rounded-xl p-3">
              <span className="text-[10px] font-black uppercase text-emerald-400 tracking-wider block mb-1">
                🛡️ Defense Status:
              </span>
              <p className="text-emerald-200/90 text-xs font-medium leading-relaxed">
                {finding.remediation}
              </p>
            </div>
          )}

        </div>
      )}
    </div>
  );
};
