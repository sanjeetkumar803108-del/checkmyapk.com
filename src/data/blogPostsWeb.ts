import type { BlogPost } from './blogPostsApk';

export const WEB_BLOG_POSTS: BlogPost[] = [
  {
    slug: 'restrict-exposed-firebase-gemini-api-keys',
    title: 'Exposed Firebase & Gemini (AIza) API Keys: How Attackers Drain Your GCP Bill',
    metaTitle: 'How to Restrict Exposed Firebase & Gemini AIza API Keys | CheckMyAPK',
    metaDescription:
      'Discover why unrestricted AIza Google Cloud keys in web bundles and APKs get hijacked for free Gemini API usage, and how to lock them down in 2 minutes.',
    category: 'Cloud & BaaS',
    owaspRef: 'OWASP-A02',
    publishedAt: '2026-11-19',
    readTime: '6 min read',
    keywords: [
      'firebase api key exposed',
      'gemini api key leak',
      'AIza key restrictions google cloud',
      'prevent gcp billing abuse',
    ],
    excerpt:
      'Firebase client keys (AIza...) are designed to identify your project, but when Google Cloud API restrictions are left open, attackers hijack that same key to burn your paid Gemini quota.',
    summaryPoints: [
      'An unrestricted AIza key inside a React bundle or Android APK can invoke ANY enabled API on that GCP project—including Generative Language (Gemini).',
      'Always apply Application Restrictions (HTTP Referrers for Web, Package + SHA-1 for Android) AND API Restrictions in Google Cloud Console.',
      'Never use the same AIza key for Firebase Auth and Gemini AI—keep Gemini keys strictly inside backend server environment variables.',
    ],
    sections: [
      {
        heading: 'The Dangerous Misconception About Firebase Client Keys',
        body: [
          'Developers often read that "Firebase API keys are safe to expose in frontend code." That is only true when the key is restricted to Firebase Auth / Installations APIs and your Firestore/RTDB security rules are locked down.',
          'When you enable the Generative Language API (Gemini) or Google Maps Platform in the same GCP project, your public Firebase AIza key automatically gains permission to call those billed APIs unless you explicitly restrict it.',
        ],
      },
      {
        heading: 'How Automated Key Scrapers Exploit Your Key',
        body: [
          'Bots scrape public websites and APKs for AIza[0-9A-Za-z-_]{35} strings, immediately test them against generativelanguage.googleapis.com/v1beta/models, and resell working keys on underground forums—causing sudden $500–$10,000 surprise bills overnight.',
        ],
      },
      {
        heading: '2-Minute Google Cloud Console Lock-Down',
        body: [
          'Open Google Cloud Console -> APIs & Services -> Credentials, click your public key, enable Application Restrictions (Websites or Android apps), and under API Restrictions whitelist ONLY Identity Toolkit, Token Service, and Firebase Installations.',
        ],
      },
    ],
    codeDiff: {
      filename: 'server/routes/aiProxy.ts (Server-Only Gemini Key)',
      language: 'typescript',
      before: `// VULNERABLE: Calling Gemini directly from browser/APK with VITE_GEMINI_KEY
const ai = new GoogleGenAI({ apiKey: import.meta.env.VITE_GEMINI_KEY });`,
      after: `// SECURE: Keep GEMINI_API_KEY strictly on server + apply rate limiting
import { GoogleGenAI } from '@google/genai';

app.post('/api/ai/analyze', requireAuth, rateLimiter, async (req, res) => {
  const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY! });
  const result = await ai.models.generateContent({
    model: 'gemini-3.8-flash',
    contents: req.body.prompt,
  });
  res.json({ text: result.text });
});`,
      verifyCommand: 'Scan your live URL or APK on CheckMyAPK.com -> Confirm 0 Unrestricted Gemini Key alerts',
    },
    faqs: [
      {
        q: 'Should I rotate my Gemini API key if it was exposed in a JS bundle?',
        a: 'Yes. Immediately regenerate or delete the exposed key in Google Cloud Console, move the new key to server-side process.env, and set a monthly GCP billing budget alert.',
      },
    ],
  },
  {
    slug: 'add-csp-hsts-x-frame-options-nextjs-vercel-express',
    title: '60-Second Fix: Add CSP, HSTS & X-Frame-Options in Next.js, Vercel & Express',
    metaTitle: 'Add CSP, HSTS & X-Frame-Options in Next.js, Vercel & Express | CheckMyAPK',
    metaDescription:
      'Copy-paste production HTTP security headers (Content-Security-Policy, HSTS, X-Frame-Options, nosniff) for Next.js, Vercel, and Node/Express.',
    category: 'Web & API',
    owaspRef: 'OWASP-A05',
    publishedAt: '2026-11-17',
    readTime: '5 min read',
    keywords: [
      'add csp header vercel.json',
      'next.config.js security headers',
      'fix missing hsts header',
      'x-frame-options clickjacking fix',
    ],
    excerpt:
      'Missing HTTP security headers are the #1 reason modern SaaS websites score a C or F on security audits. Fix all four core headers in a single config file in under 60 seconds.',
    summaryPoints: [
      'Content-Security-Policy (CSP) stops injected XSS scripts from executing or exfiltrating session data.',
      'Strict-Transport-Security (HSTS) prevents SSL-stripping downgrades on public Wi-Fi.',
      'X-Frame-Options: SAMEORIGIN and X-Content-Type-Options: nosniff block clickjacking and MIME-sniffing attacks.',
    ],
    sections: [
      {
        heading: 'Why Default Hosting Deployments Miss Security Headers',
        body: [
          'Platforms like Vercel, Netlify, Cloudflare Pages, and Express.js do not enforce strict CSP or X-Frame-Options out of the box because every app loads different fonts, analytics, or embed frames. Leaving them unconfigured leaves your users exposed to XSS and invisible-iframe clickjacking.',
        ],
      },
      {
        heading: 'Drop-In 1-File Configuration',
        body: [
          'Add the header block below to vercel.json (or next.config.js headers() / Helmet in Express) and redeploy. Test immediately with curl -I or CheckMyAPK.',
        ],
      },
    ],
    codeDiff: {
      filename: 'vercel.json (1-File Master Security Headers)',
      language: 'json',
      before: `// Missing Content-Security-Policy, HSTS, X-Frame-Options & nosniff`,
      after: `{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "X-Frame-Options", "value": "SAMEORIGIN" },
        { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Content-Security-Policy", "value": "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; frame-ancestors 'self';" }
      ]
    }
  ]
}`,
      verifyCommand: 'curl -I https://yourdomain.com',
    },
    faqs: [
      {
        q: 'Can I test a CSP header without breaking my site first?',
        a: 'Yes. Deploy Content-Security-Policy-Report-Only first, inspect browser DevTools console for any blocked scripts/fonts, whitelist legitimate origins, then switch to enforced Content-Security-Policy.',
      },
    ],
  },
  {
    slug: 'dynamic-cors-origin-reflection-vulnerability-fix',
    title: 'Dynamic CORS Origin Reflection Vulnerability Explained (With Express.js Fix)',
    metaTitle: 'Fix Dynamic CORS Origin Reflection Vulnerability in Express | CheckMyAPK',
    metaDescription:
      'Learn why cors({ origin: true, credentials: true }) lets any malicious website steal authenticated user data, and how to enforce an explicit CORS allowlist.',
    category: 'Web & API',
    owaspRef: 'OWASP-A01',
    publishedAt: '2026-11-15',
    readTime: '5 min read',
    keywords: [
      'cors origin reflection vulnerability',
      'express cors credentials true security',
      'access-control-allow-origin fix',
      'cors misconfiguration exploit',
    ],
    excerpt:
      'Reflecting the incoming Origin header alongside Access-Control-Allow-Credentials: true completely bypasses the browser Same-Origin Policy and lets rogue sites read private API responses.',
    summaryPoints: [
      'Passing origin: true with credentials: true in Express cors() echoes back ANY attacker domain.',
      'Any malicious site visited by your logged-in user can issue fetch() with credentials: "include" and read private account data.',
      'Replace dynamic reflection with an explicit Set of exact trusted origins.',
    ],
    sections: [
      {
        heading: 'How Dynamic CORS Reflection Happens',
        body: [
          'Browsers block Access-Control-Allow-Origin: * when credentials are enabled. To work around that browser error during development, developers frequently configure cors({ origin: true, credentials: true }), which blindly copies req.headers.origin into Access-Control-Allow-Origin.',
        ],
      },
      {
        heading: 'Attack Scenario: Cross-Origin Session Data Theft',
        body: [
          'An attacker sends a phishing link to your logged-in user. The attacker webpage executes fetch("https://api.yourdomain.com/api/auth/me", { credentials: "include" }). Because your API reflects the attacker origin with credentials allowed, the browser hands the full JSON response straight to the attacker.',
        ],
      },
    ],
    codeDiff: {
      filename: 'server.ts (Explicit CORS Allowlist)',
      language: 'typescript',
      before: `// VULNERABLE: Echoes back ANY attacker Origin with cookies enabled!
app.use(cors({ origin: true, credentials: true }));`,
      after: `// SECURE: Strict exact-match origin allowlist
const ALLOWED_ORIGINS = new Set([
  'https://yourdomain.com',
  'https://app.yourdomain.com',
]);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.has(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origin not allowed by CORS'));
  },
  credentials: true,
}));`,
      verifyCommand: 'curl -I -H "Origin: https://evil-attacker.example" https://yourdomain.com/api/auth/me',
    },
    faqs: [
      {
        q: 'Is checking origin.includes("yourdomain.com") safe?',
        a: 'No! An attacker can register yourdomain.com.evil.net and bypass substring checks. Always compare against an exact Set of full origins (scheme + host + port).',
      },
    ],
  },
  {
    slug: 'block-exposed-env-git-source-maps-production',
    title: 'How to Find & Block Exposed .env, .git, and .js.map Source Maps in Production',
    metaTitle: 'Block Exposed .env, .git & JS Source Maps in Production | CheckMyAPK',
    metaDescription:
      'Prevent instant full-app compromise by blocking public access to /.env, /.git/HEAD, and production JavaScript .js.map files across Nginx, Vite, and Next.js.',
    category: 'Web & API',
    owaspRef: 'OWASP-A05',
    publishedAt: '2026-11-12',
    readTime: '5 min read',
    keywords: [
      'exposed .env file fix',
      'block .git directory nginx',
      'disable production source maps vite nextjs',
      'js.map security risk',
    ],
    excerpt:
      'One misconfigured static root can expose your entire database password in /.env, full commit history in /.git, or unminified frontend source code in .js.map files.',
    summaryPoints: [
      'Automated scanners probe /.env and /.git/HEAD on every new domain within minutes of SSL certificate issuance.',
      'Public .js.map files allow anyone to reconstruct your original TypeScript/React source tree, comments, and hidden admin routes.',
      'Deny all dotfiles at the web server layer and disable browser source maps in production builds.',
    ],
    sections: [
      {
        heading: 'Why Exposed Dotfiles Are Instant Critical Findings',
        body: [
          'If /.env returns HTTP 200, attackers immediately obtain your PostgreSQL/MongoDB URI, Stripe secret, JWT signing secret, and SMTP credentials. If /.git/HEAD is readable, tools like git-dumper reconstruct your entire private repository.',
        ],
      },
      {
        heading: 'Disabling Production Source Maps Safely',
        body: [
          'If you need readable stack traces in Sentry or Datadog, upload source maps privately during CI/CD and delete .map files before deploying static assets—or set sourcemap: false in Vite and productionBrowserSourceMaps: false in Next.js.',
        ],
      },
    ],
    codeDiff: {
      filename: 'nginx.conf & vite.config.ts',
      language: 'bash',
      before: `# Vite default or misconfigured static root serving dotfiles & .js.map
export default defineConfig({ build: { sourcemap: true } });`,
      after: `# 1. Nginx: Deny all hidden dotfiles (.env, .git, .htaccess)
location ~ /\\. {
  deny all;
  return 404;
}

# 2. vite.config.ts: Disable public browser source maps
export default defineConfig({
  build: { sourcemap: false }
});`,
      verifyCommand: 'curl -i https://yourdomain.com/.env && curl -i https://yourdomain.com/.git/HEAD',
    },
    faqs: [
      {
        q: 'What should I do if /.env was already publicly accessible?',
        a: 'Blocking the file is only step one. Assume automated bots already downloaded it—immediately rotate every database password, JWT secret, and API key contained inside.',
      },
    ],
  },
  {
    slug: 'supabase-rls-firebase-rules-prevent-data-leaks',
    title: 'Supabase RLS & Firebase Realtime Database Rules: Stop Public Data Leaks',
    metaTitle: 'Supabase RLS & Firebase Security Rules Guide | CheckMyAPK',
    metaDescription:
      'Prevent anonymous attackers from dumping your entire Supabase PostgreSQL tables or Firebase Realtime Database with production-ready Row Level Security rules.',
    category: 'Cloud & BaaS',
    owaspRef: 'OWASP-A01',
    publishedAt: '2026-11-09',
    readTime: '6 min read',
    keywords: [
      'supabase rls security policy',
      'firebase realtime database publicly readable',
      'firestore security rules owner only',
      'supabase anon key security',
    ],
    excerpt:
      'Both Supabase and Firebase expose direct database endpoints to the browser and mobile apps. Without strict Row Level Security (RLS) or Security Rules, anyone with your URL can dump every row.',
    summaryPoints: [
      'A Supabase anon key is intentionally public—PostgreSQL Row Level Security (RLS) is the ONLY barrier protecting your tables.',
      'Never leave Firebase RTDB rules as ".read": true or Firestore test-mode rules active past development.',
      'Test your live endpoints unauthenticated (or scan with CheckMyAPK) to confirm anonymous reads return HTTP 401/403.',
    ],
    sections: [
      {
        heading: 'How BaaS Data Breaches Happen in Seconds',
        body: [
          'An attacker extracts your supabase.co URL and anon key (or firebaseio.com URL) from your web JS bundle or Android APK. With a single curl GET request to /rest/v1/users?select=* or /.json, an unguarded database returns every user email, phone number, and record in plaintext.',
        ],
      },
      {
        heading: 'Locking Down Supabase RLS & Firestore Rules',
        body: [
          'Enable RLS on every public schema table in Supabase and write explicit SELECT/INSERT/UPDATE/DELETE policies scoped to auth.uid(). In Firebase, require request.auth != null and verify document ownership.',
        ],
      },
    ],
    codeDiff: {
      filename: 'supabase-rls.sql & firestore.rules',
      language: 'sql',
      before: `-- VULNERABLE: RLS disabled on public.profiles (any anon key can dump all rows!)
-- Or Firestore: allow read, write: if true;`,
      after: `-- SECURE Supabase PostgreSQL Row Level Security:
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own profile"
  ON public.profiles FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can update own profile"
  ON public.profiles FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);`,
      verifyCommand: 'curl -H "apikey: YOUR_ANON_KEY" https://YOUR_PROJECT.supabase.co/rest/v1/profiles?select=*',
    },
    faqs: [
      {
        q: 'Is exposing the Supabase service_role key in client code safe if RLS is on?',
        a: 'NEVER! The service_role key completely bypasses all Row Level Security policies. It must only live on your backend server.',
      },
    ],
  },
  {
    slug: 'jwt-security-alg-none-expiration-best-practices',
    title: 'JWT Security Pitfalls: Fixing alg: none, Missing exp Claims & LocalStorage Leaks',
    metaTitle: 'JWT Security Best Practices (alg: none, exp & Cookies) | CheckMyAPK',
    metaDescription:
      'Eliminate critical JWT authentication flaws including alg: none signature bypass, infinite non-expiring tokens, PII in payloads, and XSS token theft from localStorage.',
    category: 'Web & API',
    owaspRef: 'OWASP-A07',
    publishedAt: '2026-11-06',
    readTime: '6 min read',
    keywords: [
      'jwt alg none vulnerability',
      'jwt localstorage vs httponly cookie',
      'jwt missing exp claim',
      'jsonwebtoken verify algorithms',
    ],
    excerpt:
      'JSON Web Tokens power modern APIs, but calling jwt.decode() instead of jwt.verify(), omitting expiration claims, or storing tokens in localStorage opens trivial account takeovers.',
    summaryPoints: [
      'Always pin allowed signing algorithms (e.g., algorithms: ["HS256"]) inside jwt.verify() to block alg: none and key-confusion attacks.',
      'Enforce short access-token lifetimes (15m–1h) with mandatory exp claims and zero passwords/secrets inside the Base64 payload.',
      'Prefer HttpOnly, Secure, SameSite=Strict session cookies over localStorage so XSS scripts cannot steal tokens.',
    ],
    sections: [
      {
        heading: 'Why Base64 JWT Payloads Are Not Encrypted',
        body: [
          'Anyone can Base64-decode a JWT header and payload without the secret key. Never place sensitive PII, password hashes, or internal API keys inside JWT claims.',
        ],
      },
      {
        heading: 'Hardening Signing, Verification & Storage',
        body: [
          'Sign tokens with a strong 256-bit secret from process.env, set an explicit expiresIn TTL, pin algorithms during verification, and deliver web sessions via HttpOnly cookies.',
        ],
      },
    ],
    codeDiff: {
      filename: 'server/auth/jwt.ts',
      language: 'typescript',
      before: `// VULNERABLE: No expiration, accepts alg: "none", stored in localStorage
const token = jwt.sign({ id: user.id, passwordHash: user.hash }, 'secret');
const payload = jwt.decode(token);`,
      after: `// SECURE: Short TTL, pinned algorithm, HttpOnly Secure cookie
const token = jwt.sign(
  { sub: user.id, role: user.role },
  process.env.JWT_SECRET!,
  { algorithm: 'HS256', expiresIn: '15m' }
);

const payload = jwt.verify(token, process.env.JWT_SECRET!, {
  algorithms: ['HS256'],
});

res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 15 * 60 * 1000,
});`,
      verifyCommand: 'Scan your authenticated endpoint with CheckMyAPK -> Inspect Attack Surface JWT Audit',
    },
    faqs: [
      {
        q: 'Why is localStorage risky for JWTs?',
        a: 'Any third-party script or XSS vulnerability on your page can call localStorage.getItem("token") and exfiltrate the user session. HttpOnly cookies cannot be read by JavaScript.',
      },
    ],
  },
  {
    slug: 'play-store-data-safety-restricted-permissions-guide',
    title: 'Google Play Console Data Safety & Restricted Permissions Rejection Guide',
    metaTitle: 'Fix Google Play Console Restricted Permissions & Data Safety Rejections | CheckMyAPK',
    metaDescription:
      'Avoid Google Play Store app rejections caused by QUERY_ALL_PACKAGES, SYSTEM_ALERT_WINDOW, outdated targetSdkVersion, and undeclared tracker SDKs.',
    category: 'Play Store Compliance',
    owaspRef: 'MASVS-PLATFORM-1',
    publishedAt: '2026-11-03',
    readTime: '6 min read',
    keywords: [
      'google play console rejection permissions',
      'query_all_packages play store fix',
      'play data safety tracker sdk',
      'android targetSdkVersion requirement',
    ],
    excerpt:
      'Google Play automated review bots reject builds for broad permissions, outdated targetSdkVersion, and mismatched Data Safety disclosures. Audit your final APK before uploading.',
    summaryPoints: [
      'Remove broad permissions like QUERY_ALL_PACKAGES, REQUEST_INSTALL_PACKAGES, and READ_EXTERNAL_STORAGE unless strictly core to app functionality.',
      'Replace QUERY_ALL_PACKAGES with targeted <queries> intent blocks in AndroidManifest.xml.',
      'Fingerprint every third-party analytics and ad SDK inside your compiled APK so your Play Data Safety form matches reality.',
    ],
    sections: [
      {
        heading: 'Hidden Permissions Injected by Third-Party SDKs',
        body: [
          'Even if your own AndroidManifest.xml looks clean, Gradle manifest merging often pulls in extra permissions or trackers from ad networks, crash reporters, or Capacitor/Flutter plugins. Always inspect the compiled APK.',
        ],
      },
      {
        heading: 'Using tools:node="remove" & Targeted <queries>',
        body: [
          'If an SDK injects an unwanted permission, strip it explicitly using tools:node="remove" in your app manifest, and replace QUERY_ALL_PACKAGES with exact <queries> declarations.',
        ],
      },
    ],
    codeDiff: {
      filename: 'AndroidManifest.xml (Play Store Compliant)',
      language: 'xml',
      before: `<!-- Triggers Google Play Console Restricted Permission rejection -->
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />`,
      after: `<!-- Explicitly strip unwanted SDK permissions & declare minimal <queries> -->
<uses-permission
    android:name="android.permission.QUERY_ALL_PACKAGES"
    tools:node="remove" />

<queries>
  <intent>
    <action android:name="android.intent.action.VIEW" />
    <data android:scheme="https" />
  </intent>
</queries>`,
      verifyCommand: 'Upload your release .apk to CheckMyAPK.com -> Check APK Internals (Trackers, SDKs & Permissions)',
    },
    faqs: [
      {
        q: 'What targetSdkVersion does Google Play require?',
        a: 'Google Play requires new apps and updates to target an API level within one year of the latest major Android release (API 34/35+).',
      },
    ],
  },
];
