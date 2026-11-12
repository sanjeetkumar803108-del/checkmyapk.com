# CheckMyAPK.com — AI Web & Android APK Security Auditor

Full-stack Web & Android `.apk` static, bytecode CFG/taint, and live API surface security scanner with OWASP / MASVS v2 mapping, deterministic security scoring, copy-paste framework remediation, and Gemini-powered deep fix generation.

## Core Capabilities

### Website & API Surface Audit (`POST /api/scan`)
- **JS Bundle & Chunk Secret Scanning:** Extracts `<script src>` and `<link rel="modulepreload">` bundles (up to 20 scripts) and detects OpenAI, Anthropic Claude, Stripe Live, AWS, GitHub PAT, Google Gemini/Cloud (`AIza...` with Firebase client-key context classification), PEM private keys, and MongoDB URIs.
- **Sensitive Build & Server Leaks:** Probes `/.env`, `/.git/HEAD`, and up to 2 same-origin `.js.map` source maps with content verification to minimize SPA false positives.
- **HTTP Security Headers & Cookies:** Checks CSP, HSTS, `X-Frame-Options` / `frame-ancestors`, CORS wildcard/credential exposure, `X-Content-Type-Options`, and `HttpOnly`/`Secure` cookie flags.
- **Live Cloud DB & Rate-Limit Probes:** Inspects HTML + JS bundles for Firebase RTDB (`*.firebaseio.com` / `*.firebasedatabase.app`) and Supabase (`*.supabase.co`) instances, detects `localStorage` auth token sinks, and sends a 15-request burst probe for API Denial-of-Wallet rate-limit gaps.

### Android APK Deep Audit (`POST /api/jobs/scan-apk`, `GET /api/jobs/:jobId`)
- **In-Memory Container & Manifest Verification:** Parses binary `AndroidManifest.xml` (AXML), checks `android:debuggable`, `usesCleartextTraffic`, `allowBackup`, `targetSdkVersion`, dangerous permissions (`SYSTEM_ALERT_WINDOW`, external storage), signing keystore (`META-INF/`), `res/xml/*.xml` Network Security Config, and full Exported IPC surface (`activities`, `services`, `receivers`, `providers`).
- **Multi-Layer DEX, Asset & Resource Analysis:** Detects framework (`Flutter`, `React Native`, `Capacitor`, `Unity 3D`, Native), CPU ABIs, 9 hardcoded secret patterns, 10 privacy trackers, 15 third-party SDKs, ProGuard/R8 obfuscation heuristics, and Capacitor WebView flags.
- **Dalvik Bytecode CFG & Intraprocedural Taint Engine (`server/scanner/dexAnalyzer.ts`):** Parses all `classes*.dex` binaries to verify `X509TrustManager`, `HostnameVerifier`, and `SslErrorHandler.proceed()`, tracks untrusted `Intent`/`Uri`/`Bundle`/`Clipboard` taint into `WebView`, `SQLiteDatabase`, `Runtime.exec`, and `startActivity` sinks, and inspects `Cipher.getInstance`, `SecretKeySpec`, `IvParameterSpec`, `openFileOutput`, and `PendingIntent` usage.
- **Stage 3 Live API & BaaS Probing:** Probes discovered Firebase/Supabase URLs and up to 3 extracted HTTPS backend API endpoints for live CORS, HSTS, and status health.

## Local Setup

```bash
npm install
cp .env.example .env
# Optional: set GEMINI_API_KEY in .env (falls back cleanly to deterministic rulebook if omitted/quota-limited)
npm run dev
```

## Production Build & Run

```bash
npm install
npm run build
npm start
```

> **Hosting Note:** Because APK uploads accept up to `100 MB` (`multer.memoryStorage()`) and deep scans use an asynchronous in-memory job queue (`GET /api/jobs/:jobId`), deploy the full-stack server on a persistent Node.js host such as **Railway**, **Render**, **Fly.io**, or a Linux VPS rather than pure Vercel Serverless Functions (which enforce a `4.5 MB` payload limit and ephemeral execution).
