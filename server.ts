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
import { runWebDeepAudit } from './server/scanner/webDeepScanner.ts';
import { runNetworkPostureAudit } from './server/scanner/networkPostureScanner.ts';
import { 
  generateAiSecuritySummary, 
  generateVulnerabilityDeepFix, 
  generateAiMobileAssessment 
} from './server/scanner/aiAdvisor.ts';
import { peekApkPackageName, scanApkBuffer } from './server/scanner/apkScanner.ts';
import { getPlanPolicy, type PlanPolicy } from './src/data/planPolicy.ts';
import {
  createScanJob,
  getScanJob,
  pushScanJobProgress,
  completeScanJob,
  failScanJob,
  enqueueJobTask,
  getQueueCapacity,
  subscribeScanJob
} from './server/scanner/jobQueue.ts';
import {
  AUDIT_HTTPS_AGENT,
  validateTargetSafety,
  checkClientRateLimit,
  getDomainVerificationChallenge,
  verifyDomainOwnership
} from './server/scanner/securityGuard.ts';
import {
  SESSION_COOKIE_NAME,
  registerAccount,
  authenticateAccount,
  getAccountById,
  recordUserScan,
  consumeScanTargetQuota,
  getAccountPlanById,
  updateAccountPlan,
  updateAccountBilling,
  findAccountIdByEmail,
  findAccountIdBySubscriptionId,
  hasProcessedWebhookEvent,
  markWebhookEventProcessed,
  rotateAccountToken,
  verifyFirebaseIdToken,
  upsertGoogleAccount,
  signSessionToken,
  verifySessionToken,
  parseCookieHeader,
  saveContactMessage,
  type AccountPlan
} from './server/auth/accountStore.ts';
import { dispatchContactEmail } from './server/mail/contactMailer.ts';
import {
  BillingConfigError,
  createDodoCheckoutSession,
  getDodoBillingStatus,
  resolvePlanFromProductId,
  unwrapDodoWebhook,
  type BillingCycle,
  type PaidAccountPlan,
} from './server/billing/dodoPayments.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
const PORT = process.env.PORT || 5000;
const IS_PROD = process.env.NODE_ENV === 'production' || process.argv.includes('--prod');
const MAX_APK_SIZE_MB = Number(process.env.MAX_APK_UPLOAD_MB || 150);

app.use(cors({ origin: true, credentials: true }));

// Dodo Payments webhook MUST read the raw JSON payload before express.json() parses it.
app.post('/api/webhooks/dodo', express.raw({ type: 'application/json' }), (req, res) => {
  try {
    const rawBody = Buffer.isBuffer(req.body)
      ? req.body.toString('utf8')
      : typeof req.body === 'string'
        ? req.body
        : '';

    if (!rawBody) {
      return res.status(400).json({ error: 'Missing raw webhook payload.' });
    }

    const event = unwrapDodoWebhook(rawBody, req.headers);
    const headerWebhookId = String(req.header('webhook-id') || req.header('svix-id') || '').trim();
    const dataAny = event.data as unknown as Record<string, any>;
    const entityId = String(dataAny?.subscription_id || dataAny?.payment_id || '');
    const eventKey = headerWebhookId || `${event.type}:${event.timestamp}:${entityId}`;

    if (eventKey && hasProcessedWebhookEvent(eventKey)) {
      return res.json({ received: true, duplicate: true });
    }

    let updatedUserId: string | null = null;

    if (event.type.startsWith('subscription.')) {
      const subData = event.data as any;
      const meta = (subData?.metadata || {}) as Record<string, unknown>;
      const metaUserId = typeof meta.userId === 'string' ? meta.userId.trim() : '';
      const subId = typeof subData?.subscription_id === 'string' ? subData.subscription_id.trim() : '';
      const customerEmail = typeof subData?.customer?.email === 'string' ? subData.customer.email.trim() : '';
      const customerId = typeof subData?.customer?.customer_id === 'string' ? subData.customer.customer_id : null;

      updatedUserId =
        (metaUserId && getAccountById(metaUserId) ? metaUserId : null) ||
        (subId ? findAccountIdBySubscriptionId(subId) : null) ||
        (customerEmail ? findAccountIdByEmail(customerEmail) : null);

      const resolvedProduct = resolvePlanFromProductId(subData?.product_id);
      const metaPlan = meta.plan === 'pro' || meta.plan === 'agency' ? meta.plan : null;
      const metaCycle = meta.billingCycle === 'monthly' || meta.billingCycle === 'annual' ? meta.billingCycle : undefined;
      const resolvedPlan: PaidAccountPlan | undefined = resolvedProduct?.plan || metaPlan || undefined;
      const resolvedCycle: BillingCycle | undefined = resolvedProduct?.billingCycle || metaCycle;

      if (updatedUserId) {
        if (
          event.type === 'subscription.active' ||
          event.type === 'subscription.renewed' ||
          event.type === 'subscription.plan_changed' ||
          event.type === 'subscription.unpaused' ||
          (event.type === 'subscription.updated' && subData?.status === 'active')
        ) {
          updateAccountBilling(updatedUserId, {
            plan: resolvedPlan || 'pro',
            billingCycle: resolvedCycle,
            billingStatus: 'active',
            dodoCustomerId: customerId,
            dodoSubscriptionId: subId || null,
          });
        } else if (event.type === 'subscription.past_due') {
          updateAccountBilling(updatedUserId, {
            billingStatus: 'past_due',
            dodoCustomerId: customerId,
            dodoSubscriptionId: subId || null,
          });
        } else if (
          event.type === 'subscription.cancelled' ||
          event.type === 'subscription.expired' ||
          event.type === 'subscription.failed' ||
          event.type === 'subscription.on_hold' ||
          event.type === 'subscription.paused'
        ) {
          const statusMap: Record<string, 'cancelled' | 'expired' | 'failed' | 'on_hold' | 'paused'> = {
            'subscription.cancelled': 'cancelled',
            'subscription.expired': 'expired',
            'subscription.failed': 'failed',
            'subscription.on_hold': 'on_hold',
            'subscription.paused': 'paused',
          };
          updateAccountBilling(updatedUserId, {
            plan: 'free',
            billingStatus: statusMap[event.type] || 'cancelled',
            dodoCustomerId: customerId,
            dodoSubscriptionId: subId || null,
          });
        }
      }
    }

    if (eventKey) {
      markWebhookEventProcessed(eventKey, { type: event.type, userId: updatedUserId });
    }

    return res.json({ received: true });
  } catch (err: any) {
    if (err instanceof BillingConfigError) {
      return res.status(err.statusCode).json({ error: err.message });
    }
    console.warn('[Dodo Webhook] Rejected invalid webhook:', err?.message || err);
    return res.status(400).json({ error: 'Invalid Dodo webhook signature or payload.' });
  }
});

app.use(express.json());

const authAttemptWindow = new Map<string, { count: number; resetAt: number }>();
function checkAuthRateLimit(ip: string): { allowed: boolean; retryAfterSec: number } {
  const now = Date.now();
  const entry = authAttemptWindow.get(ip);
  if (!entry || entry.resetAt <= now) {
    authAttemptWindow.set(ip, { count: 1, resetAt: now + 10 * 60 * 1000 });
    return { allowed: true, retryAfterSec: 0 };
  }
  if (entry.count >= 25) {
    return { allowed: false, retryAfterSec: Math.ceil((entry.resetAt - now) / 1000) };
  }
  entry.count += 1;
  return { allowed: true, retryAfterSec: 0 };
}

function setSessionCookie(res: express.Response, userId: string) {
  const token = signSessionToken(userId);
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    `Max-Age=${7 * 24 * 60 * 60}`
  ];
  if (IS_PROD) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(res: express.Response) {
  const parts = [
    `${SESSION_COOKIE_NAME}=`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    'Max-Age=0'
  ];
  if (IS_PROD) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function getAuthenticatedUserId(req: express.Request): string | null {
  const rawToken = parseCookieHeader(req.headers.cookie, SESSION_COOKIE_NAME);
  return verifySessionToken(rawToken);
}

// Configure Multer for in-memory APK uploads up to MAX_APK_SIZE_MB (default 75MB)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_APK_SIZE_MB * 1024 * 1024 }
});

function getClientIp(req: express.Request): string {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) {
    return xff.split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

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

// 👤 Authentication, Account & Scan History APIs
app.get('/api/auth/me', (req, res) => {
  const uid = getAuthenticatedUserId(req);
  if (!uid) return res.json({ user: null });
  const user = getAccountById(uid);
  if (!user) {
    clearSessionCookie(res);
    return res.json({ user: null });
  }
  return res.json({ user });
});

app.post('/api/auth/register', (req, res) => {
  const ipLimit = checkAuthRateLimit(getClientIp(req));
  if (!ipLimit.allowed) {
    res.setHeader('Retry-After', String(ipLimit.retryAfterSec));
    return res.status(429).json({ error: `Too many requests. Retry in ${ipLimit.retryAfterSec}s.` });
  }
  const { name = '', email = '', password = '' } = req.body || {};
  const result = registerAccount(String(name), String(email), String(password));
  if (result.error || !result.account) {
    return res.status(result.status || 400).json({ error: result.error || 'Registration failed.' });
  }
  setSessionCookie(res, result.account.id);
  return res.status(201).json({ user: result.account });
});

app.post('/api/auth/login', (req, res) => {
  const ipLimit = checkAuthRateLimit(getClientIp(req));
  if (!ipLimit.allowed) {
    res.setHeader('Retry-After', String(ipLimit.retryAfterSec));
    return res.status(429).json({ error: `Too many login attempts. Retry in ${ipLimit.retryAfterSec}s.` });
  }
  const { email = '', password = '' } = req.body || {};
  const result = authenticateAccount(String(email), String(password));
  if (result.error || !result.account) {
    return res.status(401).json({ error: result.error || 'Invalid credentials.' });
  }
  setSessionCookie(res, result.account.id);
  return res.json({ user: result.account });
});

app.post('/api/auth/firebase-google', async (req, res) => {
  const ipLimit = checkAuthRateLimit(getClientIp(req));
  if (!ipLimit.allowed) {
    res.setHeader('Retry-After', String(ipLimit.retryAfterSec));
    return res.status(429).json({ error: `Too many sign-in attempts. Retry in ${ipLimit.retryAfterSec}s.` });
  }

  const projectId = (process.env.VITE_FIREBASE_PROJECT_ID || process.env.FIREBASE_PROJECT_ID || '').trim();
  if (!projectId) {
    return res.status(503).json({
      error: 'Firebase Google Sign-In is not configured on the server (.env missing VITE_FIREBASE_PROJECT_ID).'
    });
  }

  const idToken = typeof req.body?.idToken === 'string' ? req.body.idToken.trim() : '';
  if (!idToken) {
    return res.status(400).json({ error: 'Missing Firebase ID token.' });
  }

  try {
    const profile = await verifyFirebaseIdToken(idToken, projectId);
    const user = upsertGoogleAccount({
      email: profile.email,
      name: profile.name,
      avatarUrl: profile.avatarUrl,
    });
    setSessionCookie(res, user.id);
    return res.json({ user });
  } catch (err: any) {
    return res.status(401).json({ error: err?.message || 'Google authentication failed.' });
  }
});

app.post('/api/auth/logout', (_req, res) => {
  clearSessionCookie(res);
  return res.json({ ok: true });
});

app.post('/api/auth/history', (req, res) => {
  const uid = getAuthenticatedUserId(req);
  if (!uid) return res.status(401).json({ error: 'Authentication required.' });
  const { target = '', mode = 'apk', score = 0, grade = 'B', criticalCount = 0 } = req.body || {};
  const user = recordUserScan(uid, { target, mode, score, grade, criticalCount });
  if (!user) return res.status(401).json({ error: 'Account not found.' });
  return res.json({ user });
});

app.post('/api/auth/plan', (req, res) => {
  const uid = getAuthenticatedUserId(req);
  if (!uid) return res.status(401).json({ error: 'Authentication required.' });
  const plan = req.body?.plan as AccountPlan;
  if (plan !== 'free' && plan !== 'pro' && plan !== 'agency') {
    return res.status(400).json({ error: 'Invalid plan selection.' });
  }
  if (plan !== 'free') {
    return res.status(402).json({
      error: 'Paid plans require Dodo Payments checkout before activation.',
      requiresCheckout: true,
      checkoutEndpoint: '/api/billing/checkout',
    });
  }
  const user = updateAccountBilling(uid, { plan: 'free', billingStatus: 'cancelled' });
  if (!user) return res.status(401).json({ error: 'Account not found.' });
  return res.json({ user });
});

app.get('/api/billing/status', (_req, res) => {
  return res.json(getDodoBillingStatus());
});

app.post('/api/billing/checkout', async (req, res) => {
  try {
    const uid = getAuthenticatedUserId(req);
    if (!uid) return res.status(401).json({ error: 'Please sign in before starting checkout.' });

    const account = getAccountById(uid);
    if (!account) return res.status(401).json({ error: 'Account not found.' });

    const plan = req.body?.plan;
    if (plan !== 'pro' && plan !== 'agency') {
      return res.status(400).json({ error: 'Please select a valid paid plan (pro or agency).' });
    }

    const billingCycle: BillingCycle = req.body?.billingCycle === 'annual' ? 'annual' : 'monthly';
    const host = req.get('host');
    const originUrl = host ? `${req.protocol}://${host}` : undefined;

    const session = await createDodoCheckoutSession({
      userId: account.id,
      email: account.email,
      name: account.name,
      plan: plan as PaidAccountPlan,
      billingCycle,
      originUrl,
    });

    return res.json(session);
  } catch (err: any) {
    if (err instanceof BillingConfigError) {
      return res.status(err.statusCode).json({ error: err.message });
    }
    console.error('[Dodo Checkout] Error creating session:', err);
    return res.status(502).json({
      error: err?.message || 'Could not initialize Dodo Payments checkout session.',
    });
  }
});

app.post('/api/auth/token/rotate', (req, res) => {
  const uid = getAuthenticatedUserId(req);
  if (!uid) return res.status(401).json({ error: 'Authentication required.' });
  const policy = getPlanPolicy(getAccountPlanById(uid));
  if (!policy.features.apiTokenAccess) {
    return res.status(403).json({
      error: 'Workspace CI/CD API Token & rotation is strictly exclusive to Team & Agency ($79/mo) plans.',
    });
  }
  const user = rotateAccountToken(uid);
  if (!user) return res.status(401).json({ error: 'Account not found.' });
  return res.json({ user });
});

// ✉️ Contact Us / Support Message Endpoint (Saves locally + Auto-Emails checkmyapk.com@gmail.com)
app.post('/api/contact', async (req, res) => {
  const rateCheck = checkClientRateLimit(getClientIp(req), 'web');
  if (!rateCheck.allowed) {
    res.setHeader('Retry-After', String(rateCheck.retryAfterSec));
    return res.status(429).json({
      error: `Too many requests. Please wait ${rateCheck.retryAfterSec}s before sending another message.`,
    });
  }
  try {
    const uid = getAuthenticatedUserId(req);
    const saved = saveContactMessage({
      name: String(req.body?.name || ''),
      email: String(req.body?.email || ''),
      topic: String(req.body?.topic || ''),
      userId: uid,
    });
    const mailResult = await dispatchContactEmail(saved);
    return res.status(201).json({
      ok: true,
      id: saved.id,
      receivedAt: saved.receivedAt,
      to: mailResult.to,
      emailDelivered: mailResult.delivered,
      deliveryMode: mailResult.mode,
    });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'Could not submit your message.' });
  }
});

// 🔐 Domain Ownership Challenge Generator (DNS TXT / HTML Meta / .well-known)
app.get('/api/domain-verify/challenge', (req, res) => {
  const uid = getAuthenticatedUserId(req);
  const policy = getPlanPolicy(getAccountPlanById(uid));
  if (!policy.features.burst15Req) {
    return res.status(403).json({
      error: 'Domain Ownership Verification & 15-Request Denial-of-Wallet Burst requires Pro Security ($15/mo) or Team & Agency ($79/mo).',
    });
  }
  const raw = typeof req.query.targetUrl === 'string' ? req.query.targetUrl.trim() : '';
  if (!raw) return res.status(400).json({ error: 'targetUrl query parameter is required.' });
  const normalized = raw.startsWith('http://') || raw.startsWith('https://') ? raw : `https://${raw}`;
  try {
    return res.json(getDomainVerificationChallenge(normalized));
  } catch {
    return res.status(400).json({ error: 'Invalid targetUrl format.' });
  }
});

// 🛡️ MAIN SCANNER API ENDPOINT
app.post('/api/scan', async (req, res) => {
  const clientIp = getClientIp(req);
  const rateCheck = checkClientRateLimit(clientIp, 'web');
  if (!rateCheck.allowed) {
    res.setHeader('Retry-After', String(rateCheck.retryAfterSec));
    return res.status(429).json({
      error: `Too many scan requests from this IP. Please retry in ${rateCheck.retryAfterSec}s.`
    });
  }

  const uid = getAuthenticatedUserId(req);
  const activePlan = getAccountPlanById(uid);
  const policy = getPlanPolicy(activePlan);

  const startTime = Date.now();
  const realTimeLogs: Array<{ time: string; msg: string }> = [];

  const log = (msg: string) => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
    realTimeLogs.push({ time: `[+${elapsed}s]`, msg });
    console.log(`[SecureAppAI +${elapsed}s] ${msg}`);
  };

  let { targetUrl, authHeader, authCookie } = req.body;

  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ error: 'Please provide a valid target URL.' });
  }

  if ((authHeader || authCookie) && !policy.features.authenticatedWebScan) {
    return res.status(403).json({
      error: 'Authenticated Bearer JWT / Cookie API auditing requires Pro Security ($15/mo) or Team & Agency ($79/mo).',
    });
  }

  targetUrl = targetUrl.trim();
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = `https://${targetUrl}`;
  }

  log(`Target identified: ${targetUrl}`);

  try {
    const parsedUrl = new URL(targetUrl);

    // DNS-Rebinding + Private CIDR + Metadata SSRF Protection Guard
    const ssrfCheck = await validateTargetSafety(targetUrl, { isProd: IS_PROD });
    if (!ssrfCheck.allowed) {
      return res.status(400).json({ error: ssrfCheck.reason || 'Blocked by SSRF security policy.' });
    }

    // Strict Per-Plan Monthly Unique Target & Re-scan Quota Guard
    const quota = consumeScanTargetQuota({
      userId: uid,
      clientIp,
      mode: 'web',
      rawTarget: parsedUrl.hostname,
    });
    if (!quota.allowed) {
      return res.status(429).json({ error: quota.message || 'Monthly audit quota reached.' });
    }
    log(
      `Plan check (${policy.name}): ${quota.isRescan ? 'Re-scan' : 'New target'} #${quota.targetScanCount} • ${quota.monthlyAppsUsed}/${quota.monthlyAppLimit} unique app/site slots used this month.`
    );

    log(`DNS verified (${ssrfCheck.resolvedIps[0] || parsedUrl.hostname}); connecting over ${parsedUrl.protocol}...`);

    // Step 1: Network Handshake & Fetch HTML + Headers
    // Tolerates expired/self-signed certs (AUDIT_HTTPS_AGENT) after SSRF check so TLS scanner flags them in report.
    const fetchStart = Date.now();
    const fetchTargetOnce = (tMs: number) =>
      axios.get(targetUrl, {
        timeout: tMs,
        httpsAgent: AUDIT_HTTPS_AGENT,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9'
        },
        maxRedirects: 3,
        validateStatus: () => true
      });

    let initialRes;
    try {
      initialRes = await fetchTargetOnce(12000);
    } catch (firstErr: any) {
      try {
        log(`Initial request slow/interrupted (${firstErr.message}); retrying once...`);
        initialRes = await fetchTargetOnce(12000);
      } catch (fetchErr: any) {
        log(`Connection failed: ${fetchErr.message}`);
        return res.status(400).json({
          error: `Could not connect to ${targetUrl}. Please ensure the server is online. (${fetchErr.message})`
        });
      }
    }

    // Re-check final redirect target against SSRF guard to defeat HTTP redirect-to-localhost/metadata attacks
    const finalResolvedUrl = String((initialRes.request as any)?.res?.responseUrl || targetUrl);
    if (finalResolvedUrl !== targetUrl) {
      const redirectCheck = await validateTargetSafety(finalResolvedUrl, { isProd: IS_PROD });
      if (!redirectCheck.allowed) {
        return res.status(400).json({
          error: `Target redirected to blocked internal resource: ${redirectCheck.reason}`
        });
      }
    }

    const latencyMs = Date.now() - fetchStart;
    log(`HTTP handshake complete: HTTP ${initialRes.status} in ${latencyMs}ms`);

    const html = typeof initialRes.data === 'string' ? initialRes.data : '';
    const headers = initialRes.headers;

    // Check Domain Ownership Verification (DNS TXT, meta tag, or .well-known)
    const ownership = await verifyDomainOwnership(targetUrl, html);
    const verifiedOrLocal = ownership.verified || ssrfCheck.isLoopback;
    const rateBurstCount = policy.features.burst15Req && verifiedOrLocal ? 15 : 4;
    log(
      !policy.features.burst15Req
        ? `Starter plan uses safe ${rateBurstCount}-request rate check (upgrade to Pro for verified 15-request burst).`
        : ownership.verified
        ? `Domain ownership verified via ${ownership.method}; full active checks unlocked.`
        : ssrfCheck.isLoopback
        ? `Local dev target detected; running full probe suite.`
        : `Unverified external domain: running safe ${rateBurstCount}-request non-intrusive profile.`
    );

    // Step 2: Extract JavaScript bundles (filter external origins via SSRF guard)
    const rawScriptUrls = extractScriptUrls(html, targetUrl);
    const originSafetyCache = new Map<string, boolean>([[parsedUrl.origin, true]]);
    const scriptUrls: string[] = [];
    for (const sUrl of rawScriptUrls.slice(0, 25)) {
      try {
        const sOrigin = new URL(sUrl).origin;
        let ok = originSafetyCache.get(sOrigin);
        if (ok === undefined) {
          const chk = await validateTargetSafety(sUrl, { isProd: IS_PROD });
          ok = chk.allowed;
          originSafetyCache.set(sOrigin, ok);
        }
        if (ok) scriptUrls.push(sUrl);
      } catch {}
    }
    log(`Discovered ${scriptUrls.length} safe JavaScript bundles & module chunks to audit`);

    // Step 3: Run key hunter, sensitive artifact checks (.env/.git/.js.map), headers & rate-limit probes
    log(`Executing Secret Hunter & Sensitive Artifact (.env/.git/.js.map) probes...`);
    log(`Probing HTTP Security Headers, Cookies & CORS policies...`);
    log(`Testing Denial-of-Wallet rate limits (${rateBurstCount}-request safe profile)...`);

    const [keyResult, artifactFindings, headerFindings, rateLimitFinding] = await Promise.all([
      scanForLeakedKeys(scriptUrls),
      scanSensitiveWebArtifacts(targetUrl, scriptUrls),
      Promise.resolve(scanSecurityHeaders(headers, { html })),
      probeRateLimiting(targetUrl, { burstCount: rateBurstCount, verifiedMode: verifiedOrLocal })
    ]);

    // Step 3a: Discover lazy-loaded SPA route chunks (Vite/Next/Webpack) referenced inside entry bundles
    const lazyChunkSet = new Set<string>();
    const lazyChunkRx = /["']((?:\/|(?:\.\.?\/))?(?:assets\/|_next\/static\/chunks\/|static\/js\/)[a-zA-Z0-9_.\-\/]+\.(?:js|mjs))["']/g;
    for (const sc of keyResult.collectedScripts) {
      for (const m of sc.content.matchAll(lazyChunkRx)) {
        try {
          const resolved = new URL(m[1], sc.url.startsWith('http') ? sc.url : parsedUrl.origin);
          if (
            resolved.origin === parsedUrl.origin &&
            !scriptUrls.includes(resolved.href) &&
            !lazyChunkSet.has(resolved.href)
          ) {
            lazyChunkSet.add(resolved.href);
            if (lazyChunkSet.size >= 6) break;
          }
        } catch {}
      }
      if (lazyChunkSet.size >= 6) break;
    }

    if (lazyChunkSet.size > 0) {
      const lazyUrls = Array.from(lazyChunkSet);
      const lazyResult = await scanForLeakedKeys(lazyUrls);
      scriptUrls.push(...lazyResult.scannedScripts);
      keyResult.totalBytesScanned += lazyResult.totalBytesScanned;
      keyResult.totalLinesInspected += lazyResult.totalLinesInspected;
      keyResult.collectedScripts.push(...lazyResult.collectedScripts);
      keyResult.collectedScriptContent = `${keyResult.collectedScriptContent}\n${lazyResult.collectedScriptContent}`.slice(0, 2 * 1024 * 1024);
      for (const f of lazyResult.findings) {
        if (!keyResult.findings.some((existing) => existing.type === f.type && existing.proof === f.proof)) {
          keyResult.findings.push(f);
        }
      }
      log(`Audited ${lazyResult.scannedScripts.length} lazy-loaded SPA chunk(s) referenced by entry bundles`);
    }

    // Step 3b: Feed extracted JS bundles + HTML into DB probe, DOM XSS / OpenAPI / GraphQL / JWT deep inspection!
    log(`Probing extracted client scripts for Firebase/Supabase DB rules & Auth tokens...`);
    if (authHeader || authCookie) {
      log(`Optional target-origin auth context attached (redacted from logs, same-origin only)...`);
    }
    log(`Scanning JS bundles for DOM XSS sinks, OpenAPI/Swagger, GraphQL introspection & JWT weaknesses...`);
    log(`Running Dynamic CORS Reflection, SSL/TLS cert, DNS SPF/DMARC & JS Supply-Chain (SRI) posture probes...`);

    const [dbFindings, webDeepResult, networkPostureResult] = await Promise.all([
      probeDatabaseSecurity(html, keyResult.collectedScriptContent),
      runWebDeepAudit({
        targetUrl,
        html,
        initialStatus: initialRes.status,
        collectedScripts: keyResult.collectedScripts,
        authHeader: typeof authHeader === 'string' ? authHeader : undefined,
        authCookie: typeof authCookie === 'string' ? authCookie : undefined
      }),
      runNetworkPostureAudit({
        targetUrl,
        html,
        isLoopback: ssrfCheck.isLoopback,
        collectedScripts: keyResult.collectedScripts
      })
    ]);

    const detectedTech = detectTechnologies(`${html}\n${keyResult.collectedScriptContent.slice(0, 120000)}`, headers);
    log(`Fingerprinted technologies: ${detectedTech.join(', ') || 'Standard Web Stack'}`);
    log(
      `Deep Web Surface: ${webDeepResult.surface.discoveredRoutes.length} routes, ` +
        `${webDeepResult.surface.apiEndpoints.length} API paths, ` +
        `${webDeepResult.surface.domSinks.length} DOM sinks, ` +
        `${webDeepResult.surface.jwtAudits.length} JWT(s) audited`
    );
    log(
      `Network & Supply-Chain Posture: CORS=${networkPostureResult.posture.corsReflection}, ` +
        `TLS=${networkPostureResult.posture.tlsProtocol || 'HTTP/Local'}, ` +
        `DMARC=${networkPostureResult.posture.dmarcPolicy || 'none'}, ` +
        `SRI Missing=${networkPostureResult.posture.missingSriCount}`
    );

    const transportFindings: any[] = [];
    if (parsedUrl.protocol === 'http:' && !ssrfCheck.isLoopback) {
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
    log(`Found ${keyResult.findings.length + artifactFindings.length} leaked secret/artifact alerts, ${headerFindings.filter(h => h.severity !== 'PASS' && h.severity !== 'INFO').length} header flags`);

    // Aggregate Findings
    const allFindings = [
      ...transportFindings,
      ...keyResult.findings.map(f => ({ ...f, category: 'API Keys & Secrets', owaspRef: f.owaspRef || 'OWASP-A02' })),
      ...artifactFindings.map(f => ({ ...f, category: 'Exposed Source Maps & Configs', owaspRef: f.owaspRef || 'OWASP-A05' })),
      ...headerFindings.map(f => ({ ...f, category: 'Security Headers & CORS', owaspRef: f.owaspRef || 'OWASP-A05' })),
      ...dbFindings.map(f => ({ ...f, category: 'Database & Cloud Rules', owaspRef: f.owaspRef || 'OWASP-A01' })),
      ...webDeepResult.findings.map(f => ({ ...f, owaspRef: f.owaspRef || 'OWASP-A05' })),
      ...networkPostureResult.findings.map(f => ({ ...f, owaspRef: f.owaspRef || 'OWASP-A05' })),
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
      webDeepSurface: webDeepResult.surface,
      networkPosture: networkPostureResult.posture,
      domainVerification: {
        verified: ownership.verified,
        method: ownership.method || null,
        token: ownership.token,
        burstProfile: `${rateBurstCount} reqs`
      },
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

// 🤖 ON-DEMAND AI VULNERABILITY FIX DOCTOR (Pro & Agency Exclusive)
app.post('/api/explain-vulnerability', async (req, res) => {
  const uid = getAuthenticatedUserId(req);
  const policy = getPlanPolicy(getAccountPlanById(uid));
  if (!policy.features.aiFixDoctor) {
    return res.status(403).json({
      error: 'AI Code Fix Doctor & copy-paste code patches require Pro Security ($15/mo) or Team & Agency ($79/mo).',
    });
  }

  const aiRate = checkClientRateLimit(getClientIp(req), 'ai');
  if (!aiRate.allowed) {
    res.setHeader('Retry-After', String(aiRate.retryAfterSec));
    return res.status(429).json({ error: `AI Fix Doctor rate limit reached. Retry in ${aiRate.retryAfterSec}s.` });
  }
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

  // Yield briefly to the event loop before synchronous ZIP/DEX disassembly so concurrent SSE/API requests stay responsive
  await new Promise<void>((r) => setImmediate(r));
  let apkScanResult;
  try {
    apkScanResult = await scanApkBuffer(apkBuffer, fileName);
  } catch (zipErr: any) {
    throw new Error(`Invalid or corrupted APK container (${zipErr?.message || 'unable to unpack binary entries'}).`);
  }

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
  const baasJwtHints = apkScanResult.baasJwtHints || [];
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
      ? probeDatabaseSecurity('', [...baasTargets, ...baasJwtHints].join('\n')).catch(() => [])
      : Promise.resolve([]);

    const apiProbePromises = customApiTargets.map(async (apiUrl) => {
      const probeStart = Date.now();
      try {
        const apiSafety = await validateTargetSafety(apiUrl, { isProd: IS_PROD });
        if (!apiSafety.allowed) {
          probedApis.push({
            url: apiUrl,
            status: 'Blocked (Internal/Unsafe)',
            latencyMs: Date.now() - probeStart,
            cors: 'N/A',
            hsts: false,
            reachable: false
          });
          return;
        }
        const apiRes = await axios.get(apiUrl, {
          timeout: 3500,
          httpsAgent: AUDIT_HTTPS_AGENT,
          maxRedirects: 2,
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

function authorizeApkRequest(
  req: express.Request,
  res: express.Response
): { buffer: Buffer; fileName: string; policy: PlanPolicy; packageName: string } | null {
  const clientIp = getClientIp(req);
  const apkRate = checkClientRateLimit(clientIp, 'apk');
  if (!apkRate.allowed) {
    res.setHeader('Retry-After', String(apkRate.retryAfterSec));
    res.status(429).json({ error: `APK scan rate limit reached. Retry in ${apkRate.retryAfterSec}s.` });
    return null;
  }

  const checked = validateApkUpload(req);
  if (checked.error || !checked.buffer) {
    res.status(400).json({ error: checked.error });
    return null;
  }

  const uid = getAuthenticatedUserId(req);
  const plan = getAccountPlanById(uid);
  const policy = getPlanPolicy(plan);
  const maxBytes = policy.maxApkMb * 1024 * 1024;
  if (checked.buffer.length > maxBytes) {
    const fileMb = (checked.buffer.length / 1024 / 1024).toFixed(1);
    const upgradeHint =
      policy.id === 'free'
        ? 'Upgrade to Pro Security (75 MB) or Team & Agency (150 MB).'
        : policy.id === 'pro'
        ? 'Upgrade to Team & Agency ($79/mo) for large APK builds up to 150 MB.'
        : 'Split large asset packs into Android App Bundle modules.';
    res.status(413).json({
      error: `Your APK (${fileMb} MB) exceeds the ${policy.name} ${policy.maxApkMb} MB limit. ${upgradeHint}`,
    });
    return null;
  }

  const packageName = peekApkPackageName(checked.buffer, checked.fileName!);
  const quota = consumeScanTargetQuota({
    userId: uid,
    clientIp,
    mode: 'apk',
    rawTarget: packageName,
  });
  if (!quota.allowed) {
    res.status(429).json({ error: quota.message || 'Monthly APK audit quota reached.' });
    return null;
  }

  return {
    buffer: checked.buffer,
    fileName: checked.fileName!,
    policy,
    packageName,
  };
}

// 📱 MOBILE APK DEEP SECURITY AUDIT ENDPOINT (Sync Direct Response)
app.post('/api/scan-apk', upload.single('apk'), async (req, res) => {
  const authApk = authorizeApkRequest(req, res);
  if (!authApk) return;
  try {
    const result = await runApkAuditPipeline(authApk.buffer, authApk.fileName);
    return res.json(result);
  } catch (err: any) {
    console.error('[ApkAudit] Scan error:', err);
    return res.status(500).json({ error: err.message || 'Failed to parse and audit APK file.' });
  }
});

// ⚙️ ASYNC WORKER QUEUE ENDPOINT (Concurrency-Capped Non-blocking APK Deep Audit + SSE Stream)
app.post('/api/jobs/scan-apk', upload.single('apk'), (req, res) => {
  const authApk = authorizeApkRequest(req, res);
  if (!authApk) return;

  if (getQueueCapacity().isFull) {
    return res.status(503).json({ error: 'APK worker queue is at capacity right now. Please retry in a few seconds.' });
  }

  const job = createScanJob('apk', `${authApk.fileName} (${authApk.packageName})`, authApk.policy.priorityQueue);
  let apkBuffer: Buffer | null = authApk.buffer;
  const fileName = authApk.fileName;

  const accepted = enqueueJobTask(
    job.id,
    async () => {
      try {
        if (!apkBuffer) throw new Error('APK buffer was unexpectedly released.');
        const report = await runApkAuditPipeline(apkBuffer, fileName, (progress, stage, timeLabel) => {
          pushScanJobProgress(job.id, progress, stage, timeLabel);
        });
        completeScanJob(job.id, report);
      } catch (err: any) {
        console.error(`[AsyncJob ${job.id}] Failed:`, err);
        failScanJob(job.id, err?.message || 'Async APK audit failed.');
      } finally {
        // Allow immediate garbage collection of large 10-150MB APK binary buffer
        apkBuffer = null;
      }
    },
    { priority: authApk.policy.priorityQueue }
  );

  if (!accepted) {
    failScanJob(job.id, 'APK worker queue saturated.');
    apkBuffer = null;
    return res.status(503).json({ error: 'APK worker queue is busy. Please try again shortly.' });
  }

  return res.status(202).json({
    jobId: job.id,
    status: job.status,
    progress: job.progress,
    queuePosition: job.queuePosition,
    pollUrl: `/api/jobs/${job.id}`,
    streamUrl: `/api/jobs/${job.id}/stream`
  });
});

app.get('/api/jobs/:jobId', (req, res) => {
  const job = getScanJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: 'Audit job not found or expired.' });
  }
  return res.json(job);
});

app.get('/api/jobs/:jobId/stream', (req, res) => {
  const job = getScanJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: 'Audit job not found or expired.' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const sendUpdate = (snapshot: any) => {
    res.write(`data: ${JSON.stringify(snapshot)}\n\n`);
    if (snapshot.status === 'completed' || snapshot.status === 'failed') {
      unsubscribe();
      res.end();
    }
  };

  const unsubscribe = subscribeScanJob(job.id, sendUpdate);
  sendUpdate(job);

  req.on('close', () => {
    unsubscribe();
  });
});

// Handle Multer upload errors (e.g. > MAX_APK_SIZE_MB) with clean JSON responses
app.use((err: any, _req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: `APK exceeds the ${MAX_APK_SIZE_MB}MB server memory guard limit.` });
  }
  if (err && err.name === 'MulterError') {
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  return next(err);
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
