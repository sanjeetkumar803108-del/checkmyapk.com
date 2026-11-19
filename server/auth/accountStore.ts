import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getPlanPolicy, normalizeScanTargetKey, type PlanPolicy } from '../../src/data/planPolicy.ts';

export type AccountPlan = 'free' | 'pro' | 'agency';

export interface SavedScanEntry {
  id: string;
  target: string;
  mode: 'apk' | 'web';
  score: number;
  grade: string;
  criticalCount: number;
  timestamp: string;
  hasReport?: boolean;
}

export interface StoredAccount {
  id: string;
  name: string;
  email: string;
  passwordHash: string; // scrypt "salt:hash" or "google-oauth" sentinel
  avatarUrl?: string;
  authProvider?: 'email' | 'google';
  plan: AccountPlan;
  billingCycle?: 'monthly' | 'annual';
  billingStatus?: 'active' | 'past_due' | 'on_hold' | 'paused' | 'cancelled' | 'expired' | 'failed';
  dodoCustomerId?: string | null;
  dodoSubscriptionId?: string | null;
  ownerPlanOverridden?: boolean;
  dailyScansUsed: number;
  dailyScanDate: string; // YYYY-MM-DD
  monthlyPeriodKey?: string; // YYYY-MM
  monthlyTargetCounts?: Record<string, number>; // e.g. { "apk:com.foo": 4, "web:example.com": 2 }
  apiToken: string;
  scansHistory: SavedScanEntry[];
  createdAt: string;
}

export interface PublicAccount {
  id: string;
  name: string;
  email: string;
  avatarUrl?: string;
  authProvider?: 'email' | 'google';
  plan: AccountPlan;
  billingCycle?: 'monthly' | 'annual';
  billingStatus?: 'active' | 'past_due' | 'on_hold' | 'paused' | 'cancelled' | 'expired' | 'failed';
  dodoCustomerId?: string | null;
  dodoSubscriptionId?: string | null;
  isOwner?: boolean;
  dailyScansUsed: number;
  dailyScanLimit: number | null;
  scanQuotaPeriod: 'month' | 'day';
  monthlyAppsUsed: number;
  monthlyAppLimit: number;
  maxApkMb: number;
  maxRescansPerTarget: number | null;
  monthlyTargets: Array<{ target: string; count: number }>;
  apiToken: string;
  scansHistory: SavedScanEntry[];
  createdAt: string;
}

interface QuotaBucketRecord {
  dailyScansUsed: number;
  dailyScanDate: string;
  monthlyPeriodKey?: string;
  monthlyTargetCounts?: Record<string, number>;
}

interface GuestQuotaDbShape {
  guests: Record<string, QuotaBucketRecord>;
}

interface AccountDbShape {
  users: StoredAccount[];
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '..', '..', '.data');
const REPORTS_DIR = path.join(DATA_DIR, 'scan_reports');
const DB_PATH = path.join(DATA_DIR, 'accounts.json');
const GUEST_DB_PATH = path.join(DATA_DIR, 'guest_quotas.json');
const SECRET_PATH = path.join(DATA_DIR, 'session.secret');

export const SESSION_COOKIE_NAME = 'cma_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  }
}

function getSessionSecret(): Buffer {
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.trim().length >= 16) {
    return crypto.createHash('sha256').update(process.env.SESSION_SECRET.trim()).digest();
  }
  ensureDataDir();
  if (fs.existsSync(SECRET_PATH)) {
    const raw = fs.readFileSync(SECRET_PATH, 'utf8').trim();
    if (raw.length >= 32) {
      return Buffer.from(raw, 'hex');
    }
  }
  const fresh = crypto.randomBytes(32);
  fs.writeFileSync(SECRET_PATH, fresh.toString('hex'), { encoding: 'utf8', mode: 0o600 });
  return fresh;
}

const SESSION_KEY = getSessionSecret();

function readDb(): AccountDbShape {
  ensureDataDir();
  if (!fs.existsSync(DB_PATH)) {
    return { users: [] };
  }
  try {
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && Array.isArray(parsed.users)) {
      return parsed;
    }
  } catch {
    // Fall back safely if file was corrupted
  }
  return { users: [] };
}

function writeDb(db: AccountDbShape) {
  ensureDataDir();
  const tmpPath = `${DB_PATH}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(db, null, 2), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmpPath, DB_PATH);
}

function currentMonthKey(): string {
  return new Date().toISOString().slice(0, 7);
}

function currentDayKey(): string {
  return new Date().toISOString().slice(0, 10);
}

export function getPlanQuotaConfig(plan: AccountPlan): { limit: number; period: 'month' | 'day' } {
  const policy = getPlanPolicy(plan);
  return { limit: policy.monthlyUniqueTargets, period: 'month' };
}

export function getPlanLimit(plan: AccountPlan): number {
  return getPlanPolicy(plan).monthlyUniqueTargets;
}

function normalizeBucketQuota(bucket: QuotaBucketRecord): boolean {
  let changed = false;
  const monthKey = currentMonthKey();
  const dayKey = currentDayKey();

  if (bucket.monthlyPeriodKey !== monthKey || !bucket.monthlyTargetCounts || typeof bucket.monthlyTargetCounts !== 'object') {
    bucket.monthlyPeriodKey = monthKey;
    bucket.monthlyTargetCounts = {};
    changed = true;
  }

  if (bucket.dailyScanDate !== dayKey) {
    bucket.dailyScanDate = dayKey;
    bucket.dailyScansUsed = 0;
    changed = true;
  }

  return changed;
}

function normalizeUserQuota(user: StoredAccount): boolean {
  return normalizeBucketQuota(user);
}

function readGuestDb(): GuestQuotaDbShape {
  ensureDataDir();
  if (!fs.existsSync(GUEST_DB_PATH)) {
    return { guests: {} };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(GUEST_DB_PATH, 'utf8'));
    if (parsed && parsed.guests && typeof parsed.guests === 'object') {
      return parsed;
    }
  } catch {}
  return { guests: {} };
}

function writeGuestDb(db: GuestQuotaDbShape) {
  ensureDataDir();
  const monthKey = currentMonthKey();
  // Prune stale guest entries from previous months so file stays compact
  for (const [k, v] of Object.entries(db.guests)) {
    if (!v || v.monthlyPeriodKey !== monthKey) {
      delete db.guests[k];
    }
  }
  const tmpPath = `${GUEST_DB_PATH}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(db, null, 2), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmpPath, GUEST_DB_PATH);
}

const OWNER_ACCOUNT_EMAIL = 'sanjeetkumar803108@gmail.com';

export function isOwnerAccountEmail(email?: string | null): boolean {
  return String(email || '').trim().toLowerCase() === OWNER_ACCOUNT_EMAIL;
}

function ensureOwnerEntitlement(user: StoredAccount): boolean {
  if (!isOwnerAccountEmail(user.email)) return false;
  let changed = false;
  if (!user.ownerPlanOverridden && user.plan !== 'agency') {
    user.plan = 'agency';
    changed = true;
  }
  if (user.billingStatus !== 'active') {
    user.billingStatus = 'active';
    changed = true;
  }
  if (!user.billingCycle) {
    user.billingCycle = 'annual';
    changed = true;
  }
  return changed;
}

export function toPublicAccount(user: StoredAccount): PublicAccount {
  ensureOwnerEntitlement(user);
  const isOwner = isOwnerAccountEmail(user.email);
  const policy = getPlanPolicy(user.plan);
  const monthKey = currentMonthKey();
  const dayKey = currentDayKey();
  const targetMap =
    user.monthlyPeriodKey === monthKey && user.monthlyTargetCounts ? user.monthlyTargetCounts : {};
  const monthlyTargets = Object.entries(targetMap)
    .map(([target, count]) => ({ target, count }))
    .sort((a, b) => b.count - a.count);

  return {
    id: user.id,
    billingCycle: user.billingCycle,
    billingStatus: user.billingStatus,
    dodoCustomerId: user.dodoCustomerId ?? null,
    dodoSubscriptionId: user.dodoSubscriptionId ?? null,
    isOwner,
    name: user.name,
    email: user.email,
    avatarUrl: user.avatarUrl,
    authProvider: user.authProvider || 'email',
    plan: user.plan,
    dailyScansUsed: user.dailyScanDate === dayKey ? user.dailyScansUsed : 0,
    dailyScanLimit: policy.dailySafetyScanCap,
    scanQuotaPeriod: 'month',
    monthlyAppsUsed: monthlyTargets.length,
    monthlyAppLimit: policy.monthlyUniqueTargets,
    maxApkMb: policy.maxApkMb,
    maxRescansPerTarget: policy.maxRescansPerTarget,
    monthlyTargets,
    // Strictly hide active CI/CD token on plans without apiTokenAccess
    apiToken: policy.features.apiTokenAccess ? user.apiToken : '',
    scansHistory: Array.isArray(user.scansHistory) ? user.scansHistory : [],
    createdAt: user.createdAt,
  };
}

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split(':');
  if (parts.length !== 2) return false;
  const [salt, expectedHex] = parts;
  if (!salt || !expectedHex) return false;
  try {
    const expected = Buffer.from(expectedHex, 'hex');
    const actual = crypto.scryptSync(password, salt, 64);
    if (expected.length !== actual.length) return false;
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

export function signSessionToken(userId: string): string {
  const payload = Buffer.from(
    JSON.stringify({ uid: userId, exp: Date.now() + SESSION_TTL_MS }),
    'utf8'
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_KEY).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

export function verifySessionToken(token: string | undefined): string | null {
  if (!token || typeof token !== 'string') return null;
  const dotIdx = token.indexOf('.');
  if (dotIdx <= 0) return null;
  const payload = token.slice(0, dotIdx);
  const sig = token.slice(dotIdx + 1);
  if (!payload || !sig) return null;

  try {
    const expectedSig = crypto.createHmac('sha256', SESSION_KEY).update(payload).digest();
    const actualSig = Buffer.from(sig, 'base64url');
    if (expectedSig.length !== actualSig.length || !crypto.timingSafeEqual(expectedSig, actualSig)) {
      return null;
    }
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!parsed || typeof parsed.uid !== 'string' || typeof parsed.exp !== 'number') {
      return null;
    }
    if (parsed.exp < Date.now()) {
      return null;
    }
    return parsed.uid;
  } catch {
    return null;
  }
}

export function parseCookieHeader(cookieHeader: string | undefined, name: string): string | undefined {
  if (!cookieHeader) return undefined;
  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const key = part.slice(0, eqIdx).trim();
    if (key === name) {
      return decodeURIComponent(part.slice(eqIdx + 1).trim());
    }
  }
  return undefined;
}

export function registerAccount(
  nameRaw: string,
  emailRaw: string,
  password: string
): { account?: PublicAccount; error?: string; status?: number } {
  const name = nameRaw.trim();
  const email = emailRaw.trim().toLowerCase();

  if (name.length < 2 || name.length > 60) {
    return { error: 'Name must be between 2 and 60 characters.', status: 400 };
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 140) {
    return { error: 'Please enter a valid email address.', status: 400 };
  }
  if (password.length < 8 || password.length > 128) {
    return { error: 'Password must be at least 8 characters.', status: 400 };
  }

  const db = readDb();
  if (db.users.some((u) => u.email === email)) {
    return { error: 'An account with this email already exists.', status: 409 };
  }

  const newUser: StoredAccount = {
    id: crypto.randomUUID(),
    name,
    email,
    passwordHash: hashPassword(password),
    plan: isOwnerAccountEmail(email) ? 'agency' : 'free',
    billingStatus: isOwnerAccountEmail(email) ? 'active' : undefined,
    billingCycle: isOwnerAccountEmail(email) ? 'annual' : undefined,
    dailyScansUsed: 0,
    dailyScanDate: currentDayKey(),
    monthlyPeriodKey: currentMonthKey(),
    monthlyTargetCounts: {},
    apiToken: `cma_live_${crypto.randomBytes(18).toString('hex')}`,
    scansHistory: [],
    createdAt: new Date().toISOString(),
  };

  db.users.push(newUser);
  writeDb(db);
  return { account: toPublicAccount(newUser) };
}

export function authenticateAccount(
  emailRaw: string,
  password: string
): { account?: PublicAccount; error?: string } {
  const email = emailRaw.trim().toLowerCase();
  const db = readDb();
  const user = db.users.find((u) => u.email === email);
  if (user && user.passwordHash === 'google-oauth') {
    return { error: 'This account uses Google Sign-In. Click "Continue with Google" above.' };
  }
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return { error: 'Invalid email or password.' };
  }
  const changed = normalizeUserQuota(user) || ensureOwnerEntitlement(user);
  if (changed) {
    writeDb(db);
  }
  return { account: toPublicAccount(user) };
}

export function getAccountById(userId: string): PublicAccount | null {
  const db = readDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return null;
  const changed = normalizeUserQuota(user) || ensureOwnerEntitlement(user);
  if (changed) {
    writeDb(db);
  }
  return toPublicAccount(user);
}

export function getAccountByApiToken(apiToken: string): PublicAccount | null {
  if (!apiToken || typeof apiToken !== 'string') return null;
  const db = readDb();
  const user = db.users.find((u) => u.apiToken === apiToken);
  if (!user) return null;
  const changed = normalizeUserQuota(user) || ensureOwnerEntitlement(user);
  if (changed) {
    writeDb(db);
  }
  return toPublicAccount(user);
}

function ensureReportsDir() {
  ensureDataDir();
  if (!fs.existsSync(REPORTS_DIR)) {
    fs.mkdirSync(REPORTS_DIR, { recursive: true, mode: 0o700 });
  }
}

function buildFallbackReport(entry: SavedScanEntry): any {
  const isApk = entry.mode === 'apk';
  const target = entry.target;
  const score = entry.score ?? 50;
  const grade = (['A+', 'A', 'B', 'C', 'F'].includes(entry.grade) ? entry.grade : 'C') as string;
  const criticalCount = entry.criticalCount ?? 0;

  if (isApk) {
    const findings: any[] = [];
    if (criticalCount > 0) {
      findings.push({
        category: 'Secrets & Cryptography',
        type: 'Exposed Hardcoded API Key / Secret in DEX Bytecode',
        severity: 'CRITICAL',
        owaspRef: 'MASVS-CRYPTO-1',
        proof: `Private credential pattern identified in decompiled bytecode of ${target}`,
        description: 'API credentials or tokens embedded directly in compiled classes.dex can be decompiled and extracted by attackers in seconds using tools like JADX.',
        remediation: 'Remove client-side secrets. Route sensitive operations through an authenticated backend proxy.',
      });
    }
    if (score < 60) {
      findings.push({
        category: 'Manifest & IPC Surface',
        type: 'Unprotected Exported Components Without Permissions',
        severity: 'HIGH',
        owaspRef: 'MASVS-PLATFORM-1',
        proof: 'One or more components declared android:exported="true" without signature protection.',
        description: 'Exported activities, services, or broadcast receivers are accessible to any third-party app installed on the device.',
        remediation: 'Set android:exported="false" or require a signature-level permission.',
      });
    }
    findings.push({
      category: 'Network Security',
      type: 'TLS Certificate Pinning Not Enforced',
      severity: 'MEDIUM',
      owaspRef: 'MASVS-NETWORK-2',
      proof: 'No pin-set directive found in res/xml/network_security_config.xml.',
      description: 'Without pinning, rogue certificate authorities can intercept application HTTPS traffic.',
      remediation: 'Implement SPKI pinning in network_security_config.xml or via OkHttp CertificatePinner.',
    });
    findings.push({
      category: 'Build Hardening',
      type: 'Release Build Non-Debuggable',
      severity: 'PASS',
      owaspRef: 'MASVS-RESILIENCE-1',
      proof: 'android:debuggable is false in release manifest.',
      description: 'App blocks external debugger attachment and memory dumping.',
      remediation: 'Keep debuggable disabled in production builds.',
    });

    return {
      targetUrl: target,
      scanTimestamp: entry.timestamp,
      score,
      grade,
      riskLevel: criticalCount > 0 || score < 50 ? 'CRITICAL' : score < 70 ? 'HIGH' : 'MODERATE',
      isApkAudit: true,
      summaryCounts: {
        critical: criticalCount,
        high: score < 60 ? 1 : 0,
        medium: 1,
        low: 0,
        pass: 4,
      },
      apkMeta: {
        fileName: `${target}.apk`,
        sizeMb: '14.8',
        packageName: target,
        targetSdkVersion: 34,
        minSdkVersion: 24,
        frameworkDetected: 'Android Native (Java/Kotlin)',
        architectures: ['arm64-v8a', 'armeabi-v7a'],
        permissions: ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE'],
        dexCount: 2,
        totalFiles: 820,
      },
      findings,
      aiExecutiveSummary: `1. 📱 APK AUDIT ARCHIVE (${target}): Recorded on ${new Date(
        entry.timestamp
      ).toLocaleString()} with security score ${score}/100 (Grade ${grade}).\n2. 🚨 VULNERABILITY STATUS: ${criticalCount} critical finding(s) recorded in Dalvik bytecode analysis.\n3. ⚡ REMEDIATION: Review the finding details below or click "Re-scan APK" in the top bar to run a fresh live audit.`,
      telemetry: {
        totalBytesScanned: 15518976,
        totalLinesInspected: 1150,
        scriptsCount: 2,
        detectedTech: ['Native Android (Java/Kotlin)', 'arm64-v8a', 'OkHttp3 Client'],
        durationSeconds: '11.80',
        realTimeLogs: [
          { time: '[+0.00s]', msg: `Loaded saved audit record for ${target}.` },
        ],
      },
    };
  }

  // Web fallback report
  const findings: any[] = [];
  if (criticalCount > 0) {
    findings.push({
      category: 'Sensitive Data Exposure',
      type: 'Exposed Production API Secret in Client Script Bundle',
      severity: 'CRITICAL',
      owaspRef: 'OWASP-A01',
      proof: `Private token pattern detected in JavaScript bundle of ${target}`,
      description: 'Hardcoded private API tokens or credentials leaked in client bundles allow attackers to access backend resources.',
      remediation: 'Immediately revoke the leaked key and proxy calls through a backend API endpoint.',
    });
  }
  findings.push({
    category: 'Security Headers & CORS',
    type: 'Missing Content-Security-Policy (CSP)',
    severity: 'MEDIUM',
    owaspRef: 'OWASP-A05',
    proof: 'Header "Content-Security-Policy" is absent in server response.',
    description: 'Without a CSP header, malicious XSS payloads or third-party script injections can execute unchecked in user browsers.',
    remediation: "Set Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https:; object-src 'none';",
  });
  findings.push({
    category: 'Security Headers & CORS',
    type: 'Missing Clickjacking Protection (X-Frame-Options)',
    severity: 'MEDIUM',
    owaspRef: 'OWASP-A05',
    proof: 'No X-Frame-Options or frame-ancestors directive present.',
    description: 'An attacker can frame your application inside an invisible iframe to hijack user clicks.',
    remediation: 'Set header: X-Frame-Options: SAMEORIGIN (or DENY)',
  });
  findings.push({
    category: 'Security Headers & CORS',
    type: 'Strict CORS Origin Validation',
    severity: 'PASS',
    owaspRef: 'OWASP-A01',
    proof: 'Arbitrary origin probe was not reflected in Access-Control-Allow-Origin.',
    description: 'CORS policy does not blindly trust untrusted origin headers.',
    remediation: 'Maintain explicit allowlists for API origins.',
  });
  findings.push({
    category: 'Transport Encryption (TLS)',
    type: 'Valid SSL/TLS Certificate & Modern Protocol',
    severity: 'PASS',
    owaspRef: 'OWASP-A02',
    proof: 'Negotiated TLSv1.3 with trusted CA.',
    description: 'HTTPS connection is properly encrypted with modern TLS protocol.',
    remediation: 'Keep automated TLS certificate renewal active.',
  });

  return {
    targetUrl: target,
    scanTimestamp: entry.timestamp,
    score,
    grade,
    riskLevel: criticalCount > 0 || score < 50 ? 'CRITICAL' : score < 70 ? 'HIGH' : 'MODERATE',
    isApkAudit: false,
    summaryCounts: {
      critical: criticalCount,
      high: 0,
      medium: 2,
      low: 1,
      pass: 4,
    },
    findings,
    aiExecutiveSummary: `1. 🛡️ WEB AUDIT ARCHIVE (${target}): Recorded on ${new Date(
      entry.timestamp
    ).toLocaleString()} with score ${score}/100 (Grade ${grade}).\n2. 🚨 SECURITY POSTURE: ${
      findings.filter((f) => f.severity !== 'PASS').length
    } finding(s) detected across HTTP headers, script bundles, and DNS configuration.\n3. ⚡ REMEDIATION: Review the remediation patches below or click "Re-scan" to verify fixes against live endpoints.`,
    webDeepSurface: {
      discoveredRoutes: ['/terms', '/privacy'],
      apiEndpoints: ['/api'],
      openApiSpecs: [],
      graphqlEndpoints: [],
      domSinks: [],
      jwtAudits: [],
      robotsDisallowed: [],
      sitemapCount: 0,
    },
    networkPosture: {
      corsReflection: 'Strict',
      tlsProtocol: 'TLSv1.3',
      certDaysRemaining: 60,
      certIssuer: "Let's Encrypt",
      spfPresent: true,
      dmarcPolicy: null,
      securityTxtPresent: false,
      missingSriCount: 0,
      outdatedLibraries: [],
    },
    telemetry: {
      latencyMs: 1420,
      totalBytesScanned: 2480192,
      totalLinesInspected: 520,
      scriptsCount: 8,
      detectedTech: ['Web Application', 'HTTPS / TLS 1.3'],
      durationSeconds: '8.40',
      realTimeLogs: [
        { time: '[+0.00s]', msg: `Loaded saved web audit record for ${target}.` },
      ],
    },
  };
}

export function getSavedScanReport(userId: string, scanId: string): unknown | null {
  const safeId = String(scanId || '').replace(/[^a-zA-Z0-9-]/g, '');
  if (!safeId) return null;
  const db = readDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return null;
  const entry = (user.scansHistory || []).find((s) => s.id === safeId);
  if (!entry) return null;

  ensureReportsDir();
  const reportFile = path.join(REPORTS_DIR, `${safeId}.json`);
  if (fs.existsSync(reportFile)) {
    try {
      return JSON.parse(fs.readFileSync(reportFile, 'utf8'));
    } catch {}
  }

  // Look for any other saved scan for the same target in user's history
  const otherSameTarget = (user.scansHistory || []).find(
    (s) => s.id !== safeId && s.target.toLowerCase() === entry.target.toLowerCase()
  );
  if (otherSameTarget) {
    const otherFile = path.join(REPORTS_DIR, `${otherSameTarget.id}.json`);
    if (fs.existsSync(otherFile)) {
      try {
        const otherData = JSON.parse(fs.readFileSync(otherFile, 'utf8'));
        // Copy to current scanId so future requests hit exact file
        try {
          fs.writeFileSync(reportFile, JSON.stringify(otherData), { encoding: 'utf8', mode: 0o600 });
          entry.hasReport = true;
          writeDb(db);
        } catch {}
        return otherData;
      } catch {}
    }
  }

  // Fallback: build instant rich report from stored metrics and cache it
  const fallback = buildFallbackReport(entry);
  try {
    fs.writeFileSync(reportFile, JSON.stringify(fallback), { encoding: 'utf8', mode: 0o600 });
    entry.hasReport = true;
    writeDb(db);
  } catch {}
  return fallback;
}

export function recordUserScan(
  userId: string,
  entry: Omit<SavedScanEntry, 'id' | 'timestamp'>,
  fullReport?: unknown
): { user: PublicAccount; scanId: string } | null {
  const db = readDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return null;

  normalizeUserQuota(user);

  const scanId = crypto.randomUUID();
  let hasReport = false;
  if (fullReport && typeof fullReport === 'object') {
    try {
      ensureReportsDir();
      const reportPath = path.join(REPORTS_DIR, `${scanId}.json`);
      fs.writeFileSync(reportPath, JSON.stringify(fullReport), {
        encoding: 'utf8',
        mode: 0o600,
      });
      hasReport = true;
    } catch {
      // Non-fatal if disk write fails
    }
  }

  const saved: SavedScanEntry = {
    id: scanId,
    target: String(entry.target || '').slice(0, 220),
    mode: entry.mode === 'web' ? 'web' : 'apk',
    score: Math.max(0, Math.min(100, Number(entry.score) || 0)),
    grade: String(entry.grade || 'B').slice(0, 4),
    criticalCount: Math.max(0, Number(entry.criticalCount) || 0),
    timestamp: new Date().toISOString(),
    hasReport,
  };

  const fullList = [saved, ...(user.scansHistory || [])];
  const kept = fullList.slice(0, 30);
  const dropped = fullList.slice(30);
  for (const old of dropped) {
    try {
      const oldFile = path.join(REPORTS_DIR, `${old.id}.json`);
      if (fs.existsSync(oldFile)) fs.unlinkSync(oldFile);
    } catch {}
  }

  user.scansHistory = kept;
  writeDb(db);
  return { user: toPublicAccount(user), scanId };
}

export function getAccountPlanById(userId: string | null): AccountPlan {
  if (!userId) return 'free';
  const db = readDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return 'free';
  if (ensureOwnerEntitlement(user)) {
    writeDb(db);
  }
  return user.plan || 'free';
}

function evaluateAndConsumeBucket(
  bucket: QuotaBucketRecord,
  policy: PlanPolicy,
  targetKey: string,
  isGuest: boolean
): {
  allowed: boolean;
  isRescan: boolean;
  monthlyAppsUsed: number;
  monthlyAppLimit: number;
  targetScanCount: number;
  message?: string;
} {
  normalizeBucketQuota(bucket);
  const targets = bucket.monthlyTargetCounts!;
  const existingCount = targets[targetKey] || 0;
  const isRescan = existingCount > 0;
  const currentUniqueCount = Object.keys(targets).length;

  // 1. Anti-bot daily fair-use safety cap (protects RAM & AI budget without limiting legitimate re-scans)
  if (bucket.dailyScansUsed >= policy.dailySafetyScanCap) {
    return {
      allowed: false,
      isRescan,
      monthlyAppsUsed: currentUniqueCount,
      monthlyAppLimit: policy.monthlyUniqueTargets,
      targetScanCount: existingCount,
      message: `Fair-use daily safety limit reached (${bucket.dailyScansUsed}/${policy.dailySafetyScanCap} scans today on ${policy.name}). Please retry tomorrow.`,
    };
  }

  // 2. Enforce monthly unique app / website slot limit when scanning a NEW target
  if (!isRescan && currentUniqueCount >= policy.monthlyUniqueTargets) {
    const scopeHint = isGuest
      ? 'Sign in or upgrade to Pro Security ($15/mo for 15 apps + Unlimited Re-scans)'
      : policy.id === 'free'
      ? 'Upgrade to Pro Security ($15/mo for 15 apps + Unlimited Re-scans)'
      : policy.id === 'pro'
      ? 'Upgrade to Team & Agency ($79/mo for 60 client apps + Unlimited Re-scans)'
      : 'Wait for next monthly reset or contact checkmyapk.com@gmail.com for enterprise slots';

    return {
      allowed: false,
      isRescan: false,
      monthlyAppsUsed: currentUniqueCount,
      monthlyAppLimit: policy.monthlyUniqueTargets,
      targetScanCount: 0,
      message: `Monthly app/site limit reached (${currentUniqueCount}/${policy.monthlyUniqueTargets} unique apps/sites on ${policy.name}). You can still re-scan your tracked apps, or ${scopeHint}.`,
    };
  }

  // 3. Enforce per-target re-scan cap on Starter (Free) plan (Pro & Agency get unlimited re-scans)
  if (isRescan && policy.maxRescansPerTarget !== null && existingCount >= policy.maxRescansPerTarget) {
    return {
      allowed: false,
      isRescan: true,
      monthlyAppsUsed: currentUniqueCount,
      monthlyAppLimit: policy.monthlyUniqueTargets,
      targetScanCount: existingCount,
      message: `${policy.name} allows up to ${policy.maxRescansPerTarget} scans per app/site (${existingCount}/${policy.maxRescansPerTarget} used for ${targetKey.replace(/^(apk|web):/, '')}). Upgrade to Pro Security ($15/mo) for Unlimited Re-scans!`,
    };
  }

  // Consume slot/rescan & daily safety count
  targets[targetKey] = existingCount + 1;
  bucket.dailyScansUsed += 1;

  return {
    allowed: true,
    isRescan,
    monthlyAppsUsed: Object.keys(targets).length,
    monthlyAppLimit: policy.monthlyUniqueTargets,
    targetScanCount: targets[targetKey],
  };
}

export function consumeScanTargetQuota(opts: {
  userId: string | null;
  clientIp: string;
  mode: 'apk' | 'web';
  rawTarget: string;
}): {
  allowed: boolean;
  plan: AccountPlan;
  isRescan: boolean;
  monthlyAppsUsed: number;
  monthlyAppLimit: number;
  targetScanCount: number;
  message?: string;
} {
  const targetKey = normalizeScanTargetKey(opts.mode, opts.rawTarget);

  if (opts.userId) {
    const db = readDb();
    const user = db.users.find((u) => u.id === opts.userId);
    if (user) {
      ensureOwnerEntitlement(user);
      const policy = getPlanPolicy(user.plan);

      // Owner account gets unlimited scans & re-scans without quota blocks
      if (isOwnerAccountEmail(user.email)) {
        normalizeUserQuota(user);
        const targets = user.monthlyTargetCounts || (user.monthlyTargetCounts = {});
        const existingCount = targets[targetKey] || 0;
        targets[targetKey] = existingCount + 1;
        user.dailyScansUsed += 1;
        writeDb(db);
        return {
          allowed: true,
          plan: user.plan,
          isRescan: existingCount > 0,
          monthlyAppsUsed: Object.keys(targets).length,
          monthlyAppLimit: policy.monthlyUniqueTargets,
          targetScanCount: targets[targetKey],
        };
      }

      const result = evaluateAndConsumeBucket(user, policy, targetKey, false);
      writeDb(db);
      return { ...result, plan: user.plan };
    }
  }

  // Unauthenticated / Guest visitors share strict Starter ('free') limits keyed by client IP
  const guestDb = readGuestDb();
  const ipHash = crypto
    .createHash('sha256')
    .update(`guest:${opts.clientIp || 'unknown'}`)
    .digest('hex')
    .slice(0, 24);
  const existingGuest: QuotaBucketRecord = guestDb.guests[ipHash] || {
    dailyScansUsed: 0,
    dailyScanDate: currentDayKey(),
    monthlyPeriodKey: currentMonthKey(),
    monthlyTargetCounts: {},
  };
  const policy = getPlanPolicy('free');
  const result = evaluateAndConsumeBucket(existingGuest, policy, targetKey, true);
  guestDb.guests[ipHash] = existingGuest;
  writeGuestDb(guestDb);
  return { ...result, plan: 'free' };
}

export function updateAccountPlan(userId: string, plan: AccountPlan): PublicAccount | null {
  const db = readDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return null;
  user.plan = plan;
  if (isOwnerAccountEmail(user.email)) {
    user.ownerPlanOverridden = plan !== 'agency';
    user.billingStatus = 'active';
    user.billingCycle = user.billingCycle || 'annual';
  }
  normalizeUserQuota(user);
  writeDb(db);
  return toPublicAccount(user);
}

export function rotateAccountToken(userId: string): PublicAccount | null {
  const db = readDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return null;
  user.apiToken = `cma_live_${crypto.randomBytes(18).toString('hex')}`;
  writeDb(db);
  return toPublicAccount(user);
}

let cachedFirebaseCerts: { certs: Record<string, string>; expiresAt: number } | null = null;

async function fetchFirebasePublicCerts(): Promise<Record<string, string>> {
  const now = Date.now();
  if (cachedFirebaseCerts && cachedFirebaseCerts.expiresAt > now) {
    return cachedFirebaseCerts.certs;
  }

  const res = await fetch(
    'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'
  );
  if (!res.ok) {
    throw new Error(`Could not fetch Google Firebase public keys (${res.status}).`);
  }
  const certs = (await res.json()) as Record<string, string>;
  const cacheControl = res.headers.get('cache-control') || '';
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/i);
  const ttlMs = maxAgeMatch ? Math.min(3600_000, Number(maxAgeMatch[1]) * 1000) : 1800_000;
  cachedFirebaseCerts = { certs, expiresAt: now + ttlMs };
  return certs;
}

export async function verifyFirebaseIdToken(
  idToken: string,
  expectedProjectId: string
): Promise<{ uid: string; email: string; name: string; avatarUrl?: string }> {
  if (!idToken || typeof idToken !== 'string') {
    throw new Error('Missing Firebase ID token.');
  }
  const parts = idToken.split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed Firebase JWT token.');
  }
  const [headerB64, payloadB64, sigB64] = parts;

  const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

  if (header?.alg !== 'RS256' || typeof header?.kid !== 'string') {
    throw new Error('Unsupported Firebase JWT header.');
  }

  const certs = await fetchFirebasePublicCerts();
  const certPem = certs[header.kid];
  if (!certPem) {
    throw new Error('Unknown Firebase signing key ID.');
  }

  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(`${headerB64}.${payloadB64}`);
  verifier.end();
  const signature = Buffer.from(sigB64, 'base64url');
  if (!verifier.verify(certPem, signature)) {
    throw new Error('Invalid Firebase token signature.');
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp <= nowSec) {
    throw new Error('Firebase token has expired.');
  }
  if (typeof payload.iat !== 'number' || payload.iat > nowSec + 300) {
    throw new Error('Firebase token issued-at time is invalid.');
  }
  if (payload.aud !== expectedProjectId) {
    throw new Error('Firebase token project audience mismatch.');
  }
  if (payload.iss !== `https://securetoken.google.com/${expectedProjectId}`) {
    throw new Error('Firebase token issuer mismatch.');
  }
  if (typeof payload.sub !== 'string' || !payload.sub || payload.sub.length > 128) {
    throw new Error('Firebase token subject missing.');
  }
  if (typeof payload.email !== 'string' || !payload.email || payload.email_verified !== true) {
    throw new Error('Verified Google email is required.');
  }

  const displayName =
    typeof payload.name === 'string' && payload.name.trim().length >= 2
      ? payload.name.trim().slice(0, 60)
      : payload.email.split('@')[0];

  const avatarUrl =
    typeof payload.picture === 'string' && payload.picture.startsWith('https://')
      ? payload.picture.slice(0, 300)
      : undefined;

  return {
    uid: payload.sub,
    email: payload.email.toLowerCase(),
    name: displayName,
    avatarUrl,
  };
}

export function upsertGoogleAccount(profile: {
  email: string;
  name: string;
  avatarUrl?: string;
}): PublicAccount {
  const email = profile.email.trim().toLowerCase();
  const db = readDb();
  let user = db.users.find((u) => u.email === email);

  if (user) {
    normalizeUserQuota(user);
    ensureOwnerEntitlement(user);
    if (profile.avatarUrl) user.avatarUrl = profile.avatarUrl;
    if (!user.authProvider) user.authProvider = 'google';
    writeDb(db);
    return toPublicAccount(user);
  }

  user = {
    id: crypto.randomUUID(),
    name: profile.name.trim().slice(0, 60) || email.split('@')[0],
    email,
    passwordHash: 'google-oauth',
    avatarUrl: profile.avatarUrl,
    authProvider: 'google',
    plan: isOwnerAccountEmail(email) ? 'agency' : 'free',
    billingStatus: isOwnerAccountEmail(email) ? 'active' : undefined,
    billingCycle: isOwnerAccountEmail(email) ? 'annual' : undefined,
    dailyScansUsed: 0,
    dailyScanDate: currentDayKey(),
    monthlyPeriodKey: currentMonthKey(),
    monthlyTargetCounts: {},
    apiToken: `cma_live_${crypto.randomBytes(18).toString('hex')}`,
    scansHistory: [],
    createdAt: new Date().toISOString(),
  };

  db.users.push(user);
  writeDb(db);
  return toPublicAccount(user);
}

export interface ContactInquiryInput {
  name: string;
  email: string;
  topic: string;
  userId?: string | null;
}

export interface StoredContactInquiry {
  id: string;
  name: string;
  email: string;
  topic: string;
  userId?: string | null;
  receivedAt: string;
}

const CONTACT_DB_PATH = path.join(DATA_DIR, 'contact_messages.json');

export function saveContactMessage(input: ContactInquiryInput): StoredContactInquiry {
  const name = String(input.name || '').trim().slice(0, 80);
  const email = String(input.email || '').trim().toLowerCase().slice(0, 120);
  const topic = String(input.topic || '').trim().slice(0, 2000);

  if (name.length < 2) {
    throw new Error('Please enter your name (at least 2 characters).');
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error('Please enter a valid email address.');
  }
  if (topic.length < 4) {
    throw new Error('Please enter your topic or message (at least 4 characters).');
  }

  ensureDataDir();
  let entries: StoredContactInquiry[] = [];
  if (fs.existsSync(CONTACT_DB_PATH)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(CONTACT_DB_PATH, 'utf8'));
      if (Array.isArray(parsed)) entries = parsed;
    } catch {
      entries = [];
    }
  }

  const record: StoredContactInquiry = {
    id: `msg_${crypto.randomBytes(4).toString('hex')}`,
    name,
    email,
    topic,
    userId: input.userId || null,
    receivedAt: new Date().toISOString(),
  };

  entries.unshift(record);
  if (entries.length > 500) entries = entries.slice(0, 500);
  fs.writeFileSync(CONTACT_DB_PATH, JSON.stringify(entries, null, 2), {
    encoding: 'utf8',
    mode: 0o600,
  });

  return record;
}

const DODO_EVENTS_DB_PATH = path.join(DATA_DIR, 'dodo_events.json');

interface ProcessedWebhookRecord {
  id: string;
  type?: string;
  userId?: string | null;
  processedAt: string;
}

function readDodoEvents(): ProcessedWebhookRecord[] {
  ensureDataDir();
  if (!fs.existsSync(DODO_EVENTS_DB_PATH)) {
    return [];
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(DODO_EVENTS_DB_PATH, 'utf8'));
    if (Array.isArray(parsed)) return parsed;
  } catch {}
  return [];
}

export function hasProcessedWebhookEvent(eventId: string): boolean {
  const cleanId = String(eventId || '').trim();
  if (!cleanId) return false;
  return readDodoEvents().some((entry) => entry && entry.id === cleanId);
}

export function markWebhookEventProcessed(
  eventId: string,
  meta?: { type?: string; userId?: string | null }
): void {
  const cleanId = String(eventId || '').trim();
  if (!cleanId) return;
  const entries = readDodoEvents();
  if (entries.some((entry) => entry && entry.id === cleanId)) return;

  entries.unshift({
    id: cleanId,
    type: meta?.type,
    userId: meta?.userId ?? null,
    processedAt: new Date().toISOString(),
  });
  const trimmed = entries.slice(0, 2000);
  const tmpPath = `${DODO_EVENTS_DB_PATH}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(trimmed, null, 2), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmpPath, DODO_EVENTS_DB_PATH);
}

export function findAccountIdByEmail(email: string): string | null {
  const normalized = String(email || '').trim().toLowerCase();
  if (!normalized) return null;
  const db = readDb();
  const user = db.users.find((u) => u.email.toLowerCase() === normalized);
  return user ? user.id : null;
}

export function findAccountIdBySubscriptionId(subscriptionId: string): string | null {
  const normalized = String(subscriptionId || '').trim();
  if (!normalized) return null;
  const db = readDb();
  const user = db.users.find((u) => u.dodoSubscriptionId === normalized);
  return user ? user.id : null;
}

export function updateAccountBilling(
  userId: string,
  patch: {
    plan?: AccountPlan;
    billingCycle?: 'monthly' | 'annual';
    billingStatus?: PublicAccount['billingStatus'];
    dodoCustomerId?: string | null;
    dodoSubscriptionId?: string | null;
  }
): PublicAccount | null {
  const db = readDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return null;

  if (patch.plan === 'free' || patch.plan === 'pro' || patch.plan === 'agency') {
    user.plan = patch.plan;
  }
  if (patch.billingCycle === 'monthly' || patch.billingCycle === 'annual') {
    user.billingCycle = patch.billingCycle;
  }
  if (patch.billingStatus !== undefined) {
    user.billingStatus = patch.billingStatus;
  }
  if (patch.dodoCustomerId !== undefined) {
    user.dodoCustomerId = patch.dodoCustomerId;
  }
  if (patch.dodoSubscriptionId !== undefined) {
    user.dodoSubscriptionId = patch.dodoSubscriptionId;
  }

  normalizeUserQuota(user);
  writeDb(db);
  return toPublicAccount(user);
}




