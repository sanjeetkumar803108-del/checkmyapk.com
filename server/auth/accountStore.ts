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

export function toPublicAccount(user: StoredAccount): PublicAccount {
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
    plan: 'free',
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
  if (normalizeUserQuota(user)) {
    writeDb(db);
  }
  return { account: toPublicAccount(user) };
}

export function getAccountById(userId: string): PublicAccount | null {
  const db = readDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return null;
  if (normalizeUserQuota(user)) {
    writeDb(db);
  }
  return toPublicAccount(user);
}

export function recordUserScan(
  userId: string,
  entry: Omit<SavedScanEntry, 'id' | 'timestamp'>
): PublicAccount | null {
  const db = readDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return null;

  normalizeUserQuota(user);

  const saved: SavedScanEntry = {
    id: crypto.randomUUID(),
    target: String(entry.target || '').slice(0, 220),
    mode: entry.mode === 'web' ? 'web' : 'apk',
    score: Math.max(0, Math.min(100, Number(entry.score) || 0)),
    grade: String(entry.grade || 'B').slice(0, 4),
    criticalCount: Math.max(0, Number(entry.criticalCount) || 0),
    timestamp: new Date().toISOString(),
  };

  user.scansHistory = [saved, ...(user.scansHistory || [])].slice(0, 30);
  writeDb(db);
  return toPublicAccount(user);
}

export function getAccountPlanById(userId: string | null): AccountPlan {
  if (!userId) return 'free';
  const db = readDb();
  const user = db.users.find((u) => u.id === userId);
  return user?.plan || 'free';
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
      const policy = getPlanPolicy(user.plan);
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
    plan: 'free',
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




