import dns from 'dns/promises';
import dnsStandard from 'dns';
import https from 'https';
import net from 'net';
import crypto from 'crypto';
import axios from 'axios';

/**
 * Target-only HTTPS agent used exclusively when auditing user-supplied targets.
 * Allows the scanner to connect to sites with expired/self-signed certs so our
 * TLS auditor can flag them in the report instead of aborting pre-scan.
 * Never use globally or for external verification APIs (e.g., Gemini key probe).
 */
export const AUDIT_HTTPS_AGENT = new https.Agent({
  rejectUnauthorized: false,
  keepAlive: false
});

async function resolveWithFallbackDns(host: string): Promise<Array<{ address: string }>> {
  const withTimeout = <T>(promise: Promise<T>, ms: number, errMsg: string): Promise<T> =>
    Promise.race([
      promise,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error(errMsg)), ms))
    ]);

  // 1. Primary: system resolver
  try {
    const sysRecords = await withTimeout(dns.lookup(host, { all: true }), 4500, 'DNS lookup timeout');
    if (sysRecords && sysRecords.length > 0) return sysRecords;
  } catch {
    // Fall through to resilient public DNS resolvers (Cloudflare / Google / Quad9)
  }

  // 2. Fallback: explicit UDP DNS via public resolvers (resilient against flaky Windows/ISP DNS)
  const resolver = new dnsStandard.promises.Resolver();
  resolver.setServers(['1.1.1.1', '8.8.8.8', '9.9.9.9']);

  const [v4, v6] = await withTimeout(
    Promise.all([
      resolver.resolve4(host).catch(() => [] as string[]),
      resolver.resolve6(host).catch(() => [] as string[])
    ]),
    4500,
    'DNS lookup timeout'
  );

  const combined = [...v4, ...v6].map((address) => ({ address }));
  if (combined.length === 0) {
    throw new Error('DNS lookup returned no A/AAAA records');
  }
  return combined;
}

export interface TargetSafetyResult {
  allowed: boolean;
  reason?: string;
  resolvedIps: string[];
  isLoopback: boolean;
}

const VERIFICATION_SECRET =
  process.env.DOMAIN_VERIFY_SECRET ||
  crypto.createHash('sha256').update(process.cwd() + ':checkmyapk-domain-verify').digest('hex');

const verifiedDomainsCache = new Map<string, number>(); // host -> expiresAt
const rateBuckets = new Map<string, number[]>(); // key -> timestamps ms

const ALWAYS_BLOCKED_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data'
]);

export function isMetadataOrLinkLocalIp(rawIp: string): boolean {
  const ip = normalizeIp(rawIp);
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    // 169.254.0.0/16 (cloud metadata / APIPA)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 100.64.0.0/10 (carrier-grade NAT / cloud internal)
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const lc = ip.toLowerCase();
    return lc.startsWith('fe80:');
  }
  return false;
}

function normalizeIp(rawIp: string): string {
  const lower = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (lower.startsWith('::ffff:')) {
    const mapped = lower.slice(7);
    if (net.isIPv4(mapped)) return mapped;
  }
  return lower;
}

export function isPrivateOrReservedIp(rawIp: string): boolean {
  const ip = normalizeIp(rawIp);
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 metadata / link-local
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 192 && b === 0) return true; // 192.0.0.0/24 / TEST-NET
    if (a >= 224) return true; // Multicast & reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const lc = ip.toLowerCase();
    if (lc === '::' || lc === '::1') return true;
    if (lc.startsWith('fc') || lc.startsWith('fd')) return true; // fc00::/7 ULA
    if (lc.startsWith('fe80:')) return true; // fe80::/10 link-local
    return false;
  }
  return true;
}

export function isLoopbackAddress(rawIpOrHost: string): boolean {
  const host = normalizeIp(rawIpOrHost);
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (net.isIPv4(host)) return host.startsWith('127.');
  if (net.isIPv6(host)) return host === '::1';
  return false;
}

export async function validateTargetSafety(
  targetUrl: string,
  options: {
    isProd: boolean;
    dnsLookupFn?: (host: string) => Promise<Array<{ address: string }>>;
  }
): Promise<TargetSafetyResult> {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return { allowed: false, reason: 'Invalid URL format.', resolvedIps: [], isLoopback: false };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { allowed: false, reason: 'Only http:// and https:// URLs are permitted.', resolvedIps: [], isLoopback: false };
  }

  const hostLower = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!hostLower) {
    return { allowed: false, reason: 'Target hostname is missing.', resolvedIps: [], isLoopback: false };
  }

  if (ALWAYS_BLOCKED_HOSTS.has(hostLower) || hostLower.endsWith('.internal') || hostLower.endsWith('.local')) {
    return {
      allowed: false,
      reason: 'Scanning internal (.internal/.local) or cloud metadata hosts is blocked for security.',
      resolvedIps: [],
      isLoopback: false
    };
  }

  // Direct IP literal check
  if (net.isIP(hostLower) !== 0) {
    const isLoop = isLoopbackAddress(hostLower);
    if (isMetadataOrLinkLocalIp(hostLower)) {
      return {
        allowed: false,
        reason: 'Scanning cloud metadata or link-local IP ranges is blocked.',
        resolvedIps: [hostLower],
        isLoopback: isLoop
      };
    }
    if (options.isProd && isPrivateOrReservedIp(hostLower)) {
      return {
        allowed: false,
        reason: 'Scanning private, reserved, or loopback IP addresses is disabled in production.',
        resolvedIps: [hostLower],
        isLoopback: isLoop
      };
    }
    if (!options.isProd && isPrivateOrReservedIp(hostLower) && !isLoop) {
      return {
        allowed: false,
        reason: 'Scanning private LAN ranges is blocked (only localhost dev targets are permitted locally).',
        resolvedIps: [hostLower],
        isLoopback: false
      };
    }
    return { allowed: true, resolvedIps: [hostLower], isLoopback: isLoop };
  }

  // DNS lookup check to block DNS Rebinding attacks (e.g., evil.com -> 127.0.0.1 / 169.254.169.254)
  if (isLoopbackAddress(hostLower)) {
    if (options.isProd) {
      return {
        allowed: false,
        reason: 'Scanning loopback hosts is disabled in production.',
        resolvedIps: ['127.0.0.1'],
        isLoopback: true
      };
    }
    return { allowed: true, resolvedIps: ['127.0.0.1'], isLoopback: true };
  }

  try {
    const records = options.dnsLookupFn
      ? await Promise.race([
          options.dnsLookupFn(hostLower),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error('DNS lookup timeout')), 3000))
        ])
      : await resolveWithFallbackDns(hostLower);

    const resolvedIps = records.map((r) => normalizeIp(r.address));
    if (resolvedIps.length === 0) {
      return { allowed: false, reason: `Could not resolve DNS records for ${hostLower}.`, resolvedIps: [], isLoopback: false };
    }

    for (const ip of resolvedIps) {
      if (isMetadataOrLinkLocalIp(ip)) {
        return {
          allowed: false,
          reason: `SSRF guard blocked DNS resolution pointing to metadata/link-local IP (${ip}).`,
          resolvedIps,
          isLoopback: false
        };
      }
      if (isPrivateOrReservedIp(ip)) {
        // Non-localhost external hostname resolving to loopback or private LAN is a DNS Rebinding vector!
        return {
          allowed: false,
          reason: `SSRF / DNS-Rebinding guard blocked "${hostLower}" because it resolved to internal IP (${ip}).`,
          resolvedIps,
          isLoopback: isLoopbackAddress(ip)
        };
      }
    }

    return { allowed: true, resolvedIps, isLoopback: false };
  } catch (err: any) {
    return {
      allowed: false,
      reason: `DNS validation failed for ${hostLower}: ${err?.message || 'Unknown error'}`,
      resolvedIps: [],
      isLoopback: false
    };
  }
}

export function checkClientRateLimit(
  clientIp: string,
  bucket: 'web' | 'apk' | 'ai'
): { allowed: boolean; retryAfterSec: number; remaining: number } {
  const now = Date.now();
  const windowMs = 10 * 60 * 1000;
  const maxRequests = bucket === 'ai' ? 40 : 20;
  const key = `${bucket}:${clientIp || 'unknown'}`;

  // Periodic map pruning
  if (rateBuckets.size > 500) {
    for (const [k, stamps] of rateBuckets.entries()) {
      const fresh = stamps.filter((t) => now - t < windowMs);
      if (fresh.length === 0) rateBuckets.delete(k);
      else rateBuckets.set(k, fresh);
    }
  }

  const existing = (rateBuckets.get(key) || []).filter((t) => now - t < windowMs);
  if (existing.length >= maxRequests) {
    const oldest = existing[0] || now;
    const retryAfterSec = Math.max(1, Math.ceil((windowMs - (now - oldest)) / 1000));
    rateBuckets.set(key, existing);
    return { allowed: false, retryAfterSec, remaining: 0 };
  }

  existing.push(now);
  rateBuckets.set(key, existing);
  return { allowed: true, retryAfterSec: 0, remaining: maxRequests - existing.length };
}

export function getDomainVerificationChallenge(targetUrl: string): {
  host: string;
  token: string;
  txtRecord: string;
  metaTag: string;
  wellKnownPath: string;
} {
  const host = new URL(targetUrl).hostname.toLowerCase();
  const digest = crypto.createHmac('sha256', VERIFICATION_SECRET).update(host).digest('hex').slice(0, 20);
  const token = `checkmyapk-verify=${digest}`;
  return {
    host,
    token,
    txtRecord: token,
    metaTag: `<meta name="checkmyapk-verify" content="${token}" />`,
    wellKnownPath: '/.well-known/checkmyapk-verify.txt'
  };
}

export async function verifyDomainOwnership(
  targetUrl: string,
  html?: string
): Promise<{ verified: boolean; method?: 'cache' | 'meta' | 'dns-txt' | 'well-known'; token: string }> {
  const challenge = getDomainVerificationChallenge(targetUrl);
  const now = Date.now();

  const cachedExp = verifiedDomainsCache.get(challenge.host);
  if (cachedExp && cachedExp > now) {
    return { verified: true, method: 'cache', token: challenge.token };
  }

  // 1. Check HTML <meta name="checkmyapk-verify" content="...">
  if (html && html.includes(challenge.token)) {
    verifiedDomainsCache.set(challenge.host, now + 6 * 60 * 60 * 1000);
    return { verified: true, method: 'meta', token: challenge.token };
  }

  // 2. Check DNS TXT record & /.well-known/checkmyapk-verify.txt in parallel
  const dnsPromise = Promise.race([
    dns.resolveTxt(challenge.host).then((rows) => rows.flat().some((entry) => entry.includes(challenge.token))),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 1500))
  ]).catch(() => false);

  const wellKnownUrl = `${new URL(targetUrl).origin}${challenge.wellKnownPath}`;
  const wellKnownPromise = axios
    .get(wellKnownUrl, {
      timeout: 1800,
      maxRedirects: 0,
      maxContentLength: 8192,
      validateStatus: () => true
    })
    .then((r) => r.status === 200 && typeof r.data === 'string' && r.data.includes(challenge.token))
    .catch(() => false);

  const [dnsMatch, wkMatch] = await Promise.all([dnsPromise, wellKnownPromise]);
  if (dnsMatch) {
    verifiedDomainsCache.set(challenge.host, now + 6 * 60 * 60 * 1000);
    return { verified: true, method: 'dns-txt', token: challenge.token };
  }
  if (wkMatch) {
    verifiedDomainsCache.set(challenge.host, now + 6 * 60 * 60 * 1000);
    return { verified: true, method: 'well-known', token: challenge.token };
  }

  return { verified: false, token: challenge.token };
}

