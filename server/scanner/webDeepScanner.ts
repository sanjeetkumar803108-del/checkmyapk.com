import axios from 'axios';
import { AUDIT_HTTPS_AGENT } from './securityGuard.ts';

export interface WebDeepFinding {
  category: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'PASS';
  proof: string;
  description: string;
  remediation: string;
  owaspRef?: string;
}

export interface DomSinkHit {
  type: string;
  severity: 'HIGH' | 'MEDIUM' | 'INFO';
  fileUrl: string;
  snippet: string;
  taintedByInput: boolean;
}

export interface JwtAuditItem {
  source: string;
  alg: string;
  hasExp: boolean;
  expired: boolean;
  claims: string[];
  issues: string[];
}

export interface WebDeepSurfaceSummary {
  discoveredRoutes: string[];
  apiEndpoints: string[];
  openApiSpecs: Array<{ url: string; title?: string; pathsCount: number }>;
  graphqlEndpoints: Array<{ url: string; introspectionEnabled: boolean; typesCount?: number }>;
  domSinks: DomSinkHit[];
  jwtAudits: JwtAuditItem[];
  robotsDisallowed: string[];
  sitemapCount: number;
  authAudit?: {
    enabled: boolean;
    authKind: string;
    targetStatus: number;
    protectedApiChecks: Array<{
      url: string;
      authStatus: number | string;
      unauthStatus: number | string;
    }>;
  };
}

export interface WebDeepScanResult {
  findings: WebDeepFinding[];
  surface: WebDeepSurfaceSummary;
}

const USER_AGENT = 'CheckMyAPK-Auditor/1.0 (+https://checkmyapk.com)';

const TAINT_INPUT_HINT =
  /(?:location\.(?:search|hash|href)|window\.location|URLSearchParams|window\.name|document\.(?:referrer|URL)|decodeURIComponent|event\.data)/i;

const EXPLICIT_POSTMESSAGE_SINK =
  /(?:\.(?:innerHTML|outerHTML)\s*[+]?=|(?:document\.write(?:ln)?|insertAdjacentHTML)\s*\(|\beval\s*\(|\bnew\s+Function\s*\()/i;

function isTaintedNearSink(
  text: string,
  idx: number,
  fullMatch: string,
  isMinifiedVendor: boolean
): boolean {
  if (TAINT_INPUT_HINT.test(fullMatch)) return true;
  if (!isMinifiedVendor) {
    const ctxWindow = text.slice(Math.max(0, idx - 160), Math.min(text.length, idx + 220));
    return TAINT_INPUT_HINT.test(ctxWindow);
  }

  // On minified/bundled scripts, constrain the search to the current function/expression slice
  // so adjacent unrelated functions within 220 chars do not cause false INPUT TAINT positives.
  const rawBefore = text.slice(Math.max(0, idx - 90), idx);
  const lastFnBoundary = Math.max(
    rawBefore.lastIndexOf('function'),
    rawBefore.lastIndexOf('=>{'),
    rawBefore.lastIndexOf('=> {')
  );
  const tightBefore = lastFnBoundary >= 0 ? rawBefore.slice(lastFnBoundary) : rawBefore;
  const tightAfter = text.slice(idx, Math.min(text.length, idx + fullMatch.length + 50)).split(/function\b/)[0];
  return TAINT_INPUT_HINT.test(`${tightBefore}${tightAfter}`);
}

const SENSITIVE_JWT_CLAIM_RE =
  /^(?:password|passwd|pwd|secret|client_secret|api_?key|private_?key|access_?secret|ssn|aadhaar|pan_?card|credit_?card|card_?number|cvv|pin)$/i;

const STACK_TRACE_PATTERNS = [
  /Traceback \(most recent call last\)/,
  /SQLITE_ERROR:/,
  /ECONNREFUSED\s+\d+\.\d+\.\d+\.\d+/,
  /at\s+[A-Za-z0-9_$.]+\s+\([^()\n]*(?:node_modules|server|app|dist)[^()\n]*:\d+:\d+\)/,
  /(?:TypeError|ReferenceError|SyntaxError|SequelizeDatabaseError|PrismaClientKnownRequestError):\s+[^\n]{8,}/
];

const STATIC_EXT_RE = /\.(?:js|mjs|cjs|css|png|jpg|jpeg|gif|svg|webp|ico|woff2?|ttf|eot|map|mp4|webm|pdf)(?:\?|$)/i;

function sanitizeHeaderValue(raw?: string): string {
  if (!raw || typeof raw !== 'string') return '';
  return raw.split(/[\r\n\0]/)[0].trim().slice(0, 4096);
}

export function buildSafeAuthHeaders(rawAuthHeader?: string, rawAuthCookie?: string): {
  headers: Record<string, string>;
  authKind: string;
  bearerJwtCandidate?: string;
  cookieJwtCandidates: string[];
} {
  const headers: Record<string, string> = {};
  let authHeader = sanitizeHeaderValue(rawAuthHeader);
  let authCookie = sanitizeHeaderValue(rawAuthCookie);
  const cookieJwtCandidates: string[] = [];
  let bearerJwtCandidate: string | undefined;
  const kinds: string[] = [];

  if (authHeader) {
    authHeader = authHeader.replace(/^authorization\s*:\s*/i, '').trim();
    const isRawJwt = /^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/.test(authHeader);
    if (isRawJwt) {
      authHeader = `Bearer ${authHeader}`;
    }
    headers['Authorization'] = authHeader;

    const bearerMatch = authHeader.match(/^Bearer\s+(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)$/i);
    if (bearerMatch) {
      bearerJwtCandidate = bearerMatch[1];
      kinds.push('Bearer JWT');
    } else {
      kinds.push('Authorization Header');
    }
  }

  if (authCookie) {
    authCookie = authCookie.replace(/^cookie\s*:\s*/i, '').trim();
    headers['Cookie'] = authCookie;
    kinds.push('Session Cookie');
    for (const part of authCookie.split(';')) {
      const eq = part.indexOf('=');
      if (eq <= 0) continue;
      const val = part.slice(eq + 1).trim();
      if (/^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/.test(val)) {
        cookieJwtCandidates.push(val);
      }
    }
  }

  return {
    headers,
    authKind: kinds.length > 0 ? kinds.join(' + ') : 'None',
    bearerJwtCandidate,
    cookieJwtCandidates
  };
}

function decodeBase64UrlJson(segment: string): Record<string, any> | null {
  try {
    const normalized = segment.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (normalized.length % 4)) % 4;
    const padded = normalized + '='.repeat(padLen);
    const decoded = Buffer.from(padded, 'base64').toString('utf8');
    const parsed = JSON.parse(decoded);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

function findSensitiveClaimNames(obj: Record<string, any>, depth = 0): string[] {
  if (depth > 2 || !obj || typeof obj !== 'object') return [];
  const hits: string[] = [];
  for (const key of Object.keys(obj)) {
    if (SENSITIVE_JWT_CLAIM_RE.test(key) && obj[key] !== undefined && obj[key] !== null && obj[key] !== '') {
      hits.push(key);
    } else if (obj[key] && typeof obj[key] === 'object' && !Array.isArray(obj[key])) {
      hits.push(...findSensitiveClaimNames(obj[key], depth + 1));
    }
  }
  return Array.from(new Set(hits));
}

export function analyzeJwtSecurity(
  candidates: Array<{ token: string; source: string; fromClientBundle?: boolean }>
): { audits: JwtAuditItem[]; findings: WebDeepFinding[] } {
  const audits: JwtAuditItem[] = [];
  const findings: WebDeepFinding[] = [];
  const seen = new Set<string>();

  for (const item of candidates) {
    const parts = item.token.split('.');
    if (parts.length !== 3) continue;
    const dedupKey = `${parts[0]}.${parts[1]}`;
    if (seen.has(dedupKey)) continue;

    const header = decodeBase64UrlJson(parts[0]);
    const payload = decodeBase64UrlJson(parts[1]);
    if (!header || !payload || typeof header.alg !== 'string') continue;

    seen.add(dedupKey);
    const alg = String(header.alg);
    const issues: string[] = [];
    const hasExp = typeof payload.exp === 'number' && Number.isFinite(payload.exp);
    const nowSec = Math.floor(Date.now() / 1000);
    const expired = hasExp ? payload.exp < nowSec : false;

    if (alg.toLowerCase() === 'none' || (parts[2] === '' && alg.toLowerCase() !== 'none')) {
      issues.push('Unsecured alg: none or unsigned JWT');
      findings.push({
        category: 'Authentication & JWT Security',
        type: 'JWT Token Uses Unsecured "alg: none" or Missing Signature',
        severity: 'CRITICAL',
        owaspRef: 'OWASP-A07',
        proof: `Token (${item.source}) decoded header has alg="${alg}" and signatureLength=${parts[2].length}.`,
        description:
          'An attacker can forge arbitrary admin or user claims inside an unsigned ("alg: none") JWT because the server skips cryptographic signature verification.',
        remediation:
          'Explicitly whitelist strong algorithms (e.g. algorithms: ["HS256"] or ["RS256"]) in jwt.verify() and reject "none".'
      });
    }

    if (typeof header.kid === 'string' && (header.kid.includes('..') || header.kid.includes('/') || header.kid.includes('\\'))) {
      issues.push('Suspicious kid header traversal pattern');
      findings.push({
        category: 'Authentication & JWT Security',
        type: 'JWT Key ID (kid) Path Traversal Pattern',
        severity: 'HIGH',
        owaspRef: 'OWASP-A07',
        proof: `JWT (${item.source}) header contains path-like kid="${header.kid.slice(0, 48)}".`,
        description:
          'Path traversal characters inside a JWT "kid" header can trick vulnerable verifiers into loading /dev/null or unintended files as the signing secret.',
        remediation: 'Resolve "kid" strictly through an in-memory map/JWKS lookup rather than filesystem paths.'
      });
    }

    if (!hasExp) {
      issues.push('Missing exp expiration claim');
      findings.push({
        category: 'Authentication & JWT Security',
        type: 'JWT Token Missing Expiration ("exp") Claim',
        severity: 'MEDIUM',
        owaspRef: 'OWASP-A07',
        proof: `Decoded JWT payload (${item.source}) omits the "exp" timestamp claim (claims: ${Object.keys(payload).slice(0, 8).join(', ')}).`,
        description:
          'Tokens without an "exp" expiration remain valid forever if leaked once in browser logs, proxies, or localStorage.',
        remediation: 'Always sign JWTs with a short-lived expiration (e.g. expiresIn: "15m" or "1h") and refresh token rotation.'
      });
    } else if (typeof payload.iat === 'number' && payload.exp - payload.iat > 30 * 86400) {
      const days = Math.round((payload.exp - payload.iat) / 86400);
      issues.push(`Long TTL (${days}d)`);
      findings.push({
        category: 'Authentication & JWT Security',
        type: 'JWT Token Has Excessive Lifetime (>30 Days)',
        severity: 'LOW',
        owaspRef: 'OWASP-A07',
        proof: `Token (${item.source}) has a ${days}-day validity window without short rotation.`,
        description:
          'Long-lived stateless JWTs cannot be easily revoked after password resets or device loss.',
        remediation: 'Use short-lived access tokens (15m–1h) paired with revocable HttpOnly refresh tokens.'
      });
    }

    const sensitiveClaims = findSensitiveClaimNames(payload);
    if (sensitiveClaims.length > 0) {
      issues.push(`Sensitive claim(s): ${sensitiveClaims.join(', ')}`);
      findings.push({
        category: 'Authentication & JWT Security',
        type: 'Sensitive PII or Secret Embedded in Unencrypted JWT Payload',
        severity: 'HIGH',
        owaspRef: 'OWASP-A02',
        proof: `JWT payload (${item.source}) embeds unencrypted sensitive field(s): ${sensitiveClaims.join(', ')}`,
        description:
          'Standard JWS JWT payloads are only Base64URL-encoded, NOT encrypted. Anyone with the token can decode sensitive fields directly.',
        remediation: 'Remove passwords, secrets, and PII from JWT claims; keep only opaque user IDs (sub) and non-sensitive roles.'
      });
    }

    if (item.fromClientBundle) {
      issues.push('Hardcoded in client bundle');
      findings.push({
        category: 'Authentication & JWT Security',
        type: 'Hardcoded JWT Bearer Token Exposed in Client Code',
        severity: 'MEDIUM',
        owaspRef: 'OWASP-A02',
        proof: `Embedded JWT (alg=${alg}, claims=${Object.keys(payload).slice(0, 5).join(',')}) detected inside ${item.source}.`,
        description:
          'Hardcoded JWT tokens shipped in public HTML or JS bundles can be extracted and replayed by any anonymous visitor.',
        remediation: 'Issue JWTs dynamically only after server-side authentication and remove static tokens from frontend bundles.'
      });
    }

    if (issues.length === 0) {
      findings.push({
        category: 'Authentication & JWT Security',
        type: 'JWT Token Structure & Expiration Hardened',
        severity: 'PASS',
        owaspRef: 'OWASP-A07',
        proof: `Verified JWT (${item.source}) uses alg="${alg}", enforces "exp", and leaks no sensitive payload keys.`,
        description: 'Passive JWT inspection found valid cryptographic algorithm metadata, expiration enforcement, and clean claims.',
        remediation: 'Continue rotating signing keys and enforcing short access token lifetimes.'
      });
    }

    audits.push({
      source: item.source,
      alg,
      hasExp,
      expired,
      claims: Object.keys(payload).slice(0, 10),
      issues
    });
  }

  return { audits, findings };
}

function compactSnippet(raw: string, maxLen = 88): string {
  const cleaned = raw.replace(/\s+/g, ' ').trim();
  return cleaned.length > maxLen ? `${cleaned.slice(0, maxLen)}...` : cleaned;
}

function isMinifiedOrVendorBundle(scriptUrl: string, content: string): boolean {
  if (/(?:gstatic\.com|googleapis\.com|cdnjs\.|jsdelivr\.net|unpkg\.com|recaptcha)/i.test(scriptUrl)) {
    return true;
  }
  const lineCount = content.split('\n').length;
  const avgLineLen = content.length / Math.max(1, lineCount);
  return content.length > 3500 && avgLineLen > 240;
}

export function scanDomXssSinks(
  html: string,
  collectedScripts: Array<{ url: string; content: string }>,
  baseUrl: string
): { domSinks: DomSinkHit[]; findings: WebDeepFinding[] } {
  const domSinks: DomSinkHit[] = [];
  const sources: Array<{ url: string; content: string }> = [];

  // Extract inline scripts from HTML (avoid scanning markup tags as JS)
  const inlineChunks: string[] = [];
  const inlineRegex = /<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let inlineMatch: RegExpExecArray | null;
  while ((inlineMatch = inlineRegex.exec(html)) !== null) {
    if (inlineMatch[1] && inlineMatch[1].trim().length > 0) {
      inlineChunks.push(inlineMatch[1]);
    }
  }
  if (inlineChunks.length > 0) {
    sources.push({ url: `${baseUrl} (inline <script>)`, content: inlineChunks.join('\n') });
  }
  for (const sc of collectedScripts) {
    sources.push(sc);
  }

  const sinkRules: Array<{
    label: string;
    findingType: string;
    regex: RegExp;
    isSafe?: (matchText: string, argText: string) => boolean;
  }> = [
    {
      label: 'dangerouslySetInnerHTML',
      findingType: 'DOM XSS Sink: Unsafe dangerouslySetInnerHTML / Raw HTML Render',
      regex: /dangerouslySetInnerHTML\s*[:=]\s*\{\s*(?:\{\s*)?__html\s*:\s*([^}]{1,100})/g,
      isSafe: (_m, arg) => {
        const trimmed = arg.trim();
        if (/DOMPurify\.sanitize|sanitizeHtml/i.test(trimmed)) return true;
        if (/^(?:""|''|``|"<[^$]*"|'<[^$]*')$/.test(trimmed)) return true;
        return false;
      }
    },
    {
      label: 'eval / new Function',
      findingType: 'Unsafe Dynamic Code Execution Sink (eval / new Function)',
      regex: /\b(?:eval|new\s+Function)\s*\(\s*([^);\n]{1,90})/g,
      isSafe: (_m, arg) => {
        const t = arg.trim();
        // Ignore common bundler global-this idioms and constant string-only literals
        if (/^['"`]use strict['"`]/.test(t)) return true;
        if (/^['"`]return this['"`]/.test(t)) return true;
        if (/^(?:"[^"$\\]*"|'[^'$\\]*')$/.test(t)) return true;
        return false;
      }
    },
    {
      label: 'innerHTML / document.write',
      findingType: 'DOM XSS Sink: Unsanitized innerHTML / document.write Assignment',
      regex: /(?:\.(?:innerHTML|outerHTML)\s*[+]?=|(?:document\.write(?:ln)?|insertAdjacentHTML)\s*\()\s*([^;\n}]{1,90})/g,
      isSafe: (_m, arg) => {
        const t = arg.trim();
        // Skip safe resets & static string literals (common in ReactDOM/libraries)
        if (/^(?:""|''|``|void\s+0|null|undefined)$/.test(t)) return true;
        if (/^(?:"[^"$+]*"|'[^'$+]*')$/.test(t)) return true;
        return false;
      }
    },
    {
      label: "postMessage('*', '*')",
      findingType: 'Insecure Cross-Window postMessage Wildcard or Missing Origin Check',
      regex: /\.postMessage\s*\([^,\n]{1,70},\s*(['"`])\*(\1)\s*\)/g
    },
    {
      label: 'postMessage Missing Origin Check',
      findingType: 'Insecure Cross-Window postMessage Wildcard or Missing Origin Check',
      regex: /addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:function\s*\([^)]*\)|(?:\([^)]*\)|[a-zA-Z_$][\w$]*)\s*=>)\s*\{([\s\S]{1,260}?)\}\s*(?:,\s*(?:false|true|\{[^}]*\})\s*)?\)/g,
      isSafe: (fullMatch) => {
        // Only flag when the message handler actually reads .data and skips .origin validation
        if (!/\.data\b/.test(fullMatch)) return true;
        if (/\.origin\b/.test(fullMatch)) return true;
        return false;
      }
    }
  ];

  const groupedByFinding = new Map<string, DomSinkHit[]>();
  const seenKeys = new Set<string>();

  for (const src of sources) {
    if (domSinks.length >= 25) break;
    // Skip very large 3rd-party external CDN analytics scripts to avoid noise
    if (/googletagmanager|google-analytics|gtag|fbevents|hotjar|clarity\.ms/i.test(src.url)) continue;

    const text = src.content;
    const isMinifiedVendor = isMinifiedOrVendorBundle(src.url, text);
    const usesTrustedTypes = /trustedTypes\s*\.\s*createPolicy/i.test(text);

    for (const rule of sinkRules) {
      const rx = new RegExp(rule.regex.source, rule.regex.flags);
      let hitsInScript = 0;
      for (const m of text.matchAll(rx)) {
        if (hitsInScript >= 2 || domSinks.length >= 25) break;
        const fullMatch = m[0];
        const argText = m[1] ?? '';
        if (rule.isSafe && rule.isSafe(fullMatch, argText)) continue;

        const idx = m.index ?? 0;
        const taintedByInput = isTaintedNearSink(text, idx, fullMatch, isMinifiedVendor);

        // Suppress minified/vendor/Trusted-Types untainted .innerHTML=b / eval(b) false positives
        if (
          !taintedByInput &&
          (isMinifiedVendor || usesTrustedTypes) &&
          (rule.label === 'innerHTML / document.write' ||
            rule.label === 'eval / new Function' ||
            rule.label === 'dangerouslySetInnerHTML')
        ) {
          continue;
        }

        // Suppress minified/vendor postMessage false positives when the handler merely delegates (no explicit DOM/eval sink)
        if (
          isMinifiedVendor &&
          rule.label === 'postMessage Missing Origin Check' &&
          !EXPLICIT_POSTMESSAGE_SINK.test(fullMatch)
        ) {
          continue;
        }

        const snippet = compactSnippet(fullMatch);
        const dedup = `${rule.label}|${src.url}|${snippet.slice(0, 40)}`;
        if (seenKeys.has(dedup)) continue;
        seenKeys.add(dedup);
        hitsInScript++;

        const hit: DomSinkHit = {
          type: rule.label,
          severity: taintedByInput ? 'HIGH' : 'MEDIUM',
          fileUrl: compactSnippet(src.url, 100),
          snippet,
          taintedByInput
        };
        domSinks.push(hit);

        const arr = groupedByFinding.get(rule.findingType) || [];
        arr.push(hit);
        groupedByFinding.set(rule.findingType, arr);
      }
    }
  }

  const findings: WebDeepFinding[] = [];
  for (const [findingType, hits] of groupedByFinding.entries()) {
    const anyTainted = hits.some((h) => h.taintedByInput);
    const first = hits[0];
    findings.push({
      category: 'Client DOM XSS & Unsafe JS Sinks',
      type: findingType,
      severity: anyTainted ? 'HIGH' : 'MEDIUM',
      owaspRef: 'OWASP-A03',
      proof: `Detected ${hits.length} sink occurrence(s), e.g. in ${compactSnippet(first.fileUrl, 96)} -> "${first.snippet}"${
        anyTainted ? ' [Input Source Reachable Nearby]' : ''
      }`,
      description:
        'Unsafe browser JavaScript sinks can execute attacker-controlled HTML or scripts in the victim session if URL parameters, postMessage payloads, or API fields reach them unsanitized.',
      remediation:
        'Use textContent/React JSX escaping instead of raw innerHTML/dangerouslySetInnerHTML (or sanitize with DOMPurify), eliminate eval/new Function, and validate event.origin strictly on postMessage listeners.'
    });
  }

  return { domSinks, findings };
}

function compactUrlPath(p: string, maxLen = 110): string {
  return p.length > maxLen ? `${p.slice(0, maxLen - 3)}...` : p;
}

function extractStaticRoutesAndApis(
  html: string,
  collectedScripts: Array<{ url: string; content: string }>,
  baseUrl: string
): { apiPaths: string[]; pageRoutes: string[]; graphqlHints: string[] } {
  const apiSet = new Set<string>();
  const routeSet = new Set<string>();
  const gqlSet = new Set<string>();
  let targetOrigin = '';
  try {
    targetOrigin = new URL(baseUrl).origin;
  } catch {
    return { apiPaths: [], pageRoutes: [], graphqlHints: [] };
  }

  const combined = [html, ...collectedScripts.map((s) => s.content)].join('\n');

  // Extract relative API / GraphQL / v1..v3 paths inside JS strings & HTML
  const apiRegex = /["'`](\/(?:api|v[1-3]|graphql|gql|rest)(?:\/[a-zA-Z0-9._:{}-]+){0,5})["'`]/g;
  for (const m of combined.matchAll(apiRegex)) {
    const p = compactUrlPath(m[1], 110);
    if (!p || STATIC_EXT_RE.test(p) || p.includes('node_modules')) continue;
    if (p.toLowerCase().includes('graphql') || p === '/gql') {
      gqlSet.add(p);
    }
    apiSet.add(p);
    if (apiSet.size >= 30) break;
  }

  // Extract absolute same-origin API URLs too
  const absApiRegex = /https?:\/\/[a-zA-Z0-9.-]+(?::\d+)?(\/(?:api|v[1-3]|graphql|rest)(?:\/[a-zA-Z0-9._:{}-]+){0,4})/g;
  for (const m of combined.matchAll(absApiRegex)) {
    try {
      const parsed = new URL(m[0]);
      if (parsed.origin === targetOrigin && !STATIC_EXT_RE.test(parsed.pathname)) {
        const cleanPath = compactUrlPath(parsed.pathname, 110);
        if (cleanPath.toLowerCase().includes('graphql')) gqlSet.add(cleanPath);
        apiSet.add(cleanPath);
      }
    } catch {}
  }

  // Extract internal HTML anchor routes
  const hrefRegex = /<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)["']/gi;
  for (const m of html.matchAll(hrefRegex)) {
    try {
      const u = new URL(m[1], baseUrl);
      if (u.origin === targetOrigin && !STATIC_EXT_RE.test(u.pathname) && u.pathname !== '/') {
        routeSet.add(compactUrlPath(u.pathname, 110));
        if (routeSet.size >= 25) break;
      }
    } catch {}
  }

  return {
    apiPaths: Array.from(apiSet),
    pageRoutes: Array.from(routeSet),
    graphqlHints: Array.from(gqlSet)
  };
}

function isHtmlDocument(body: string, contentType?: string): boolean {
  const ct = String(contentType || '').toLowerCase();
  if (ct.includes('text/html')) return true;
  const trimmed = body.trimStart().toLowerCase();
  return trimmed.startsWith('<!doctype') || trimmed.startsWith('<html');
}

function detectVerboseStackTrace(rawBody: any): string | null {
  const text = typeof rawBody === 'string' ? rawBody.slice(0, 12000) : JSON.stringify(rawBody ?? '').slice(0, 12000);
  for (const rx of STACK_TRACE_PATTERNS) {
    const match = text.match(rx);
    if (match) return compactSnippet(match[0], 72);
  }
  return null;
}

export async function runWebDeepAudit(params: {
  targetUrl: string;
  html: string;
  initialStatus: number;
  collectedScripts: Array<{ url: string; content: string }>;
  authHeader?: string;
  authCookie?: string;
}): Promise<WebDeepScanResult> {
  const { targetUrl, html, initialStatus, collectedScripts, authHeader, authCookie } = params;
  const findings: WebDeepFinding[] = [];
  let targetOrigin = '';
  try {
    targetOrigin = new URL(targetUrl).origin;
  } catch {
    return {
      findings,
      surface: {
        discoveredRoutes: [],
        apiEndpoints: [],
        openApiSpecs: [],
        graphqlEndpoints: [],
        domSinks: [],
        jwtAudits: [],
        robotsDisallowed: [],
        sitemapCount: 0
      }
    };
  }

  // 1. Static DOM XSS & Unsafe JS Sinks Scan
  const { domSinks, findings: domFindings } = scanDomXssSinks(html, collectedScripts, targetUrl);
  findings.push(...domFindings);

  // 2. Auth Header Parsing + Passive JWT Security Analyzer (user-provided + bundle-embedded JWTs)
  const authCfg = buildSafeAuthHeaders(authHeader, authCookie);
  const jwtCandidates: Array<{ token: string; source: string; fromClientBundle?: boolean }> = [];
  if (authCfg.bearerJwtCandidate) {
    jwtCandidates.push({ token: authCfg.bearerJwtCandidate, source: 'Authorization Bearer Input' });
  }
  for (const ckJwt of authCfg.cookieJwtCandidates) {
    jwtCandidates.push({ token: ckJwt, source: 'Auth Cookie Input' });
  }

  const jwtRegex = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*(?=["'\s,;)`]|$)/g;
  for (const sc of [{ url: `${targetUrl} (HTML)`, content: html }, ...collectedScripts]) {
    for (const m of sc.content.matchAll(jwtRegex)) {
      jwtCandidates.push({ token: m[0], source: sc.url, fromClientBundle: true });
      if (jwtCandidates.length >= 10) break;
    }
    if (jwtCandidates.length >= 10) break;
  }

  const { audits: jwtAudits, findings: jwtFindings } = analyzeJwtSecurity(jwtCandidates);
  findings.push(...jwtFindings);

  // 3. Multi-Route, OpenAPI, Robots/Sitemap & GraphQL Discovery
  const staticExtracted = extractStaticRoutesAndApis(html, collectedScripts, targetUrl);
  const discoveredRoutes = new Set<string>(staticExtracted.pageRoutes);
  const apiEndpoints = new Set<string>(staticExtracted.apiPaths);
  const openApiSpecs: Array<{ url: string; title?: string; pathsCount: number }> = [];
  const graphqlEndpoints: Array<{ url: string; introspectionEnabled: boolean; typesCount?: number }> = [];
  const robotsDisallowed: string[] = [];
  let sitemapCount = 0;

  const sameOriginHeaders = (withAuth: boolean): Record<string, string> => ({
    'User-Agent': USER_AGENT,
    ...(withAuth ? authCfg.headers : {})
  });

  // Safe parallel probes on same-origin well-known metadata paths
  const openApiCandidates = ['/openapi.json', '/swagger.json', '/v3/api-docs'];
  const gqlCandidates = Array.from(new Set([...staticExtracted.graphqlHints, '/graphql', '/api/graphql'])).slice(0, 3);
  const sitemapCandidates = new Set<string>([`${targetOrigin}/sitemap.xml`]);

  const [robotsRes, ...specAndGqlResults] = await Promise.all([
    axios
      .get(`${targetOrigin}/robots.txt`, {
        timeout: 3200,
        httpsAgent: AUDIT_HTTPS_AGENT,
        maxContentLength: 256 * 1024,
        maxRedirects: 2,
        validateStatus: () => true,
        headers: { 'User-Agent': USER_AGENT }
      })
      .catch(() => null),
    ...openApiCandidates.map(async (specPath) => {
      const specUrl = `${targetOrigin}${specPath}`;
      try {
        const res = await axios.get(specUrl, {
          timeout: 3500,
          httpsAgent: AUDIT_HTTPS_AGENT,
          maxContentLength: 1024 * 1024,
          maxRedirects: 0,
          validateStatus: () => true,
          headers: sameOriginHeaders(Object.keys(authCfg.headers).length > 0)
        });
        return { kind: 'openapi' as const, url: specUrl, res };
      } catch {
        return { kind: 'openapi' as const, url: specUrl, res: null };
      }
    }),
    ...gqlCandidates.map(async (gqlPath) => {
      const gqlUrl = `${targetOrigin}${gqlPath}`;
      try {
        const res = await axios.post(
          gqlUrl,
          { query: '{ __schema { queryType { name } types { name kind } } }' },
          {
            timeout: 3500,
            httpsAgent: AUDIT_HTTPS_AGENT,
            maxContentLength: 512 * 1024,
            maxRedirects: 0,
            validateStatus: () => true,
            headers: {
              'Content-Type': 'application/json',
              ...sameOriginHeaders(Object.keys(authCfg.headers).length > 0)
            }
          }
        );
        return { kind: 'graphql' as const, url: gqlUrl, res };
      } catch {
        return { kind: 'graphql' as const, url: gqlUrl, res: null };
      }
    })
  ]);

  if (robotsRes && robotsRes.status === 200 && typeof robotsRes.data === 'string' && !isHtmlDocument(robotsRes.data, robotsRes.headers['content-type'])) {
    for (const line of robotsRes.data.split(/\r?\n/)) {
      const dis = line.match(/^Disallow:\s*(\S+)/i);
      if (dis && dis[1] && dis[1] !== '/') {
        robotsDisallowed.push(dis[1]);
        discoveredRoutes.add(dis[1]);
      }
      const sm = line.match(/^Sitemap:\s*(\S+)/i);
      if (sm && sm[1]) {
        try {
          const parsedSm = new URL(sm[1], targetOrigin);
          if (parsedSm.origin === targetOrigin) sitemapCandidates.add(parsedSm.href);
        } catch {}
      }
    }
  }

  // Fetch up to 1 sitemap (same-origin) to gather real multi-route coverage
  const firstSitemap = Array.from(sitemapCandidates)[0];
  if (firstSitemap) {
    try {
      const smRes = await axios.get(firstSitemap, {
        timeout: 3200,
        httpsAgent: AUDIT_HTTPS_AGENT,
        maxContentLength: 512 * 1024,
        maxRedirects: 1,
        validateStatus: () => true,
        headers: { 'User-Agent': USER_AGENT }
      });
      if (smRes.status === 200 && typeof smRes.data === 'string' && smRes.data.includes('<loc>')) {
        for (const m of smRes.data.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
          try {
            const u = new URL(m[1]);
            if (u.origin === targetOrigin) {
              sitemapCount++;
              if (discoveredRoutes.size < 35) discoveredRoutes.add(u.pathname);
            }
          } catch {}
        }
      }
    } catch {}
  }

  // Inspect OpenAPI & GraphQL probe responses
  let openapiExposedCount = 0;
  for (const item of specAndGqlResults) {
    if (!item.res) continue;
    if (item.kind === 'openapi' && item.res.status === 200) {
      const raw = typeof item.res.data === 'string' ? item.res.data : JSON.stringify(item.res.data ?? '');
      if (isHtmlDocument(raw, item.res.headers['content-type'])) continue;
      let parsed: any = typeof item.res.data === 'object' ? item.res.data : null;
      if (!parsed) {
        try {
          parsed = JSON.parse(raw);
        } catch {}
      }
      if (parsed && (parsed.openapi || parsed.swagger) && parsed.paths && typeof parsed.paths === 'object') {
        const specPaths = Object.keys(parsed.paths);
        openApiSpecs.push({
          url: item.url,
          title: typeof parsed.info?.title === 'string' ? parsed.info.title : undefined,
          pathsCount: specPaths.length
        });
        for (const p of specPaths.slice(0, 12)) apiEndpoints.add(p);
        openapiExposedCount++;
        findings.push({
          category: 'API Surface & Schema Exposure',
          type: 'Public OpenAPI / Swagger Specification Exposed',
          severity: 'MEDIUM',
          owaspRef: 'OWASP-API09',
          proof: `GET ${item.url} returned HTTP 200 exposing ${specPaths.length} API endpoint(s) (sample: ${specPaths.slice(0, 4).join(', ')}).`,
          description:
            'Exposing raw OpenAPI/Swagger schemas publicly maps out every internal endpoint, expected parameter, and auth schema for attackers.',
          remediation: 'Restrict Swagger/OpenAPI JSON endpoints to authenticated internal users or disable documentation routes in production.'
        });
      }
    }

    if (item.kind === 'graphql' && item.res.status === 200 && item.res.data?.data?.__schema) {
      const schemaTypes = Array.isArray(item.res.data.data.__schema.types) ? item.res.data.data.__schema.types : [];
      const customTypes = schemaTypes
        .map((t: any) => t?.name)
        .filter((n: any) => typeof n === 'string' && !n.startsWith('__'));
      graphqlEndpoints.push({
        url: item.url,
        introspectionEnabled: true,
        typesCount: customTypes.length
      });
      findings.push({
        category: 'API Surface & Schema Exposure',
        type: 'GraphQL Schema Introspection Enabled in Production',
        severity: 'MEDIUM',
        owaspRef: 'OWASP-API09',
        proof: `POST ${item.url} (__schema query) returned HTTP 200 revealing ${customTypes.length} schema type(s): ${customTypes.slice(0, 5).join(', ')}`,
        description:
          'Production GraphQL introspection lets attackers download your entire backend graph of queries, mutations, and object fields in a single request.',
        remediation: 'Disable GraphQL introspection in production (e.g., ApolloServer({ introspection: process.env.NODE_ENV !== "production" })).'
      });
    } else if (item.kind === 'graphql' && (item.res.status === 400 || item.res.status === 401 || item.res.status === 403 || item.res.status === 405)) {
      graphqlEndpoints.push({
        url: item.url,
        introspectionEnabled: false
      });
    }
  }

  // 4. Safe Read-Only GET Audit on up to 4 Discovered API Routes (+ Authenticated Comparison if provided)
  const hasAuth = Object.keys(authCfg.headers).length > 0;
  let authTargetStatus = initialStatus;
  const protectedApiChecks: Array<{ url: string; authStatus: number | string; unauthStatus: number | string }> = [];

  if (hasAuth) {
    try {
      const authPageRes = await axios.get(targetUrl, {
        timeout: 4000,
        httpsAgent: AUDIT_HTTPS_AGENT,
        maxRedirects: 0,
        validateStatus: () => true,
        headers: {
          ...sameOriginHeaders(true),
          Accept: 'text/html,application/json,*/*'
        }
      });
      authTargetStatus = authPageRes.status;
      const trace = detectVerboseStackTrace(authPageRes.data);
      if (trace) {
        findings.push({
          category: 'Authenticated API & Error Leakage',
          type: 'Verbose Server Stack Trace Exposed in Response',
          severity: 'MEDIUM',
          owaspRef: 'OWASP-A05',
          proof: `Authenticated GET ${targetUrl} returned stack frame / DB error signature: "${trace}"`,
          description:
            'Stack traces expose file paths, framework versions, database engines, and internal logic to attackers.',
          remediation: 'Use a global production error handler that returns generic JSON errors and logs full stack traces server-side.'
        });
      }
    } catch {}
  } else {
    const homeTrace = detectVerboseStackTrace(html);
    if (homeTrace) {
      findings.push({
        category: 'API Surface & Schema Exposure',
        type: 'Verbose Server Stack Trace Exposed in Response',
        severity: 'MEDIUM',
        owaspRef: 'OWASP-A05',
        proof: `GET ${targetUrl} response body contains debug stack trace signature: "${homeTrace}"`,
        description: 'Unmasked server stack traces leak internal source paths and dependency versions.',
        remediation: 'Disable debug/stack trace output when NODE_ENV === "production".'
      });
    }
  }

  // Prioritize concrete non-parameterized GET API paths for passive read-only inspection
  const probeApiPaths = Array.from(apiEndpoints)
    .filter((p) => !p.includes('{') && !p.includes(':') && !p.includes('*'))
    .slice(0, 4);

  let stackLeakReported = false;
  let unauthPiiReported = false;
  let accessControlPassed = false;

  await Promise.all(
    probeApiPaths.map(async (apiPath) => {
      const fullApiUrl = `${targetOrigin}${apiPath}`;
      try {
        const unauthRes = await axios.get(fullApiUrl, {
          timeout: 3200,
          httpsAgent: AUDIT_HTTPS_AGENT,
          maxContentLength: 256 * 1024,
          maxRedirects: 0,
          validateStatus: () => true,
          headers: sameOriginHeaders(false)
        });

        let authStatus: number | string = 'N/A';
        if (hasAuth) {
          const authRes = await axios.get(fullApiUrl, {
            timeout: 3200,
            httpsAgent: AUDIT_HTTPS_AGENT,
            maxContentLength: 256 * 1024,
            maxRedirects: 0,
            validateStatus: () => true,
            headers: sameOriginHeaders(true)
          });
          authStatus = authRes.status;
          protectedApiChecks.push({
            url: apiPath,
            authStatus,
            unauthStatus: unauthRes.status
          });

          if (!accessControlPassed && authRes.status === 200 && (unauthRes.status === 401 || unauthRes.status === 403)) {
            accessControlPassed = true;
            findings.push({
              category: 'Authenticated API & Error Leakage',
              type: 'Authenticated API Endpoint Enforces Access Control',
              severity: 'PASS',
              owaspRef: 'OWASP-API01',
              proof: `${apiPath} returned HTTP ${unauthRes.status} without auth vs HTTP 200 with provided credentials.`,
              description: 'Discovered API endpoint rejects unauthenticated callers while serving authenticated requests.',
              remediation: 'Verify object-level ownership (IDOR checks) on every resource endpoint.'
            });
          }

          if (!stackLeakReported) {
            const authTrace = detectVerboseStackTrace(authRes.data);
            if (authTrace) {
              stackLeakReported = true;
              findings.push({
                category: 'Authenticated API & Error Leakage',
                type: 'Verbose Server Stack Trace Exposed in Response',
                severity: 'MEDIUM',
                owaspRef: 'OWASP-A05',
                proof: `Authenticated GET ${apiPath} leaked stack/DB error trace: "${authTrace}"`,
                description: 'Internal exceptions are returned directly in API responses.',
                remediation: 'Sanitize API error responses in production and strip error.stack before sending JSON.'
              });
            }
          }
        }

        if (!stackLeakReported) {
          const unauthTrace = detectVerboseStackTrace(unauthRes.data);
          if (unauthTrace) {
            stackLeakReported = true;
            findings.push({
              category: 'API Surface & Schema Exposure',
              type: 'Verbose Server Stack Trace Exposed in Response',
              severity: 'MEDIUM',
              owaspRef: 'OWASP-A05',
              proof: `GET ${apiPath} leaked stack/DB error trace: "${unauthTrace}"`,
              description: 'API endpoint exposes internal stack frames or database error strings.',
              remediation: 'Return generic error messages to API callers and log detailed exceptions server-side.'
            });
          }
        }

        // Check if unauthenticated JSON response directly exposes sensitive fields (passwordHash / apiKey / ssn / email list)
        if (!unauthPiiReported && unauthRes.status === 200 && unauthRes.data && typeof unauthRes.data === 'object') {
          const jsonSample = JSON.stringify(unauthRes.data).slice(0, 6000);
          const piiMatch = jsonSample.match(/"(passwordHash|password_hash|password|secretKey|privateKey|ssn|accessToken)"\s*:/i);
          if (piiMatch && !isHtmlDocument(jsonSample, unauthRes.headers['content-type'])) {
            unauthPiiReported = true;
            findings.push({
              category: 'API Surface & Schema Exposure',
              type: 'Unauthenticated API Endpoint Exposes Sensitive Fields',
              severity: 'HIGH',
              owaspRef: 'OWASP-API03',
              proof: `Unauthenticated GET ${apiPath} returned HTTP 200 JSON containing field "${piiMatch[1]}".`,
              description:
                'This API route serves sensitive credential or user fields to anonymous requests without authentication.',
              remediation:
                'Require authentication middleware and explicitly whitelist safe DTO projection fields before serializing JSON responses.'
            });
          }
        }
      } catch {}
    })
  );

  // If OpenAPI check didn't find anything exposed and GraphQL introspection wasn't enabled, log a helpful clean note only if an API surface existed
  if (openapiExposedCount === 0 && graphqlEndpoints.some((g) => !g.introspectionEnabled)) {
    findings.push({
      category: 'API Surface & Schema Exposure',
      type: 'GraphQL Introspection Disabled / Protected',
      severity: 'PASS',
      owaspRef: 'OWASP-API09',
      proof: `Probed GraphQL endpoint(s) (${graphqlEndpoints.map((g) => g.url).join(', ')}) rejected anonymous __schema introspection.`,
      description: 'GraphQL schema introspection is not exposed publicly.',
      remediation: 'Keep introspection disabled in production builds.'
    });
  }

  return {
    findings,
    surface: {
      discoveredRoutes: Array.from(discoveredRoutes).slice(0, 30),
      apiEndpoints: Array.from(apiEndpoints).slice(0, 30),
      openApiSpecs,
      graphqlEndpoints,
      domSinks,
      jwtAudits,
      robotsDisallowed: robotsDisallowed.slice(0, 15),
      sitemapCount,
      ...(hasAuth
        ? {
            authAudit: {
              enabled: true,
              authKind: authCfg.authKind,
              targetStatus: authTargetStatus,
              protectedApiChecks
            }
          }
        : {})
    }
  };
}
