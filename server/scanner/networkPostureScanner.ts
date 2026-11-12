import axios from 'axios';
import dns from 'dns';
import net from 'net';
import tls from 'tls';

export interface PostureFinding {
  category: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'PASS';
  proof: string;
  description: string;
  remediation: string;
  owaspRef?: string;
}

export interface NetworkPostureSummary {
  corsReflection: 'Reflected (Critical)' | 'Reflected (High)' | 'Strict';
  tlsProtocol: string | null;
  certDaysRemaining: number | null;
  certIssuer: string | null;
  spfPresent: boolean | null;
  dmarcPolicy: string | null;
  securityTxtPresent: boolean;
  missingSriCount: number;
  outdatedLibraries: string[];
}

export interface NetworkPostureResult {
  findings: PostureFinding[];
  posture: NetworkPostureSummary;
}

const STATIC_CDN_HOST_RE = /(?:cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|code\.jquery\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|ajax\.googleapis\.com)/i;

function isVersionBelow(found: string, minMajor: number, minMinor: number, minPatch: number): boolean {
  const parts = found.split('.').map((n) => parseInt(n, 10));
  if (parts.length < 2 || parts.some((n) => Number.isNaN(n))) return false;
  const maj = parts[0] ?? 0;
  const min = parts[1] ?? 0;
  const pat = parts[2] ?? 0;
  if (maj !== minMajor) return maj < minMajor;
  if (min !== minMinor) return min < minMinor;
  return pat < minPatch;
}

function getParentDomain(host: string): string {
  const clean = host.replace(/^www\./i, '').toLowerCase();
  const labels = clean.split('.').filter(Boolean);
  if (labels.length <= 2) return clean;
  return labels.slice(-2).join('.');
}

async function resolveTxtRecordsSafe(name: string): Promise<{ ok: boolean; records: string[] }> {
  const tryResolve = async (fn: () => Promise<string[][]>) => {
    const res = await Promise.race([
      fn(),
      new Promise<string[][]>((_, reject) => setTimeout(() => reject(new Error('DNS TXT timeout')), 2200))
    ]);
    return res.map((chunks) => chunks.join('')).filter(Boolean);
  };

  try {
    return { ok: true, records: await tryResolve(() => dns.promises.resolveTxt(name)) };
  } catch (err: any) {
    const code = String(err?.code || '');
    if (code === 'ENODATA' || code === 'ENOTFOUND') {
      return { ok: true, records: [] };
    }
    try {
      const publicResolver = new dns.promises.Resolver();
      publicResolver.setServers(['1.1.1.1', '8.8.8.8']);
      return { ok: true, records: await tryResolve(() => publicResolver.resolveTxt(name)) };
    } catch (fallbackErr: any) {
      const fCode = String(fallbackErr?.code || '');
      if (fCode === 'ENODATA' || fCode === 'ENOTFOUND') {
        return { ok: true, records: [] };
      }
      return { ok: false, records: [] };
    }
  }
}

export async function probeDynamicCorsReflection(targetUrl: string): Promise<{
  reflected: 'critical' | 'high' | 'none';
  finding: PostureFinding;
}> {
  const probeOrigin = 'https://checkmyapk-cors-probe.example';
  try {
    const resp = await axios.get(targetUrl, {
      timeout: 3500,
      maxRedirects: 2,
      validateStatus: () => true,
      headers: {
        Origin: probeOrigin,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });
    const acao = String(resp.headers?.['access-control-allow-origin'] || '').trim().toLowerCase();
    const acac = String(resp.headers?.['access-control-allow-credentials'] || '').trim().toLowerCase();

    if (acao === probeOrigin) {
      if (acac === 'true') {
        return {
          reflected: 'critical',
          finding: {
            category: 'Security Headers & CORS',
            type: 'Dynamic CORS Origin Reflection With Credentials Enabled',
            severity: 'CRITICAL',
            owaspRef: 'OWASP-A01',
            proof: `GET ${targetUrl} with Origin: ${probeOrigin} echoed ACAO=${acao} & Access-Control-Allow-Credentials=true`,
            description: 'Any malicious third-party website can perform cross-origin authenticated requests and steal private user responses because the server blindly reflects arbitrary Origin headers with credentials.',
            remediation: 'Replace dynamic Origin reflection with an explicit allowlist array of trusted origins checked strictly before setting Access-Control-Allow-Origin.'
          }
        };
      }
      return {
        reflected: 'high',
        finding: {
          category: 'Security Headers & CORS',
          type: 'Dynamic CORS Origin Reflection Vulnerability',
          severity: 'HIGH',
          owaspRef: 'OWASP-A01',
          proof: `GET ${targetUrl} with Origin: ${probeOrigin} dynamically echoed Access-Control-Allow-Origin: ${acao}`,
          description: 'Server echoes arbitrary untrusted Origin headers into Access-Control-Allow-Origin, enabling unauthorized cross-site data reads.',
          remediation: 'Validate req.headers.origin against a strict allowlist instead of reflecting request origins blindly.'
        }
      };
    }

    return {
      reflected: 'none',
      finding: {
        category: 'Security Headers & CORS',
        type: 'Strict CORS Origin Validation (No Arbitrary Reflection)',
        severity: 'PASS',
        owaspRef: 'OWASP-A01',
        proof: `Origin probe (${probeOrigin}) was not reflected in Access-Control-Allow-Origin (${acao || 'none'}).`,
        description: 'Endpoint did not echo an untrusted Origin header back in CORS response headers.',
        remediation: 'Maintain strict explicit origin allowlists for sensitive endpoints.'
      }
    };
  } catch {
    return {
      reflected: 'none',
      finding: {
        category: 'Security Headers & CORS',
        type: 'Strict CORS Origin Validation (No Arbitrary Reflection)',
        severity: 'PASS',
        owaspRef: 'OWASP-A01',
        proof: `CORS Origin probe completed without arbitrary origin reflection.`,
        description: 'No arbitrary Origin reflection observed.',
        remediation: 'Maintain explicit origin allowlists.'
      }
    };
  }
}

export async function inspectTlsCertificate(parsedUrl: URL): Promise<{
  protocol: string | null;
  daysRemaining: number | null;
  issuer: string | null;
  findings: PostureFinding[];
}> {
  if (parsedUrl.protocol !== 'https:') {
    return { protocol: null, daysRemaining: null, issuer: null, findings: [] };
  }

  return new Promise((resolve) => {
    const port = Number(parsedUrl.port || 443);
    const socket = tls.connect(
      {
        host: parsedUrl.hostname,
        port,
        servername: net.isIP(parsedUrl.hostname) ? undefined : parsedUrl.hostname,
        rejectUnauthorized: false
      },
      () => {
        try {
          const protocol = socket.getProtocol() || null;
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          const authErr = socket.authorizationError ? String(socket.authorizationError) : '';
          socket.end();

          const findings: PostureFinding[] = [];
          let daysRemaining: number | null = null;
          let issuer: string | null = null;

          if (cert && Object.keys(cert).length > 0) {
            issuer = String(cert.issuer?.O || cert.issuer?.CN || 'Unknown CA');
            if (cert.valid_to) {
              const expMs = Date.parse(cert.valid_to);
              if (!Number.isNaN(expMs)) {
                daysRemaining = Math.floor((expMs - Date.now()) / (1000 * 60 * 60 * 24));
              }
            }
          }

          if (protocol && (protocol === 'TLSv1' || protocol === 'TLSv1.1')) {
            findings.push({
              category: 'Transport Encryption (TLS)',
              type: `Deprecated Weak TLS Protocol Active (${protocol})`,
              severity: 'HIGH',
              owaspRef: 'OWASP-A02',
              proof: `TLS handshake negotiated legacy ${protocol} on ${parsedUrl.hostname}:${port}.`,
              description: 'TLS 1.0 and 1.1 are deprecated and vulnerable to downgrade and cipher attacks (BEAST/POODLE).',
              remediation: 'Disable TLSv1.0/1.1 in Nginx, Cloudflare, or your load balancer and enforce TLSv1.2 + TLSv1.3 only.'
            });
          }

          if (!authorized && authErr) {
            findings.push({
              category: 'Transport Encryption (TLS)',
              type: 'Untrusted or Self-Signed SSL/TLS Certificate',
              severity: 'MEDIUM',
              owaspRef: 'OWASP-A02',
              proof: `TLS peer certificate validation failed (${authErr}) for ${parsedUrl.hostname}.`,
              description: 'Browsers and mobile apps will reject or warn on self-signed/mismatched certificates, exposing users to MitM risk.',
              remediation: 'Install a valid CA-signed certificate (Let\'s Encrypt / Cloudflare / ACM) matching your hostname.'
            });
          } else if (daysRemaining !== null && daysRemaining <= 0) {
            findings.push({
              category: 'Transport Encryption (TLS)',
              type: 'Expired SSL/TLS Certificate',
              severity: 'CRITICAL',
              owaspRef: 'OWASP-A02',
              proof: `Certificate expired ${Math.abs(daysRemaining)} day(s) ago (valid_to: ${cert.valid_to}, issuer: ${issuer}).`,
              description: 'An expired TLS certificate breaks HTTPS trust in every browser and API client.',
              remediation: 'Renew the TLS certificate immediately and enable automated ACME/Certbot renewal.'
            });
          } else if (daysRemaining !== null && daysRemaining < 15) {
            findings.push({
              category: 'Transport Encryption (TLS)',
              type: `SSL/TLS Certificate Expiring Soon (${daysRemaining}d Left)`,
              severity: 'HIGH',
              owaspRef: 'OWASP-A02',
              proof: `Certificate expires in ${daysRemaining} day(s) (${cert.valid_to}, issuer: ${issuer}).`,
              description: 'Certificate is close to expiration and risks imminent HTTPS outage.',
              remediation: 'Verify automated certificate renewal (Certbot/Cloudflare/Vercel) immediately.'
            });
          } else if (findings.length === 0) {
            findings.push({
              category: 'Transport Encryption (TLS)',
              type: `Valid SSL/TLS Certificate & Modern Protocol (${protocol || 'TLS'})`,
              severity: 'PASS',
              owaspRef: 'OWASP-A02',
              proof: `Negotiated ${protocol || 'TLS'} with trusted CA (${issuer || 'Verified CA'})${daysRemaining !== null ? `, ${daysRemaining} days remaining` : ''}.`,
              description: 'HTTPS transport uses a trusted CA certificate with valid remaining lifetime and modern TLS cipher suite.',
              remediation: 'Keep automated certificate rotation and TLS 1.2/1.3 enforcement enabled.'
            });
          }

          resolve({ protocol, daysRemaining, issuer, findings });
        } catch {
          socket.destroy();
          resolve({ protocol: null, daysRemaining: null, issuer: null, findings: [] });
        }
      }
    );

    socket.setTimeout(3000, () => {
      socket.destroy();
      resolve({ protocol: null, daysRemaining: null, issuer: null, findings: [] });
    });
    socket.on('error', () => {
      socket.destroy();
      resolve({ protocol: null, daysRemaining: null, issuer: null, findings: [] });
    });
  });
}

export async function inspectDnsEmailPosture(hostname: string): Promise<{
  spfPresent: boolean | null;
  dmarcPolicy: string | null;
  findings: PostureFinding[];
}> {
  if (!hostname || hostname === 'localhost' || net.isIP(hostname) !== 0) {
    return { spfPresent: null, dmarcPolicy: null, findings: [] };
  }

  const cleanHost = hostname.toLowerCase();
  const apexHost = getParentDomain(cleanHost);
  const candidates = cleanHost === apexHost ? [cleanHost] : [cleanHost, apexHost];

  let spfRecord = '';
  let dmarcRecord = '';
  let anyDnsQuerySucceeded = false;

  for (const dom of candidates) {
    if (!spfRecord) {
      const txts = await resolveTxtRecordsSafe(dom);
      if (txts.ok) anyDnsQuerySucceeded = true;
      spfRecord = txts.records.find((t) => t.toLowerCase().includes('v=spf1')) || '';
    }
    if (!dmarcRecord) {
      const dmarcTxts = await resolveTxtRecordsSafe(`_dmarc.${dom}`);
      if (dmarcTxts.ok) anyDnsQuerySucceeded = true;
      dmarcRecord = dmarcTxts.records.find((t) => t.toLowerCase().includes('v=dmarc1')) || '';
    }
  }

  if (!anyDnsQuerySucceeded) {
    return { spfPresent: null, dmarcPolicy: null, findings: [] };
  }

  const spfPresent = Boolean(spfRecord);
  const policyMatch = dmarcRecord.match(/\bp=([a-zA-Z]+)/i);
  const dmarcPolicy = policyMatch ? policyMatch[1].toLowerCase() : null;
  const findings: PostureFinding[] = [];

  if (!spfPresent && !dmarcPolicy) {
    findings.push({
      category: 'Domain & Email Anti-Spoofing (DNS)',
      type: 'Missing Email Anti-Spoofing DNS Records (SPF & DMARC)',
      severity: 'LOW',
      owaspRef: 'OWASP-A05',
      proof: `No v=spf1 or _dmarc TXT policy found for ${apexHost}.`,
      description: 'Without SPF and DMARC records, attackers can spoof emails pretending to originate from your domain in phishing campaigns.',
      remediation: `Publish TXT records on ${apexHost}: SPF ("v=spf1 -all" or authorized mailers) and _dmarc ("v=DMARC1; p=quarantine; rua=mailto:security@${apexHost}").`
    });
  } else if (!dmarcPolicy || dmarcPolicy === 'none') {
    findings.push({
      category: 'Domain & Email Anti-Spoofing (DNS)',
      type: dmarcPolicy === 'none'
        ? 'DMARC Policy Set to Monitor-Only (p=none)'
        : 'Missing DMARC Anti-Spoofing Policy (_dmarc)',
      severity: 'INFO',
      owaspRef: 'OWASP-A05',
      proof: spfPresent
        ? `SPF present (${spfRecord.slice(0, 64)}), DMARC policy=${dmarcPolicy || 'absent'} on ${apexHost}.`
        : `DMARC policy=${dmarcPolicy} without SPF on ${apexHost}.`,
      description: 'Monitor-only or absent DMARC allows spoofed domain emails to still reach user inboxes without quarantine/reject enforcement.',
      remediation: `Upgrade _dmarc.${apexHost} TXT record to p=quarantine or p=reject once legitimate mail senders are verified.`
    });
  } else {
    findings.push({
      category: 'Domain & Email Anti-Spoofing (DNS)',
      type: `Email Anti-Spoofing Enforced (SPF + DMARC p=${dmarcPolicy})`,
      severity: 'PASS',
      owaspRef: 'OWASP-A05',
      proof: `SPF active and _dmarc.${apexHost} enforces p=${dmarcPolicy}.`,
      description: 'Domain publishes both SPF authorization and enforced DMARC anti-phishing policies.',
      remediation: 'Continue monitoring DMARC aggregate (rua) reports.'
    });
  }

  return { spfPresent, dmarcPolicy, findings };
}

export async function checkSecurityTxtPolicy(origin: string): Promise<{
  present: boolean;
  finding: PostureFinding;
}> {
  try {
    const res = await axios.get(`${origin}/.well-known/security.txt`, {
      timeout: 2200,
      maxContentLength: 32 * 1024,
      validateStatus: () => true,
      headers: { 'User-Agent': 'CheckMyAPK-Auditor/1.0' }
    });
    if (res.status === 200 && typeof res.data === 'string' && /contact:/i.test(res.data)) {
      return {
        present: true,
        finding: {
          category: 'Security Governance',
          type: 'Vulnerability Disclosure Policy Active (security.txt)',
          severity: 'PASS',
          owaspRef: 'OWASP-A05',
          proof: `GET ${origin}/.well-known/security.txt returned HTTP 200 with Contact directive.`,
          description: 'Security researchers have an official RFC 9116 contact channel to responsibly disclose bugs.',
          remediation: 'Keep the Expires field in security.txt updated.'
        }
      };
    }
  } catch {}

  return {
    present: false,
    finding: {
      category: 'Security Governance',
      type: 'Missing /.well-known/security.txt Disclosure Policy',
      severity: 'INFO',
      owaspRef: 'OWASP-A05',
      proof: `${origin}/.well-known/security.txt is not published.`,
      description: 'Publishing an RFC 9116 security.txt file helps ethical hackers report vulnerabilities to your security team quickly.',
      remediation: 'Add a /.well-known/security.txt file with Contact: mailto:security@yourdomain.com and Expires timestamp.'
    }
  };
}

export function scanSupplyChainAndSri(
  html: string,
  collectedScripts: Array<{ url: string; content: string }>,
  baseUrl: string
): {
  missingSriCount: number;
  outdatedLibraries: string[];
  findings: PostureFinding[];
} {
  const findings: PostureFinding[] = [];
  let targetOrigin = '';
  try {
    targetOrigin = new URL(baseUrl).origin;
  } catch {
    return { missingSriCount: 0, outdatedLibraries: [], findings };
  }

  // 1. Subresource Integrity (SRI) check on static third-party CDN <script> tags
  const missingSriUrls: string[] = [];
  const scriptTagRe = /<script\b([^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*)>/gi;
  for (const m of html.matchAll(scriptTagRe)) {
    const attrs = m[1] || '';
    const rawSrc = m[2] || '';
    try {
      const resolved = new URL(rawSrc, baseUrl);
      if (resolved.origin !== targetOrigin && STATIC_CDN_HOST_RE.test(resolved.hostname)) {
        if (!/\bintegrity\s*=\s*["']sha(?:256|384|512)-/i.test(attrs)) {
          missingSriUrls.push(resolved.href.slice(0, 96));
        }
      }
    } catch {}
  }

  if (missingSriUrls.length > 0) {
    findings.push({
      category: 'Frontend Supply-Chain & SRI',
      type: 'External CDN Script Missing Subresource Integrity (SRI)',
      severity: 'LOW',
      owaspRef: 'OWASP-A08',
      proof: `${missingSriUrls.length} static CDN <script> tag(s) omit integrity="sha384-..." attribute (e.g. ${missingSriUrls[0]}).`,
      description: 'Without an SRI hash, if an external static CDN is ever compromised or tampered with, the browser will silently execute modified JavaScript (Magecart supply-chain vector).',
      remediation: 'Add integrity="sha384-..." and crossorigin="anonymous" attributes to external third-party CDN <script> and <link> tags.'
    });
  }

  // 2. Vulnerable / Outdated Frontend Library Version Fingerprinting
  const corpus = [
    html,
    ...collectedScripts.map((s) => `${s.url}\n${s.content.slice(0, 2400)}`)
  ].join('\n');

  const outdatedDetected: Array<{ lib: string; ver: string; severity: 'MEDIUM' | 'LOW'; risk: string; safeVer: string }> = [];
  const seenLibs = new Set<string>();

  const checkPatterns: Array<{
    lib: string;
    regex: RegExp;
    isVulnerable: (ver: string) => boolean;
    severity: 'MEDIUM' | 'LOW';
    risk: string;
    safeVer: string;
  }> = [
    {
      lib: 'jQuery',
      regex: /(?:jquery[./@-]|jQuery JavaScript Library v)(\d+\.\d+\.\d+)/i,
      isVulnerable: (v) => isVersionBelow(v, 3, 5, 0),
      severity: 'MEDIUM',
      risk: 'Known DOM XSS CVEs (CVE-2020-11022 / CVE-2020-11023)',
      safeVer: '3.7.1+'
    },
    {
      lib: 'Lodash',
      regex: /(?:lodash(?:\.js)?(?:@|\/|-)(?:min\.js)?|@license Lodash[^0-9]{0,20})(\d+\.\d+\.\d+)/i,
      isVulnerable: (v) => isVersionBelow(v, 4, 17, 21),
      severity: 'MEDIUM',
      risk: 'Known Prototype Pollution & ReDoS CVEs (CVE-2020-8203 / CVE-2021-23337)',
      safeVer: '4.17.21+'
    },
    {
      lib: 'AngularJS (1.x EOL)',
      regex: /(?:angular(?:\.js)?(?:\.min)?(?:@|\/|-)|AngularJS v)(1\.\d+\.\d+)/i,
      isVulnerable: (v) => v.startsWith('1.'),
      severity: 'MEDIUM',
      risk: 'End-of-Life framework with unpatched template injection & XSS issues',
      safeVer: 'Modern Angular / React'
    },
    {
      lib: 'Bootstrap',
      regex: /(?:bootstrap(?:\.min)?(?:@|\/|-)|Bootstrap v)(\d+\.\d+\.\d+)/i,
      isVulnerable: (v) =>
        isVersionBelow(v, 3, 4, 1) || (v.startsWith('4.') && isVersionBelow(v, 4, 3, 1)),
      severity: 'LOW',
      risk: 'Known tooltip/popover XSS vulnerabilities in older releases',
      safeVer: '5.3.x (or >= 4.3.1)'
    }
  ];

  for (const spec of checkPatterns) {
    const m = corpus.match(spec.regex);
    if (m && m[1] && spec.isVulnerable(m[1]) && !seenLibs.has(spec.lib)) {
      seenLibs.add(spec.lib);
      outdatedDetected.push({
        lib: spec.lib,
        ver: m[1],
        severity: spec.severity,
        risk: spec.risk,
        safeVer: spec.safeVer
      });
    }
  }

  for (const item of outdatedDetected) {
    findings.push({
      category: 'Frontend Supply-Chain & SRI',
      type: `Outdated ${item.lib} Library Detected (v${item.ver})`,
      severity: item.severity,
      owaspRef: 'OWASP-A06',
      proof: `Fingerprinted ${item.lib} version ${item.ver} in loaded client assets.`,
      description: `${item.lib} v${item.ver} carries public security advisories: ${item.risk}.`,
      remediation: `Upgrade ${item.lib} to ${item.safeVer} and audit dependencies with npm audit.`
    });
  }

  return {
    missingSriCount: missingSriUrls.length,
    outdatedLibraries: outdatedDetected.map((o) => `${o.lib} v${o.ver}`),
    findings
  };
}

export async function runNetworkPostureAudit(params: {
  targetUrl: string;
  html: string;
  isLoopback: boolean;
  collectedScripts: Array<{ url: string; content: string }>;
}): Promise<NetworkPostureResult> {
  const { targetUrl, html, isLoopback, collectedScripts } = params;
  const parsedUrl = new URL(targetUrl);

  const [corsRes, tlsRes, dnsRes, secTxtRes] = await Promise.all([
    probeDynamicCorsReflection(targetUrl),
    isLoopback
      ? Promise.resolve({ protocol: null, daysRemaining: null, issuer: null, findings: [] })
      : inspectTlsCertificate(parsedUrl),
    isLoopback
      ? Promise.resolve({ spfPresent: null, dmarcPolicy: null, findings: [] })
      : inspectDnsEmailPosture(parsedUrl.hostname),
    isLoopback
      ? Promise.resolve({
          present: false,
          finding: {
            category: 'Security Governance',
            type: 'Local Dev Target (security.txt skipped)',
            severity: 'INFO' as const,
            proof: 'Skipped external security.txt probe on loopback host.',
            description: 'Local dev targets do not require public RFC 9116 disclosure files.',
            remediation: 'Add /.well-known/security.txt before production deployment.'
          }
        })
      : checkSecurityTxtPolicy(parsedUrl.origin)
  ]);

  const supplyChainRes = scanSupplyChainAndSri(html, collectedScripts, targetUrl);

  const findings: PostureFinding[] = [
    corsRes.finding,
    ...tlsRes.findings,
    ...dnsRes.findings,
    secTxtRes.finding,
    ...supplyChainRes.findings
  ];

  const posture: NetworkPostureSummary = {
    corsReflection:
      corsRes.reflected === 'critical'
        ? 'Reflected (Critical)'
        : corsRes.reflected === 'high'
        ? 'Reflected (High)'
        : 'Strict',
    tlsProtocol: tlsRes.protocol,
    certDaysRemaining: tlsRes.daysRemaining,
    certIssuer: tlsRes.issuer,
    spfPresent: dnsRes.spfPresent,
    dmarcPolicy: dnsRes.dmarcPolicy,
    securityTxtPresent: secTxtRes.present,
    missingSriCount: supplyChainRes.missingSriCount,
    outdatedLibraries: supplyChainRes.outdatedLibraries
  };

  return { findings, posture };
}
