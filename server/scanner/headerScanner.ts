export interface HeaderFinding {
  type: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'PASS';
  proof: string;
  description: string;
  remediation: string;
  owaspRef?: string;
}

function splitSetCookieValues(rawSetCookie: any): string[] {
  if (Array.isArray(rawSetCookie)) {
    return rawSetCookie.map((c) => String(c).trim()).filter(Boolean);
  }
  const str = String(rawSetCookie || '').trim();
  if (!str) return [];
  // Split comma-joined Set-Cookie headers only when followed by "<cookieName>=", preserving Expires=Thu, 01 Jan...
  return str
    .split(/,\s*(?=[!#$%&'*+\-.^_`|~0-9A-Za-z]+=)/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function scanSecurityHeaders(headers: Record<string, any>, options?: { html?: string }): HeaderFinding[] {
  const findings: HeaderFinding[] = [];
  const normalized: Record<string, string> = {};

  for (const k of Object.keys(headers)) {
    normalized[k.toLowerCase()] = Array.isArray(headers[k]) ? headers[k].join('\n') : String(headers[k]);
  }

  const enforcedCsp = normalized['content-security-policy'] || '';
  const reportOnlyCsp = normalized['content-security-policy-report-only'] || '';
  const metaCspMatch = options?.html
    ? options.html.match(/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/i)
    : null;

  // 1. Content-Security-Policy (CSP) — check enforced header, <meta>, and Report-Only mode
  if (enforcedCsp || metaCspMatch) {
    const proofSource = enforcedCsp ? enforcedCsp.slice(0, 72) : metaCspMatch![0].slice(0, 72);
    findings.push({
      type: 'Content-Security-Policy (CSP) Active',
      severity: 'PASS',
      owaspRef: 'OWASP-A05',
      proof: `${proofSource}...`,
      description: 'Server provides an enforced Content-Security-Policy restricting unauthorized script executions.',
      remediation: 'Keep your CSP directives updated and minimize unsafe-inline usage.'
    });
  } else if (reportOnlyCsp) {
    findings.push({
      type: 'Content-Security-Policy Running in Report-Only Mode',
      severity: 'INFO',
      owaspRef: 'OWASP-A05',
      proof: `Content-Security-Policy-Report-Only: ${reportOnlyCsp.slice(0, 72)}...`,
      description: 'A Content-Security-Policy-Report-Only header is present, meaning violations are monitored without blocking script execution yet.',
      remediation: 'Once violation telemetry looks clean, promote Content-Security-Policy-Report-Only to enforced Content-Security-Policy.'
    });
  } else {
    findings.push({
      type: 'Missing Content-Security-Policy (CSP)',
      severity: 'MEDIUM',
      owaspRef: 'OWASP-A05',
      proof: 'Header "Content-Security-Policy" and Report-Only policy are absent in server response.',
      description: 'Without a CSP header, malicious XSS payloads or third-party script injections can execute unchecked in the user browser.',
      remediation: "Set a strong CSP header, e.g. Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';"
    });
  }

  // 2. Strict-Transport-Security (HSTS)
  if (!normalized['strict-transport-security']) {
    findings.push({
      type: 'Missing Strict-Transport-Security (HSTS)',
      severity: 'LOW',
      owaspRef: 'OWASP-A02',
      proof: 'Header "Strict-Transport-Security" not found.',
      description: 'HSTS ensures browsers only connect over secure HTTPS, preventing SSL-stripping and man-in-the-middle attacks.',
      remediation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
    });
  }

  // 3. X-Frame-Options (Clickjacking)
  if (!normalized['x-frame-options'] && !normalized['content-security-policy']?.includes('frame-ancestors')) {
    findings.push({
      type: 'Missing Clickjacking Protection (X-Frame-Options)',
      severity: 'MEDIUM',
      owaspRef: 'OWASP-A05',
      proof: 'No X-Frame-Options or frame-ancestors directive present.',
      description: 'An attacker can frame your application inside an invisible iframe on a phishing website to hijack user clicks and actions.',
      remediation: 'Set header: X-Frame-Options: SAMEORIGIN (or DENY)'
    });
  }

  // 4. Insecure CORS Wildcard Check
  const corsOrigin = normalized['access-control-allow-origin'];
  const corsCreds = normalized['access-control-allow-credentials'];
  if (corsOrigin === '*' && corsCreds === 'true') {
    findings.push({
      type: 'Critical Insecure CORS Configuration',
      severity: 'HIGH',
      owaspRef: 'OWASP-A01',
      proof: 'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true',
      description: 'Any rogue website on the internet can make authenticated API requests on behalf of logged-in users.',
      remediation: 'Specify explicit trusted origins in Access-Control-Allow-Origin instead of wildcard *.'
    });
  } else if (corsOrigin === '*') {
    findings.push({
      type: 'Permissive CORS Wildcard (*)',
      severity: 'LOW',
      owaspRef: 'OWASP-A01',
      proof: 'Access-Control-Allow-Origin: *',
      description: 'API endpoints can be requested by any external domain.',
      remediation: 'If your API contains private user data, whitelist specific client domains.'
    });
  }

  // 5. X-Content-Type-Options
  if (!String(normalized['x-content-type-options'] || '').toLowerCase().includes('nosniff')) {
    findings.push({
      type: 'Missing X-Content-Type-Options',
      severity: 'LOW',
      proof: 'Header "X-Content-Type-Options: nosniff" is missing.',
      description: 'Prevents MIME-type sniffing where browsers execute uploaded images or text files as executable JavaScript.',
      remediation: 'Set header: X-Content-Type-Options: nosniff',
      owaspRef: 'OWASP-A05'
    });
  }

  // 6. Insecure Set-Cookie Flags (parse comma-joined cookies accurately & distinguish __Secure-/preference cookies)
  const rawSetCookie = headers['set-cookie'];
  if (rawSetCookie) {
    const cookies = splitSetCookieValues(rawSetCookie);
    const AUTH_COOKIE_RE = /(?:^__Host-|session|sess|sid|auth|token|jwt|refresh|login|passwd|xsrf|csrf)/i;
    const TELEMETRY_COOKIE_RE = /^(?:__Secure-(?:STRP|ENID|1PSID|3PSID|PAPISID)|SEARCH_SAMESITE|AEC|NID|SOCS|CONSENT|PREF|OTZ|UULE|DV|LANG|LOCALE|THEME|_ga|_gid|_fbp|_gcl)/i;

    const authWeak: Array<{ name: string; missing: string[] }> = [];
    const prefNonAuth: Array<{ name: string; missing: string[] }> = [];
    const clientReadableSecure: string[] = [];

    for (const raw of cookies) {
      const segments = raw.split(';').map((s) => s.trim());
      const nameVal = segments[0] || '';
      const eqIdx = nameVal.indexOf('=');
      const cookieName = (eqIdx > 0 ? nameVal.slice(0, eqIdx) : nameVal).trim();
      if (!cookieName) continue;

      const attrSet = new Set(segments.slice(1).map((s) => s.toLowerCase()));
      const isSecurePrefix = /^__(?:Secure|Host)-/i.test(cookieName);
      const hasSecure = attrSet.has('secure') || isSecurePrefix;
      const hasHttpOnly = attrSet.has('httponly');

      const missing: string[] = [];
      if (!hasSecure) missing.push('Secure');
      if (!hasHttpOnly) missing.push('HttpOnly');
      if (missing.length === 0) continue;

      const isExplicitAuth = AUTH_COOKIE_RE.test(cookieName);
      const isPreferenceOrTelemetry = TELEMETRY_COOKIE_RE.test(cookieName);

      if (isPreferenceOrTelemetry && !isExplicitAuth) {
        prefNonAuth.push({ name: cookieName.slice(0, 48), missing });
      } else if (!hasSecure || isExplicitAuth) {
        authWeak.push({ name: cookieName.slice(0, 48), missing });
      } else {
        // Non-auth cookie with Secure/__Secure- present, intentionally readable by JS
        clientReadableSecure.push(cookieName.slice(0, 48));
      }
    }

    if (authWeak.length > 0) {
      const sample = authWeak[0];
      findings.push({
        type: `Insecure Session Cookie Flags (Missing ${sample.missing.join(' & ')})`,
        severity: 'MEDIUM',
        proof: `Cookie "${sample.name}" missing ${sample.missing.join(' and ')} flag(s) (${authWeak.length} cookie(s) checked).`,
        description: 'Cookies lacking HttpOnly can be read by XSS scripts, while cookies lacking Secure can be transmitted over cleartext HTTP.',
        remediation: 'Set sensitive/session cookies with HttpOnly; Secure; SameSite=Lax (or Strict).',
        owaspRef: 'OWASP-A07'
      });
    } else if (prefNonAuth.length > 0) {
      findings.push({
        type: `Non-Auth Preference Cookie Detected (${prefNonAuth[0].name})`,
        severity: 'INFO',
        proof: `Preference/telemetry cookie(s) "${prefNonAuth.map(p => p.name).slice(0, 3).join(', ')}" omit ${prefNonAuth[0].missing.join(' / ')} — typical for UI/localization preferences rather than auth sessions.`,
        description: 'Non-authentication preference cookies do not expose user credentials, though sensitive cookies should always enforce Secure + HttpOnly.',
        remediation: 'Confirm these cookies store zero PII/session tokens; add Secure flag where browser compatibility permits.',
        owaspRef: 'OWASP-A07'
      });
    } else if (clientReadableSecure.length > 0) {
      findings.push({
        type: 'Client-Readable Secure Cookies Present (No HttpOnly)',
        severity: 'INFO',
        proof: `Cookies "${clientReadableSecure.slice(0, 3).join(', ')}" carry Secure/__Secure- transport protection without HttpOnly (common for non-session client/CSRF state).`,
        description: 'Transport encryption (Secure) is active, though JavaScript can read these non-session cookies.',
        remediation: 'If any of these cookies store authentication credentials or session tokens, add the HttpOnly attribute.',
        owaspRef: 'OWASP-A07'
      });
    }
  }

  return findings;
}

