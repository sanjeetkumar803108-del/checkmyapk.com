export interface HeaderFinding {
  type: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'PASS';
  proof: string;
  description: string;
  remediation: string;
  owaspRef?: string;
}

export function scanSecurityHeaders(headers: Record<string, any>): HeaderFinding[] {
  const findings: HeaderFinding[] = [];
  const normalized: Record<string, string> = {};

  for (const k of Object.keys(headers)) {
    normalized[k.toLowerCase()] = Array.isArray(headers[k]) ? headers[k].join('\n') : String(headers[k]);
  }

  // 1. Content-Security-Policy (CSP)
  if (!normalized['content-security-policy']) {
    findings.push({
      type: 'Missing Content-Security-Policy (CSP)',
      severity: 'MEDIUM',
      owaspRef: 'OWASP-A05',
      proof: 'Header "Content-Security-Policy" is absent in server response.',
      description: 'Without a CSP header, malicious XSS payloads or third-party script injections can execute unchecked in the user browser.',
      remediation: "Set a strong CSP header, e.g. Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';"
    });
  } else {
    findings.push({
      type: 'Content-Security-Policy (CSP) Active',
      severity: 'PASS',
      owaspRef: 'OWASP-A05',
      proof: normalized['content-security-policy'].slice(0, 60) + '...',
      description: 'Server provides a Content-Security-Policy restricting unauthorized script executions.',
      remediation: 'Keep your CSP directives updated and minimize unsafe-inline usage.'
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
  if (normalized['x-content-type-options'] !== 'nosniff') {
    findings.push({
      type: 'Missing X-Content-Type-Options',
      severity: 'LOW',
      proof: 'Header "X-Content-Type-Options: nosniff" is missing.',
      description: 'Prevents MIME-type sniffing where browsers execute uploaded images or text files as executable JavaScript.',
      remediation: 'Set header: X-Content-Type-Options: nosniff',
      owaspRef: 'OWASP-A05'
    });
  }

  // 6. Insecure Set-Cookie Flags (if server sets cookies)
  const rawSetCookie = headers['set-cookie'];
  if (rawSetCookie) {
    const cookies = Array.isArray(rawSetCookie) ? rawSetCookie : [String(rawSetCookie)];
    const weakCookies = cookies.filter(c => {
      const lc = c.toLowerCase();
      return !lc.includes('httponly') || !lc.includes('secure');
    });
    if (weakCookies.length > 0) {
      findings.push({
        type: 'Insecure Session Cookie Flags (Missing HttpOnly / Secure)',
        severity: 'MEDIUM',
        proof: `Set-Cookie missing HttpOnly or Secure attribute: ${weakCookies[0].split(';')[0]}`,
        description: 'Cookies lacking HttpOnly can be stolen via XSS, while cookies lacking Secure can be intercepted over unencrypted HTTP.',
        remediation: 'Set all auth/session cookies with HttpOnly; Secure; SameSite=Lax (or Strict).',
        owaspRef: 'OWASP-A07'
      });
    }
  }

  return findings;
}

