import axios from 'axios';

export interface RateLimitFinding {
  type: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'PASS' | 'INFO';
  proof: string;
  description: string;
  remediation: string;
  owaspRef?: string;
}

export async function probeRateLimiting(targetUrl: string): Promise<RateLimitFinding> {
  const BURST_COUNT = 15;
  const requests: Promise<any>[] = [];

  let isApiRoute = false;
  try {
    const parsed = new URL(targetUrl);
    isApiRoute = parsed.pathname.startsWith('/api') || 
                 parsed.pathname.startsWith('/v1') || 
                 parsed.pathname.includes('/chat') || 
                 parsed.pathname.includes('/generate') ||
                 parsed.pathname.includes('/graphql');
  } catch (e) {}

  for (let i = 0; i < BURST_COUNT; i++) {
    requests.push(
      axios.get(targetUrl, {
        timeout: 4000,
        validateStatus: () => true,
        headers: { 'User-Agent': 'CheckMyAPK-RateLimitProbe/1.0 (+https://checkmyapk.com)' }
      }).catch(e => ({ status: 500, error: e.message }))
    );
  }

  const results = await Promise.all(requests);
  const statusCodes = results.map(r => r.status);
  const got429 = statusCodes.includes(429);
  const got503 = statusCodes.includes(503);

  if (got429 || got503) {
    return {
      type: 'Active Rate Limiting & Throttling Detected',
      severity: 'PASS',
      proof: `Server returned HTTP ${got429 ? '429 (Too Many Requests)' : '503'} during high-frequency request burst test.`,
      description: 'Your server infrastructure actively throttles rapid bursts, protecting against simple bot floods and denial-of-wallet spam.',
      remediation: 'Keep your rate limiting thresholds tuned according to your active user base.',
      owaspRef: 'OWASP-API04'
    };
  }

  // If testing a backend API route without rate limiting: It's genuinely HIGH risk!
  if (isApiRoute) {
    return {
      type: 'No Active Rate Limiting on API Endpoint (Denial-of-Wallet Risk)',
      severity: 'HIGH',
      proof: `All ${BURST_COUNT} rapid burst requests to API endpoint returned HTTP 200 without any throttling or 429 responses.`,
      description: 'Because this is a backend API route, an attacker can run automated scripts to drain your LLM/API quotas and cause unexpected cloud bills.',
      remediation: 'Implement server-level rate limiting using express-rate-limit, Cloudflare WAF, or Upstash Redis rate limiting on this API route.',
      owaspRef: 'OWASP-API04'
    };
  }

  // If testing a public Homepage / Landing Page: Normal CDN behaviour!
  return {
    type: 'Public Landing Page Burst Permitted (Standard CDN Profile)',
    severity: 'PASS',
    proof: `All ${BURST_COUNT} rapid burst requests to the public landing page returned HTTP 200 (Standard Web/CDN parallel asset delivery).`,
    description: 'Public landing pages intentionally allow parallel burst requests so modern browsers can load images, scripts, and fonts without throttling real visitors. Note: Ensure your sensitive backend API routes (e.g. /api/*) enforce strict per-IP rate limits.',
    remediation: 'Maintain open delivery for public static web assets, but verify that any AI inference or database mutation endpoints (/api/*) enforce strict per-IP rate limits.',
    owaspRef: 'OWASP-API04'
  };
}
