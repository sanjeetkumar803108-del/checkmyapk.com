import axios from 'axios';

export interface DbProbeFinding {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'PASS' | 'INFO';
  proof: string;
  description: string;
  remediation: string;
  owaspRef?: string;
}

export async function probeDatabaseSecurity(html: string, scriptsContent: string): Promise<DbProbeFinding[]> {
  const findings: DbProbeFinding[] = [];
  const combined = `${html}\n${scriptsContent}`;

  // 1. Firebase Realtime Database Probes (up to 3 unique origins)
  const firebaseMatches = Array.from(
    new Set(combined.match(/https:\/\/[a-zA-Z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)/g) || [])
  ).slice(0, 3);

  await Promise.all(
    firebaseMatches.map(async (dbUrl) => {
      try {
        const probeRes = await axios.get(`${dbUrl}/.json?shallow=true`, {
          timeout: 5000,
          validateStatus: () => true
        });

        if (probeRes.status === 200 && probeRes.data !== null) {
          findings.push({
            type: 'Firebase Realtime Database Publicly Readable',
            severity: 'CRITICAL',
            proof: `Unauthenticated GET to "${dbUrl}/.json" returned HTTP 200 with data keys: ${Object.keys(probeRes.data).slice(0, 3).join(', ')}`,
            description: 'Your Firebase database rules allow anyone on the internet to read your entire database without authentication!',
            remediation: 'Go to Firebase Console -> Realtime Database -> Rules. Change ".read": true to ".read": "auth != null" or specific user UID rules.',
            owaspRef: 'OWASP-A01'
          });
        } else {
          findings.push({
            type: 'Firebase Database Rules Protected',
            severity: 'PASS',
            proof: `Unauthenticated GET to "${dbUrl}/.json" returned HTTP ${probeRes.status} (Access Denied).`,
            description: 'Firebase Realtime Database properly rejects anonymous reads.',
            remediation: 'Maintain strict owner-based security rules.',
            owaspRef: 'OWASP-A01'
          });
        }
      } catch {
        // Network blocked or DB does not exist
      }
    })
  );

  // 2. Supabase PostgREST Probes (up to 3 unique origins, attaching discovered anon JWT apikey when present)
  const supabaseUrls = Array.from(
    new Set(combined.match(/https:\/\/[a-zA-Z0-9-]+\.supabase\.co/g) || [])
  ).slice(0, 3);
  const candidateJwts = Array.from(
    new Set(combined.match(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g) || [])
  ).slice(0, 5);

  await Promise.all(
    supabaseUrls.map(async (supaUrl) => {
      try {
        const urlIdx = combined.indexOf(supaUrl);
        const nearbyText = urlIdx >= 0 ? combined.slice(Math.max(0, urlIdx - 600), urlIdx + 800) : '';
        const nearbyJwt = nearbyText.match(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/)?.[0];
        const anonKey = nearbyJwt || candidateJwts[0];
        const reqHeaders: Record<string, string> = anonKey
          ? { apikey: anonKey, Authorization: `Bearer ${anonKey}` }
          : {};

        const probeRes = await axios.get(`${supaUrl}/rest/v1/`, {
          timeout: 5000,
          validateStatus: () => true,
          headers: reqHeaders
        });

        if (probeRes.status === 200 && probeRes.data && typeof probeRes.data === 'object') {
          const exposedTables = probeRes.data.paths
            ? Object.keys(probeRes.data.paths).filter((p) => p !== '/').slice(0, 4)
            : [];
          if (exposedTables.length > 0 || !anonKey) {
            findings.push({
              type: 'Supabase PostgREST Schema Exposed',
              severity: 'HIGH',
              proof: `Request to ${supaUrl}/rest/v1/${anonKey ? ' (with client anon apikey)' : ''} returned HTTP 200 exposing table schema${exposedTables.length > 0 ? `: ${exposedTables.join(', ')}` : '.'}`,
              description: 'Exposed PostgREST endpoints without strict Row Level Security (RLS) allow visitors to inspect tables and potentially query or modify rows.',
              remediation: 'Ensure Row Level Security (RLS) is ENABLED with strict auth.uid() policies on every PostgreSQL table in Supabase Dashboard.',
              owaspRef: 'OWASP-A01'
            });
          }
        }
      } catch {}
    })
  );

  // 3. Sensitive LocalStorage / Session Keys
  const lsTokenMatch = combined.match(/localStorage\.setItem\(\s*["'](?:token|auth_token|jwt|jwt_token|access_token|id_token)["']/i);
  if (lsTokenMatch) {
    findings.push({
      type: 'JWT / Auth Token in LocalStorage',
      severity: 'HIGH',
      proof: `Detected sensitive auth token storage in browser localStorage (${lsTokenMatch[0]}...).`,
      description: 'Storing sensitive authentication tokens in localStorage makes them vulnerable to exfiltration via any Cross-Site Scripting (XSS) vulnerability.',
      remediation: 'Store authentication session tokens in HttpOnly, Secure, SameSite=Strict cookies instead of localStorage.',
      owaspRef: 'OWASP-A07'
    });
  }

  return findings;
}

