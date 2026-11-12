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

  // 1. Firebase Realtime Database Probe
  const firebaseDbMatch = combined.match(/https:\/\/([a-zA-Z0-9-]+)\.(?:firebaseio\.com|firebasedatabase\.app)/);
  if (firebaseDbMatch) {
    const dbUrl = firebaseDbMatch[0];
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
    } catch (err: any) {
      // Network blocked or DB does not exist
    }
  }

  // 2. Supabase Public Probe
  const supabaseUrlMatch = combined.match(/https:\/\/([a-zA-Z0-9-]+)\.supabase\.co/);
  if (supabaseUrlMatch) {
    const supaUrl = supabaseUrlMatch[0];
    try {
      const probeRes = await axios.get(`${supaUrl}/rest/v1/`, {
        timeout: 5000,
        validateStatus: () => true
      });

      if (probeRes.status === 200) {
        findings.push({
          type: 'Supabase PostgREST Schema Exposed',
          severity: 'HIGH',
          proof: `Anonymous request to ${supaUrl}/rest/v1/ returned public table schema.`,
          description: 'Public tables without Row Level Security (RLS) can be queried and modified by any visitor.',
          remediation: 'Ensure Row Level Security (RLS) is ENABLED on every PostgreSQL table in your Supabase project dashboard.',
          owaspRef: 'OWASP-A01'
        });
      }
    } catch (e: any) {}
  }

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

