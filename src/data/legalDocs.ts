export type LegalDocId = 'privacy' | 'terms' | 'refund';

export interface LegalSection {
  title: string;
  body: string;
}

export interface LegalDocument {
  id: LegalDocId;
  title: string;
  subtitle: string;
  effectiveDate: string;
  badge: string;
  sections: LegalSection[];
}

export const PRIVACY_POLICY_DOC: LegalDocument = {
  id: 'privacy',
  title: 'Privacy Policy — CheckMyAPK.com',
  subtitle: 'Zero-Retention Security Architecture & Workspace Data Practices',
  effectiveDate: 'November 12, 2026',
  badge: 'Zero-Retention RAM',
  sections: [
    {
      title: '1. Zero-Retention APK & Artifact Processing',
      body: 'Uploaded Android .apk files remain strictly inside volatile server memory buffers during manifest (AndroidBinaryXML), classes*.dex, native .so, and resource inspection. CheckMyAPK never writes your APK binaries or extracted application code to persistent disk storage, never shares builds with third parties, and releases memory buffers as soon as your audit report is produced.',
    },
    {
      title: '2. Account & Authentication Data We Store',
      body: 'When you create an account or sign in via Email/Password or Google OAuth (powered by Firebase Authentication), we store only your display name, email address, cryptographic password hash (salted scrypt for email sign-ins) or Google avatar URL, selected plan tier, daily scan counter, personal Workspace API token, and your latest 20 audit score summaries (target name, mode, score, grade, critical count, and timestamp).',
    },
    {
      title: '3. Same-Origin Credentials & Web Probe Privacy',
      body: 'If you supply optional Bearer JWT headers or Session Cookies for authenticated Website & API audits, those credentials are transmitted strictly to the target origin over the live scan request and are never logged, saved to disk, or persisted in scan history.',
    },
    {
      title: '4. Cookies, Local Storage & Session Security',
      body: 'CheckMyAPK sets a single signed HMAC-SHA256 HttpOnly, SameSite=Lax session cookie (cma_session, 7-day expiry) solely to keep you signed in securely. Your browser localStorage may store non-sensitive UI state such as your Dark/Light theme preference (checkmyapk_theme) and local score delta comparisons.',
    },
    {
      title: '5. AI Remediation & Third-Party Services',
      body: 'When AI threat synthesis is enabled, only sanitized vulnerability metadata (severity, rule category, and redacted technical proof) is evaluated to generate framework-specific fix patches—never full uploaded APK files or private passwords. We do not sell user data or serve behavioral ad trackers.',
    },
    {
      title: '6. Data Control, Token Rotation & Account Deletion',
      body: 'You may export reports (PDF, JSON, Markdown) locally, rotate your personal Workspace API token inside Account Settings at any time, or request complete account deletion by contacting checkmyapk.com@gmail.com.',
    },
  ],
};

export const TERMS_OF_SERVICE_DOC: LegalDocument = {
  id: 'terms',
  title: 'Terms of Service — CheckMyAPK.com',
  subtitle: 'Authorized Security Assessment Rules, Disclaimers & Acceptable Use',
  effectiveDate: 'November 12, 2026',
  badge: 'v2.0',
  sections: [
    {
      title: '1. Authorized Security Testing Only (Strict Rule)',
      body: 'By using CheckMyAPK.com, you represent and warrant that you own the Android APK, domain, or API endpoint being scanned, or hold explicit written authorization from its owner. Scanning unauthorized third-party systems, bypassing network protections, or weaponizing findings is strictly prohibited and will result in immediate access revocation.',
    },
    {
      title: '2. Domain Ownership & Rate-Burst Verification',
      body: 'Unverified public web targets are restricted to a gentle 4-request rate-limit probe so live websites are never disrupted. Running the full 15-request Denial-of-Wallet burst test requires verifying domain control using CheckMyAPK’s DNS TXT record or HTML Meta Tag challenge.',
    },
    {
      title: '3. Account Credentials & Workspace API Tokens',
      body: 'You are responsible for safeguarding your login credentials and personal Workspace API token (cma_live_*). Do not commit personal API tokens to public repositories; if a token is exposed, rotate it immediately from your Account Dashboard.',
    },
    {
      title: '4. Automated Findings & No-Warranty Disclaimer',
      body: 'Audit reports combine deterministic checks (Confirmed) with static pattern matching (Heuristic • Verify Context). All scores, compliance tags, and remediation code patches are provided "AS IS" to assist engineering QA and Play Store reviews—they do not constitute legal certification (SOC 2, ISO 27001, PCI-DSS) or replace an authorized manual penetration test.',
    },
    {
      title: '5. Subscription Plans, Quotas & Billing Availability',
      body: 'Starter accounts allow up to 2 unique apps/sites per month (max 3 scans per target, 25MB APK). Pro Security allows 15 unique apps/sites per month with unlimited fair-use re-scans (75MB APK), and Team & Agency allows 60 unique apps/sites per month with unlimited fair-use re-scans (150MB APK, CI/CD API tokens, and priority queue). CheckMyAPK may adjust fair-use safeguards to preserve platform stability.',
    },
    {
      title: '6. Limitation of Liability & Contact',
      body: 'To the maximum extent permitted by law, CheckMyAPK.com is not liable for indirect damages, downtime, or target misconfigurations arising from scan results or remediation changes applied without engineer review. Legal and abuse notices may be sent to checkmyapk.com@gmail.com.',
    },
  ],
};

export const REFUND_POLICY_DOC: LegalDocument = {
  id: 'refund',
  title: 'Refund & Cancellation Policy — CheckMyAPK.com',
  subtitle: 'Subscription Cancellation Rules, 7-Day Refund Eligibility & Billing Support',
  effectiveDate: 'November 12, 2026',
  badge: 'Cancel Anytime',
  sections: [
    {
      title: '1. Cancel Anytime (No Cancellation Fees)',
      body: 'You may cancel your Pro Security or Team & Agency subscription at any time from your Account Billing Settings or payment portal before the next renewal date. Upon cancellation, you will not be charged again, and all paid features remain active until the end of your current monthly or annual billing cycle.',
    },
    {
      title: '2. 7-Day First-Purchase Refund Window',
      body: 'If you are dissatisfied with a first-time paid subscription due to an unresolved platform malfunction or unmet core capability, you may request a full refund within 7 calendar days of the initial payment—provided the account has not been used for high-volume automated commercial scanning or bulk API extraction during that window.',
    },
    {
      title: '3. Duplicate or Accidental Billing Errors',
      body: 'Any verified duplicate charge, double invoice, or technical billing error caused by payment gateway retry issues is eligible for an immediate 100% refund regardless of usage.',
    },
    {
      title: '4. Non-Refundable Situations & Abuse Protection',
      body: 'Partial mid-cycle prorated refunds are not issued for unused days after cancellation, nor for renewal cycles where cancellation was not completed prior to renewal (except within 48 hours if zero scans occurred in the new cycle). Accounts suspended or terminated for violating Authorized Security Testing rules or abusing Workspace API tokens are not eligible for refunds.',
    },
    {
      title: '5. Refund Processing Timeline',
      body: 'Approved refunds are issued back to your original payment method through our merchant-of-record payment partner (such as Dodo Payments). Depending on your card issuer or bank, funds typically appear within 5–10 business days.',
    },
    {
      title: '6. How to Request a Refund or Billing Help',
      body: 'Email checkmyapk.com@gmail.com from your registered account address with your Payment/Invoice ID and a short summary of the issue. Billing and refund requests are reviewed by our support desk within 24 hours.',
    },
  ],
};

export const LEGAL_DOCS_BY_ID: Record<LegalDocId, LegalDocument> = {
  privacy: PRIVACY_POLICY_DOC,
  terms: TERMS_OF_SERVICE_DOC,
  refund: REFUND_POLICY_DOC,
};

export const LEGAL_DOC_PATHS: Record<LegalDocId, string> = {
  privacy: '/privacy-policy',
  terms: '/terms',
  refund: '/refund-policy',
};

export function resolveLegalDocFromUrl(pathname: string, search: string): LegalDocId | null {
  const normalizedPath = pathname.replace(/\/+$/, '').toLowerCase();
  if (normalizedPath === '/privacy' || normalizedPath === '/privacy-policy') return 'privacy';
  if (normalizedPath === '/terms' || normalizedPath === '/terms-of-service') return 'terms';
  if (
    normalizedPath === '/refund' ||
    normalizedPath === '/refund-policy' ||
    normalizedPath === '/cancellation-policy'
  ) {
    return 'refund';
  }
  const param = new URLSearchParams(search).get('legal')?.toLowerCase();
  if (param === 'privacy' || param === 'terms' || param === 'refund') return param;
  return null;
}

