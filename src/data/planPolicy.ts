import type { AccountPlan } from '../types/account';

export interface PlanPolicy {
  id: AccountPlan;
  name: string;
  monthlyPriceUsd: number;
  annualMonthlyPriceUsd: number;
  monthlyUniqueTargets: number;
  maxRescansPerTarget: number | null; // null = unlimited re-scans on tracked targets
  dailySafetyScanCap: number;
  maxApkMb: number;
  priorityQueue: boolean;
  features: {
    unlimitedRescans: boolean;
    scoreDelta: boolean;
    aiFixDoctor: boolean;
    exports: boolean;
    authenticatedWebScan: boolean;
    burst15Req: boolean;
    apiTokenAccess: boolean;
  };
}

export const PLAN_POLICIES: Record<AccountPlan, PlanPolicy> = {
  free: {
    id: 'free',
    name: 'Starter',
    monthlyPriceUsd: 0,
    annualMonthlyPriceUsd: 0,
    monthlyUniqueTargets: 2,
    maxRescansPerTarget: 3,
    dailySafetyScanCap: 10,
    maxApkMb: 25,
    priorityQueue: false,
    features: {
      unlimitedRescans: false,
      scoreDelta: false,
      aiFixDoctor: false,
      exports: false,
      authenticatedWebScan: false,
      burst15Req: false,
      apiTokenAccess: false,
    },
  },
  pro: {
    id: 'pro',
    name: 'Pro Security',
    monthlyPriceUsd: 15,
    annualMonthlyPriceUsd: 12,
    monthlyUniqueTargets: 15,
    maxRescansPerTarget: null,
    dailySafetyScanCap: 60,
    maxApkMb: 75,
    priorityQueue: false,
    features: {
      unlimitedRescans: true,
      scoreDelta: true,
      aiFixDoctor: true,
      exports: true,
      authenticatedWebScan: true,
      burst15Req: true,
      apiTokenAccess: false,
    },
  },
  agency: {
    id: 'agency',
    name: 'Team & Agency',
    monthlyPriceUsd: 79,
    annualMonthlyPriceUsd: 49,
    monthlyUniqueTargets: 60,
    maxRescansPerTarget: null,
    dailySafetyScanCap: 150,
    maxApkMb: 150,
    priorityQueue: true,
    features: {
      unlimitedRescans: true,
      scoreDelta: true,
      aiFixDoctor: true,
      exports: true,
      authenticatedWebScan: true,
      burst15Req: true,
      apiTokenAccess: true,
    },
  },
};

export function getPlanPolicy(plan?: AccountPlan | null): PlanPolicy {
  if (plan === 'pro') return PLAN_POLICIES.pro;
  if (plan === 'agency') return PLAN_POLICIES.agency;
  return PLAN_POLICIES.free;
}

export function normalizeScanTargetKey(mode: 'apk' | 'web', rawTarget: string): string {
  const cleaned = String(rawTarget || '').trim();
  if (mode === 'web') {
    try {
      const urlStr = /^https?:\/\//i.test(cleaned) ? cleaned : `https://${cleaned}`;
      const host = new URL(urlStr).hostname.toLowerCase().replace(/^www\./, '');
      return `web:${host || 'unknown-host'}`;
    } catch {
      const host = cleaned.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].replace(/^www\./, '');
      return `web:${host || 'unknown-host'}`;
    }
  }
  const pkg = cleaned.toLowerCase().replace(/[^a-z0-9._-]/g, '_');
  return `apk:${pkg || 'unknown.package'}`;
}

export interface PlanCardDisplayMeta {
  id: AccountPlan;
  name: string;
  tagline: string;
  badge?: string;
  priceMonthly: number;
  priceAnnual: number;
  annualTotalUsd: number;
  subtitle: string;
  highlights: string[];
  highlighted?: boolean;
}

export const PLAN_DISPLAY_CARDS: PlanCardDisplayMeta[] = [
  {
    id: 'free',
    name: PLAN_POLICIES.free.name,
    tagline: 'Scan & Discover Flaws',
    priceMonthly: PLAN_POLICIES.free.monthlyPriceUsd,
    priceAnnual: PLAN_POLICIES.free.annualMonthlyPriceUsd,
    annualTotalUsd: 0,
    subtitle: `Scan & discover flaws across up to ${PLAN_POLICIES.free.monthlyUniqueTargets} unique apps or sites per month.`,
    highlights: [
      `${PLAN_POLICIES.free.monthlyUniqueTargets} unique Apps or Sites per month`,
      `Up to ${PLAN_POLICIES.free.maxRescansPerTarget} scans per target • Max ${PLAN_POLICIES.free.maxApkMb}MB APK`,
      'Score breakdown, Grade & full risk list',
      'RAM-only zero-retention APK processing',
    ],
  },
  {
    id: 'pro',
    name: PLAN_POLICIES.pro.name,
    tagline: 'Best for Solo Devs & Startups',
    badge: 'Most Popular • Beta Free',
    priceMonthly: PLAN_POLICIES.pro.monthlyPriceUsd,
    priceAnnual: PLAN_POLICIES.pro.annualMonthlyPriceUsd,
    annualTotalUsd: PLAN_POLICIES.pro.annualMonthlyPriceUsd * 12,
    subtitle: 'Fix vulnerabilities fast with Unlimited Re-scans & full AI Code Fix Doctor.',
    highlights: [
      `${PLAN_POLICIES.pro.monthlyUniqueTargets} unique Apps or Sites per month + Unlimited Re-scans`,
      `Up to ${PLAN_POLICIES.pro.maxApkMb}MB APK builds + Score Delta tracking`,
      'Full AI Code Fix Doctor & copy-paste patches',
      'Print-ready PDF, JSON, Markdown & GitHub PR exports',
      'Authenticated JWT/Cookie & verified 15-req Burst probe',
    ],
    highlighted: true,
  },
  {
    id: 'agency',
    name: PLAN_POLICIES.agency.name,
    tagline: 'Built for Studios & Security Teams',
    badge: 'CI/CD & Priority',
    priceMonthly: PLAN_POLICIES.agency.monthlyPriceUsd,
    priceAnnual: PLAN_POLICIES.agency.annualMonthlyPriceUsd,
    annualTotalUsd: PLAN_POLICIES.agency.annualMonthlyPriceUsd * 12,
    subtitle: `4x client capacity, large ${PLAN_POLICIES.agency.maxApkMb}MB APKs & Workspace CI/CD automation.`,
    highlights: [
      `${PLAN_POLICIES.agency.monthlyUniqueTargets} unique Client Apps or Sites per month + Unlimited Re-scans`,
      'Everything in Pro Security included',
      `Large APK build support up to ${PLAN_POLICIES.agency.maxApkMb}MB`,
      'Workspace CI/CD API Token (cma_live_*) & rotation',
      'Priority Async APK Worker Queue lane',
    ],
  },
];

export type ComparisonCell =
  | boolean
  | {
      text: string;
      emphasis?: 'cyan' | 'emerald' | 'purple' | 'muted';
    };

export interface ComparisonRow {
  label: string;
  detail: string;
  starter: ComparisonCell;
  pro: ComparisonCell;
  agency: ComparisonCell;
}

export interface ComparisonGroup {
  id: 'quotas' | 'engine' | 'fixes' | 'automation';
  title: string;
  rows: ComparisonRow[];
}

export const PRICING_COMPARISON_GROUPS: ComparisonGroup[] = [
  {
    id: 'quotas',
    title: 'Quotas & Upload Capacity',
    rows: [
      {
        label: 'Unique Apps / Sites per Month',
        detail: 'Tracked automatically by Android packageName or root web hostname.',
        starter: { text: `${PLAN_POLICIES.free.monthlyUniqueTargets} targets / mo` },
        pro: { text: `${PLAN_POLICIES.pro.monthlyUniqueTargets} targets / mo`, emphasis: 'cyan' },
        agency: { text: `${PLAN_POLICIES.agency.monthlyUniqueTargets} targets / mo`, emphasis: 'purple' },
      },
      {
        label: 'Same-App Re-Scans (v1 → v2 → v3)',
        detail: 'Re-audit builds of an already tracked app after fixing findings.',
        starter: { text: `Max ${PLAN_POLICIES.free.maxRescansPerTarget} / target`, emphasis: 'muted' },
        pro: { text: 'Unlimited', emphasis: 'emerald' },
        agency: { text: 'Unlimited', emphasis: 'emerald' },
      },
      {
        label: 'Max Android .APK Binary Size',
        detail: 'In-memory zero-storage unzip & DEX decompilation limit.',
        starter: { text: `${PLAN_POLICIES.free.maxApkMb} MB` },
        pro: { text: `${PLAN_POLICIES.pro.maxApkMb} MB`, emphasis: 'cyan' },
        agency: { text: `${PLAN_POLICIES.agency.maxApkMb} MB`, emphasis: 'purple' },
      },
      {
        label: 'Daily Anti-Bot Fair-Use Cap',
        detail: 'Daily automated burst safety guard against abusive script loops.',
        starter: { text: `${PLAN_POLICIES.free.dailySafetyScanCap} scans / day`, emphasis: 'muted' },
        pro: { text: `${PLAN_POLICIES.pro.dailySafetyScanCap} scans / day` },
        agency: { text: `${PLAN_POLICIES.agency.dailySafetyScanCap} scans / day` },
      },
    ],
  },
  {
    id: 'engine',
    title: 'Deep APK & Web Security Engine',
    rows: [
      {
        label: 'APK DEX, Manifest & Native .so ELF Audit',
        detail: 'OWASP MASVS checks, hardcoded keys, debuggable flags & native protections.',
        starter: PLAN_POLICIES.free.monthlyUniqueTargets > 0,
        pro: PLAN_POLICIES.pro.monthlyUniqueTargets > 0,
        agency: PLAN_POLICIES.agency.monthlyUniqueTargets > 0,
      },
      {
        label: 'Live Web TLS, Headers, CORS & JS Secret Scan',
        detail: 'AST DOM XSS sinks, exposed .env/.git, SPF/DMARC & SRI verification.',
        starter: true,
        pro: true,
        agency: true,
      },
      {
        label: 'RAM-Only Zero-Retention File Processing',
        detail: 'Uploaded binaries stay in volatile RAM buffers and never touch disk.',
        starter: true,
        pro: true,
        agency: true,
      },
      {
        label: 'Score Delta & Fixed / New Issues Diff',
        detail: 'Track +pts improvements and resolved vulnerabilities between scans.',
        starter: PLAN_POLICIES.free.features.scoreDelta,
        pro: PLAN_POLICIES.pro.features.scoreDelta,
        agency: PLAN_POLICIES.agency.features.scoreDelta,
      },
      {
        label: 'Authenticated JWT / Session Cookie Scan',
        detail: 'Forward same-origin Bearer JWT or Cookie headers to audit gated routes.',
        starter: PLAN_POLICIES.free.features.authenticatedWebScan,
        pro: PLAN_POLICIES.pro.features.authenticatedWebScan,
        agency: PLAN_POLICIES.agency.features.authenticatedWebScan,
      },
      {
        label: 'Domain Ownership Verify + 15-Req Burst',
        detail: 'DNS TXT or HTML Meta verification to test Denial-of-Wallet rate limits.',
        starter: { text: '4-req gentle only', emphasis: 'muted' },
        pro: { text: '15-req Verified Burst', emphasis: 'cyan' },
        agency: { text: '15-req Verified Burst', emphasis: 'purple' },
      },
    ],
  },
  {
    id: 'fixes',
    title: 'AI Remediation & Developer Exports',
    rows: [
      {
        label: 'Gemini AI Code Fix Doctor',
        detail: 'Deep contextual root-cause explanation and tailored remediation steps.',
        starter: PLAN_POLICIES.free.features.aiFixDoctor,
        pro: PLAN_POLICIES.pro.features.aiFixDoctor,
        agency: PLAN_POLICIES.agency.features.aiFixDoctor,
      },
      {
        label: 'Copy-Paste Framework Patches',
        detail: 'One-click code snippets for Android Studio, Gradle, Next.js, Express & Nginx.',
        starter: PLAN_POLICIES.free.features.aiFixDoctor,
        pro: PLAN_POLICIES.pro.features.aiFixDoctor,
        agency: PLAN_POLICIES.agency.features.aiFixDoctor,
      },
      {
        label: '60-Second Master Header Fix Pack',
        detail: 'Complete vercel.json, next.config.js & Helmet hardening config in one file.',
        starter: PLAN_POLICIES.free.features.aiFixDoctor,
        pro: PLAN_POLICIES.pro.features.aiFixDoctor,
        agency: PLAN_POLICIES.agency.features.aiFixDoctor,
      },
      {
        label: 'PDF, JSON, Markdown & GitHub PR Export',
        detail: 'Share Play Store review evidence or copy PR summaries for Slack/GitHub.',
        starter: PLAN_POLICIES.free.features.exports,
        pro: PLAN_POLICIES.pro.features.exports,
        agency: PLAN_POLICIES.agency.features.exports,
      },
    ],
  },
  {
    id: 'automation',
    title: 'CI/CD Automation, Queue & Support',
    rows: [
      {
        label: 'Workspace CI/CD API Token (cma_live_*)',
        detail: 'Generate and rotate scoped API keys for GitHub Actions & CI pipelines.',
        starter: PLAN_POLICIES.free.features.apiTokenAccess,
        pro: PLAN_POLICIES.pro.features.apiTokenAccess,
        agency: { text: 'Exclusive Included', emphasis: 'purple' },
      },
      {
        label: 'Priority Async APK Worker Queue',
        detail: 'Client builds jump ahead of standard queue during heavy traffic.',
        starter: PLAN_POLICIES.free.priorityQueue,
        pro: PLAN_POLICIES.pro.priorityQueue,
        agency: { text: 'Priority Lane', emphasis: 'purple' },
      },
      {
        label: 'Support & Billing Guarantee',
        detail: 'Cancel anytime before renewal • 7-day technical failure refund guarantee.',
        starter: { text: 'Standard Docs', emphasis: 'muted' },
        pro: { text: 'Priority Email' },
        agency: { text: 'Dedicated Support', emphasis: 'emerald' },
      },
    ],
  },
];

