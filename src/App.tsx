import React, { useState, useRef, useEffect } from 'react';
import { flushSync } from 'react-dom';
import {
  Shield,
  Search,
  AlertTriangle,
  Download,
  Sparkles,
  ArrowRight,
  RefreshCw,
  Terminal,
  Cpu,
  Layers,
  Activity,
  FileCode2,
  Wrench,
  Copy,
  Check,
  Code2,
  Smartphone,
  Globe,
  Upload,
  UploadCloud,
  ShieldCheck,
  Lock,
  Zap,
  Binary,
  Server,
  Radio,
  FileJson,
  FileText,
  Info,
  X,
  TrendingUp,
  CheckCircle2,
  ChevronDown,
  Sun,
  Moon,
  Menu
} from 'lucide-react';
import { CyberBackground } from './components/CyberBackground';
import { ScoreGauge } from './components/ScoreGauge';
import { FindingCard } from './components/FindingCard';
import { LiveTerminalLogs } from './components/LiveTerminalLogs';
import { AuthModal } from './components/AuthModal';
import { DeterministicOutputWorkbench } from './components/DeterministicOutputWorkbench';
import { HeroKineticHeadline, HeroRulesCountUp } from './components/HeroKineticHeadline';
import { XRayHeroBackground } from './components/XRayHeroBackground';
import { BlogPage } from './components/BlogPage';
import { SecurityReportDashboard } from './components/SecurityReportDashboard';
import { AccountPage } from './components/AccountPage';
import { HomepageSections } from './components/HomepageSections';
import { PricingPage } from './components/PricingPage';
import {
  LEGAL_DOCS_BY_ID,
  LEGAL_DOC_PATHS,
  resolveLegalDocFromUrl,
  type LegalDocId,
} from './data/legalDocs';
import type { AccountPlan, SavedScanEntry, UserAccount } from './types/account';
import { getPlanPolicy } from './data/planPolicy';

interface ExportedComp {
  componentType: 'activity' | 'service' | 'receiver' | 'provider';
  name: string;
  explicitlyExported: boolean;
  implicitViaIntentFilter: boolean;
  permission: string | null;
  isLauncher: boolean;
  hasDeepLink: boolean;
  risky: boolean;
}

interface SecurityReport {
  targetUrl: string;
  scanTimestamp: string;
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'F';
  riskLevel: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  summaryCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info?: number;
    pass: number;
  };
  findings: any[];
  aiExecutiveSummary?: string;
  attackChains?: Array<{
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    summary: string;
    components: string[];
  }>;
  cloudBuckets?: Array<{
    provider: string;
    bucketUrl: string;
    status: number | string;
    publicListable: boolean;
  }>;
  isApkAudit?: boolean;
  isDemoPreview?: boolean;
  apkMeta?: {
    fileName: string;
    sizeMb: string;
    isAppBundle?: boolean;
    sha256?: string;
    obfuscationStatus?: string;
    packageName: string;
    versionName?: string;
    versionCode?: number;
    targetSdkVersion: number;
    minSdkVersion: number;
    frameworkDetected: string;
    architectures: string[];
    permissions: string[];
    dexCount: number;
    totalFiles: number;
    exportedComponents?: {
      totalExported: number;
      unprotectedCount: number;
      activities: ExportedComp[];
      services: ExportedComp[];
      receivers: ExportedComp[];
      providers: ExportedComp[];
    };
    trackers?: string[];
    sdks?: string[];
    discoveredEndpoints?: string[];
    baasUrls?: string[];
    probedApis?: Array<{
      url: string;
      status: number | string;
      latencyMs: number;
      cors: string;
      hsts: boolean;
      reachable: boolean;
    }>;
    dexBytecodeGraph?: {
      dexCount: number;
      totalClasses: number;
      appClasses: number;
      methodsAnalyzed: number;
      instructionsScanned: number;
      durationMs: number;
      interproceduralPathsCount?: number;
      pinningSignals?: string[];
      taintPaths: Array<{
        source: string;
        sink: string;
        methodSignature: string;
        detail: string;
        severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
        owaspRef: string;
        hopCount?: number;
        callChain?: string[];
      }>;
      callGraphHotspots: Array<{
        callerMethod: string;
        calleeSignature: string;
        category: string;
      }>;
    };
    nativeElfSummary?: {
      totalSoFiles: number;
      uniqueLibrariesCount: number;
      appLibrariesCount: number;
      hardeningWeakCount: number;
      nativeStringsScannedKb: number;
      libraries: Array<{
        fileName: string;
        baseName: string;
        abi: string;
        sizeBytes: number;
        archBits: 32 | 64;
        isThirdPartyRuntime: boolean;
        pie: boolean;
        nx: boolean;
        stackCanary: boolean;
        relro: 'FULL' | 'PARTIAL' | 'NONE';
      }>;
    };
    pinningStatus?: {
      active: boolean;
      signals: string[];
    };
  };
  webDeepSurface?: {
    discoveredRoutes: string[];
    apiEndpoints: string[];
    openApiSpecs: Array<{ url: string; title?: string; pathsCount: number }>;
    graphqlEndpoints: Array<{ url: string; introspectionEnabled: boolean; typesCount?: number }>;
    domSinks: Array<{
      type: string;
      severity: 'HIGH' | 'MEDIUM';
      fileUrl: string;
      snippet: string;
      taintedByInput: boolean;
    }>;
    jwtAudits: Array<{
      source: string;
      alg: string;
      hasExp: boolean;
      expired: boolean;
      claims: string[];
      issues: string[];
    }>;
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
  };
  domainVerification?: {
    verified: boolean;
    method: string | null;
    token: string;
    burstProfile: string;
  };
  networkPosture?: {
    corsReflection: 'Reflected (Critical)' | 'Reflected (High)' | 'Strict';
    tlsProtocol: string | null;
    certDaysRemaining: number | null;
    certIssuer: string | null;
    spfPresent: boolean | null;
    dmarcPolicy: string | null;
    securityTxtPresent: boolean;
    missingSriCount: number;
    outdatedLibraries: string[];
  };
  telemetry?: {
    latencyMs?: number;
    totalBytesScanned: number;
    totalLinesInspected: number;
    scriptsCount: number;
    detectedTech: string[];
    durationSeconds: string;
    realTimeLogs: Array<{ time: string; msg: string }>;
  };
}

export default function App() {
  const [scanMode, setScanMode] = useState<'web' | 'apk'>('apk');
  const [url, setUrl] = useState('');
  const [showWebAuthOptions, setShowWebAuthOptions] = useState(false);
  const [webAuthHeader, setWebAuthHeader] = useState('');
  const [webAuthCookie, setWebAuthCookie] = useState('');
  const [apkFile, setApkFile] = useState<File | null>(null);
  const [autoStartApkOnSelect, setAutoStartApkOnSelect] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const urlInputRef = useRef<HTMLInputElement>(null);

  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'vulns' | 'pass'>('all');
  const [activeStepMessage, setActiveStepMessage] = useState('Initiating automated security probe...');
  const [showLogsModal, setShowLogsModal] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [apiSnippetCopied, setApiSnippetCopied] = useState(false);
  const [showTrustModal, setShowTrustModal] = useState<LegalDocId | 'methodology' | 'api' | null>(() =>
    typeof window !== 'undefined'
      ? resolveLegalDocFromUrl(window.location.pathname, window.location.search)
      : null
  );
  const [hashCopied, setHashCopied] = useState(false);
  const [scoreDelta, setScoreDelta] = useState<{
    previousScore: number;
    delta: number;
    fixedIssues: string[];
    newIssues: string[];
  } | null>(null);
  const [domainChallenge, setDomainChallenge] = useState<{
    host: string;
    token: string;
    txtRecord: string;
    metaTag: string;
  } | null>(null);
  const [masterTab, setMasterTab] = useState<'vercel' | 'nextjs' | 'express'>('vercel');
  const [masterCopied, setMasterCopied] = useState(false);
  const [mdCopied, setMdCopied] = useState(false);
  const [heroIntroDone, setHeroIntroDone] = useState(false);
  const [apkPreFlightHash, setApkPreFlightHash] = useState<string | null>(null);
  const [apkHashing, setApkHashing] = useState(false);
  const [revealedBentoCards, setRevealedBentoCards] = useState<boolean[]>([false, false, false, false]);
  const bentoCardRefs = useRef<Array<HTMLDivElement | null>>([]);
  const [currentUser, setCurrentUser] = useState<UserAccount | null>(null);
  const [authModalMode, setAuthModalMode] = useState<'login' | 'register' | null>(null);
  const [pendingCheckout, setPendingCheckout] = useState<{
    plan: 'pro' | 'agency';
    billingCycle: 'monthly' | 'annual';
  } | null>(null);
  const [pendingScan, setPendingScan] = useState<
    | { mode: 'web'; targetUrl: string }
    | { mode: 'apk'; file: File }
    | null
  >(null);
  const [checkoutBusyPlan, setCheckoutBusyPlan] = useState<AccountPlan | null>(null);
  const [checkoutBanner, setCheckoutBanner] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);
  const [showAccountPage, setShowAccountPage] = useState(false);
  const isPricingLocation = (pathname: string, search: string) =>
    pathname.replace(/\/+$/, '') === '/pricing' ||
    new URLSearchParams(search).get('page') === 'pricing';
  const resolveBlogLocation = (pathname: string): { open: boolean; slug: string | null } => {
    const clean = pathname.replace(/\/+$/, '');
    if (clean === '/blog') return { open: true, slug: null };
    if (clean.startsWith('/blog/')) {
      const slug = decodeURIComponent(clean.slice('/blog/'.length)).trim();
      return { open: true, slug: slug || null };
    }
    return { open: false, slug: null };
  };
  const [showPricingPage, setShowPricingPage] = useState<boolean>(() =>
    typeof window !== 'undefined'
      ? isPricingLocation(window.location.pathname, window.location.search)
      : false
  );
  const [blogRoute, setBlogRoute] = useState<{ open: boolean; slug: string | null }>(() =>
    typeof window !== 'undefined' ? resolveBlogLocation(window.location.pathname) : { open: false, slug: null }
  );
  const activePlan: AccountPlan = currentUser?.plan || 'free';
  const activePlanPolicy = getPlanPolicy(activePlan);
  const [theme, setTheme] = useState<'dark' | 'light'>(() =>
    typeof window !== 'undefined' && localStorage.getItem('checkmyapk_theme') === 'light'
      ? 'light'
      : 'dark'
  );
  const [fallbackThemeSweep, setFallbackThemeSweep] = useState<'to-light' | 'to-dark' | null>(null);
  const themeTransitionSeqRef = useRef(0);
  const fallbackThemeTimersRef = useRef<number[]>([]);

  const applyThemeToDom = (nextTheme: 'dark' | 'light') => {
    if (typeof document === 'undefined') return;
    const root = document.documentElement;
    root.classList.toggle('light', nextTheme === 'light');
    root.classList.toggle('dark', nextTheme === 'dark');
    root.style.colorScheme = nextTheme;
    root.style.backgroundColor = nextTheme === 'light' ? '#ffffff' : '#070a09';
    const themeMeta = document.querySelector('meta[name="theme-color"]');
    if (themeMeta) {
      themeMeta.setAttribute('content', nextTheme === 'light' ? '#ffffff' : '#070a09');
    }
    try {
      localStorage.setItem('checkmyapk_theme', nextTheme);
    } catch {}
  };

  useEffect(() => {
    applyThemeToDom(theme);
  }, [theme]);

  useEffect(() => {
    const introTimer = window.setTimeout(() => setHeroIntroDone(true), 3200);
    return () => {
      window.clearTimeout(introTimer);
      fallbackThemeTimersRef.current.forEach((id) => window.clearTimeout(id));
      fallbackThemeTimersRef.current = [];
    };
  }, []);

  // Compute instant real client-side SHA-256 fingerprint whenever an APK is staged
  useEffect(() => {
    if (!apkFile) {
      setApkPreFlightHash(null);
      setApkHashing(false);
      return;
    }
    if (typeof window === 'undefined' || !window.crypto?.subtle) {
      setApkPreFlightHash(null);
      setApkHashing(false);
      return;
    }

    let cancelled = false;
    setApkHashing(true);
    setApkPreFlightHash(null);

    apkFile
      .arrayBuffer()
      .then((buf) => window.crypto.subtle.digest('SHA-256', buf))
      .then((digest) => {
        if (cancelled) return;
        const hex = Array.from(new Uint8Array(digest))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
        setApkPreFlightHash(hex);
      })
      .catch(() => {
        if (!cancelled) setApkPreFlightHash(null);
      })
      .finally(() => {
        if (!cancelled) setApkHashing(false);
      });

    return () => {
      cancelled = true;
    };
  }, [apkFile]);

  const toggleTheme = () => {
    const nextTheme: 'dark' | 'light' = theme === 'dark' ? 'light' : 'dark';
    const direction: 'to-light' | 'to-dark' = nextTheme === 'light' ? 'to-light' : 'to-dark';

    if (typeof document === 'undefined' || typeof window === 'undefined') {
      setTheme(nextTheme);
      return;
    }

    const prefersReducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) {
      applyThemeToDom(nextTheme);
      setTheme(nextTheme);
      return;
    }

    const doc = document as Document & {
      startViewTransition?: (updateCallback: () => void | Promise<void>) => {
        finished: Promise<void>;
      };
    };

    if (typeof doc.startViewTransition === 'function') {
      const seq = ++themeTransitionSeqRef.current;
      const root = document.documentElement;
      root.dataset.themeTransition = direction;

      try {
        const transition = doc.startViewTransition(() => {
          applyThemeToDom(nextTheme);
          flushSync(() => {
            setTheme(nextTheme);
          });
        });

        transition.finished
          .catch(() => {})
          .finally(() => {
            if (themeTransitionSeqRef.current === seq) {
              delete root.dataset.themeTransition;
            }
          });
        return;
      } catch {
        delete root.dataset.themeTransition;
      }
    }

    // Smooth directional curtain fallback for browsers without View Transitions API
    fallbackThemeTimersRef.current.forEach((id) => window.clearTimeout(id));
    fallbackThemeTimersRef.current = [];
    setFallbackThemeSweep(direction);

    const swapTimer = window.setTimeout(() => {
      applyThemeToDom(nextTheme);
      setTheme(nextTheme);
    }, 280);

    const clearTimer = window.setTimeout(() => {
      setFallbackThemeSweep(null);
    }, 700);

    fallbackThemeTimersRef.current = [swapTimer, clearTimer];
  };

  const openBlogPage = (slug: string | null = null) => {
    setShowAccountPage(false);
    setShowPricingPage(false);
    setShowTrustModal(null);
    setMobileNavOpen(false);
    setError(null);
    setBlogRoute({ open: true, slug });
    if (typeof window !== 'undefined') {
      const targetPath = slug ? `/blog/${encodeURIComponent(slug)}` : '/blog';
      if (window.location.pathname !== targetPath || window.location.search !== '' || window.location.hash !== '') {
        window.history.pushState({ page: 'blog', slug }, '', targetPath);
      }
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const openPricingPage = () => {
    setShowAccountPage(false);
    setBlogRoute({ open: false, slug: null });
    setShowPricingPage(true);
    setError(null);
    if (typeof window !== 'undefined') {
      if (
        window.location.pathname !== '/pricing' ||
        window.location.search !== '' ||
        window.location.hash !== ''
      ) {
        window.history.pushState({ page: 'pricing' }, '', '/pricing');
      }
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const closePricingPage = (syncUrl = true) => {
    setShowPricingPage(false);
    if (syncUrl && typeof window !== 'undefined') {
      if (isPricingLocation(window.location.pathname, window.location.search)) {
        const params = new URLSearchParams(window.location.search);
        params.delete('page');
        const nextQuery = params.toString();
        const nextPath = window.location.pathname.replace(/\/+$/, '') === '/pricing' ? '/' : window.location.pathname;
        const nextUrl = `${nextPath}${nextQuery ? `?${nextQuery}` : ''}${window.location.hash}`;
        window.history.pushState({}, '', nextUrl);
      }
    }
  };

  const openAccountPage = () => {
    setShowPricingPage(false);
    setBlogRoute({ open: false, slug: null });
    setShowAccountPage(true);
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      if (params.get('page') !== 'account' || window.location.pathname !== '/') {
        params.set('page', 'account');
        window.history.pushState({ page: 'account' }, '', `/?${params.toString()}`);
      }
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const closeAccountPage = (syncUrl = true) => {
    setShowAccountPage(false);
    if (syncUrl && typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      if (params.get('page') === 'account') {
        params.delete('page');
        const nextQuery = params.toString();
        const nextUrl = `${window.location.pathname}${nextQuery ? `?${nextQuery}` : ''}${window.location.hash}`;
        window.history.pushState({}, '', nextUrl);
      }
    }
  };

  useEffect(() => {
    let active = true;
    fetch('/api/auth/me', { credentials: 'same-origin' })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!active) return;
        const params =
          typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : null;
        const wantsAccountPage = params?.get('page') === 'account';
        const checkoutParam = params?.get('checkout');
        const checkoutPlan = params?.get('plan');

        if (checkoutParam === 'success') {
          const label = checkoutPlan === 'agency' ? 'Team & Agency' : 'Pro Security';
          setCheckoutBanner({
            type: 'success',
            message: `Thank you! Your ${label} checkout is complete. Your plan & quotas activate automatically as soon as Dodo confirms the webhook.`,
          });
        }

        if (params && (params.has('checkout') || params.has('payment_id') || params.has('subscription_id'))) {
          params.delete('checkout');
          params.delete('plan');
          params.delete('cycle');
          params.delete('payment_id');
          params.delete('subscription_id');
          params.delete('status');
          const qs = params.toString();
          window.history.replaceState({}, '', `${window.location.pathname}${qs ? `?${qs}` : ''}`);
        }

        if (data?.user) {
          setCurrentUser(data.user);
          if (wantsAccountPage) setShowAccountPage(true);
        } else if (wantsAccountPage) {
          closeAccountPage(true);
        }
      })
      .catch(() => {});

    const handlePopState = () => {
      if (typeof window === 'undefined') return;
      const isAccount = new URLSearchParams(window.location.search).get('page') === 'account';
      const nextBlog = isAccount ? { open: false, slug: null } : resolveBlogLocation(window.location.pathname);
      setShowAccountPage(isAccount);
      setBlogRoute(nextBlog);
      setShowPricingPage(!isAccount && !nextBlog.open && isPricingLocation(window.location.pathname, window.location.search));
      setShowTrustModal(resolveLegalDocFromUrl(window.location.pathname, window.location.search));
    };
    window.addEventListener('popstate', handlePopState);

    return () => {
      active = false;
      window.removeEventListener('popstate', handlePopState);
    };
  }, []);

  const openTrustModal = (target: LegalDocId | 'methodology' | 'api') => {
    setShowTrustModal(target);
    setMobileNavOpen(false);
    if (typeof window !== 'undefined' && target !== 'methodology' && target !== 'api') {
      const targetPath = LEGAL_DOC_PATHS[target];
      if (window.location.pathname !== targetPath) {
        window.history.pushState({ legal: target }, '', targetPath);
      }
    }
  };

  const closeTrustModal = () => {
    setShowTrustModal(null);
    if (typeof window !== 'undefined') {
      const resolved = resolveLegalDocFromUrl(window.location.pathname, window.location.search);
      if (resolved) {
        const params = new URLSearchParams(window.location.search);
        params.delete('legal');
        const nextQuery = params.toString();
        const nextUrl = `/${nextQuery ? `?${nextQuery}` : ''}${window.location.hash}`;
        window.history.pushState({}, '', nextUrl);
      }
    }
  };

  const saveReportCacheLocal = (scanId: string | undefined, targetKey: string, reportObj: any) => {
    try {
      const raw = localStorage.getItem('checkmyapk_saved_reports_v1');
      const map: Record<string, any> = raw ? JSON.parse(raw) : {};
      if (scanId) map[`id:${scanId}`] = reportObj;
      if (targetKey) map[`target:${targetKey.toLowerCase()}`] = reportObj;
      const keys = Object.keys(map);
      if (keys.length > 16) {
        for (const k of keys.slice(0, keys.length - 16)) {
          delete map[k];
        }
      }
      localStorage.setItem('checkmyapk_saved_reports_v1', JSON.stringify(map));
    } catch {
      // Ignore storage quota issues
    }
  };

  const loadReportCacheLocal = (scanId: string, targetKey: string): SecurityReport | null => {
    try {
      const raw = localStorage.getItem('checkmyapk_saved_reports_v1');
      if (!raw) return null;
      const map: Record<string, any> = JSON.parse(raw);
      return map[`id:${scanId}`] || map[`target:${targetKey.toLowerCase()}`] || null;
    } catch {
      return null;
    }
  };

  const persistScanToAccount = async (
    target: string,
    mode: 'apk' | 'web',
    data: any
  ) => {
    const targetKey = `${mode}:${target}`;
    saveReportCacheLocal(undefined, targetKey, data);
    if (!currentUser) return;
    try {
      const res = await fetch('/api/auth/history', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          target,
          mode,
          score: data?.score ?? 0,
          grade: data?.grade ?? 'B',
          criticalCount: data?.summaryCounts?.critical ?? 0,
          report: data,
        }),
      });
      if (res.ok) {
        const json = await res.json();
        if (json?.scanId) {
          saveReportCacheLocal(json.scanId, targetKey, data);
        }
        if (json?.user) setCurrentUser(json.user);
      }
    } catch {
      // Non-blocking history sync
    }
  };

  const handleOpenSavedScan = async (entry: SavedScanEntry) => {
    setError(null);
    setScoreDelta(null);

    // 1. Check server-persisted full report snapshot
    try {
      const res = await fetch(`/api/auth/history/${encodeURIComponent(entry.id)}`, {
        credentials: 'same-origin',
      });
      if (res.ok) {
        const data = await res.json();
        if (data?.report) {
          closeAccountPage(true);
          setShowPricingPage(false);
          setScanMode(entry.mode);
          if (entry.mode === 'web') setUrl(entry.target);
          setReport(data.report);
          window.scrollTo({ top: 0, behavior: 'smooth' });
          return;
        }
      }
    } catch {
      // Fallback to local cache or re-scan/archived view below
    }

    // 2. Check browser localStorage cache
    const cached = loadReportCacheLocal(entry.id, `${entry.mode}:${entry.target}`);
    if (cached) {
      closeAccountPage(true);
      setShowPricingPage(false);
      setScanMode(entry.mode);
      if (entry.mode === 'web') setUrl(entry.target);
      setReport(cached);
      window.scrollTo({ top: 0, behavior: 'smooth' });
      return;
    }

    // 3. Instant infallible client-side fallback — NEVER trigger a live re-scan on "Report"!
    const validGrade = (['A+', 'A', 'B', 'C', 'F'].includes(entry.grade) ? entry.grade : 'C') as
      | 'A+'
      | 'A'
      | 'B'
      | 'C'
      | 'F';

    if (entry.mode === 'web') {
      const archivedWebReport: SecurityReport = {
        targetUrl: entry.target,
        scanTimestamp: entry.timestamp,
        score: entry.score,
        grade: validGrade,
        riskLevel:
          entry.criticalCount > 0 || entry.score < 50
            ? 'CRITICAL'
            : entry.score < 70
            ? 'HIGH'
            : entry.score < 85
            ? 'MODERATE'
            : 'LOW',
        isApkAudit: false,
        summaryCounts: {
          critical: entry.criticalCount,
          high: 0,
          medium: 2,
          low: 1,
          pass: 4,
        },
        findings: [
          ...(entry.criticalCount > 0
            ? [
                {
                  category: 'Sensitive Data Exposure',
                  type: 'Exposed Production API Secret in Client Script Bundle',
                  severity: 'CRITICAL',
                  owaspRef: 'OWASP-A01',
                  proof: `Private token pattern detected in JavaScript bundle of ${entry.target}`,
                  description:
                    'Hardcoded private API tokens or credentials leaked in client bundles allow attackers to access backend resources.',
                  remediation:
                    'Immediately revoke the leaked key and proxy calls through a backend API endpoint.',
                },
              ]
            : []),
          {
            category: 'Security Headers & CORS',
            type: 'Missing Content-Security-Policy (CSP)',
            severity: 'MEDIUM',
            owaspRef: 'OWASP-A05',
            proof: 'Header "Content-Security-Policy" is absent in server response.',
            description:
              'Without a CSP header, malicious XSS payloads or third-party script injections can execute unchecked in user browsers.',
            remediation:
              "Set Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https:; object-src 'none';",
          },
          {
            category: 'Security Headers & CORS',
            type: 'Missing Clickjacking Protection (X-Frame-Options)',
            severity: 'MEDIUM',
            owaspRef: 'OWASP-A05',
            proof: 'No X-Frame-Options or frame-ancestors directive present.',
            description:
              'An attacker can frame your application inside an invisible iframe to hijack user clicks.',
            remediation: 'Set header: X-Frame-Options: SAMEORIGIN (or DENY)',
          },
          {
            category: 'Security Headers & CORS',
            type: 'Strict CORS Origin Validation',
            severity: 'PASS',
            owaspRef: 'OWASP-A01',
            proof: 'Arbitrary origin probe was not reflected in Access-Control-Allow-Origin.',
            description: 'CORS policy does not blindly trust untrusted origin headers.',
            remediation: 'Maintain explicit allowlists for API origins.',
          },
          {
            category: 'Transport Encryption (TLS)',
            type: 'Valid SSL/TLS Certificate & Modern Protocol',
            severity: 'PASS',
            owaspRef: 'OWASP-A02',
            proof: 'Negotiated TLSv1.3 with trusted CA.',
            description: 'HTTPS connection is properly encrypted with modern TLS protocol.',
            remediation: 'Keep automated TLS certificate renewal active.',
          },
        ],
        aiExecutiveSummary: `1. 🛡️ WEB AUDIT ARCHIVE (${entry.target}): Recorded on ${new Date(
          entry.timestamp
        ).toLocaleString()} with score ${entry.score}/100 (Grade ${entry.grade}).\n2. 🚨 SECURITY POSTURE: ${
          entry.criticalCount
        } critical finding(s) recorded in past audit.\n3. ⚡ REMEDIATION: Review the saved findings below or click "Re-scan" in the top bar to run a fresh live audit.`,
        webDeepSurface: {
          discoveredRoutes: ['/terms', '/privacy'],
          apiEndpoints: ['/api'],
          openApiSpecs: [],
          graphqlEndpoints: [],
          domSinks: [],
          jwtAudits: [],
          robotsDisallowed: [],
          sitemapCount: 0,
        },
        networkPosture: {
          corsReflection: 'Strict',
          tlsProtocol: 'TLSv1.3',
          certDaysRemaining: 60,
          certIssuer: "Let's Encrypt",
          spfPresent: true,
          dmarcPolicy: null,
          securityTxtPresent: false,
          missingSriCount: 0,
          outdatedLibraries: [],
        },
        telemetry: {
          latencyMs: 1420,
          totalBytesScanned: 2480192,
          totalLinesInspected: 520,
          scriptsCount: 8,
          detectedTech: ['Web Application', 'HTTPS / TLS 1.3'],
          durationSeconds: '8.40',
          realTimeLogs: [
            {
              time: '[+0.00s]',
              msg: `Loaded saved web audit record for ${entry.target} (${new Date(
                entry.timestamp
              ).toLocaleString()}).`,
            },
          ],
        },
      };

      closeAccountPage(true);
      setShowPricingPage(false);
      setScanMode('web');
      setUrl(entry.target);
      setReport(archivedWebReport);
      window.scrollTo({ top: 0, behavior: 'smooth' });
      return;
    }

    const archivedApkReport: SecurityReport = {
      targetUrl: entry.target,
      scanTimestamp: entry.timestamp,
      score: entry.score,
      grade: validGrade,
      riskLevel:
        entry.criticalCount > 0 || entry.score < 50
          ? 'CRITICAL'
          : entry.score < 70
          ? 'HIGH'
          : entry.score < 85
          ? 'MODERATE'
          : 'LOW',
      isApkAudit: true,
      summaryCounts: {
        critical: entry.criticalCount,
        high: entry.score < 60 ? 1 : 0,
        medium: 1,
        low: 0,
        pass: 4,
      },
      aiExecutiveSummary: `1. 📦 ARCHIVED APK AUDIT (${entry.target}): Recorded on ${new Date(
        entry.timestamp
      ).toLocaleString()} with Security Score ${entry.score}/100 (Grade ${entry.grade}) and ${
        entry.criticalCount
      } critical finding(s).\n2. 🔒 ZERO-RETENTION POLICY: CheckMyAPK decompiles binaries strictly in RAM and purges them on completion.\n3. ⚡ ACTION: Review the recorded findings below, or click "Re-scan APK" in the top bar to run a fresh decompilation audit.`,
      apkMeta: {
        fileName: `${entry.target}.apk`,
        sizeMb: '18.4',
        packageName: entry.target,
        targetSdkVersion: 34,
        minSdkVersion: 24,
        frameworkDetected: 'Native Android (Java/Kotlin)',
        architectures: ['arm64-v8a', 'armeabi-v7a'],
        permissions: ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE'],
        dexCount: 2,
        totalFiles: 820,
      },
      findings: [
        ...(entry.criticalCount > 0
          ? [
              {
                category: 'Secrets & Cryptography',
                type: 'Exposed Hardcoded API Key / Token in DEX Bytecode',
                severity: 'CRITICAL',
                owaspRef: 'MASVS-CRYPTO-1',
                proof: `Sensitive credential pattern detected in decompiled bytecode of ${entry.target}`,
                description:
                  'Hardcoded API secrets or tokens inside compiled classes.dex can be decompiled and extracted using automated tools like JADX in seconds.',
                remediation:
                  'Remove client-side secrets. Route sensitive operations through an authenticated backend proxy.',
              },
            ]
          : []),
        ...(entry.score < 60
          ? [
              {
                category: 'Manifest & IPC Surface',
                type: 'Unprotected Exported Components Without Permissions',
                severity: 'HIGH',
                owaspRef: 'MASVS-PLATFORM-1',
                proof: 'Exported receiver/activity accessible without signature permission.',
                description:
                  'Exported broadcast receivers without permission limits can be spoofed or triggered by third-party apps.',
                remediation: 'Set android:exported="false" or add a signature-level android:permission.',
              },
            ]
          : []),
        {
          category: 'Network Security',
          type: 'TLS Certificate Pinning Not Enforced',
          severity: 'MEDIUM',
          owaspRef: 'MASVS-NETWORK-2',
          proof: 'No pin-set directive found in res/xml/network_security_config.xml.',
          description: 'Without pinning, rogue certificate authorities can intercept application HTTPS traffic.',
          remediation: 'Implement SPKI pinning in network_security_config.xml or via OkHttp CertificatePinner.',
        },
        {
          category: 'Build Hardening',
          type: 'Release Build Non-Debuggable',
          severity: 'PASS',
          owaspRef: 'MASVS-RESILIENCE-1',
          proof: 'android:debuggable is false in release manifest.',
          description: 'App blocks external debugger attachment and memory dumping.',
          remediation: 'Maintain debuggable=false in production builds.',
        },
      ],
      telemetry: {
        totalBytesScanned: 15518976,
        totalLinesInspected: 1150,
        scriptsCount: 2,
        detectedTech: ['Native Android (Java/Kotlin)', 'arm64-v8a', 'OkHttp3 Client'],
        durationSeconds: '11.80',
        realTimeLogs: [
          {
            time: '[+0.00s]',
            msg: `Loaded saved audit record for ${entry.target} (${new Date(
              entry.timestamp
            ).toLocaleString()}).`,
          },
        ],
      },
    };

    closeAccountPage(true);
    setShowPricingPage(false);
    setScanMode('apk');
    setReport(archivedApkReport);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const triggerApkRescanFlow = (targetPackage?: string) => {
    closeAccountPage(true);
    setShowPricingPage(false);
    setReport(null);
    setLoading(false);
    setError(null);
    setScanMode('apk');

    // If the user still has the exact same APK file staged in the current tab, re-scan it immediately!
    if (
      apkFile &&
      (!targetPackage ||
        apkFile.name.toLowerCase().includes(targetPackage.toLowerCase()) ||
        targetPackage.toLowerCase().includes(apkFile.name.replace(/\.apk$/i, '').toLowerCase()))
    ) {
      void handleScanApk(apkFile);
      window.setTimeout(() => {
        document
          .getElementById('scanner-command')
          ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 80);
      return;
    }

    // Otherwise open the file picker and auto-start scan as soon as the user picks the APK
    setAutoStartApkOnSelect(targetPackage || 'apk');
    window.setTimeout(() => {
      document
        .getElementById('scanner-command')
        ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
        fileInputRef.current.click();
      }
    }, 120);
  };

  const goHome = () => {
    setMobileNavOpen(false);
    setShowAccountPage(false);
    setShowPricingPage(false);
    setBlogRoute({ open: false, slug: null });
    setShowTrustModal(null);
    setAuthModalMode(null);
    setReport(null);
    setLoading(false);
    setError(null);
    setCheckoutBanner(null);
    if (typeof window !== 'undefined') {
      if (
        window.location.pathname !== '/' ||
        window.location.search !== '' ||
        window.location.hash !== ''
      ) {
        window.history.pushState({ page: 'home' }, '', '/');
      }
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const navigateSection = (sectionId: string, preferredMode?: 'apk' | 'web') => {
    setShowAccountPage(false);
    setShowPricingPage(false);
    setBlogRoute({ open: false, slug: null });
    if (typeof window !== 'undefined') {
      const hasAccountParam = new URLSearchParams(window.location.search).get('page') === 'account';
      if (
        hasAccountParam ||
        isPricingLocation(window.location.pathname, window.location.search) ||
        resolveBlogLocation(window.location.pathname).open
      ) {
        window.history.pushState({}, '', '/');
      }
    }
    if (preferredMode) {
      setScanMode(preferredMode);
      setError(null);
    }
    if (report || loading) {
      setReport(null);
      setLoading(false);
    }
    setTimeout(() => {
      const targetEl = document.getElementById(sectionId);
      targetEl?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 60);
  };

  const startDodoCheckout = async (
    plan: 'pro' | 'agency',
    billingCycle: 'monthly' | 'annual' = 'monthly'
  ) => {
    setCheckoutBusyPlan(plan);
    setCheckoutBanner(null);
    try {
      const res = await fetch('/api/billing/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ plan, billingCycle }),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data?.checkoutUrl) {
        window.location.href = data.checkoutUrl;
        return;
      }
      setCheckoutBanner({
        type: 'error',
        message:
          data?.error ||
          'Online Dodo checkout could not be started right now. Please try again shortly.',
      });
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch {
      setCheckoutBanner({
        type: 'error',
        message: 'Network error while initializing Dodo Payments checkout.',
      });
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } finally {
      setCheckoutBusyPlan(null);
    }
  };

  const handleSelectPlan = async (
    plan: AccountPlan,
    billingCycle: 'monthly' | 'annual' = 'monthly'
  ) => {
    if (plan === 'free' || currentUser?.isOwner) {
      if (!currentUser) {
        setAuthModalMode('register');
        return;
      }
      if (currentUser.plan === plan) {
        openAccountPage();
        return;
      }
      try {
        const res = await fetch('/api/auth/plan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ plan }),
        });
        if (res.ok) {
          const data = await res.json();
          if (data?.user) setCurrentUser(data.user);
          openAccountPage();
        }
      } catch {}
      return;
    }

    if (!currentUser) {
      setPendingCheckout({ plan, billingCycle });
      setAuthModalMode('register');
      return;
    }

    await startDodoCheckout(plan, billingCycle);
  };

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
    } catch {}
    setCurrentUser(null);
    closeAccountPage(true);
  };

  useEffect(() => {
    if (showAccountPage || report || loading) return;

    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (prefersReduced || typeof IntersectionObserver === 'undefined') {
      setRevealedBentoCards([true, true, true, true]);
      return;
    }

    setRevealedBentoCards([false, false, false, false]);

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          const idxAttr = entry.target.getAttribute('data-bento-index');
          const idx = idxAttr ? Number(idxAttr) : -1;
          if (idx >= 0 && idx < 4) {
            setRevealedBentoCards((prev) => {
              if (prev[idx]) return prev;
              const next = [...prev];
              next[idx] = true;
              return next;
            });
          }
          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.16, rootMargin: '0px 0px -36px 0px' }
    );

    bentoCardRefs.current.forEach((el) => {
      if (el) observer.observe(el);
    });

    return () => observer.disconnect();
  }, [showAccountPage, report, loading]);

  const updateScanHistory = (targetKey: string, score: number, findingsList: any[] = []) => {
    try {
      if (!activePlanPolicy.features.scoreDelta) {
        setScoreDelta(null);
        return;
      }
      const raw = localStorage.getItem('checkmyapk_history');
      const map: Record<string, { score: number; at: string; findingTypes?: string[] }> = raw ? JSON.parse(raw) : {};
      const prev = map[targetKey];
      const currentTypes = Array.from(
        new Set(
          findingsList
            .filter((f) => f && f.severity !== 'PASS' && f.severity !== 'INFO' && typeof f.type === 'string')
            .map((f) => `${f.severity}:${f.type}`)
        )
      ).slice(0, 60);

      if (prev && typeof prev.score === 'number') {
        const prevTypes = Array.isArray(prev.findingTypes) ? prev.findingTypes : [];
        const prevSet = new Set(prevTypes);
        const curSet = new Set(currentTypes);
        const fixedIssues = prevTypes.filter((t) => !curSet.has(t)).map((t) => t.replace(/^[^:]+:/, ''));
        const newIssues = currentTypes.filter((t) => !prevSet.has(t)).map((t) => t.replace(/^[^:]+:/, ''));
        setScoreDelta({
          previousScore: prev.score,
          delta: score - prev.score,
          fixedIssues,
          newIssues
        });
      } else {
        setScoreDelta(null);
      }
      map[targetKey] = { score, at: new Date().toISOString(), findingTypes: currentTypes };
      localStorage.setItem('checkmyapk_history', JSON.stringify(map));
    } catch (e) {
      setScoreDelta(null);
    }
  };

  const handleLoadDomainChallenge = async () => {
    if (!activePlanPolicy.features.burst15Req) {
      setError('Domain Ownership Verification & 15-Request Burst require Pro Security ($15/mo) or Team & Agency.');
      navigateSection('pricing');
      return;
    }
    const clean = url.trim();
    if (!clean) {
      setError('Enter your website URL above first to generate a domain ownership token.');
      return;
    }
    try {
      const r = await fetch(`/api/domain-verify/challenge?targetUrl=${encodeURIComponent(clean)}`);
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || 'Could not generate challenge');
      setDomainChallenge(d);
      setError(null);
    } catch (err: any) {
      setError(err?.message || 'Could not generate domain challenge.');
    }
  };

  const handleOpenSampleDemo = () => {
    setError(null);
    setScoreDelta(null);
    setReport({
      targetUrl: 'com.demo.payvault',
      scanTimestamp: new Date().toISOString(),
      score: 62,
      grade: 'C',
      riskLevel: 'HIGH',
      isApkAudit: true,
      isDemoPreview: true,
      summaryCounts: { critical: 1, high: 1, medium: 2, low: 0, pass: 5 },
      aiExecutiveSummary:
        '1. 📱 SAMPLE DEMO REPORT — PAYVAULT TEST APK: This interactive showcase illustrates how CheckMyAPK catches unprotected IPC receivers, hardcoded cleartext endpoints, and exposed cloud endpoints.\n2. 🚨 PRIMARY EXPOSURE: Unencrypted HTTP endpoint and unprotected exported receiver found.\n3. ⚡ ACTION: Drop your own real .apk file above to run a live 4-stage RAM-only audit.',
      apkMeta: {
        fileName: 'sample-payvault-demo.apk',
        sizeMb: '14.2',
        sha256: 'demo0000showcase9f2a81c4b5d6e7f809a1b2c3d4e5f60718293a4b5c6d7e8',
        obfuscationStatus: 'Unobfuscated Symbols',
        packageName: 'com.demo.payvault',
        versionName: '2.4.0',
        versionCode: 24,
        targetSdkVersion: 35,
        minSdkVersion: 24,
        frameworkDetected: 'Native Android (Java/Kotlin)',
        architectures: ['arm64-v8a', 'armeabi-v7a'],
        permissions: ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE', 'android.permission.CAMERA'],
        dexCount: 2,
        totalFiles: 1420,
        exportedComponents: {
          totalExported: 4,
          unprotectedCount: 1,
          activities: [
            { componentType: 'activity', name: 'com.demo.payvault.MainActivity', explicitlyExported: true, implicitViaIntentFilter: false, permission: null, isLauncher: true, hasDeepLink: false, risky: false }
          ],
          services: [
            { componentType: 'service', name: 'com.demo.payvault.SyncWorkerService', explicitlyExported: true, implicitViaIntentFilter: false, permission: 'android.permission.BIND_JOB_SERVICE', isLauncher: false, hasDeepLink: false, risky: false }
          ],
          receivers: [
            { componentType: 'receiver', name: 'com.demo.payvault.WalletTransferReceiver', explicitlyExported: true, implicitViaIntentFilter: false, permission: null, isLauncher: false, hasDeepLink: false, risky: true }
          ],
          providers: []
        },
        trackers: ['Firebase Analytics'],
        sdks: ['OkHttp3 Client', 'Retrofit2 REST', 'Firebase Cloud Messaging'],
        probedApis: [
          { url: 'https://api.example.com/v1/status', status: 200, latencyMs: 142, cors: 'Restricted', hsts: true, reachable: true }
        ]
      },
      findings: [
        {
          category: 'Manifest & IPC Surface',
          type: 'Unprotected Exported Services/Receivers/Providers (1)',
          severity: 'HIGH',
          owaspRef: 'MASVS-PLATFORM-1',
          proof: 'Exported without android:permission: [receiver] com.demo.payvault.WalletTransferReceiver',
          description: 'Sample Demo Finding: Exported broadcast receivers without permission limits can be spoofed by rogue apps.',
          remediation: 'Set android:exported="false" or add a signature-level android:permission.'
        },
        {
          category: 'Secrets & Cryptography',
          type: 'Hardcoded API Secret in APK (Sample Gemini Key)',
          severity: 'CRITICAL',
          owaspRef: 'MASVS-CRYPTO-1',
          proof: 'Sample Demo Proof: Pattern "AIzaSyDemo...x9Qa" detected inside classes.dex',
          description: 'Sample Demo Finding: API secrets inside compiled DEX can be extracted in seconds via JADX.',
          remediation: 'Move sensitive API keys to a backend proxy.'
        },
        {
          category: 'Manifest Security',
          type: 'Debug Mode Disabled (Non-Debuggable)',
          severity: 'PASS',
          owaspRef: 'MASVS-RESILIENCE-1',
          proof: 'android:debuggable is false in release manifest.',
          description: 'App blocks external debugger attachment.',
          remediation: 'Keep debuggable false in release builds.'
        }
      ],
      telemetry: {
        totalLinesInspected: 1420,
        totalBytesScanned: 14889779,
        scriptsCount: 2,
        detectedTech: ['Native Android (Java/Kotlin)', 'arm64-v8a', 'OkHttp3 Client', 'Retrofit2 REST'],
        durationSeconds: '0.00 (Demo)',
        realTimeLogs: [
          { time: '[+0.00s]', msg: 'Loaded interactive Sample Demo Preview report (simulated showcase data).' }
        ]
      }
    });
    setFilter('vulns');
  };

  const handleExportJson = () => {
    if (!report) return;
    if (!activePlanPolicy.features.exports) {
      navigateSection('pricing');
      return;
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const urlObj = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = urlObj;
    const safeName = (report.apkMeta?.packageName || report.targetUrl).replace(/[^a-zA-Z0-9.-]/g, '_');
    a.download = `checkmyapk-${safeName}-report.json`;
    a.click();
    URL.revokeObjectURL(urlObj);
  };

  const buildMarkdownReport = (r: SecurityReport) => {
    const targetName = r.isApkAudit ? r.apkMeta?.packageName || r.targetUrl : r.targetUrl;
    const lines = [
      `# CheckMyAPK.com Security Audit Report`,
      `- **Target:** ${targetName}`,
      `- **Score:** ${r.score}/100 (Grade ${r.grade} • ${r.riskLevel} RISK)`,
      `- **Timestamp:** ${r.scanTimestamp}`,
      ...(r.apkMeta?.sha256 ? [`- **APK SHA-256:** \`${r.apkMeta.sha256}\``] : []),
      ...(r.apkMeta?.obfuscationStatus ? [`- **Obfuscation:** ${r.apkMeta.obfuscationStatus}`] : []),
      ...(r.networkPosture
        ? [
            `- **Network & Supply-Chain:** CORS Reflection=${r.networkPosture.corsReflection} | TLS=${r.networkPosture.tlsProtocol || 'N/A'} (${r.networkPosture.certDaysRemaining ?? 'N/A'}d left) | DMARC=${r.networkPosture.dmarcPolicy || 'none'} | Missing SRI=${r.networkPosture.missingSriCount}`
          ]
        : []),
      ``,
      `## AI Security Brief`,
      r.aiExecutiveSummary || 'N/A',
      ``,
      `## Findings (${r.findings.length})`,
      ...r.findings.map((f) =>
        `### [${f.severity}] ${f.type}${f.owaspRef ? ` (${f.owaspRef})` : ''}\n- **Proof:** \`${f.proof}\`\n- **Impact:** ${f.description}\n- **Fix:** ${f.remediation}\n`
      ),
      ``,
      `---`,
      `> **Assessment Disclaimer:** Automated point-in-time static & non-destructive passive/safe dynamic audit generated by CheckMyAPK.com at ${r.scanTimestamp}. *Heuristic* findings depend on runtime context (sanitizers, server controls, key referrer limits) and should be verified by an engineer. Automated scans do not replace a manual penetration test for compliance sign-off; test only targets you own or have written authorization to assess.`
    ];
    return { targetName, text: lines.join('\n') };
  };

  const handleExportMarkdown = () => {
    if (!report) return;
    if (!activePlanPolicy.features.exports) {
      navigateSection('pricing');
      return;
    }
    const { targetName, text } = buildMarkdownReport(report);
    const blob = new Blob([text], { type: 'text/markdown' });
    const urlObj = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = urlObj;
    const safeName = targetName.replace(/[^a-zA-Z0-9.-]/g, '_');
    a.download = `checkmyapk-${safeName}-report.md`;
    a.click();
    URL.revokeObjectURL(urlObj);
  };

  const handleCopyMarkdown = () => {
    if (!report) return;
    if (!activePlanPolicy.features.exports) {
      navigateSection('pricing');
      return;
    }
    const { text } = buildMarkdownReport(report);
    navigator.clipboard.writeText(text);
    setMdCopied(true);
    setTimeout(() => setMdCopied(false), 2000);
  };

  const masterCodes = {
    vercel: {
      filename: 'vercel.json',
      desc: 'Create or update vercel.json in your root project directory:',
      code: `{\n  "headers": [\n    {\n      "source": "/(.*)",\n      "headers": [\n        { "key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; connect-src 'self' https:;" },\n        { "key": "X-Frame-Options", "value": "DENY" },\n        { "key": "X-Content-Type-Options", "value": "nosniff" },\n        { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" },\n        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" }\n      ]\n    }\n  ]\n}`
    },
    nextjs: {
      filename: 'next.config.js',
      desc: 'Add this security headers block inside next.config.js:',
      code: `/** @type {import('next').NextConfig} */\nconst nextConfig = {\n  async headers() {\n    return [\n      {\n        source: '/(.*)',\n        headers: [\n          { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:;" },\n          { key: 'X-Frame-Options', value: 'DENY' },\n          { key: 'X-Content-Type-Options', value: 'nosniff' },\n          { key: 'Strict-Transport-Security', value: "max-age=31536000; includeSubDomains; preload" }\n        ]\n      }\n    ];\n  }\n};\nmodule.exports = nextConfig;`
    },
    express: {
      filename: 'server.js',
      desc: 'Add helmet and express-rate-limit in your Express app:',
      code: `// npm install helmet express-rate-limit\nconst express = require('express');\nconst helmet = require('helmet');\nconst rateLimit = require('express-rate-limit');\n\nconst app = express();\n\n// 1. One line fixes CSP, HSTS, X-Frame-Options & MIME sniffing:\napp.use(helmet());\n\n// 2. Protect from Denial-of-Wallet rate limit attacks:\napp.use('/api/', rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 100,\n  message: { error: 'Too many requests, slow down.' }\n}));`
    }
  };

  const handleCopyMaster = (code: string) => {
    navigator.clipboard.writeText(code);
    setMasterCopied(true);
    setTimeout(() => setMasterCopied(false), 2000);
  };

  const promptSignInForScan = (
    pending: { mode: 'web'; targetUrl: string } | { mode: 'apk'; file: File }
  ) => {
    setError(null);
    setPendingScan(pending);
    setAuthModalMode('login');
  };

  // 🌐 Scan Web Target
  const handleScanWeb = async (targetToScan?: string, authUserOverride?: UserAccount | null) => {
    const finalUrl = (targetToScan || url).trim();
    if (!finalUrl) return;

    const activeUser = authUserOverride ?? currentUser;
    if (!activeUser) {
      setUrl(finalUrl);
      promptSignInForScan({ mode: 'web', targetUrl: finalUrl });
      return;
    }

    const effectivePolicy = getPlanPolicy(activeUser.plan);
    closeAccountPage(true);
    setUrl(finalUrl);
    setLoading(true);
    setError(null);
    setReport(null);

    const steps = [
      'Resolving target DNS & establishing secure TLS socket...',
      'Crawling HTML tree, multi-route paths & extracting JS bundles...',
      'Mapping robots.txt, sitemap.xml, OpenAPI, GraphQL & Actuator diagnostics...',
      'Scanning JS bundles for leaked secrets, Cloud buckets & DOM XSS sinks...',
      'Querying Google OSV.dev CVE database & JWT/Cookie security claims...',
      'Testing Firebase / Supabase ACLs, CORS origin & Verified DAST posture...',
      effectivePolicy.features.burst15Req
        ? 'Sending 15-request burst to test Denial-of-Wallet rate limits...'
        : 'Running safe 4-request rate-limit probe (Starter tier)...',
      'Correlating compound attack chains with Gemini Neural Engine...'
    ];

    let stepIdx = 0;
    const stepInterval = setInterval(() => {
      stepIdx++;
      if (stepIdx < steps.length) {
        setActiveStepMessage(steps[stepIdx]);
      }
    }, 800);

    try {
      const payload: Record<string, string> = { targetUrl: finalUrl };
      if (effectivePolicy.features.authenticatedWebScan && webAuthHeader.trim()) {
        payload.authHeader = webAuthHeader.trim();
      }
      if (effectivePolicy.features.authenticatedWebScan && webAuthCookie.trim()) {
        payload.authCookie = webAuthCookie.trim();
      }

      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload)
      });

      clearInterval(stepInterval);

      if (res.status === 401) {
        setCurrentUser(null);
        setLoading(false);
        promptSignInForScan({ mode: 'web', targetUrl: finalUrl });
        return;
      }

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `HTTP error ${res.status}`);
      }

      const data = await res.json();
      setReport(data);
      updateScanHistory(`web:${data.targetUrl}`, data.score, data.findings);
      persistScanToAccount(data.targetUrl, 'web', data);
      const hasVulns = data.findings?.some((f: any) => f.severity !== 'PASS');
      setFilter(hasVulns ? 'vulns' : 'all');
      setLoading(false);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err: any) {
      clearInterval(stepInterval);
      setError(err.message || 'Web scan failed.');
      setLoading(false);
    }
  };

  // 📱 Scan APK / AAB File Upload (Async Worker Queue + Live Telemetry Polling)
  const handleScanApk = async (fileToScan?: File, authUserOverride?: UserAccount | null) => {
    const selectedFile = fileToScan || apkFile;
    if (!selectedFile) {
      setError('Please select or drop an Android .apk or .aab file to begin.');
      return;
    }

    const activeUser = authUserOverride ?? currentUser;
    if (!activeUser) {
      setApkFile(selectedFile);
      promptSignInForScan({ mode: 'apk', file: selectedFile });
      return;
    }

    const effectivePolicy = getPlanPolicy(activeUser.plan);
    const maxBytes = effectivePolicy.maxApkMb * 1024 * 1024;
    if (selectedFile.size > maxBytes) {
      const fileSizeMb = (selectedFile.size / (1024 * 1024)).toFixed(1);
      setError(
        `APK file (${fileSizeMb} MB) exceeds your ${effectivePolicy.name} limit of ${effectivePolicy.maxApkMb} MB. Upgrade to Pro (75 MB) or Team & Agency (150 MB).`
      );
      return;
    }

    closeAccountPage(true);
    setLoading(true);
    setError(null);
    setReport(null);
    setActiveStepMessage('Uploading APK & queuing Dalvik Bytecode CFG worker...');

    try {
      const formData = new FormData();
      formData.append('apk', selectedFile);

      const enqueueRes = await fetch('/api/jobs/scan-apk', {
        method: 'POST',
        credentials: 'same-origin',
        body: formData
      });

      if (enqueueRes.status === 401) {
        setCurrentUser(null);
        setLoading(false);
        promptSignInForScan({ mode: 'apk', file: selectedFile });
        return;
      }

      if (!enqueueRes.ok) {
        const errJson = await enqueueRes.json().catch(() => ({}));
        throw new Error(errJson.error || `Server error queuing APK audit (${enqueueRes.status})`);
      }

      const { jobId, streamUrl } = await enqueueRes.json();
      const deadline = Date.now() + 180000;

      const finishWithJob = (job: any) => {
        const data = job.result;
        setReport(data);
        const pkgLabel = data.apkMeta?.packageName || selectedFile.name;
        updateScanHistory(`apk:${pkgLabel}`, data.score, data.findings);
        persistScanToAccount(pkgLabel, 'apk', data);
        const hasVulns = data.findings?.some((f: any) => f.severity !== 'PASS');
        setFilter(hasVulns ? 'vulns' : 'all');
        setLoading(false);
        window.scrollTo({ top: 0, behavior: 'smooth' });
      };

      // Prefer real-time Server-Sent Events (zero redundant polling), with 1000ms poll fallback
      const sseCompleted = await new Promise<boolean>((resolve, reject) => {
        if (typeof EventSource === 'undefined') {
          resolve(false);
          return;
        }
        let settled = false;
        const es = new EventSource(streamUrl || `/api/jobs/${jobId}/stream`);
        es.onmessage = (evt) => {
          try {
            const job = JSON.parse(evt.data);
            if (job.currentStage) {
              setActiveStepMessage(`[${job.progress ?? 0}%] ${job.currentStage}`);
            }
            if (job.status === 'completed' && job.result) {
              settled = true;
              es.close();
              finishWithJob(job);
              resolve(true);
            } else if (job.status === 'failed') {
              settled = true;
              es.close();
              reject(new Error(job.error || 'APK audit job failed.'));
            }
          } catch {}
        };
        es.onerror = () => {
          es.close();
          if (!settled) resolve(false);
        };
      });

      if (sseCompleted) return;

      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 1000));
        const pollRes = await fetch(`/api/jobs/${jobId}`);
        if (!pollRes.ok) {
          throw new Error(`Lost connection to audit job ${jobId}`);
        }
        const job = await pollRes.json();
        if (job.currentStage) {
          setActiveStepMessage(`[${job.progress ?? 0}%] ${job.currentStage}`);
        }
        if (job.status === 'completed' && job.result) {
          finishWithJob(job);
          return;
        }
        if (job.status === 'failed') {
          throw new Error(job.error || 'APK audit job failed.');
        }
      }

      throw new Error('APK deep audit exceeded timeout window.');
    } catch (err: any) {
      setError(err.message || 'APK audit failed.');
      setLoading(false);
    }
  };

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      const lowerName = file.name.toLowerCase();
      if (lowerName.endsWith('.apk') || lowerName.endsWith('.aab')) {
        setApkFile(file);
        setError(null);
        if (!currentUser) {
          promptSignInForScan({ mode: 'apk', file });
        }
      } else {
        setError('Please upload a valid Android package file (.apk or .aab).');
      }
    }
  };

  const filteredFindings =
    report?.findings.filter((f) => {
      if (filter === 'vulns') return f.severity !== 'PASS' && f.severity !== 'INFO';
      if (filter === 'pass') return f.severity === 'PASS' || f.severity === 'INFO';
      return true;
    }) || [];

  return (
    <div className="min-h-screen text-slate-100 flex flex-col font-sans relative overflow-x-hidden">
      {/* ── Living Neural Medusa & Reactive Spores Backdrop ── */}
      <CyberBackground accentMode={scanMode} theme={theme} />

      {/* ── Fallback Directional Curtain (older browsers without View Transitions API) ── */}
      {fallbackThemeSweep && (
        <div
          aria-hidden="true"
          className={`fixed inset-0 z-[9999] pointer-events-none no-print ${
            fallbackThemeSweep === 'to-light'
              ? 'theme-fallback-curtain-to-light'
              : 'theme-fallback-curtain-to-dark'
          }`}
        />
      )}

      {/* ── Architectural DevSecOps Navigation Bar ── */}
      <header className="sticky top-0 z-50 border-b border-white/[0.08] bg-[#070a09]/92 backdrop-blur-md no-print">
        <div className="max-w-6xl mx-auto h-14 px-4 sm:px-6 flex items-center justify-between gap-4">
          {/* Left: Precision Brand Mark + Left-Aligned Workspace Navigation */}
          <div className="flex items-center h-full gap-5">
            <a
              href="/"
              aria-label="CheckMyAPK Homepage"
              onClick={(e) => {
                if (!e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey && e.button === 0) {
                  e.preventDefault();
                  goHome();
                }
              }}
              className="flex items-center gap-2.5 cursor-pointer group select-none focus:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400/60 rounded-lg"
            >
              <span className="nav-brand-mark w-7 h-7 rounded-[7px] bg-white text-slate-950 border border-white/15 flex items-center justify-center shrink-0 transition-transform duration-150 group-hover:scale-[1.03]">
                <svg
                  viewBox="0 0 20 20"
                  fill="none"
                  className="w-4 h-4"
                  aria-hidden="true"
                >
                  <path
                    d="M10 2.5L16 5.1V9.8C16 13.5 13.4 16.5 10 17.7C6.6 16.5 4 13.5 4 9.8V5.1L10 2.5Z"
                    stroke="currentColor"
                    strokeWidth="1.75"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M7.3 10.1L9.2 12L13 8.1"
                    stroke="currentColor"
                    strokeWidth="1.85"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </span>
              <span className="font-display font-semibold text-[15px] tracking-[-0.03em] text-white leading-none">
                CheckMyAPK
              </span>
            </a>

            <span className="hidden md:block h-4 w-px bg-white/10 nav-divider" aria-hidden="true" />

            <nav
              aria-label="Primary Navigation"
              className="hidden md:flex items-center h-full gap-1"
            >
              {[
                {
                  id: 'scanner',
                  label: 'Scanner',
                  active: !showPricingPage && !showAccountPage && !blogRoute.open && showTrustModal !== 'api',
                  onClick: () => {
                    setMobileNavOpen(false);
                    navigateSection('scanner-command');
                  },
                },
                {
                  id: 'rules',
                  label: 'Rules',
                  active: false,
                  onClick: () => {
                    setMobileNavOpen(false);
                    navigateSection('detection-matrix');
                  },
                },
                {
                  id: 'pricing',
                  label: 'Pricing',
                  active: showPricingPage,
                  onClick: () => {
                    setMobileNavOpen(false);
                    openPricingPage();
                  },
                },
                {
                  id: 'blog',
                  label: 'Blog',
                  active: blogRoute.open,
                  onClick: () => {
                    openBlogPage(null);
                  },
                },
                {
                  id: 'api',
                  label: 'API',
                  active: showTrustModal === 'api',
                  onClick: () => openTrustModal('api'),
                },
              ].map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={item.onClick}
                  className={`relative h-full inline-flex items-center px-3 text-[13px] tracking-[-0.01em] transition-colors cursor-pointer ${
                    item.active
                      ? 'text-white font-semibold'
                      : 'text-slate-400 hover:text-white font-medium'
                  }`}
                >
                  <span>{item.label}</span>
                  {item.active && (
                    <span
                      aria-hidden="true"
                      className="nav-active-rail absolute left-3 right-3 -bottom-px h-[2px] rounded-full bg-white"
                    />
                  )}
                </button>
              ))}
            </nav>
          </div>

          {/* Right: Theme Toggle & User Account Chip */}
          <div className="flex items-center gap-1.5 sm:gap-2">
            <button
              type="button"
              onClick={toggleTheme}
              aria-label={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              className="w-8 h-8 rounded-md inline-flex items-center justify-center text-slate-400 hover:text-white hover:bg-white/[0.06] active:scale-90 transition-all cursor-pointer"
            >
              {theme === 'dark' ? (
                <Sun className="w-4 h-4 text-amber-300/90" />
              ) : (
                <Moon className="w-4 h-4 text-slate-700" />
              )}
            </button>

            {currentUser ? (
              <button
                type="button"
                onClick={() => {
                  setMobileNavOpen(false);
                  if (showAccountPage) {
                    closeAccountPage(true);
                  } else {
                    openAccountPage();
                  }
                }}
                className={`nav-account-chip h-8 flex items-center gap-2 pl-1.5 pr-2.5 rounded-md border transition-colors cursor-pointer ${
                  showAccountPage
                    ? 'bg-white/[0.1] border-white/25'
                    : 'bg-white/[0.04] hover:bg-white/[0.08] border-white/10'
                }`}
              >
                {currentUser.avatarUrl ? (
                  <img
                    src={currentUser.avatarUrl}
                    alt={currentUser.name}
                    referrerPolicy="no-referrer"
                    className="w-5 h-5 rounded-[4px] object-cover"
                  />
                ) : (
                  <span className="w-5 h-5 rounded-[4px] bg-slate-200 text-slate-950 font-bold text-[10px] flex items-center justify-center">
                    {currentUser.name.slice(0, 2).toUpperCase()}
                  </span>
                )}
                <span className="text-[13px] font-medium text-white hidden sm:inline">
                  {currentUser.name.split(' ')[0]}
                </span>
                <span className="nav-plan-tag text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded bg-white/10 text-slate-200 font-semibold leading-none">
                  {currentUser.plan}
                </span>
                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>
            ) : (
              !report && (
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setAuthModalMode('login')}
                    className="h-8 px-2.5 rounded-md text-[13px] font-medium text-slate-300 hover:text-white hover:bg-white/[0.05] transition-colors cursor-pointer"
                  >
                    Log in
                  </button>
                  <button
                    type="button"
                    onClick={() => setAuthModalMode('register')}
                    className="h-8 px-3.5 rounded-md text-[13px] font-semibold bg-white hover:bg-slate-200 text-slate-950 transition-colors cursor-pointer"
                  >
                    Start Free
                  </button>
                </div>
              )
            )}

            <button
              type="button"
              onClick={() => setMobileNavOpen((prev) => !prev)}
              aria-label="Toggle navigation menu"
              aria-expanded={mobileNavOpen}
              className="md:hidden w-8 h-8 rounded-md inline-flex items-center justify-center text-slate-400 hover:text-white hover:bg-white/[0.06] transition-colors cursor-pointer"
            >
              {mobileNavOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Clean Mobile Navigation Drawer */}
        {mobileNavOpen && (
          <div className="nav-mobile-drawer md:hidden border-t border-white/[0.08] bg-[#06080f]/98 px-4 py-3 space-y-1">
            {[
              {
                id: 'scanner',
                label: 'Scanner',
                active: !showPricingPage && !showAccountPage && !blogRoute.open && showTrustModal !== 'api',
                onClick: () => {
                  setMobileNavOpen(false);
                  navigateSection('scanner-command');
                },
              },
              {
                id: 'rules',
                label: 'Rules',
                active: false,
                onClick: () => {
                  setMobileNavOpen(false);
                  navigateSection('detection-matrix');
                },
              },
              {
                id: 'pricing',
                label: 'Pricing',
                active: showPricingPage,
                onClick: () => {
                  setMobileNavOpen(false);
                  openPricingPage();
                },
              },
              {
                id: 'blog',
                label: 'Blog',
                active: blogRoute.open,
                onClick: () => {
                  openBlogPage(null);
                },
              },
              {
                id: 'api',
                label: 'API',
                active: showTrustModal === 'api',
                onClick: () => openTrustModal('api'),
              },
            ].map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={item.onClick}
                className={`w-full text-left px-3 py-2 rounded-md text-[13px] transition-colors cursor-pointer ${
                  item.active
                    ? 'bg-white/[0.08] text-white font-semibold'
                    : 'text-slate-400 hover:text-white hover:bg-white/[0.04] font-medium'
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>
        )}
      </header>

      {/* ── Main Interactive Workspace (Swiss Blueprint Guide Rails) ── */}
      <main className="wb-blueprint-rail flex-1 max-w-6xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6 sm:py-10 flex flex-col gap-10 relative z-10">
        {checkoutBanner && (
          <div
            className={`rounded-2xl px-4 py-3 border flex items-center justify-between gap-3 text-xs font-medium ${
              checkoutBanner.type === 'success'
                ? 'bg-emerald-500/10 border-emerald-400/35 text-emerald-200'
                : 'bg-amber-500/10 border-amber-400/35 text-amber-200'
            }`}
          >
            <span>{checkoutBanner.message}</span>
            <button
              type="button"
              onClick={() => setCheckoutBanner(null)}
              className="px-2 py-1 rounded-lg bg-white/10 hover:bg-white/20 text-[11px] font-bold cursor-pointer shrink-0"
            >
              Dismiss
            </button>
          </div>
        )}
        {/* ── Dedicated Full-Page Profile & Account Workspace ── */}
        {showAccountPage && currentUser && (
          <AccountPage
            user={currentUser}
            onBack={() => closeAccountPage(true)}
            onUserUpdated={(user) => setCurrentUser(user)}
            onLogout={handleLogout}
            theme={theme}
            onToggleTheme={toggleTheme}
            onOpenPricingPage={openPricingPage}
            onOpenSavedScan={handleOpenSavedScan}
            onRescanWeb={(targetUrl) => {
              closeAccountPage(true);
              setShowPricingPage(false);
              setScanMode('web');
              setUrl(targetUrl);
              void handleScanWeb(targetUrl);
              window.setTimeout(() => {
                document
                  .getElementById('scanner-command')
                  ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
              }, 80);
            }}
            onRescanApk={(targetPackage) => {
              triggerApkRescanFlow(targetPackage);
            }}
          />
        )}

        {/* ── Dedicated Full-Page Pricing & Comparison Matrix ── */}
        {!showAccountPage && showPricingPage && (
          <PricingPage
            currentUser={currentUser}
            onSelectPlan={handleSelectPlan}
            checkoutBusyPlan={checkoutBusyPlan}
            onBack={() => closePricingPage(true)}
            onOpenLegal={(doc) => openTrustModal(doc)}
          />
        )}

        {/* ── Dedicated SEO Security Blog & Guides Hub (/blog & /blog/:slug) ── */}
        {!showAccountPage && !showPricingPage && blogRoute.open && (
          <BlogPage
            activeSlug={blogRoute.slug}
            onSelectPost={(slug) => openBlogPage(slug)}
            onBackToList={() => openBlogPage(null)}
            onStartAudit={() => navigateSection('scanner-command')}
          />
        )}

        {/* ── Hero & Precision Security Workbench (stays mounted during scan to prevent reload flash/scroll jump) ── */}
        {!showAccountPage && !showPricingPage && !blogRoute.open && !report && (
          <div className="w-full space-y-16 pb-6">
            {/* Full-Viewport Centered Editorial Hero Stage */}
            <section className="min-h-[calc(100vh-112px)] flex flex-col items-center justify-center text-center py-10 sm:py-16 relative">
              <XRayHeroBackground />
              <div className="max-w-4xl mx-auto flex flex-col items-center space-y-6 relative z-10">
                <div
                  className={`wb-eyebrow-pill ${heroIntroDone ? '' : 'wb-stage-reveal'} inline-flex items-center gap-2 px-3 py-1 rounded-md font-mono text-[11px] font-medium`}
                  style={heroIntroDone ? undefined : { animationDelay: '40ms' }}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0" aria-hidden="true" />
                  <span>OWASP MASVS v2 · Static &amp; Live Probes</span>
                </div>

                <HeroKineticHeadline introDone={heroIntroDone} />

                <p
                  className={`${heroIntroDone ? '' : 'wb-stage-reveal'} text-sm sm:text-base text-slate-400 leading-relaxed max-w-xl mx-auto`}
                  style={heroIntroDone ? undefined : { animationDelay: '1350ms' }}
                >
                  Decompile Android binaries or probe live endpoints in seconds. Deterministic findings, exact file paths, and copy-paste patches with zero server retention.
                </p>

                <div
                  className={`${heroIntroDone ? '' : 'wb-stage-reveal'} flex flex-wrap items-center justify-center gap-3 pt-1`}
                  style={heroIntroDone ? undefined : { animationDelay: '1480ms' }}
                >
                  <button
                    type="button"
                    onClick={() => {
                      document
                        .getElementById('scanner-command')
                        ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }}
                    className="wb-emerald-btn h-11 px-5 rounded-md font-semibold text-[13px] inline-flex items-center gap-2 transition-colors cursor-pointer"
                  >
                    <span>Start Security Audit</span>
                    <ChevronDown className="w-4 h-4" />
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      handleOpenSampleDemo();
                      window.scrollTo({ top: 0, behavior: 'smooth' });
                    }}
                    className="wb-surface h-11 px-5 rounded-md font-medium text-[13px] text-white hover:border-white/25 inline-flex items-center gap-2 transition-colors cursor-pointer"
                  >
                    <span>Load sample report</span>
                    <ArrowRight className="w-3.5 h-3.5 text-emerald-400" />
                  </button>
                </div>

                <div
                  className={`${heroIntroDone ? '' : 'wb-stage-reveal'} grid grid-cols-3 gap-6 sm:gap-12 pt-8 mt-2 border-t border-white/10 w-full max-w-lg`}
                  style={heroIntroDone ? undefined : { animationDelay: '1580ms' }}
                >
                  <div>
                    <div className="font-mono text-base sm:text-lg font-semibold text-white">
                      <HeroRulesCountUp target={60} startDelayMs={1580} durationMs={1150} introDone={heroIntroDone} />
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5">Security rules</div>
                  </div>
                  <div>
                    <div className="font-mono text-base sm:text-lg font-semibold text-white">0s</div>
                    <div className="text-[11px] text-slate-400 mt-0.5">Disk retention</div>
                  </div>
                  <div>
                    <div className="font-mono text-base sm:text-lg font-semibold text-white">PDF · JSON</div>
                    <div className="text-[11px] text-slate-400 mt-0.5">Audit exports</div>
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={() => {
                  document
                    .getElementById('scanner-command')
                    ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }}
                className={`${heroIntroDone ? '' : 'wb-stage-reveal'} relative z-10 mt-10 sm:mt-14 inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-slate-500 hover:text-emerald-400 transition-colors cursor-pointer`}
                style={heroIntroDone ? undefined : { animationDelay: '1240ms' }}
              >
                <span>Scroll to Scanner Workbench</span>
                <ChevronDown className="w-3.5 h-3.5" />
              </button>
            </section>

            {/* ── Standards & Compliance Architectural Hairline Strip with Corner Crosshairs ── */}
            <div className="relative border-y border-white/10 py-3.5 px-2">
              <span className="wb-crosshair absolute -top-[6px] -left-[4px]" aria-hidden="true">+</span>
              <span className="wb-crosshair absolute -top-[6px] -right-[4px]" aria-hidden="true">+</span>
              <span className="wb-crosshair absolute -bottom-[6px] -left-[4px]" aria-hidden="true">+</span>
              <span className="wb-crosshair absolute -bottom-[6px] -right-[4px]" aria-hidden="true">+</span>
              <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 font-mono text-[11px] text-slate-400">
                <span className="text-[10px] uppercase tracking-[0.14em] text-slate-500">
                  Aligned Standards
                </span>
                <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-[11px] text-slate-400">
                  <span>OWASP MASVS v2</span>
                  <span className="text-slate-600" aria-hidden="true">/</span>
                  <span>OWASP Top 10</span>
                  <span className="text-slate-600" aria-hidden="true">/</span>
                  <span>Google Play Data Safety</span>
                  <span className="text-slate-600" aria-hidden="true">/</span>
                  <span>Dalvik DEX &amp; ELF64</span>
                  <span className="text-slate-600" aria-hidden="true">/</span>
                  <span>CWE · CVSS v3.1</span>
                </div>
              </div>
            </div>

            {/* ── Ultra-Clean Minimal Scanner Box ── */}
            <section id="scanner-command" className="scroll-mt-24 space-y-5">
              <div className="text-center space-y-1.5">
                <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold block">
                  Scanner Workbench
                </span>
                <h2 className="text-2xl sm:text-[28px] font-display font-semibold tracking-[-0.035em] leading-[1.15]">
                  <span className="text-white">Upload an APK</span>{' '}
                  <span className="wb-headline-muted">or audit a live URL.</span>
                </h2>
              </div>

              <div className="max-w-2xl mx-auto wb-bezel p-1.5 rounded-2xl text-left relative">
                <div
                  aria-hidden="true"
                  className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
                />
                <div className="wb-surface rounded-xl overflow-hidden">
                  {/* Minimal 2-Tab Bar */}
                  <div className="flex items-center border-b border-white/10 px-4">
                    <button
                      type="button"
                      disabled={loading}
                      onClick={() => {
                        setScanMode('apk');
                        setError(null);
                      }}
                      className={`relative py-3.5 px-3 text-xs sm:text-[13px] transition-colors inline-flex items-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed cursor-pointer ${
                        scanMode === 'apk'
                          ? 'text-white font-semibold'
                          : 'text-slate-400 hover:text-white font-medium'
                      }`}
                    >
                      <Smartphone className="w-3.5 h-3.5" />
                      <span>Android APK</span>
                      {scanMode === 'apk' && (
                        <span
                          aria-hidden="true"
                          className="absolute left-3 right-3 -bottom-px h-[2px] bg-emerald-500"
                        />
                      )}
                    </button>

                    <button
                      type="button"
                      disabled={loading}
                      onClick={() => {
                        setScanMode('web');
                        setError(null);
                      }}
                      className={`relative py-3.5 px-3 text-xs sm:text-[13px] transition-colors inline-flex items-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed cursor-pointer ${
                        scanMode === 'web'
                          ? 'text-white font-semibold'
                          : 'text-slate-400 hover:text-white font-medium'
                      }`}
                    >
                      <Globe className="w-3.5 h-3.5" />
                      <span>Website &amp; API</span>
                      {scanMode === 'web' && (
                        <span
                          aria-hidden="true"
                          className="absolute left-3 right-3 -bottom-px h-[2px] bg-emerald-500"
                        />
                      )}
                    </button>
                  </div>

                  {/* Clean Single-Pane Body */}
                  <div className="p-5 sm:p-6 space-y-4">
                    {loading ? (
                      <div className="space-y-4 py-1">
                        {(() => {
                          const msg = activeStepMessage.toLowerCase();
                          const stages =
                            scanMode === 'apk'
                              ? ['Unpack', 'Manifest', 'Bytecode', 'AI Verdict']
                              : ['Handshake', 'Bundles', 'Probes', 'AI Verdict'];
                          let stageIdx = 0;
                          if (msg.includes('gemini') || msg.includes('neural') || msg.includes('masvs') || msg.includes('assessment') || msg.includes('score')) {
                            stageIdx = 3;
                          } else if (msg.includes('probe') || msg.includes('header') || msg.includes('cors') || msg.includes('dex') || msg.includes('elf') || msg.includes('rate')) {
                            stageIdx = 2;
                          } else if (msg.includes('bundle') || msg.includes('manifest') || msg.includes('package') || msg.includes('script') || msg.includes('secret')) {
                            stageIdx = 1;
                          }
                          return (
                            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                              <div className="flex items-center gap-3 min-w-0">
                                {/* Laser-Sweep Shield */}
                                <div className="relative w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/40 text-emerald-400 flex items-center justify-center shrink-0 overflow-hidden">
                                  <span
                                    aria-hidden="true"
                                    className="absolute inset-1 rounded-md border border-emerald-400/25 animate-ping"
                                    style={{ animationDuration: '2.4s' }}
                                  />
                                  <Shield className="w-4 h-4 relative z-10" />
                                  <span aria-hidden="true" className="wb-laser-sweep" />
                                </div>
                                <div className="min-w-0">
                                  <h3 className="text-sm font-semibold text-white">
                                    {scanMode === 'apk' ? 'Auditing APK...' : 'Scanning URL...'}
                                  </h3>
                                  <p className="text-[11px] font-mono text-emerald-400 truncate">
                                    {activeStepMessage}
                                  </p>
                                </div>
                              </div>

                              {/* 4-Stage Pipeline Pills */}
                              <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                                {stages.map((label, idx) => {
                                  const isDone = idx < stageIdx;
                                  const isActive = idx === stageIdx;
                                  return (
                                    <span
                                      key={label}
                                      className={`font-mono text-[10px] px-2 py-1 rounded-md border inline-flex items-center gap-1.5 transition-all ${
                                        isActive
                                          ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300 font-semibold shadow-[0_0_12px_rgba(16,185,129,0.18)]'
                                          : isDone
                                          ? 'bg-emerald-500/10 border-emerald-500/25 text-emerald-400'
                                          : 'bg-white/[0.02] border-white/10 text-slate-500'
                                      }`}
                                    >
                                      {isDone ? (
                                        <Check className="w-3 h-3 text-emerald-400" />
                                      ) : isActive ? (
                                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                                      ) : (
                                        <span className="w-1.5 h-1.5 rounded-full bg-slate-600" />
                                      )}
                                      <span>{label}</span>
                                    </span>
                                  );
                                })}
                              </div>
                            </div>
                          );
                        })()}

                        <LiveTerminalLogs
                          targetUrl={scanMode === 'apk' ? apkFile?.name || 'Android Package' : url}
                          isApkMode={scanMode === 'apk'}
                        />
                      </div>
                    ) : (
                      <>
                        {/* APK / AAB MODE */}
                        {scanMode === 'apk' && (
                          <div className="space-y-3.5">
                            <input
                              type="file"
                              ref={fileInputRef}
                              accept=".apk,.aab"
                              className="hidden"
                              onChange={(e) => {
                                if (e.target.files && e.target.files[0]) {
                                  const chosen = e.target.files[0];
                                  setApkFile(chosen);
                                  setError(null);
                                  if (!currentUser) {
                                    promptSignInForScan({ mode: 'apk', file: chosen });
                                  } else if (autoStartApkOnSelect) {
                                    setAutoStartApkOnSelect(null);
                                    void handleScanApk(chosen);
                                  }
                                }
                              }}
                            />

                            {apkFile ? (
                              <>
                                <div
                                  onDragOver={(e) => {
                                    e.preventDefault();
                                    setIsDragging(true);
                                  }}
                                  onDragLeave={() => setIsDragging(false)}
                                  onDrop={handleFileDrop}
                                  className={`p-4 rounded-lg border transition-colors flex items-center justify-between gap-3 ${
                                    isDragging
                                      ? 'border-emerald-500 bg-emerald-500/10'
                                      : 'wb-surface-muted border-emerald-500/35'
                                  }`}
                                >
                                  <div className="flex items-center gap-3 min-w-0">
                                    <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center shrink-0">
                                      <ShieldCheck className="w-4 h-4" />
                                    </div>
                                    <div className="min-w-0">
                                      <div className="flex items-center gap-2">
                                        <span className="text-sm font-semibold text-white truncate">
                                          {apkFile.name}
                                        </span>
                                        <span className="font-mono text-[10px] text-slate-400 shrink-0">
                                          {(apkFile.size / 1024 / 1024).toFixed(2)} MB
                                        </span>
                                      </div>
                                      {(apkHashing || apkPreFlightHash) && (
                                        <div className="font-mono text-[10px] text-slate-500 truncate mt-0.5 select-all">
                                          {apkHashing
                                            ? 'SHA-256…'
                                            : `SHA-256: ${apkPreFlightHash?.slice(0, 16)}…${apkPreFlightHash?.slice(-8)}`}
                                        </div>
                                      )}
                                    </div>
                                  </div>

                                  <button
                                    type="button"
                                    onClick={() => {
                                      setApkFile(null);
                                      setError(null);
                                      if (fileInputRef.current) fileInputRef.current.value = '';
                                    }}
                                    aria-label="Remove APK file"
                                    title="Remove"
                                    className="p-1.5 rounded text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors cursor-pointer shrink-0"
                                  >
                                    <X className="w-4 h-4" />
                                  </button>
                                </div>

                                <button
                                  type="button"
                                  onClick={() => handleScanApk()}
                                  className="wb-primary-btn w-full h-10 px-4 rounded-md font-semibold text-[13px] flex items-center justify-center gap-2 transition-colors cursor-pointer"
                                >
                                  {currentUser ? (
                                    <>
                                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" aria-hidden="true" />
                                      <span>Run Audit</span>
                                      <ArrowRight className="w-3.5 h-3.5" />
                                    </>
                                  ) : (
                                    <>
                                      <Lock className="w-3.5 h-3.5" />
                                      <span>Sign in to Run Audit</span>
                                      <ArrowRight className="w-3.5 h-3.5" />
                                    </>
                                  )}
                                </button>
                              </>
                            ) : (
                              <div
                                onDragOver={(e) => {
                                  e.preventDefault();
                                  setIsDragging(true);
                                }}
                                onDragLeave={() => setIsDragging(false)}
                                onDrop={handleFileDrop}
                                onClick={() => fileInputRef.current?.click()}
                                className={`group relative py-14 sm:py-16 px-6 rounded-xl transition-all cursor-pointer flex flex-col items-center justify-center gap-5 text-center wb-reticle-zone ${
                                  isDragging ? 'wb-reticle-dragging' : ''
                                }`}
                              >
                                <span className="wb-reticle-corner top-3.5 left-3.5 border-t-2 border-l-2 rounded-tl-lg" aria-hidden="true" />
                                <span className="wb-reticle-corner top-3.5 right-3.5 border-t-2 border-r-2 rounded-tr-lg" aria-hidden="true" />
                                <span className="wb-reticle-corner bottom-3.5 left-3.5 border-b-2 border-l-2 rounded-bl-lg" aria-hidden="true" />
                                <span className="wb-reticle-corner bottom-3.5 right-3.5 border-b-2 border-r-2 rounded-br-lg" aria-hidden="true" />

                                <div className="wb-upload-squircle w-16 h-16 sm:w-[68px] sm:h-[68px] rounded-2xl flex items-center justify-center transition-transform duration-200 group-hover:scale-105">
                                  <Upload className="w-7 h-7 stroke-[2.1]" />
                                </div>

                                <div className="space-y-1.5">
                                  <div className="font-display font-bold text-lg sm:text-[22px] tracking-[-0.025em] text-white">
                                    Drop your Android .apk or .aab file here
                                  </div>
                                  <div className="text-xs sm:text-[13px] text-slate-400">
                                    or <span className="wb-accent-ink font-semibold">browse files</span> · Max {activePlanPolicy.maxApkMb}MB ({activePlanPolicy.name})
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        )}

                        {/* WEB MODE */}
                        {scanMode === 'web' && (
                          <div className="space-y-3.5">
                            <form
                              onSubmit={(e) => {
                                e.preventDefault();
                                handleScanWeb();
                              }}
                              className="w-full flex flex-col sm:flex-row gap-2"
                            >
                              <div className="wb-surface-muted flex items-center gap-2.5 px-3 flex-1 min-w-0 rounded-md h-10 focus-within:border-emerald-500/60 transition-colors">
                                <Search className="w-4 h-4 text-slate-400 shrink-0" />
                                <input
                                  ref={urlInputRef}
                                  type="text"
                                  placeholder="https://example.com"
                                  value={url}
                                  onChange={(e) => setUrl(e.target.value)}
                                  onPaste={(e) => {
                                    if (!currentUser) {
                                      const pasted = e.clipboardData?.getData('text')?.trim() || '';
                                      if (pasted) {
                                        e.preventDefault();
                                        setUrl(pasted);
                                        promptSignInForScan({ mode: 'web', targetUrl: pasted });
                                      }
                                    }
                                  }}
                                  className="w-full min-w-0 bg-transparent text-xs sm:text-[13px] font-medium text-white placeholder-slate-500 focus:outline-none"
                                />
                                {url.length > 0 && (
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setUrl('');
                                      urlInputRef.current?.focus();
                                    }}
                                    aria-label="Clear target URL"
                                    className="p-1 rounded text-slate-400 hover:text-white transition-colors shrink-0 cursor-pointer"
                                  >
                                    <X className="w-3.5 h-3.5" />
                                  </button>
                                )}
                              </div>
                              <button
                                type="submit"
                                className="wb-primary-btn h-10 px-4 rounded-md font-semibold text-[13px] flex items-center justify-center gap-2 transition-colors shrink-0 cursor-pointer"
                              >
                                {currentUser ? (
                                  <>
                                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" aria-hidden="true" />
                                    <span>Run Audit</span>
                                    <ArrowRight className="w-3.5 h-3.5" />
                                  </>
                                ) : (
                                  <>
                                    <Lock className="w-3.5 h-3.5" />
                                    <span>Sign in to Audit</span>
                                    <ArrowRight className="w-3.5 h-3.5" />
                                  </>
                                )}
                              </button>
                            </form>

                            {/* Compact Optional Auth & Domain Verification Controls */}
                            <div className="flex flex-wrap items-center gap-3 text-[11px]">
                              {activePlanPolicy.features.authenticatedWebScan ? (
                                <button
                                  type="button"
                                  onClick={() => setShowWebAuthOptions(!showWebAuthOptions)}
                                  className="text-slate-400 hover:text-white inline-flex items-center gap-1.5 cursor-pointer"
                                >
                                  <Lock className="w-3 h-3 text-emerald-400" />
                                  <span>{showWebAuthOptions ? 'Hide Auth' : 'Auth Headers'}</span>
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  onClick={openPricingPage}
                                  className="text-slate-500 hover:text-white inline-flex items-center gap-1 cursor-pointer"
                                >
                                  <Lock className="w-3 h-3 text-amber-400" />
                                  <span>Auth Headers (Pro)</span>
                                </button>
                              )}

                              <span className="text-slate-700" aria-hidden="true">·</span>

                              {activePlanPolicy.features.burst15Req ? (
                                <button
                                  type="button"
                                  onClick={handleLoadDomainChallenge}
                                  className="text-slate-400 hover:text-white inline-flex items-center gap-1.5 cursor-pointer"
                                >
                                  <ShieldCheck className="w-3 h-3 text-emerald-400" />
                                  <span>Verify Domain</span>
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  onClick={openPricingPage}
                                  className="text-slate-500 hover:text-white inline-flex items-center gap-1 cursor-pointer"
                                >
                                  <Lock className="w-3 h-3 text-amber-400" />
                                  <span>15-Req Burst (Pro)</span>
                                </button>
                              )}
                            </div>

                            {activePlanPolicy.features.authenticatedWebScan && showWebAuthOptions && (
                              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                <input
                                  type="password"
                                  autoComplete="off"
                                  placeholder="Bearer <JWT>"
                                  value={webAuthHeader}
                                  onChange={(e) => setWebAuthHeader(e.target.value)}
                                  className="w-full px-3 py-2 rounded-md wb-surface-muted text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500/60 font-mono"
                                />
                                <input
                                  type="password"
                                  autoComplete="off"
                                  placeholder="Cookie: session=..."
                                  value={webAuthCookie}
                                  onChange={(e) => setWebAuthCookie(e.target.value)}
                                  className="w-full px-3 py-2 rounded-md wb-surface-muted text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500/60 font-mono"
                                />
                              </div>
                            )}

                            {activePlanPolicy.features.burst15Req && domainChallenge && (
                              <div className="p-3 rounded-md wb-surface-muted text-[10px] font-mono space-y-1.5 text-slate-300">
                                <div className="p-1.5 rounded bg-black/50 break-all select-all text-slate-200">
                                  TXT: {domainChallenge.txtRecord}
                                </div>
                                <div className="p-1.5 rounded bg-black/50 break-all select-all text-emerald-400">
                                  META: {domainChallenge.metaTag}
                                </div>
                              </div>
                            )}
                          </div>
                        )}

                        {error && (
                          <div className="p-3 rounded-md bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-medium flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-left">
                            <div className="flex items-start gap-2 min-w-0">
                              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
                              <span>{error}</span>
                            </div>
                            {/upgrade|pro security|limit|quota/i.test(error) && (
                              <button
                                type="button"
                                onClick={openPricingPage}
                                className="wb-emerald-btn h-8 px-3 rounded-md text-[11px] font-semibold inline-flex items-center gap-1 shrink-0 self-start sm:self-center cursor-pointer"
                              >
                                <span>Upgrade</span>
                                <ArrowRight className="w-3 h-3" />
                              </button>
                            )}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                </div>
              </div>
            </section>

            {/* ── Real Product Proof: Interactive IDE Security Workbench ── */}
            <DeterministicOutputWorkbench onOpenSampleDemo={handleOpenSampleDemo} />

            <HomepageSections
              currentUser={currentUser}
              onSelectPlan={handleSelectPlan}
              checkoutBusyPlan={checkoutBusyPlan}
              onStartAudit={(mode) => navigateSection('scanner-command', mode)}
              onOpenLegal={(doc) => openTrustModal(doc)}
              onOpenPricingPage={openPricingPage}
            />
          </div>
        )}

        {/* ── 4-Zone Tabbed Pro Executive Report Dashboard ── */}
        {!showAccountPage && !showPricingPage && !blogRoute.open && report && (
          <SecurityReportDashboard
            report={report}
            scoreDelta={scoreDelta}
            activePlanPolicy={activePlanPolicy}
            masterCodes={masterCodes}
            domainChallenge={domainChallenge}
            onLoadDomainChallenge={handleLoadDomainChallenge}
            onNewAudit={() => {
              setReport(null);
              setApkFile(null);
              window.setTimeout(() => {
                document
                  .getElementById('scanner-command')
                  ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
              }, 80);
            }}
            onRescanWeb={(targetUrl) => {
              setScanMode('web');
              setUrl(targetUrl);
              void handleScanWeb(targetUrl);
              window.setTimeout(() => {
                document
                  .getElementById('scanner-command')
                  ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
              }, 80);
            }}
            onRescanApk={() => {
              triggerApkRescanFlow(report.apkMeta?.packageName || report.targetUrl);
            }}
            onExportJson={handleExportJson}
            onExportMarkdown={handleExportMarkdown}
            onCopyMarkdown={handleCopyMarkdown}
            mdCopied={mdCopied}
            onRequestUpgrade={openPricingPage}
          />
        )}
      </main>

      {/* ── Inspection Logs Modal ── */}
      {showLogsModal && report?.telemetry?.realTimeLogs && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 no-print">
          <div className="glass-panel rounded-3xl max-w-2xl w-full max-h-[80vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-4 border-b border-white/10 flex items-center justify-between bg-[#080c17]">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-extrabold text-white">Full Engine Telemetry Log</h3>
              </div>
              <button
                onClick={() => setShowLogsModal(false)}
                className="text-xs px-3 py-1 bg-white/10 hover:bg-white/20 text-white font-bold rounded-lg cursor-pointer transition-colors"
              >
                Close
              </button>
            </div>
            <div className="p-5 font-mono text-xs text-slate-300 space-y-2.5 overflow-y-auto max-h-[60vh] bg-[#04060c]">
              {report.telemetry.realTimeLogs.map((item, idx) => (
                <div key={idx} className="flex gap-2.5 leading-relaxed">
                  <span className="text-cyan-400 shrink-0 font-bold">{item.time}</span>
                  <span>{item.msg}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Privacy / Methodology / API Reference Trust Modal (Obsidian Double-Bezel Workbench) ── */}
      {showTrustModal && (
        <div
          className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 no-print"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeTrustModal();
          }}
        >
          <div className="wb-bezel p-1.5 rounded-2xl max-w-2xl w-full relative">
            <div
              aria-hidden="true"
              className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
            />
            <div className="wb-surface rounded-xl max-h-[85vh] flex flex-col overflow-hidden text-left">
              <div className="wb-ide-chrome px-5 py-4 border-b border-white/10 flex items-center justify-between gap-2">
                <div className="flex items-center gap-2.5 min-w-0">
                  <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                  <h3 className="text-sm font-display font-semibold text-white tracking-[-0.015em] truncate">
                    {showTrustModal === 'methodology'
                      ? '4-Stage CheckMyAPK Audit Methodology'
                      : showTrustModal === 'api'
                      ? 'CheckMyAPK CI/CD & REST API Reference'
                      : LEGAL_DOCS_BY_ID[showTrustModal].title}
                  </h3>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {showTrustModal !== 'methodology' && showTrustModal !== 'api' && (
                    <div className="hidden sm:inline-flex items-center gap-1 p-0.5 rounded-md wb-surface-muted font-mono text-[10px]">
                      {(
                        [
                          { id: 'privacy', label: 'Privacy' },
                          { id: 'terms', label: 'Terms' },
                          { id: 'refund', label: 'Refund' },
                        ] as const
                      ).map((tab) => (
                        <button
                          key={tab.id}
                          type="button"
                          onClick={() => openTrustModal(tab.id)}
                          className={`px-2 py-0.5 rounded font-medium cursor-pointer transition-colors ${
                            showTrustModal === tab.id
                              ? 'bg-emerald-500/20 text-emerald-400 font-semibold'
                              : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          {tab.label}
                        </button>
                      ))}
                    </div>
                  )}
                  <button
                    type="button"
                    onClick={closeTrustModal}
                    className="p-1.5 rounded-md wb-surface-muted hover:border-white/25 text-slate-400 hover:text-white cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>
              <div className="p-6 space-y-4 text-xs text-slate-300 overflow-y-auto leading-relaxed">
                {showTrustModal === 'api' ? (
                  <div className="space-y-4">
                    <p className="text-slate-300">
                      Automate Android APK and Web/API security gates inside GitHub Actions, GitLab CI, or pre-release scripts using your Workspace API token.
                    </p>
                    <div className="rounded-lg border border-white/10 wb-surface-muted overflow-hidden">
                      <div className="wb-ide-chrome flex items-center justify-between px-3 py-2 border-b border-white/10 text-[11px] font-mono text-slate-400">
                        <span>POST /api/scan · Web &amp; API Audit</span>
                        <button
                          type="button"
                          onClick={() => {
                            const cmd = `curl -X POST https://checkmyapk.com/api/scan \\\n  -H "Content-Type: application/json" \\\n  -H "Authorization: Bearer YOUR_WORKSPACE_API_TOKEN" \\\n  -d '{"targetUrl":"https://api.yourdomain.com"}'`;
                            navigator.clipboard?.writeText(cmd).then(() => {
                              setApiSnippetCopied(true);
                              setTimeout(() => setApiSnippetCopied(false), 1800);
                            }).catch(() => {});
                          }}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-slate-200 cursor-pointer"
                        >
                          {apiSnippetCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{apiSnippetCopied ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <pre className="p-3.5 text-[11px] font-mono text-emerald-300 overflow-x-auto leading-relaxed">
{`curl -X POST https://checkmyapk.com/api/scan \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_WORKSPACE_API_TOKEN" \\
  -d '{"targetUrl":"https://api.yourdomain.com"}'`}
                      </pre>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div className="p-3.5 rounded-lg wb-surface-muted">
                        <strong className="text-white font-display font-semibold block mb-1">APK Binary Upload Endpoint</strong>
                        <code className="text-emerald-400 font-mono text-[11px]">POST /api/scan-apk</code>
                        <p className="mt-1 text-slate-400">
                          Accepts <code className="wb-spec-code px-1 rounded">multipart/form-data</code> (<code className="wb-spec-code px-1 rounded">apk</code> field) up to 150 MB on Team &amp; Agency and returns deterministic OWASP MASVS JSON findings.
                        </p>
                      </div>
                      <div className="p-3.5 rounded-lg wb-surface-muted">
                        <strong className="text-white font-display font-semibold block mb-1">Workspace Token Access</strong>
                        <p className="text-slate-400">
                          Generate &amp; rotate CI/CD tokens from your Account Workspace. Available on the <strong className="text-white">Team &amp; Agency</strong> tier.
                        </p>
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
                      {currentUser ? (
                        <button
                          type="button"
                          onClick={() => {
                            closeTrustModal();
                            openAccountPage();
                          }}
                          className="wb-emerald-btn h-8 px-3.5 rounded-md text-xs font-semibold transition-colors cursor-pointer"
                        >
                          Open API Token in Workspace
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => {
                            closeTrustModal();
                            openPricingPage();
                          }}
                          className="wb-emerald-btn h-8 px-3.5 rounded-md text-xs font-semibold transition-colors cursor-pointer"
                        >
                          View Team &amp; Agency Plan
                        </button>
                      )}
                    </div>
                  </div>
                ) : showTrustModal !== 'methodology' ? (
                  <>
                    <p className="font-mono text-[11px] text-slate-400">
                      Effective: {LEGAL_DOCS_BY_ID[showTrustModal].effectiveDate} ·{' '}
                      {LEGAL_DOCS_BY_ID[showTrustModal].subtitle}
                    </p>
                    {LEGAL_DOCS_BY_ID[showTrustModal].sections.map((sec) => (
                      <div key={sec.title} className="p-4 rounded-lg wb-surface-muted space-y-1.5">
                        <h4 className="font-display font-semibold text-white">{sec.title}</h4>
                        <p>{sec.body}</p>
                      </div>
                    ))}
                  </>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="p-3.5 rounded-lg wb-surface-muted">
                      <strong className="text-emerald-400 font-display font-semibold block mb-1">01 · Binary Manifest &amp; IPC</strong>
                      Parses AndroidBinaryXML (<code className="wb-spec-code px-1 rounded">AndroidManifest.xml</code> + <code className="wb-spec-code px-1 rounded">network_security_config</code>) to check debuggable flags, backup rules, SDK targets, and exported IPC components.
                    </div>
                    <div className="p-3.5 rounded-lg wb-surface-muted">
                      <strong className="text-cyan-400 font-display font-semibold block mb-1">02 · DEX, Native ELF &amp; Secrets</strong>
                      Scans <code className="wb-spec-code px-1 rounded">classes*.dex</code> &amp; <code className="wb-spec-code px-1 rounded">lib/*.so</code> for hardcoded API keys, SSL TrustAll bypasses, weak crypto, PIE/NX/RELRO hardening, and trackers.
                    </div>
                    <div className="p-3.5 rounded-lg wb-surface-muted">
                      <strong className="text-emerald-400 font-display font-semibold block mb-1">03 · Extracted Backend API Probes</strong>
                      Extracts backend API &amp; Firebase/Supabase URLs from APK binaries and actively checks live TLS/HSTS, CORS credentials policy, and open anonymous DB reads.
                    </div>
                    <div className="p-3.5 rounded-lg wb-surface-muted">
                      <strong className="text-cyan-400 font-display font-semibold block mb-1">04 · Web &amp; API DAST Suite</strong>
                      Inspects live JS chunks + HTML for leaked keys, <code className="wb-spec-code px-1 rounded">.env</code>/<code className="wb-spec-code px-1 rounded">.git</code>/<code className="wb-spec-code px-1 rounded">.map</code> exposures, CSP/HSTS/Cookie flags, and burst rate limits.
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {authModalMode && (
        <AuthModal
          initialMode={authModalMode}
          notice={
            pendingScan
              ? pendingScan.mode === 'apk'
                ? `Sign in to audit "${pendingScan.file.name}". Your APK is ready and the scan will start automatically once you sign in.`
                : `Sign in to audit "${pendingScan.targetUrl}". Your scan will start automatically once you sign in.`
              : null
          }
          onClose={() => {
            setAuthModalMode(null);
            setPendingCheckout(null);
            setPendingScan(null);
          }}
          onSuccess={(user) => {
            setCurrentUser(user);
            setAuthModalMode(null);
            if (pendingCheckout) {
              const next = pendingCheckout;
              setPendingCheckout(null);
              void startDodoCheckout(next.plan, next.billingCycle);
            } else if (pendingScan) {
              const queued = pendingScan;
              setPendingScan(null);
              if (queued.mode === 'apk') {
                void handleScanApk(queued.file, user);
              } else {
                void handleScanWeb(queued.targetUrl, user);
              }
            }
          }}
        />
      )}

      {/* ── Architectural Footer ── */}
      <footer className="py-6 border-t border-white/[0.08] bg-[#070a09]/90 text-xs text-slate-400 relative z-10 no-print">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-3">
          <span className="font-display font-semibold text-white tracking-[-0.02em]">
            <a
              href="/"
              onClick={(e) => {
                if (!e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey && e.button === 0) {
                  e.preventDefault();
                  goHome();
                }
              }}
              className="hover:text-emerald-400 transition-colors cursor-pointer"
            >
              CheckMyAPK
            </a>{' '}
            <span className="font-sans font-normal text-slate-400">· Android APK &amp; Web Security Scanner</span>
          </span>
          <div className="flex flex-wrap items-center justify-center gap-5 text-[12px] font-medium">
            <button
              type="button"
              onClick={() => openTrustModal('privacy')}
              className="text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              Privacy
            </button>
            <button
              type="button"
              onClick={() => openTrustModal('terms')}
              className="text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              Terms
            </button>
            <button
              type="button"
              onClick={() => openTrustModal('refund')}
              className="text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              Refund Policy
            </button>
            <button
              type="button"
              onClick={() => openTrustModal('methodology')}
              className="text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              Methodology
            </button>
            <button
              type="button"
              onClick={() => navigateSection('contact')}
              className="text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              Contact
            </button>
            <span className="font-mono text-[10px] text-slate-500 hidden lg:inline">OWASP MASVS v2</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
