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
import { AccountPage } from './components/AccountPage';
import { HomepageSections } from './components/HomepageSections';
import { PricingPage } from './components/PricingPage';
import {
  LEGAL_DOCS_BY_ID,
  LEGAL_DOC_PATHS,
  resolveLegalDocFromUrl,
  type LegalDocId,
} from './data/legalDocs';
import type { AccountPlan, UserAccount } from './types/account';
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
  isApkAudit?: boolean;
  isDemoPreview?: boolean;
  apkMeta?: {
    fileName: string;
    sizeMb: string;
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
  const [previewFindingIdx, setPreviewFindingIdx] = useState(0);
  const [previewPatchCopied, setPreviewPatchCopied] = useState(false);
  const [cliCopied, setCliCopied] = useState(false);
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
  const [checkoutBusyPlan, setCheckoutBusyPlan] = useState<AccountPlan | null>(null);
  const [checkoutBanner, setCheckoutBanner] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);
  const [showAccountPage, setShowAccountPage] = useState(false);
  const isPricingLocation = (pathname: string, search: string) =>
    pathname.replace(/\/+$/, '') === '/pricing' ||
    new URLSearchParams(search).get('page') === 'pricing';
  const [showPricingPage, setShowPricingPage] = useState<boolean>(() =>
    typeof window !== 'undefined'
      ? isPricingLocation(window.location.pathname, window.location.search)
      : false
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
    try {
      localStorage.setItem('checkmyapk_theme', nextTheme);
    } catch {}
  };

  useEffect(() => {
    applyThemeToDom(theme);
  }, [theme]);

  useEffect(() => {
    const introTimer = window.setTimeout(() => setHeroIntroDone(true), 1600);
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

  const openPricingPage = () => {
    setShowAccountPage(false);
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
      setShowAccountPage(isAccount);
      setShowPricingPage(!isAccount && isPricingLocation(window.location.pathname, window.location.search));
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

  const persistScanToAccount = async (
    target: string,
    mode: 'apk' | 'web',
    data: { score?: number; grade?: string; summaryCounts?: { critical?: number } }
  ) => {
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
        }),
      });
      if (res.ok) {
        const json = await res.json();
        if (json?.user) setCurrentUser(json.user);
      }
    } catch {
      // Non-blocking history sync
    }
  };

  const navigateSection = (sectionId: string, preferredMode?: 'apk' | 'web') => {
    setShowAccountPage(false);
    setShowPricingPage(false);
    if (typeof window !== 'undefined') {
      const hasAccountParam = new URLSearchParams(window.location.search).get('page') === 'account';
      if (hasAccountParam || isPricingLocation(window.location.pathname, window.location.search)) {
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
    if (plan === 'free') {
      if (!currentUser) {
        setAuthModalMode('register');
        return;
      }
      if (currentUser.plan === 'free') {
        openAccountPage();
        return;
      }
      try {
        const res = await fetch('/api/auth/plan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ plan: 'free' }),
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

  // 🌐 Scan Web Target
  const handleScanWeb = async (targetToScan?: string) => {
    const finalUrl = (targetToScan || url).trim();
    if (!finalUrl) return;

    closeAccountPage(true);
    setUrl(finalUrl);
    setLoading(true);
    setError(null);
    setReport(null);

    const steps = [
      'Resolving target DNS & establishing secure TLS socket...',
      'Crawling HTML document tree and extracting script bundles...',
      'Mapping robots.txt, sitemap.xml, OpenAPI specs & GraphQL endpoints...',
      'Scanning JS bundles for leaked secrets & Static DOM XSS sinks...',
      'Auditing JWT claims, HTTP Security Headers & CORS origin policies...',
      'Testing Firebase / Supabase rules & passive API route error leaks...',
      activePlanPolicy.features.burst15Req
        ? 'Sending 15-request burst to test Denial-of-Wallet rate limits...'
        : 'Running safe 4-request rate-limit probe (Starter tier)...',
      'Invoking Gemini Neural Engine for custom architectural threat synthesis...'
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
      if (activePlanPolicy.features.authenticatedWebScan && webAuthHeader.trim()) {
        payload.authHeader = webAuthHeader.trim();
      }
      if (activePlanPolicy.features.authenticatedWebScan && webAuthCookie.trim()) {
        payload.authCookie = webAuthCookie.trim();
      }

      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      clearInterval(stepInterval);

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

  // 📱 Scan APK File Upload (Async Worker Queue + Live Telemetry Polling)
  const handleScanApk = async (fileToScan?: File) => {
    const selectedFile = fileToScan || apkFile;
    if (!selectedFile) {
      setError('Please select or drop an Android .apk file to begin.');
      return;
    }

    const maxBytes = activePlanPolicy.maxApkMb * 1024 * 1024;
    if (selectedFile.size > maxBytes) {
      const fileSizeMb = (selectedFile.size / (1024 * 1024)).toFixed(1);
      setError(
        `APK file (${fileSizeMb} MB) exceeds your ${activePlanPolicy.name} limit of ${activePlanPolicy.maxApkMb} MB. Upgrade to Pro (75 MB) or Team & Agency (150 MB).`
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
        body: formData
      });

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
      if (file.name.endsWith('.apk')) {
        setApkFile(file);
        setError(null);
      } else {
        setError('Please upload a valid Android package file (.apk).');
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
            <button
              type="button"
              onClick={() => {
                setMobileNavOpen(false);
                closeAccountPage(true);
                closePricingPage(true);
                setReport(null);
                setError(null);
              }}
              className="flex items-center gap-2.5 cursor-pointer group select-none focus:outline-none"
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
            </button>

            <span className="hidden md:block h-4 w-px bg-white/10 nav-divider" aria-hidden="true" />

            <nav
              aria-label="Primary Navigation"
              className="hidden md:flex items-center h-full gap-1"
            >
              {[
                {
                  id: 'scanner',
                  label: 'Scanner',
                  active: !showPricingPage && !showAccountPage && showTrustModal !== 'api',
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
                  id: 'api',
                  label: 'API',
                  active: showTrustModal === 'api',
                  onClick: () => openTrustModal('api'),
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

          {/* Right: Contextual Report Exports + Utility + Crisp Action */}
          <div className="flex items-center gap-1.5 sm:gap-2">
            {!showAccountPage && !showPricingPage && report && (
              activePlanPolicy.features.exports ? (
                <>
                  <button
                    type="button"
                    onClick={handleExportJson}
                    title="Download JSON Security Telemetry"
                    className="h-8 px-2.5 rounded-md text-[12px] font-medium bg-white/[0.05] hover:bg-white/[0.1] text-slate-200 border border-white/10 transition-colors hidden sm:inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <FileJson className="w-3.5 h-3.5 text-amber-400" />
                    <span>JSON</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleExportMarkdown}
                    title="Download Markdown Issue Report"
                    className="h-8 px-2.5 rounded-md text-[12px] font-medium bg-white/[0.05] hover:bg-white/[0.1] text-slate-200 border border-white/10 transition-colors hidden sm:inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <FileText className="w-3.5 h-3.5 text-purple-400" />
                    <span>MD</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleCopyMarkdown}
                    title="Copy Markdown Summary for GitHub PR / Slack"
                    className="h-8 px-2.5 rounded-md text-[12px] font-medium bg-white/[0.05] hover:bg-white/[0.1] text-slate-200 border border-white/10 transition-colors hidden lg:inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    {mdCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-300" />}
                    <span>{mdCopied ? 'Copied' : 'Copy PR'}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => window.print()}
                    className="h-8 px-3 rounded-md text-[12px] font-semibold bg-white/[0.07] hover:bg-white/[0.13] text-slate-100 border border-white/10 transition-colors inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-cyan-400" />
                    <span>PDF</span>
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  onClick={openPricingPage}
                  title="PDF, JSON, Markdown & PR exports require Pro Security or Team & Agency"
                  className="h-8 px-3 rounded-md text-[12px] font-semibold bg-amber-500/10 hover:bg-amber-500/15 text-amber-300 border border-amber-500/30 transition-colors hidden sm:inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <Lock className="w-3 h-3" />
                  <span>Unlock Exports</span>
                </button>
              )
            )}

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
                active: !showPricingPage && !showAccountPage && showTrustModal !== 'api',
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
                id: 'api',
                label: 'API',
                active: showTrustModal === 'api',
                onClick: () => openTrustModal('api'),
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
            onRescanWeb={(targetUrl) => {
              closeAccountPage(true);
              setScanMode('web');
              setUrl(targetUrl);
              handleScanWeb(targetUrl);
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

        {/* ── Hero & Precision Security Workbench (stays mounted during scan to prevent reload flash/scroll jump) ── */}
        {!showAccountPage && !showPricingPage && !report && (
          <div className="w-full space-y-16 pb-6">
            {/* Full-Viewport Centered Editorial Hero Stage */}
            <section className="min-h-[calc(100vh-112px)] flex flex-col items-center justify-center text-center py-10 sm:py-16 relative">
              <div className="max-w-4xl mx-auto flex flex-col items-center space-y-6">
                <div
                  className={`wb-eyebrow-pill ${heroIntroDone ? '' : 'wb-stage-reveal'} inline-flex items-center gap-2 px-3 py-1 rounded-md font-mono text-[11px] font-medium`}
                  style={heroIntroDone ? undefined : { animationDelay: '40ms' }}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0" aria-hidden="true" />
                  <span>OWASP MASVS v2 · Static &amp; Live Probes</span>
                </div>

                <h1
                  aria-label="Find leaked secrets and flaws in your APK or Web App."
                  className="font-display font-bold text-4xl sm:text-6xl lg:text-[66px] leading-[1.07] tracking-[-0.045em] text-white"
                >
                  <span className="inline-flex flex-wrap items-baseline justify-center gap-x-[0.26em] gap-y-1">
                    {[
                      { text: 'Find', cls: 'text-white' },
                      { text: 'leaked', cls: 'wb-accent-ink' },
                      { text: 'secrets', cls: 'wb-accent-ink' },
                      { text: 'and', cls: 'text-white' },
                      { text: 'flaws', cls: 'text-white' },
                    ].map((word, idx) => (
                      <span key={word.text} className="wb-word-mask">
                        <span
                          className={`${heroIntroDone ? 'inline-block' : 'wb-word-inner'} ${word.cls}`}
                          style={heroIntroDone ? undefined : { animationDelay: `${110 + idx * 75}ms` }}
                        >
                          {word.text}
                        </span>
                      </span>
                    ))}
                  </span>
                  <br className="hidden sm:block" />{' '}
                  <span className="inline-flex flex-wrap items-baseline justify-center gap-x-[0.26em] gap-y-1">
                    {[
                      { text: 'in', cls: 'wb-headline-muted' },
                      { text: 'your', cls: 'wb-headline-muted' },
                      { text: 'APK', cls: 'text-white' },
                      { text: 'or', cls: 'wb-headline-muted' },
                      { text: 'Web', cls: 'text-white' },
                      { text: 'App.', cls: 'text-white' },
                    ].map((word, idx) => (
                      <span key={`${word.text}-${idx}`} className="wb-word-mask">
                        <span
                          className={`${heroIntroDone ? 'inline-block' : 'wb-word-inner'} ${word.cls}`}
                          style={heroIntroDone ? undefined : { animationDelay: `${500 + idx * 75}ms` }}
                        >
                          {word.text}
                        </span>
                      </span>
                    ))}
                  </span>
                </h1>

                <p
                  className={`${heroIntroDone ? '' : 'wb-stage-reveal'} text-sm sm:text-base text-slate-400 leading-relaxed max-w-xl mx-auto`}
                  style={heroIntroDone ? undefined : { animationDelay: '940ms' }}
                >
                  Decompile Android binaries or probe live endpoints in seconds. Deterministic findings, exact file paths, and copy-paste patches with zero server retention.
                </p>

                <div
                  className={`${heroIntroDone ? '' : 'wb-stage-reveal'} flex flex-wrap items-center justify-center gap-3 pt-1`}
                  style={heroIntroDone ? undefined : { animationDelay: '1040ms' }}
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
                  style={heroIntroDone ? undefined : { animationDelay: '1140ms' }}
                >
                  <div>
                    <div className="font-mono text-base sm:text-lg font-semibold text-white">35+</div>
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
                className={`${heroIntroDone ? '' : 'wb-stage-reveal'} mt-10 sm:mt-14 inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-slate-500 hover:text-emerald-400 transition-colors cursor-pointer`}
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

            {/* ── Below-the-Fold Full-Width 2-Pane Security IDE Workbench + Live CLI Preview ── */}
            <section id="scanner-command" className="scroll-mt-24 space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3 text-left">
                <div className="space-y-1">
                  <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold">
                    Interactive Workbench
                  </span>
                  <h2 className="text-2xl sm:text-[28px] font-display font-semibold tracking-[-0.03em] text-white">
                    Upload an Android APK or audit a live URL.
                  </h2>
                </div>
                <span className="font-mono text-[11px] text-slate-500">
                  RAM-only · Max {activePlanPolicy.maxApkMb}MB · {activePlanPolicy.name}
                </span>
              </div>

              {(() => {
                const targetArmed =
                  scanMode === 'apk' ? Boolean(apkFile) : url.trim().length > 0;
                const liveCliCmd =
                  scanMode === 'apk'
                    ? apkFile
                      ? `checkmyapk audit ./${apkFile.name}${
                          apkPreFlightHash ? ` --sha256 ${apkPreFlightHash.slice(0, 12)}` : ''
                        } --masvs-v2 --ram-only`
                      : `checkmyapk audit ./app-release.apk --masvs-v2 --ram-only`
                    : `checkmyapk probe ${url.trim() || 'https://your-website.com'} --headers --ast --burst=${
                        activePlanPolicy.features.burst15Req ? 15 : 4
                      }`;

                const armedStages =
                  scanMode === 'apk'
                    ? [
                        {
                          step: '01',
                          name: 'AndroidManifest.xml',
                          detail: 'Debuggable flag, backup rules & exported IPC components',
                        },
                        {
                          step: '02',
                          name: 'classes*.dex Bytecode',
                          detail: 'High-entropy API keys, secrets & weak cipher detection',
                        },
                        {
                          step: '03',
                          name: 'lib/**/*.so (ELF64)',
                          detail: 'NX stack, PIE, Stack Canary & Full RELRO hardening',
                        },
                        {
                          step: '04',
                          name: 'Auto Backend Probes',
                          detail: 'Live TLS, CORS & anonymous Firebase / Supabase checks',
                        },
                      ]
                    : [
                        {
                          step: '01',
                          name: 'JS Bundle AST Scan',
                          detail: 'Leaked keys, exposed tokens & DOM XSS sink analysis',
                        },
                        {
                          step: '02',
                          name: 'Artifact Exposure',
                          detail: 'Public .env, .git, .js.map & hidden config discovery',
                        },
                        {
                          step: '03',
                          name: 'Transport & Headers',
                          detail: 'TLS posture, HSTS, CSP, SRI & HttpOnly cookie flags',
                        },
                        {
                          step: '04',
                          name: 'Rate-Limit Burst',
                          detail: `${
                            activePlanPolicy.features.burst15Req ? '15-request' : '4-request safe'
                          } Denial-of-Wallet stress profile`,
                        },
                      ];

                return (
                  <div className="wb-bezel p-1.5 rounded-2xl text-left">
                    <div className="wb-surface rounded-xl overflow-hidden">
                      {/* IDE Header Bar: Flush Underline Mode Tabs + Live Status */}
                      <div className="flex items-center justify-between border-b border-white/10 px-4 gap-2">
                        <div className="flex items-center">
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
                            <span className="font-mono text-[10px] text-slate-400 bg-white/[0.05] px-1.5 py-0.5 rounded">
                              .apk
                            </span>
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
                            <span className="font-mono text-[10px] text-slate-400 bg-white/[0.05] px-1.5 py-0.5 rounded">
                              URL
                            </span>
                            {scanMode === 'web' && (
                              <span
                                aria-hidden="true"
                                className="absolute left-3 right-3 -bottom-px h-[2px] bg-emerald-500"
                              />
                            )}
                          </button>
                        </div>

                        <span className="hidden sm:inline-flex items-center gap-2 font-mono text-[10px] text-slate-400 shrink-0">
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              targetArmed ? 'bg-emerald-400 animate-pulse' : 'bg-emerald-500'
                            }`}
                            aria-hidden="true"
                          />
                          <span>{targetArmed ? 'TARGET ARMED · MASVS v2.1' : 'MASVS v2.1 · 35 RULES'}</span>
                        </span>
                      </div>

                      {/* Live Reactive CLI Command Preview Strip */}
                      <div className="px-4 py-2.5 border-b border-white/10 wb-surface-muted border-x-0 border-t-0 flex items-center justify-between gap-3 font-mono text-[11px]">
                        <div className="flex items-center gap-2 min-w-0 overflow-x-auto">
                          <span className="text-emerald-400 select-none shrink-0">$</span>
                          <code className="text-slate-300 whitespace-nowrap select-all">
                            {liveCliCmd}
                          </code>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            navigator.clipboard
                              ?.writeText(liveCliCmd)
                              .then(() => {
                                setCliCopied(true);
                                setTimeout(() => setCliCopied(false), 1600);
                              })
                              .catch(() => {});
                          }}
                          title="Copy CLI preview command"
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-white/[0.05] hover:bg-white/[0.1] border border-white/10 text-[10px] text-slate-400 hover:text-white transition-colors cursor-pointer shrink-0"
                        >
                          {cliCopied ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                          <span className="hidden sm:inline">{cliCopied ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>

                      {/* 2-Pane Connected IDE Body */}
                      <div className="grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-white/10">
                        {/* Left Pane (60%): Optical Scanner Reticle / URL Input Console / Inline Live Scan */}
                        <div className="lg:col-span-7 p-5 sm:p-6 flex flex-col justify-between gap-4">
                          {loading ? (
                            <div className="space-y-4 py-2">
                              <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/35 text-emerald-400 flex items-center justify-center shrink-0">
                                  <RefreshCw className="w-5 h-5 animate-spin" />
                                </div>
                                <div className="min-w-0">
                                  <h3 className="text-sm font-semibold text-white">
                                    {scanMode === 'apk'
                                      ? 'Decompiling & Auditing APK Binary...'
                                      : 'Running Live Security Probes...'}
                                  </h3>
                                  <p className="text-[11px] font-mono text-emerald-400 truncate mt-0.5">
                                    ❯ {activeStepMessage}
                                  </p>
                                </div>
                              </div>

                              <LiveTerminalLogs
                                targetUrl={scanMode === 'apk' ? apkFile?.name || 'Android Package' : url}
                                isApkMode={scanMode === 'apk'}
                              />
                            </div>
                          ) : (
                            <>
                          {/* APK MODE */}
                          {scanMode === 'apk' && (
                            <div className="space-y-4">
                              <input
                                type="file"
                                ref={fileInputRef}
                                accept=".apk"
                                className="hidden"
                                onChange={(e) => {
                                  if (e.target.files && e.target.files[0]) {
                                    setApkFile(e.target.files[0]);
                                    setError(null);
                                  }
                                }}
                              />

                              {apkFile ? (
                                /* Real Client-Side APK Pre-Flight Inspector Card */
                                <div
                                  onDragOver={(e) => {
                                    e.preventDefault();
                                    setIsDragging(true);
                                  }}
                                  onDragLeave={() => setIsDragging(false)}
                                  onDrop={handleFileDrop}
                                  className={`p-4 sm:p-5 rounded-lg border transition-colors space-y-3.5 ${
                                    isDragging
                                      ? 'border-emerald-500 bg-emerald-500/10'
                                      : 'wb-surface-muted border-emerald-500/40'
                                  }`}
                                >
                                  <div className="flex items-start justify-between gap-3">
                                    <div className="flex items-center gap-3 min-w-0">
                                      <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/35 text-emerald-400 flex items-center justify-center shrink-0">
                                        <ShieldCheck className="w-5 h-5" />
                                      </div>
                                      <div className="min-w-0">
                                        <div className="flex items-center gap-2 flex-wrap">
                                          <h3 className="text-sm font-semibold text-white truncate">
                                            {apkFile.name}
                                          </h3>
                                          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-white/[0.06] border border-white/10 text-slate-300 shrink-0">
                                            {(apkFile.size / 1024 / 1024).toFixed(2)} MB
                                          </span>
                                        </div>
                                        <p className="text-[11px] text-slate-400 mt-0.5">
                                          Staged in memory · Ready for binary decompilation
                                        </p>
                                      </div>
                                    </div>

                                    <div className="flex items-center gap-1 shrink-0">
                                      <button
                                        type="button"
                                        onClick={() => fileInputRef.current?.click()}
                                        className="px-2 py-1 rounded text-[11px] font-medium text-slate-400 hover:text-white hover:bg-white/[0.06] transition-colors cursor-pointer"
                                      >
                                        Change
                                      </button>
                                      <button
                                        type="button"
                                        onClick={() => {
                                          setApkFile(null);
                                          setError(null);
                                          if (fileInputRef.current) fileInputRef.current.value = '';
                                        }}
                                        aria-label="Remove APK file"
                                        title="Remove file"
                                        className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors cursor-pointer"
                                      >
                                        <X className="w-4 h-4" />
                                      </button>
                                    </div>
                                  </div>

                                  {/* Live Browser-Computed SHA-256 Fingerprint */}
                                  <div className="px-3 py-2 rounded-md bg-white/[0.03] border border-white/10 flex items-center justify-between gap-2 font-mono text-[11px]">
                                    <span className="text-slate-500 shrink-0 uppercase text-[10px]">SHA-256</span>
                                    <span className="text-slate-300 truncate select-all">
                                      {apkHashing
                                        ? 'Computing local cryptographic digest...'
                                        : apkPreFlightHash
                                        ? `${apkPreFlightHash.slice(0, 18)}…${apkPreFlightHash.slice(-14)}`
                                        : 'Verified on upload'}
                                    </span>
                                  </div>

                                  {/* 4-Stage Pipeline Readiness Chips */}
                                  <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
                                    {['Manifest XML', 'Dalvik DEX', 'Native ELF', 'Secrets'].map((stage) => (
                                      <span
                                        key={stage}
                                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/25 text-emerald-400"
                                      >
                                        <Check className="w-2.5 h-2.5" />
                                        <span>{stage}</span>
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              ) : (
                                /* Optical Viewfinder Reticle Dropzone */
                                <div
                                  onDragOver={(e) => {
                                    e.preventDefault();
                                    setIsDragging(true);
                                  }}
                                  onDragLeave={() => setIsDragging(false)}
                                  onDrop={handleFileDrop}
                                  onClick={() => fileInputRef.current?.click()}
                                  className={`group relative p-7 sm:p-8 rounded-lg transition-colors cursor-pointer flex flex-col items-center justify-center gap-3.5 text-center wb-reticle-zone ${
                                    isDragging ? 'wb-reticle-dragging border-emerald-500/70' : 'hover:border-emerald-500/40'
                                  }`}
                                >
                                  {/* 4 Optical Viewfinder Corner Brackets */}
                                  <span className="wb-reticle-corner top-2.5 left-2.5 border-t-2 border-l-2 rounded-tl-[2px]" aria-hidden="true" />
                                  <span className="wb-reticle-corner top-2.5 right-2.5 border-t-2 border-r-2 rounded-tr-[2px]" aria-hidden="true" />
                                  <span className="wb-reticle-corner bottom-2.5 left-2.5 border-b-2 border-l-2 rounded-bl-[2px]" aria-hidden="true" />
                                  <span className="wb-reticle-corner bottom-2.5 right-2.5 border-b-2 border-r-2 rounded-br-[2px]" aria-hidden="true" />

                                  <div className="w-11 h-11 rounded-lg border bg-white/[0.04] border-white/10 group-hover:border-emerald-500/40 text-slate-300 group-hover:text-emerald-400 flex items-center justify-center transition-colors">
                                    <UploadCloud className="w-5 h-5" />
                                  </div>

                                  <div className="space-y-1">
                                    <h3 className="text-sm font-semibold text-white">
                                      Drop your Android .apk file here
                                    </h3>
                                    <p className="text-xs text-slate-400">
                                      Drag &amp; drop binary package or select from disk · Max {activePlanPolicy.maxApkMb}MB
                                    </p>
                                  </div>

                                  <span className="inline-flex items-center gap-1.5 h-8 px-3.5 rounded-md text-xs font-medium wb-surface border border-white/15 text-white group-hover:border-emerald-500/45 transition-colors">
                                    <span>Select .apk File</span>
                                  </span>
                                </div>
                              )}

                              <button
                                type="button"
                                disabled={!apkFile}
                                onClick={() => handleScanApk()}
                                className={`w-full h-10 px-4 rounded-md font-semibold text-[13px] flex items-center justify-between gap-2 transition-colors ${
                                  apkFile
                                    ? 'wb-primary-btn cursor-pointer'
                                    : 'wb-btn-standby cursor-not-allowed'
                                }`}
                              >
                                <span className="inline-flex items-center gap-2">
                                  <span
                                    className={`w-2 h-2 rounded-full shrink-0 ${
                                      apkFile ? 'bg-emerald-500' : 'bg-slate-600'
                                    }`}
                                    aria-hidden="true"
                                  />
                                  <span>
                                    {apkFile ? 'Run APK Security Audit' : 'Select an .apk binary to enable audit'}
                                  </span>
                                </span>
                                <span className="inline-flex items-center gap-1.5">
                                  {apkFile && (
                                    <kbd className="wb-keycap font-mono text-[10px] px-1.5 py-0.5 rounded hidden sm:inline">
                                      ↵
                                    </kbd>
                                  )}
                                  <ArrowRight className="w-3.5 h-3.5" />
                                </span>
                              </button>

                              <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-white/10 text-[11px] text-slate-400">
                                <button
                                  type="button"
                                  onClick={handleOpenSampleDemo}
                                  className="inline-flex items-center gap-1 text-emerald-400 hover:underline font-medium cursor-pointer"
                                >
                                  <span>Load sample audit report</span>
                                  <ArrowRight className="w-3 h-3" />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => setShowTrustModal('privacy')}
                                  className="inline-flex items-center gap-1.5 text-slate-400 hover:text-white cursor-pointer"
                                >
                                  <Lock className="w-3 h-3 text-emerald-400" />
                                  <span>RAM-only · Zero disk storage</span>
                                </button>
                              </div>
                            </div>
                          )}

                          {/* WEB MODE */}
                          {scanMode === 'web' && (
                            <div className="space-y-4">
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
                                    placeholder="https://your-website.com"
                                    value={url}
                                    onChange={(e) => setUrl(e.target.value)}
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
                                      title="Clear URL"
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
                                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" aria-hidden="true" />
                                  <span>Run Audit</span>
                                  <kbd className="wb-keycap font-mono text-[10px] px-1.5 py-0.5 rounded hidden sm:inline">
                                    ↵
                                  </kbd>
                                </button>
                              </form>

                              {/* Optional Authenticated API & JWT Audit */}
                              <div className="space-y-2 pt-1">
                                {activePlanPolicy.features.authenticatedWebScan ? (
                                  <>
                                    <button
                                      type="button"
                                      onClick={() => setShowWebAuthOptions(!showWebAuthOptions)}
                                      className="text-[11px] font-medium text-emerald-400 hover:underline inline-flex items-center gap-1.5 cursor-pointer"
                                    >
                                      <Lock className="w-3 h-3" />
                                      <span>
                                        {showWebAuthOptions
                                          ? 'Hide Bearer JWT / Cookie inputs'
                                          : '+ Optional: Audit with Bearer JWT or Session Cookie'}
                                      </span>
                                    </button>

                                    {showWebAuthOptions && (
                                      <div className="p-3.5 rounded-md wb-surface-muted space-y-2.5">
                                        <div className="text-[11px] text-slate-400">
                                          Credentials are forwarded strictly to the target&apos;s own origin for safe read-only checks and are never logged or stored.
                                        </div>
                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                          <input
                                            type="password"
                                            autoComplete="off"
                                            placeholder="Bearer <JWT_TOKEN> (optional)"
                                            value={webAuthHeader}
                                            onChange={(e) => setWebAuthHeader(e.target.value)}
                                            className="w-full px-3 py-2 rounded-md bg-[#050811]/85 border border-white/10 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500/60 font-mono"
                                          />
                                          <input
                                            type="password"
                                            autoComplete="off"
                                            placeholder="Cookie: session=... (optional)"
                                            value={webAuthCookie}
                                            onChange={(e) => setWebAuthCookie(e.target.value)}
                                            className="w-full px-3 py-2 rounded-md bg-[#050811]/85 border border-white/10 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500/60 font-mono"
                                          />
                                        </div>
                                      </div>
                                    )}
                                  </>
                                ) : (
                                  <button
                                    type="button"
                                    onClick={openPricingPage}
                                    className="text-[11px] font-medium text-slate-400 hover:text-white inline-flex items-center gap-1.5 cursor-pointer"
                                  >
                                    <Lock className="w-3 h-3 text-amber-400" />
                                    <span>Authenticated Bearer JWT / Cookie Scan</span>
                                    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold uppercase bg-amber-500/15 text-amber-300 border border-amber-500/30">
                                      Pro
                                    </span>
                                  </button>
                                )}

                                <div className="flex items-center justify-between flex-wrap gap-2">
                                  {activePlanPolicy.features.burst15Req ? (
                                    <button
                                      type="button"
                                      onClick={handleLoadDomainChallenge}
                                      className="text-[11px] font-medium text-emerald-400 hover:underline inline-flex items-center gap-1.5 cursor-pointer"
                                    >
                                      <ShieldCheck className="w-3.5 h-3.5" />
                                      <span>Verify Domain Ownership (15-Request Rate Burst)</span>
                                    </button>
                                  ) : (
                                    <button
                                      type="button"
                                      onClick={openPricingPage}
                                      className="text-[11px] font-medium text-slate-400 hover:text-white inline-flex items-center gap-1.5 cursor-pointer"
                                    >
                                      <Lock className="w-3 h-3 text-amber-400" />
                                      <span>Verify Domain Ownership (15-Request Burst)</span>
                                      <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold uppercase bg-amber-500/15 text-amber-300 border border-amber-500/30">
                                        Pro
                                      </span>
                                    </button>
                                  )}
                                  <span className="text-[10px] font-mono text-slate-500">
                                    {activePlanPolicy.features.burst15Req
                                      ? 'Default: 4-req safe profile'
                                      : 'Starter: 4-req safe profile'}
                                  </span>
                                </div>

                                {activePlanPolicy.features.burst15Req && domainChallenge && (
                                  <div className="p-3 rounded-md wb-surface-muted text-[10px] font-mono space-y-1.5 text-slate-300">
                                    <div className="text-emerald-400 font-semibold">
                                      Add TXT record or HTML Meta Tag to verify &quot;{domainChallenge.host}&quot;:
                                    </div>
                                    <div className="p-1.5 rounded bg-black/50 break-all select-all text-slate-200">
                                      DNS TXT: {domainChallenge.txtRecord}
                                    </div>
                                    <div className="p-1.5 rounded bg-black/50 break-all select-all text-emerald-400">
                                      HTML Meta: {domainChallenge.metaTag}
                                    </div>
                                  </div>
                                )}
                              </div>

                              {/* Quick Test Targets */}
                              <div className="flex items-center justify-between flex-wrap gap-2 pt-3 border-t border-white/10 text-[11px] text-slate-400">
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <span className="font-mono text-slate-500">Quick targets:</span>
                                  <button
                                    type="button"
                                    onClick={() => handleScanWeb('http://localhost:3000')}
                                    className="px-2 py-0.5 rounded font-mono bg-white/[0.04] hover:bg-white/[0.09] border border-white/10 text-slate-300 transition-colors cursor-pointer"
                                  >
                                    localhost:3000
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => handleScanWeb('https://salowtech.com')}
                                    className="px-2 py-0.5 rounded font-mono bg-white/[0.04] hover:bg-white/[0.09] border border-white/10 text-slate-300 transition-colors cursor-pointer"
                                  >
                                    salowtech.com
                                  </button>
                                </div>
                                <button
                                  type="button"
                                  onClick={handleOpenSampleDemo}
                                  className="inline-flex items-center gap-1 text-emerald-400 hover:underline font-medium cursor-pointer"
                                >
                                  <span>Sample report</span>
                                  <ArrowRight className="w-3 h-3" />
                                </button>
                              </div>
                            </div>
                          )}

                          {error && (
                            <div className="p-3.5 rounded-md bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-medium flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-left">
                              <div className="flex items-start gap-2.5 min-w-0">
                                <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
                                <span className="leading-relaxed">{error}</span>
                              </div>
                              {/upgrade|pro security|limit|quota/i.test(error) && (
                                <button
                                  type="button"
                                  onClick={openPricingPage}
                                  className="wb-emerald-btn h-8 px-3 rounded-md text-[11px] font-semibold inline-flex items-center gap-1 shrink-0 self-start sm:self-center cursor-pointer"
                                >
                                  <span>Upgrade Plan</span>
                                  <ArrowRight className="w-3 h-3" />
                                </button>
                              )}
                            </div>
                          )}
                            </>
                          )}
                        </div>

                        {/* Right Pane (40%): Live Armed Pipeline & Guardrail Telemetry Sidebar */}
                        <aside className="lg:col-span-5 wb-surface-muted border-0 p-5 sm:p-6 flex flex-col justify-between gap-5">
                          <div className="space-y-4">
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500 font-semibold">
                                Armed Pipeline · {scanMode === 'apk' ? 'APK Binary' : 'Web & API'}
                              </span>
                              <span
                                className={`font-mono text-[10px] px-1.5 py-0.5 rounded border ${
                                  loading || targetArmed
                                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                                    : 'bg-white/[0.04] border-white/10 text-slate-400'
                                }`}
                              >
                                {loading ? 'Scanning...' : targetArmed ? 'Armed' : '4 Stages'}
                              </span>
                            </div>

                            <ol className="space-y-3">
                              {armedStages.map((stage) => (
                                <li
                                  key={stage.step}
                                  className="flex items-start gap-3 text-xs"
                                >
                                  <span
                                    className={`font-mono text-[10px] px-1.5 py-0.5 rounded border shrink-0 mt-0.5 transition-colors ${
                                      targetArmed
                                        ? 'bg-emerald-500/10 border-emerald-500/35 text-emerald-400'
                                        : 'bg-white/[0.03] border-white/10 text-slate-500'
                                    }`}
                                  >
                                    {stage.step}
                                  </span>
                                  <div className="min-w-0">
                                    <div className="font-semibold text-white leading-snug">
                                      {stage.name}
                                    </div>
                                    <div className="text-[11px] text-slate-400 leading-relaxed">
                                      {stage.detail}
                                    </div>
                                  </div>
                                </li>
                              ))}
                            </ol>
                          </div>

                          <div className="border-t border-white/10 pt-4 grid grid-cols-2 gap-3 font-mono text-[11px]">
                            <div>
                              <div className="text-[10px] text-slate-500 uppercase">Retention</div>
                              <div className="text-slate-200 mt-0.5">0s (RAM buffer)</div>
                            </div>
                            <div>
                              <div className="text-[10px] text-slate-500 uppercase">Payload Cap</div>
                              <div className="text-slate-200 mt-0.5">{activePlanPolicy.maxApkMb} MB</div>
                            </div>
                            <div>
                              <div className="text-[10px] text-slate-500 uppercase">Exports</div>
                              <div className="text-slate-200 mt-0.5">JSON · MD · PDF</div>
                            </div>
                            <div>
                              <div className="text-[10px] text-slate-500 uppercase">Engine</div>
                              <div className="text-emerald-400 mt-0.5 inline-flex items-center gap-1.5">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
                                <span>{targetArmed ? 'Armed' : 'Ready'}</span>
                              </div>
                            </div>
                          </div>
                        </aside>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </section>

            {/* ── Real Product Proof: Interactive Split Audit & Git Diff Preview ── */}
            <section id="features" className="scroll-mt-20 space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-white/10 pb-5">
                <div className="space-y-1.5 text-left">
                  <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold">
                    Deterministic Output
                  </span>
                  <h2 className="text-2xl sm:text-[28px] font-display font-semibold tracking-[-0.03em] text-white">
                    Exact file paths and copy-paste patches, not generic alerts.
                  </h2>
                </div>
                <button
                  type="button"
                  onClick={handleOpenSampleDemo}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400 hover:underline cursor-pointer self-start sm:self-auto"
                >
                  <span>Open full interactive sample report</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>

              {(() => {
                const sampleFindings = [
                  {
                    severity: 'CRITICAL',
                    badge: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
                    rule: 'MASVS-STORAGE-1',
                    title: 'Hardcoded Firebase / Stripe Secret in DEX Bytecode',
                    location: 'classes2.dex · com/app/Config.class:41',
                    file: 'Backend Proxy Pattern (NetworkClient.kt)',
                    diff: [
                      { type: 'ctx', text: '  // Never embed live API secrets inside APK bytecode' },
                      { type: 'del', text: '- val stripeKey = "sk_live_51N9x...REDACTED"' },
                      { type: 'del', text: '- val auth = "Bearer $stripeKey"' },
                      { type: 'add', text: '+ val checkoutUrl = "https://api.yourapp.com/v1/billing/checkout"' },
                      { type: 'add', text: '+ val auth = "Bearer ${sessionStore.getUserJwt()}"' },
                    ],
                  },
                  {
                    severity: 'HIGH',
                    badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
                    rule: 'MASVS-CODE-2',
                    title: 'Production APK Built With android:debuggable="true"',
                    location: 'AndroidManifest.xml · <application>',
                    file: 'app/src/main/AndroidManifest.xml',
                    diff: [
                      { type: 'ctx', text: '  <application' },
                      { type: 'ctx', text: '      android:name=".MainApplication"' },
                      { type: 'del', text: '-     android:debuggable="true"' },
                      { type: 'del', text: '-     android:allowBackup="true"' },
                      { type: 'add', text: '+     android:debuggable="false"' },
                      { type: 'add', text: '+     android:allowBackup="false"' },
                      { type: 'ctx', text: '      android:usesCleartextTraffic="false">' },
                    ],
                  },
                  {
                    severity: 'MEDIUM',
                    badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
                    rule: 'OWASP-A05',
                    title: 'Missing Strict-Transport-Security & CSP Headers',
                    location: 'https://api.yourapp.com · HTTP Response',
                    file: 'vercel.json / Express Security Middleware',
                    diff: [
                      { type: 'ctx', text: '  app.use((req, res, next) => {' },
                      { type: 'del', text: '-   // Missing HSTS & Content-Security-Policy headers' },
                      { type: 'add', text: '+   res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");' },
                      { type: 'add', text: '+   res.setHeader("Content-Security-Policy", "default-src \'self\'; object-src \'none\'");' },
                      { type: 'ctx', text: '    next();' },
                      { type: 'ctx', text: '  });' },
                    ],
                  },
                ];
                const activeSample = sampleFindings[previewFindingIdx] || sampleFindings[0];

                return (
                  <div className="wb-bezel p-1.5 rounded-2xl">
                  <div className="wb-surface rounded-xl overflow-hidden grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-white/10 text-left">
                    {/* Left: Findings List */}
                    <div className="lg:col-span-5 divide-y divide-white/[0.08]">
                      <div className="px-4 py-3 font-mono text-[10px] uppercase tracking-wider text-slate-500 flex items-center justify-between">
                        <span>Parsed Findings (3)</span>
                        <span>Click row to inspect diff</span>
                      </div>
                      {sampleFindings.map((item, idx) => {
                        const selected = idx === previewFindingIdx;
                        return (
                          <button
                            key={item.title}
                            type="button"
                            onClick={() => {
                              setPreviewFindingIdx(idx);
                              setPreviewPatchCopied(false);
                            }}
                            className={`w-full text-left px-4 py-4 transition-colors cursor-pointer space-y-1.5 ${
                              selected ? 'bg-white/[0.05]' : 'hover:bg-white/[0.03]'
                            }`}
                          >
                            <div className="flex items-center gap-2">
                              <span className={`font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border ${item.badge}`}>
                                {item.severity}
                              </span>
                              <span className="font-mono text-[10px] text-slate-400">
                                {item.rule}
                              </span>
                            </div>
                            <div className="text-xs sm:text-[13px] font-semibold text-white">
                              {item.title}
                            </div>
                            <div className="font-mono text-[11px] text-slate-400 truncate">
                              {item.location}
                            </div>
                          </button>
                        );
                      })}
                    </div>

                    {/* Right: Unified Diff Patch Viewer */}
                    <div className="lg:col-span-7 flex flex-col wb-surface-muted border-0">
                      <div className="px-4 py-2.5 border-b border-white/10 flex items-center justify-between gap-2 font-mono text-[11px]">
                        <span className="text-slate-300 truncate">{activeSample.file}</span>
                        <div className="flex items-center gap-2.5 shrink-0">
                          <span className="text-[10px] text-emerald-400 hidden sm:inline">Recommended Patch</span>
                          <button
                            type="button"
                            onClick={() => {
                              const patchText = activeSample.diff
                                .filter((l) => l.type !== 'del')
                                .map((l) => l.text.replace(/^[+-]\s?/, ''))
                                .join('\n');
                              navigator.clipboard
                                ?.writeText(patchText)
                                .then(() => {
                                  setPreviewPatchCopied(true);
                                  setTimeout(() => setPreviewPatchCopied(false), 1800);
                                })
                                .catch(() => {});
                            }}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-[10px] text-slate-300 hover:text-white transition-colors cursor-pointer"
                          >
                            {previewPatchCopied ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                            <span>{previewPatchCopied ? 'Copied' : 'Copy Patch'}</span>
                          </button>
                        </div>
                      </div>
                      <div className="p-4 font-mono text-[11.5px] leading-6 overflow-x-auto flex-1">
                        {activeSample.diff.map((line, lineIdx) => (
                          <div
                            key={lineIdx}
                            className={`px-2.5 py-0.5 rounded-sm whitespace-pre ${
                              line.type === 'del'
                                ? 'wb-diff-del'
                                : line.type === 'add'
                                ? 'wb-diff-add'
                                : 'text-slate-400'
                            }`}
                          >
                            {line.text}
                          </div>
                        ))}
                      </div>
                      <div className="px-4 py-2.5 border-t border-white/10 flex items-center justify-between text-[11px] text-slate-400">
                        <span>Evidence verified via static parser + rule engine</span>
                        <span className="font-mono text-[10px] text-slate-500">Confirmed</span>
                      </div>
                    </div>
                  </div>
                  </div>
                );
              })()}
            </section>

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

        {/* ── Executive Report Dashboard ── */}
        {!showAccountPage && !showPricingPage && report && (
          <div className="flex flex-col gap-6 pb-10">
            {report.isDemoPreview && (
              <div className="p-3.5 rounded-2xl bg-amber-500/15 border border-amber-400/35 text-amber-200 text-xs font-bold flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-amber-300 shrink-0" />
                  <span>
                    SAMPLE DEMO PREVIEW — Interactive showcase showing how CheckMyAPK reports vulnerable test APKs. Upload your own `.apk` for a real audit.
                  </span>
                </div>
                <button
                  onClick={() => setReport(null)}
                  className="px-3 py-1 rounded-lg bg-amber-400 text-slate-950 font-black text-[11px] hover:brightness-110 cursor-pointer shrink-0"
                >
                  Scan Real APK
                </button>
              </div>
            )}

            {/* Target Header Bar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 glass-panel p-5 rounded-3xl">
              <div className="flex items-center gap-3.5">
                <div
                  className={`w-12 h-12 rounded-2xl flex items-center justify-center shrink-0 ${
                    report.isApkAudit
                      ? 'bg-purple-500/15 border border-purple-400/40 text-purple-300 cyber-glow-purple'
                      : 'bg-cyan-500/15 border border-cyan-400/40 text-cyan-300 cyber-glow-cyan'
                  }`}
                >
                  {report.isApkAudit ? <Smartphone className="w-6 h-6" /> : <Shield className="w-6 h-6" />}
                </div>
                <div>
                  <span className="text-[10px] font-black uppercase tracking-widest text-slate-400 block">
                    {report.isApkAudit ? 'Android APK Audit Target' : 'Web Security Audit Target'}
                  </span>
                  <div className="text-base font-black text-white flex items-center gap-2 flex-wrap">
                    <span>{report.isApkAudit ? report.apkMeta?.packageName || report.targetUrl : report.targetUrl}</span>
                    {report.isApkAudit && report.apkMeta && (
                      <span className="text-[11px] font-bold text-purple-200 bg-purple-500/20 border border-purple-400/30 px-2.5 py-0.5 rounded-full">
                        {report.apkMeta.fileName} • {report.apkMeta.sizeMb} MB
                        {report.apkMeta.versionName ? ` • v${report.apkMeta.versionName}` : ''}
                      </span>
                    )}
                    {activePlanPolicy.features.scoreDelta && scoreDelta && (
                      <span
                        className={`text-[10px] font-black px-2 py-0.5 rounded-full border inline-flex items-center gap-1 ${
                          scoreDelta.delta >= 0
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                            : 'bg-rose-500/15 text-rose-300 border-rose-400/30'
                        }`}
                      >
                        <TrendingUp className="w-3 h-3" />
                        {scoreDelta.delta > 0
                          ? `+${scoreDelta.delta} pts vs prev (${scoreDelta.previousScore}→${report.score})`
                          : scoreDelta.delta < 0
                          ? `${scoreDelta.delta} pts vs prev (${scoreDelta.previousScore}→${report.score})`
                          : `Consistent (${report.score}/100)`}
                        {(scoreDelta.fixedIssues.length > 0 || scoreDelta.newIssues.length > 0) &&
                          ` • ${scoreDelta.fixedIssues.length} Fixed • ${scoreDelta.newIssues.length} New`}
                      </span>
                    )}
                    {!report.isApkAudit && report.domainVerification && (
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                          report.domainVerification.verified
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                            : 'bg-white/[0.05] text-slate-300 border-white/10'
                        }`}
                      >
                        {report.domainVerification.verified
                          ? `Verified Owner (${report.domainVerification.method})`
                          : `Safe Mode (${report.domainVerification.burstProfile})`}
                      </span>
                    )}
                  </div>
                  {activePlanPolicy.features.scoreDelta && scoreDelta && scoreDelta.fixedIssues.length > 0 && (
                    <div className="mt-1 text-[10px] text-emerald-300 font-semibold">
                      Resolved since last scan: {scoreDelta.fixedIssues.slice(0, 3).join(' • ')}
                      {scoreDelta.fixedIssues.length > 3 ? ` (+${scoreDelta.fixedIssues.length - 3} more)` : ''}
                    </div>
                  )}
                  {report.isApkAudit && report.apkMeta?.sha256 && (
                    <div className="flex items-center gap-2 flex-wrap mt-1.5 text-[10px] font-mono text-slate-400">
                      <button
                        type="button"
                        onClick={() => {
                          navigator.clipboard.writeText(report.apkMeta!.sha256!);
                          setHashCopied(true);
                          setTimeout(() => setHashCopied(false), 1800);
                        }}
                        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-cyan-300 cursor-pointer"
                        title="Click to copy full SHA-256 fingerprint"
                      >
                        <span>SHA-256: {report.apkMeta.sha256.slice(0, 16)}...</span>
                        {hashCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                      {report.apkMeta.obfuscationStatus && (
                        <span className="px-2 py-0.5 rounded-md bg-white/[0.04] border border-white/10 text-slate-300">
                          Code: {report.apkMeta.obfuscationStatus}
                        </span>
                      )}
                      {report.telemetry?.durationSeconds && (
                        <span className="px-2 py-0.5 rounded-md bg-emerald-500/10 border border-emerald-500/20 text-emerald-300">
                          {report.telemetry.durationSeconds}s
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-2.5 no-print">
                {report.telemetry?.realTimeLogs && (
                  <button
                    onClick={() => setShowLogsModal(true)}
                    className="px-4 py-2 rounded-xl text-xs font-bold bg-white/[0.06] hover:bg-white/[0.12] text-cyan-300 border border-white/10 transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                    Logs ({report.telemetry.realTimeLogs.length})
                  </button>
                )}
                <button
                  onClick={() => {
                    setReport(null);
                    setApkFile(null);
                  }}
                  className="px-4 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-cyan-500/20 to-purple-500/20 hover:from-cyan-500/30 hover:to-purple-500/30 text-white border border-white/15 transition-all flex items-center justify-center gap-1.5 cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  New Audit
                </button>
              </div>
            </div>

            {/* Technical Telemetry Row */}
            {report.telemetry && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {report.isApkAudit && report.apkMeta ? (
                    <>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <Cpu className="w-5 h-5 text-purple-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">Framework</span>
                          <span className="text-xs font-extrabold text-white">{report.apkMeta.frameworkDetected}</span>
                        </div>
                      </div>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <Smartphone className="w-5 h-5 text-cyan-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">SDK Level</span>
                          <span className="text-xs font-extrabold text-white">
                            Target {report.apkMeta.targetSdkVersion} (Min {report.apkMeta.minSdkVersion})
                          </span>
                        </div>
                      </div>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <Layers className="w-5 h-5 text-amber-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">Bytecode</span>
                          <span className="text-xs font-extrabold text-white">{report.apkMeta.dexCount} DEX Archives</span>
                        </div>
                      </div>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <FileCode2 className="w-5 h-5 text-emerald-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">Permissions</span>
                          <span className="text-xs font-extrabold text-white">{report.apkMeta.permissions.length} Declared</span>
                        </div>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <Activity className="w-5 h-5 text-cyan-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">Latency</span>
                          <span className="text-xs font-extrabold text-white">{report.telemetry.latencyMs || 0} ms</span>
                        </div>
                      </div>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <FileCode2 className="w-5 h-5 text-emerald-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">Inspected</span>
                          <span className="text-xs font-extrabold text-white">
                            {report.telemetry.totalLinesInspected.toLocaleString()} lines ({(report.telemetry.totalBytesScanned / 1024).toFixed(0)} KB)
                          </span>
                        </div>
                      </div>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <Layers className="w-5 h-5 text-amber-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">JS Bundles</span>
                          <span className="text-xs font-extrabold text-white">{report.telemetry.scriptsCount} Chunks</span>
                        </div>
                      </div>
                      <div className="glass-card p-4 rounded-2xl flex items-center gap-3">
                        <Cpu className="w-5 h-5 text-purple-400 shrink-0" />
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">Stack</span>
                          <div className="flex gap-1 flex-wrap mt-0.5">
                            {report.telemetry.detectedTech.map((t, idx) => (
                              <span key={idx} className="text-[10px] font-bold bg-cyan-500/15 text-cyan-300 px-1.5 py-0.5 rounded">
                                {t}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </>
                  )}
                </div>

                {/* Web Deep Surface: Multi-Route, OpenAPI, GraphQL, DOM XSS Sinks & JWT */}
                {!report.isApkAudit && report.webDeepSurface && (
                  <div className="glass-card p-5 rounded-2xl border border-cyan-500/25 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Globe className="w-4 h-4 text-cyan-400" />
                        <h3 className="text-xs font-black uppercase tracking-wider text-white">
                          Stage 2.5: Web Attack Surface, DOM XSS Sinks &amp; API/JWT Audit
                        </h3>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
                        <span className="px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 font-bold">
                          {report.webDeepSurface.discoveredRoutes.length} Routes • {report.webDeepSurface.apiEndpoints.length} APIs
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded-full font-black border ${
                            report.webDeepSurface.domSinks.length > 0
                              ? 'bg-rose-500/15 text-rose-300 border-rose-400/30'
                              : 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                          }`}
                        >
                          {report.webDeepSurface.domSinks.length} DOM Sink(s)
                        </span>
                        {report.webDeepSurface.graphqlEndpoints.length > 0 && (
                          <span
                            className={`px-2 py-0.5 rounded-full font-bold border ${
                              report.webDeepSurface.graphqlEndpoints.some((g) => g.introspectionEnabled)
                                ? 'bg-amber-500/15 text-amber-300 border-amber-400/30'
                                : 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                            }`}
                          >
                            GraphQL:{' '}
                            {report.webDeepSurface.graphqlEndpoints.some((g) => g.introspectionEnabled)
                              ? 'Introspection Open'
                              : 'Protected'}
                          </span>
                        )}
                        {report.webDeepSurface.jwtAudits.length > 0 && (
                          <span className="px-2 py-0.5 rounded-full bg-purple-500/15 text-purple-300 border border-purple-400/30 font-bold">
                            JWT Audited: {report.webDeepSurface.jwtAudits.length}
                          </span>
                        )}
                        {report.webDeepSurface.authAudit?.enabled && (
                          <span className="px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-400/30 font-bold">
                            Auth: {report.webDeepSurface.authAudit.authKind} (HTTP {report.webDeepSurface.authAudit.targetStatus})
                          </span>
                        )}
                        {report.networkPosture && (
                          <>
                            <span
                              className={`px-2 py-0.5 rounded-full font-bold border ${
                                report.networkPosture.corsReflection === 'Strict'
                                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                                  : 'bg-rose-500/15 text-rose-300 border-rose-400/30'
                              }`}
                            >
                              CORS Probe: {report.networkPosture.corsReflection}
                            </span>
                            {report.networkPosture.tlsProtocol && (
                              <span className="px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 font-bold">
                                {report.networkPosture.tlsProtocol}
                                {report.networkPosture.certDaysRemaining !== null
                                  ? ` (${report.networkPosture.certDaysRemaining}d cert)`
                                  : ''}
                              </span>
                            )}
                            {report.networkPosture.spfPresent !== null && (
                              <span
                                className={`px-2 py-0.5 rounded-full font-bold border ${
                                  report.networkPosture.spfPresent &&
                                  (report.networkPosture.dmarcPolicy === 'reject' ||
                                    report.networkPosture.dmarcPolicy === 'quarantine')
                                    ? 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                                    : 'bg-amber-500/15 text-amber-300 border-amber-400/30'
                                }`}
                              >
                                SPF:{report.networkPosture.spfPresent ? 'Yes' : 'No'} • DMARC:{report.networkPosture.dmarcPolicy || 'none'}
                              </span>
                            )}
                          </>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 text-[11px] font-mono">
                      {/* Routes & OpenAPI */}
                      <div className="p-3 rounded-xl bg-[#050811]/80 border border-white/5 space-y-1.5">
                        <div className="text-[10px] font-black uppercase text-cyan-300">
                          Routes, Sitemap &amp; OpenAPI ({report.webDeepSurface.openApiSpecs.length} Spec)
                        </div>
                        <div className="max-h-28 overflow-y-auto space-y-1 pr-1 text-slate-300">
                          {report.webDeepSurface.openApiSpecs.map((sp, i) => (
                            <div key={i} className="text-amber-300 truncate" title={sp.url}>
                              OpenAPI: {sp.url.replace(/^https?:\/\/[^/]+/, '')} ({sp.pathsCount} paths)
                            </div>
                          ))}
                          {report.webDeepSurface.apiEndpoints.slice(0, 6).map((ep, i) => (
                            <div key={`ep-${i}`} className="text-emerald-300 truncate" title={ep}>
                              API: {ep}
                            </div>
                          ))}
                          {report.webDeepSurface.discoveredRoutes.slice(0, 5).map((rt, i) => (
                            <div key={`rt-${i}`} className="text-slate-400 truncate" title={rt}>
                              Route: {rt}
                            </div>
                          ))}
                          {report.webDeepSurface.apiEndpoints.length === 0 &&
                            report.webDeepSurface.discoveredRoutes.length === 0 &&
                            report.webDeepSurface.openApiSpecs.length === 0 && (
                              <div className="text-slate-500">No extra routes or OpenAPI docs exposed.</div>
                            )}
                        </div>
                      </div>

                      {/* Static DOM XSS Sinks */}
                      <div className="p-3 rounded-xl bg-[#050811]/80 border border-white/5 space-y-1.5">
                        <div className="text-[10px] font-black uppercase text-rose-300">
                          Static DOM XSS Sinks ({report.webDeepSurface.domSinks.length})
                        </div>
                        <div className="max-h-28 overflow-y-auto space-y-1.5 pr-1">
                          {report.webDeepSurface.domSinks.length > 0 ? (
                            report.webDeepSurface.domSinks.slice(0, 6).map((sink, i) => (
                              <div key={i} className="p-1.5 rounded bg-rose-500/10 border border-rose-500/20">
                                <div className="flex items-center justify-between gap-1 text-[10px]">
                                  <span className="font-bold text-rose-300">{sink.type}</span>
                                  {sink.taintedByInput && (
                                    <span className="px-1 rounded bg-rose-500/30 text-white text-[9px]">INPUT TAINT</span>
                                  )}
                                </div>
                                <div className="text-slate-300 text-[10px] truncate" title={sink.snippet}>
                                  {sink.snippet}
                                </div>
                              </div>
                            ))
                          ) : (
                            <div className="text-emerald-300">0 unsafe eval / innerHTML / postMessage sinks matched.</div>
                          )}
                        </div>
                      </div>

                      {/* JWT & Auth Control Checks */}
                      <div className="p-3 rounded-xl bg-[#050811]/80 border border-white/5 space-y-1.5">
                        <div className="text-[10px] font-black uppercase text-purple-300">
                          JWT &amp; Auth Session Audit ({report.webDeepSurface.jwtAudits.length})
                        </div>
                        <div className="max-h-28 overflow-y-auto space-y-1.5 pr-1">
                          {report.webDeepSurface.jwtAudits.map((jt, i) => (
                            <div key={i} className="p-1.5 rounded bg-purple-500/10 border border-purple-500/20 space-y-0.5">
                              <div className="flex items-center justify-between text-[10px]">
                                <span className="text-purple-200 font-bold">alg: {jt.alg}</span>
                                <span className={jt.hasExp ? 'text-emerald-300' : 'text-amber-300'}>
                                  {jt.hasExp ? (jt.expired ? 'Expired exp' : 'Valid exp') : 'No exp'}
                                </span>
                              </div>
                              <div className="text-[10px] text-slate-400 truncate">
                                Claims: {jt.claims.join(', ')}
                              </div>
                              {jt.issues.length > 0 && (
                                <div className="text-[10px] text-rose-300 truncate">{jt.issues.join(' • ')}</div>
                              )}
                            </div>
                          ))}
                          {report.webDeepSurface.authAudit?.protectedApiChecks.slice(0, 4).map((chk, i) => (
                            <div key={`chk-${i}`} className="text-[10px] text-slate-300 flex justify-between gap-2">
                              <span className="truncate">{chk.url}</span>
                              <span className="shrink-0 text-cyan-300">
                                {chk.authStatus} vs {chk.unauthStatus}
                              </span>
                            </div>
                          ))}
                          {report.webDeepSurface.jwtAudits.length === 0 &&
                            (!report.webDeepSurface.authAudit ||
                              report.webDeepSurface.authAudit.protectedApiChecks.length === 0) && (
                              <div className="text-slate-500">
                                No client JWTs found. Attach an optional Bearer JWT above to audit session claims &amp; protected routes.
                              </div>
                            )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Ostorlab-Level APK Intelligence Bento Modules */}
                {report.isApkAudit && report.apkMeta && (
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    {/* 1. Exported Components Surface */}
                    {report.apkMeta.exportedComponents && (
                      <div className="glass-card p-5 rounded-2xl border border-white/10 space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Shield className="w-4 h-4 text-cyan-400" />
                            <h3 className="text-xs font-black uppercase tracking-wider text-white">
                              Exported IPC Surface
                            </h3>
                          </div>
                          <span
                            className={`text-[10px] font-black px-2 py-0.5 rounded-full border ${
                              report.apkMeta.exportedComponents.unprotectedCount > 0
                                ? 'bg-amber-500/15 text-amber-300 border-amber-400/30'
                                : 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                            }`}
                          >
                            {report.apkMeta.exportedComponents.unprotectedCount > 0
                              ? `${report.apkMeta.exportedComponents.unprotectedCount} Unprotected`
                              : `${report.apkMeta.exportedComponents.totalExported} Audited`}
                          </span>
                        </div>

                        <div className="grid grid-cols-4 gap-1.5 text-center">
                          {[
                            { label: 'Activities', count: report.apkMeta.exportedComponents.activities.length },
                            { label: 'Services', count: report.apkMeta.exportedComponents.services.length },
                            { label: 'Receivers', count: report.apkMeta.exportedComponents.receivers.length },
                            { label: 'Providers', count: report.apkMeta.exportedComponents.providers.length }
                          ].map((box, idx) => (
                            <div key={idx} className="p-2 rounded-xl bg-[#050811]/80 border border-white/5">
                              <span className="text-sm font-black text-white block">{box.count}</span>
                              <span className="text-[9px] font-bold uppercase text-slate-400">{box.label}</span>
                            </div>
                          ))}
                        </div>

                        <div className="space-y-1.5 max-h-28 overflow-y-auto pr-1 text-[11px] font-mono">
                          {[
                            ...report.apkMeta.exportedComponents.activities,
                            ...report.apkMeta.exportedComponents.services,
                            ...report.apkMeta.exportedComponents.receivers,
                            ...report.apkMeta.exportedComponents.providers
                          ].slice(0, 8).map((c, idx) => (
                            <div
                              key={idx}
                              className="flex items-center justify-between gap-2 px-2.5 py-1 rounded-lg bg-[#050811]/70 border border-white/5"
                            >
                              <span className="truncate text-slate-300" title={c.name}>
                                <span className="text-cyan-400">[{c.componentType[0].toUpperCase()}]</span>{' '}
                                {c.name.split('.').slice(-2).join('.')}
                              </span>
                              <span
                                className={`text-[9px] font-bold px-1.5 py-0.5 rounded shrink-0 ${
                                  c.risky
                                    ? 'bg-rose-500/20 text-rose-300'
                                    : c.isLauncher
                                    ? 'bg-cyan-500/20 text-cyan-300'
                                    : 'bg-emerald-500/15 text-emerald-300'
                                }`}
                              >
                                {c.risky ? 'UNPROTECTED' : c.isLauncher ? 'LAUNCHER' : 'GUARDED'}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* 2. Trackers & 3rd-Party SDKs */}
                    <div className="glass-card p-5 rounded-2xl border border-white/10 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Radio className="w-4 h-4 text-purple-400" />
                          <h3 className="text-xs font-black uppercase tracking-wider text-white">
                            Trackers & Embedded SDKs
                          </h3>
                        </div>
                        <span className="text-[10px] font-black px-2 py-0.5 rounded-full bg-purple-500/15 text-purple-300 border border-purple-400/30">
                          {(report.apkMeta.trackers?.length || 0) + (report.apkMeta.sdks?.length || 0)} Detected
                        </span>
                      </div>

                      <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                        <div>
                          <span className="text-[10px] font-bold uppercase text-amber-300 block mb-1">
                            Analytics & Ad Trackers ({report.apkMeta.trackers?.length || 0})
                          </span>
                          <div className="flex flex-wrap gap-1.5">
                            {report.apkMeta.trackers && report.apkMeta.trackers.length > 0 ? (
                              report.apkMeta.trackers.map((t, idx) => (
                                <span
                                  key={idx}
                                  className="text-[10px] font-bold px-2 py-0.5 rounded-lg bg-amber-500/15 text-amber-200 border border-amber-400/25"
                                >
                                  {t}
                                </span>
                              ))
                            ) : (
                              <span className="text-[11px] text-slate-500">No ad/analytics trackers detected</span>
                            )}
                          </div>
                        </div>

                        <div>
                          <span className="text-[10px] font-bold uppercase text-cyan-300 block mb-1">
                            Core & Payment SDKs ({report.apkMeta.sdks?.length || 0})
                          </span>
                          <div className="flex flex-wrap gap-1.5">
                            {report.apkMeta.sdks && report.apkMeta.sdks.length > 0 ? (
                              report.apkMeta.sdks.map((s, idx) => (
                                <span
                                  key={idx}
                                  className="text-[10px] font-bold px-2 py-0.5 rounded-lg bg-cyan-500/15 text-cyan-200 border border-cyan-400/25"
                                >
                                  {s}
                                </span>
                              ))
                            ) : (
                              <span className="text-[11px] text-slate-500">Zero external SDK footprints found</span>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* 3. Stage 3 Extracted Backend APIs */}
                    <div className="glass-card p-5 rounded-2xl border border-white/10 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Server className="w-4 h-4 text-emerald-400" />
                          <h3 className="text-xs font-black uppercase tracking-wider text-white">
                            Stage 3: Backend APIs
                          </h3>
                        </div>
                        <span className="text-[10px] font-black px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-400/30">
                          {report.apkMeta.probedApis?.length || 0} Live Probed
                        </span>
                      </div>

                      <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1 text-[11px] font-mono">
                        {report.apkMeta.probedApis && report.apkMeta.probedApis.length > 0 ? (
                          report.apkMeta.probedApis.map((api, idx) => (
                            <div
                              key={idx}
                              className="p-2 rounded-xl bg-[#050811]/80 border border-white/5 space-y-1"
                            >
                              <div className="flex items-center justify-between gap-2">
                                <span className="truncate text-cyan-300 font-semibold" title={api.url}>
                                  {api.url.replace(/^https?:\/\//, '')}
                                </span>
                                <span
                                  className={`text-[9px] font-black px-1.5 py-0.5 rounded shrink-0 ${
                                    api.reachable
                                      ? 'bg-emerald-500/20 text-emerald-300'
                                      : 'bg-slate-500/20 text-slate-300'
                                  }`}
                                >
                                  {api.reachable ? `HTTP ${api.status} • ${api.latencyMs}ms` : String(api.status)}
                                </span>
                              </div>
                              <div className="flex items-center gap-2 text-[9px] text-slate-400">
                                <span>HSTS: {api.hsts ? 'Yes' : 'No'}</span>
                                <span>•</span>
                                <span className="truncate">CORS: {api.cors}</span>
                              </div>
                            </div>
                          ))
                        ) : (
                          <div className="p-3 rounded-xl bg-[#050811]/60 border border-white/5 text-slate-400 text-[11px]">
                            No custom external API origins were hardcoded in DEX/JS bundles.
                          </div>
                        )}
                        {report.apkMeta.baasUrls && report.apkMeta.baasUrls.length > 0 && (
                          <div className="pt-1 flex flex-wrap gap-1">
                            {report.apkMeta.baasUrls.map((b, idx) => (
                              <span key={idx} className="text-[9px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 truncate max-w-full">
                                BaaS: {b.replace('https://', '')}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* 4. Stage 2.5: Dalvik Bytecode Control-Flow, Cross-Method Taint & Native ELF Inspection */}
                {report.isApkAudit && report.apkMeta?.dexBytecodeGraph && (
                  <div className="glass-card p-5 rounded-2xl border border-purple-500/25 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Binary className="w-4 h-4 text-purple-400" />
                        <h3 className="text-xs font-black uppercase tracking-wider text-white">
                          Stage 2.5: Dalvik Bytecode CFG &amp; Cross-Method Taint Graph
                        </h3>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
                        <span className="px-2 py-0.5 rounded-full bg-purple-500/15 text-purple-300 border border-purple-400/30 font-bold">
                          {report.apkMeta.dexBytecodeGraph.methodsAnalyzed.toLocaleString()} Methods • {report.apkMeta.dexBytecodeGraph.instructionsScanned.toLocaleString()} Opcodes ({report.apkMeta.dexBytecodeGraph.durationMs}ms)
                        </span>
                        {report.apkMeta.pinningStatus && (
                          <span
                            className={`px-2 py-0.5 rounded-full font-bold border ${
                              report.apkMeta.pinningStatus.active
                                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                                : 'bg-amber-500/15 text-amber-300 border-amber-400/30'
                            }`}
                          >
                            {report.apkMeta.pinningStatus.active ? 'SSL Pinning: Active' : 'SSL Pinning: Not Detected'}
                          </span>
                        )}
                        <span
                          className={`px-2 py-0.5 rounded-full font-black border ${
                            report.apkMeta.dexBytecodeGraph.taintPaths.length > 0
                              ? 'bg-rose-500/15 text-rose-300 border-rose-400/30'
                              : 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                          }`}
                        >
                          {report.apkMeta.dexBytecodeGraph.taintPaths.length > 0
                            ? `${report.apkMeta.dexBytecodeGraph.taintPaths.length} Taint Flow(s)${
                                (report.apkMeta.dexBytecodeGraph.interproceduralPathsCount || 0) > 0
                                  ? ` (${report.apkMeta.dexBytecodeGraph.interproceduralPathsCount} Multi-Hop)`
                                  : ''
                              }`
                            : '0 Taint Leaks'}
                        </span>
                      </div>
                    </div>

                    {report.apkMeta.dexBytecodeGraph.taintPaths.length > 0 && (
                      <div className="space-y-1.5">
                        {report.apkMeta.dexBytecodeGraph.taintPaths.slice(0, 6).map((tp, idx) => (
                          <div key={idx} className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/25 text-[11px] font-mono">
                            <div className="flex items-center justify-between gap-2 text-rose-300 font-bold">
                              <span>
                                {tp.source} ➔ {tp.sink}
                                {tp.hopCount && tp.hopCount >= 2 ? ` (${tp.hopCount}-Hop Chain)` : ''}
                              </span>
                              <span className="text-[9px] px-1.5 py-0.5 rounded bg-rose-500/20">{tp.owaspRef}</span>
                            </div>
                            <div className="text-slate-300 mt-1 break-all">
                              {tp.callChain && tp.callChain.length >= 2 ? tp.callChain.join(' ➔ ') : tp.methodSignature}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {report.apkMeta.dexBytecodeGraph.callGraphHotspots.length > 0 && (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 pt-1 max-h-36 overflow-y-auto pr-1">
                        {report.apkMeta.dexBytecodeGraph.callGraphHotspots.slice(0, 9).map((edge, idx) => (
                          <div key={idx} className="p-2 rounded-xl bg-[#050811]/80 border border-white/5 text-[10px] font-mono space-y-0.5">
                            <span className="text-[9px] font-black uppercase text-cyan-300">{edge.category}</span>
                            <div className="text-slate-300 truncate" title={edge.callerMethod}>{edge.callerMethod}</div>
                            <div className="text-purple-300 truncate" title={edge.calleeSignature}>↳ {edge.calleeSignature}</div>
                          </div>
                        ))}
                      </div>
                    )}

                    {report.apkMeta.nativeElfSummary && report.apkMeta.nativeElfSummary.uniqueLibrariesCount > 0 && (
                      <div className="pt-2 border-t border-white/10 space-y-2">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="text-[11px] font-black uppercase tracking-wider text-cyan-300">
                            Native ELF (.so) Binary Matrix ({report.apkMeta.nativeElfSummary.uniqueLibrariesCount} Unique • {report.apkMeta.nativeElfSummary.appLibrariesCount} App Libs • {report.apkMeta.nativeElfSummary.nativeStringsScannedKb} KB Strings)
                          </span>
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                              report.apkMeta.nativeElfSummary.hardeningWeakCount > 0
                                ? 'bg-amber-500/15 text-amber-300 border-amber-400/30'
                                : 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
                            }`}
                          >
                            {report.apkMeta.nativeElfSummary.hardeningWeakCount > 0
                              ? `${report.apkMeta.nativeElfSummary.hardeningWeakCount} Weak Binary Flag(s)`
                              : 'PIE / NX / RELRO Hardened'}
                          </span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-32 overflow-y-auto pr-1 text-[10px] font-mono">
                          {report.apkMeta.nativeElfSummary.libraries.slice(0, 9).map((lib, idx) => (
                            <div key={idx} className="p-2 rounded-xl bg-[#050811]/80 border border-white/5 flex flex-col gap-1">
                              <div className="flex items-center justify-between gap-2">
                                <span className="truncate font-bold text-slate-200" title={lib.fileName}>{lib.baseName}</span>
                                <span className="text-[9px] text-slate-400 shrink-0">{lib.archBits}b {lib.abi}</span>
                              </div>
                              <div className="flex flex-wrap gap-1 text-[9px]">
                                <span className={`px-1.5 rounded ${lib.pie ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/20 text-rose-300'}`}>PIE</span>
                                <span className={`px-1.5 rounded ${lib.nx ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/20 text-rose-300'}`}>NX</span>
                                <span className={`px-1.5 rounded ${lib.stackCanary ? 'bg-emerald-500/15 text-emerald-300' : 'bg-amber-500/15 text-amber-300'}`}>Canary</span>
                                <span className={`px-1.5 rounded ${lib.relro !== 'NONE' ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/20 text-rose-300'}`}>RELRO:{lib.relro}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="mt-2 flex items-center justify-between flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={handleLoadDomainChallenge}
                        className="text-[11px] font-bold text-emerald-300 hover:text-emerald-200 inline-flex items-center gap-1.5 cursor-pointer"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Verify Domain Ownership (Unlock Full 15-Request Rate Burst)</span>
                      </button>
                      <span className="text-[10px] text-slate-500">
                        Unverified public targets use a safe 4-request gentle profile
                      </span>
                    </div>

                    {domainChallenge && (
                      <div className="mt-2 p-3 rounded-2xl bg-[#050811]/90 border border-emerald-500/25 text-[10px] font-mono space-y-1.5 text-slate-300">
                        <div className="text-emerald-300 font-bold">
                          Add either TXT record or HTML Meta Tag to verify &quot;{domainChallenge.host}&quot;:
                        </div>
                        <div className="p-1.5 rounded bg-black/60 break-all select-all text-cyan-300">
                          DNS TXT: {domainChallenge.txtRecord}
                        </div>
                        <div className="p-1.5 rounded bg-black/60 break-all select-all text-emerald-300">
                          HTML Meta: {domainChallenge.metaTag}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Scorecard Overview Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <ScoreGauge score={report.score} grade={report.grade} riskLevel={report.riskLevel} />

              <div className="md:col-span-2 grid grid-cols-2 sm:grid-cols-5 gap-3 glass-panel p-5 rounded-3xl">
                <div className="p-3 rounded-2xl bg-rose-500/10 border border-rose-500/25 text-center flex flex-col items-center justify-center">
                  <span className="text-3xl font-black text-rose-400">{report.summaryCounts.critical}</span>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-rose-300 mt-1">Critical</span>
                </div>
                <div className="p-3 rounded-2xl bg-orange-500/10 border border-orange-500/25 text-center flex flex-col items-center justify-center">
                  <span className="text-3xl font-black text-orange-400">{report.summaryCounts.high}</span>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-orange-300 mt-1">High Risk</span>
                </div>
                <div className="p-3 rounded-2xl bg-amber-500/10 border border-amber-500/25 text-center flex flex-col items-center justify-center">
                  <span className="text-3xl font-black text-amber-400">{report.summaryCounts.medium}</span>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-amber-300 mt-1">Medium</span>
                </div>
                <div className="p-3 rounded-2xl bg-blue-500/10 border border-blue-500/25 text-center flex flex-col items-center justify-center">
                  <span className="text-3xl font-black text-blue-400">{report.summaryCounts.low}</span>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-blue-300 mt-1">Low Risk</span>
                </div>
                <div className="p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/25 text-center flex flex-col items-center justify-center">
                  <span className="text-3xl font-black text-emerald-400">{report.summaryCounts.pass}</span>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-300 mt-1">Passed</span>
                </div>

                {report.aiExecutiveSummary && (
                  <div className="col-span-2 sm:col-span-5 mt-2 p-4 rounded-2xl bg-[#050811]/90 border border-cyan-500/25 text-xs shadow-inner">
                    <div className="flex items-center gap-1.5 text-cyan-400 font-black mb-2">
                      <Sparkles className="w-4 h-4" />
                      <span>
                        {report.isApkAudit
                          ? 'CheckMyAPK Neural Mobile Penetration Brief:'
                          : 'CheckMyAPK Neural Web Security Synthesis:'}
                      </span>
                    </div>
                    <div className="text-slate-300 whitespace-pre-line leading-relaxed text-[12px] font-medium">
                      {report.aiExecutiveSummary}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* 🛠️ Master Remediation Playbook (Web Only — only when Header/CORS gaps exist) */}
            {!report.isApkAudit &&
              report.findings.some(
                (f) =>
                  f.severity !== 'PASS' &&
                  f.severity !== 'INFO' &&
                  /header|cors/i.test(f.category || '')
              ) && (
              <div className="glass-panel border-emerald-500/30 rounded-3xl p-5 space-y-4 shadow-xl">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
                      <Wrench className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-sm font-black text-white flex items-center gap-2 flex-wrap">
                        <span>60-Second Master Fix: Resolve All Headers in 1 File</span>
                        <span className="text-[10px] font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/25 px-2 py-0.5 rounded-full">
                          {activePlanPolicy.features.aiFixDoctor ? 'Recommended' : 'Pro Security'}
                        </span>
                      </h3>
                      <p className="text-xs text-slate-400">
                        {activePlanPolicy.features.aiFixDoctor
                          ? 'Paste this single configuration snippet into your repository to harden all web headers instantly:'
                          : 'Copy-paste Master Header remediation packs for Vercel, Next.js & Express unlock on Pro Security ($15/mo) and Team & Agency.'}
                      </p>
                    </div>
                  </div>

                  {activePlanPolicy.features.aiFixDoctor ? (
                    <div className="flex items-center gap-1 bg-[#050811] p-1 rounded-xl border border-white/10 text-xs shrink-0">
                      {(['vercel', 'nextjs', 'express'] as const).map((tab) => (
                        <button
                          key={tab}
                          onClick={() => setMasterTab(tab)}
                          className={`px-3 py-1.5 rounded-lg font-bold transition-all cursor-pointer ${
                            masterTab === tab ? 'bg-emerald-500 text-slate-950' : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          {tab === 'vercel' ? 'Vercel' : tab === 'nextjs' ? 'Next.js' : 'Node/Express'}
                        </button>
                      ))}
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={openPricingPage}
                      className="px-3.5 py-2 rounded-xl text-xs font-extrabold bg-gradient-to-r from-amber-500 to-orange-500 text-slate-950 hover:brightness-110 transition-all inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
                    >
                      <Lock className="w-3.5 h-3.5" />
                      <span>Unlock Master Fix</span>
                    </button>
                  )}
                </div>

                {activePlanPolicy.features.aiFixDoctor && (
                  <div className="rounded-2xl border border-white/10 bg-[#050811] overflow-hidden text-xs">
                    <div className="flex items-center justify-between px-4 py-2.5 bg-white/[0.04] border-b border-white/10">
                      <div className="flex items-center gap-2 text-slate-300 font-mono text-[11px]">
                        <Code2 className="w-4 h-4 text-emerald-400" />
                        <span>{masterCodes[masterTab].filename}</span>
                      </div>
                      <button
                        onClick={() => handleCopyMaster(masterCodes[masterTab].code)}
                        className="flex items-center gap-1.5 text-xs font-bold text-emerald-300 hover:text-emerald-200 transition-colors bg-emerald-500/15 px-3 py-1 rounded-lg border border-emerald-500/30 cursor-pointer"
                      >
                        {masterCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        {masterCopied ? 'Copied!' : 'Copy Config'}
                      </button>
                    </div>
                    <pre className="p-4 text-[11px] font-mono text-emerald-300 overflow-x-auto leading-relaxed select-all max-h-48">
                      {masterCodes[masterTab].code}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {/* Findings Filter Bar */}
            <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-3">
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={() => setFilter('vulns')}
                  className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    filter === 'vulns'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                      : 'text-slate-400 hover:text-slate-200 bg-white/[0.03] border border-white/5'
                  }`}
                >
                  Vulnerabilities ({report.findings.filter((f) => f.severity !== 'PASS' && f.severity !== 'INFO').length})
                </button>
                <button
                  onClick={() => setFilter('pass')}
                  className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    filter === 'pass'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'text-slate-400 hover:text-slate-200 bg-white/[0.03] border border-white/5'
                  }`}
                >
                  {(() => {
                    const passAndInfoCount = report.findings.filter(
                      (f) => f.severity === 'PASS' || f.severity === 'INFO'
                    ).length;
                    const hasInfo = report.findings.some((f) => f.severity === 'INFO');
                    return `${hasInfo ? 'Passed & Info' : 'Passed Checks'} (${passAndInfoCount})`;
                  })()}
                </button>
                <button
                  onClick={() => setFilter('all')}
                  className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    filter === 'all'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-slate-200 bg-white/[0.03] border border-white/5'
                  }`}
                >
                  All Items ({report.findings.length})
                </button>
              </div>
            </div>

            {/* Findings List */}
            <div className="flex flex-col gap-3">
              {filteredFindings.length === 0 ? (
                <div className="p-10 text-center glass-card rounded-2xl text-slate-400 text-xs font-medium">
                  No security findings match this filter. Switch to "All Items" or "Passed Checks" to view full audit telemetry!
                </div>
              ) : (
                filteredFindings.map((finding, idx) => (
                  <FindingCard
                    key={idx}
                    finding={finding}
                    detectedTech={report.telemetry?.detectedTech}
                    targetUrl={report.targetUrl}
                    defaultExpanded={idx < 2}
                    canUseAiFixDoctor={activePlanPolicy.features.aiFixDoctor}
                    onRequestUpgrade={openPricingPage}
                  />
                ))
              )}
            </div>

            {/* ── Enterprise Automated Audit Disclaimer (Screen + PDF Export) ── */}
            <div className="glass-card rounded-2xl border border-white/10 p-4 sm:p-5 text-[11px] text-slate-400 leading-relaxed space-y-1.5 print:break-inside-avoid">
              <div className="flex items-center gap-2 text-slate-200 font-extrabold uppercase tracking-wider text-[10px]">
                <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>Automated Point-in-Time Security Assessment Disclaimer</span>
              </div>
              <p>
                This report reflects automated static analysis and non-destructive passive/safe dynamic checks performed by{' '}
                <strong className="text-slate-300">CheckMyAPK.com</strong> at{' '}
                <span className="font-mono text-slate-300">{report.scanTimestamp}</span>. Items labeled{' '}
                <span className="text-emerald-300 font-bold">Confirmed</span> were verified via live HTTP/TLS/DNS telemetry,
                read-only probes, or manifest/bytecode structure; items labeled{' '}
                <span className="text-amber-300 font-bold">Heuristic • Verify Context</span> use static pattern matching and
                may require engineer review for upstream sanitizers, WAF rules, or API/HTTP-referrer restrictions.
              </p>
              <p className="text-slate-500">
                Automated scanners cannot detect every server-side or business-logic flaw and are not a substitute for an
                authorized manual penetration test or formal compliance audit (SOC 2 / ISO 27001). Always assess only domains
                and applications you own or have explicit authorization to test.
              </p>
            </div>
          </div>
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

      {/* ── Privacy / Methodology Trust Modal ── */}
      {showTrustModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 no-print">
          <div className="glass-panel rounded-3xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden border border-white/15">
            <div className="p-4 border-b border-white/10 flex items-center justify-between gap-2 bg-[#080c17]">
              <div className="flex items-center gap-2 min-w-0">
                <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                <h3 className="text-sm font-black text-white truncate">
                  {showTrustModal === 'methodology'
                    ? '4-Stage CheckMyAPK Audit Methodology'
                    : showTrustModal === 'api'
                    ? 'CheckMyAPK CI/CD & REST API Reference'
                    : LEGAL_DOCS_BY_ID[showTrustModal].title}
                </h3>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {showTrustModal !== 'methodology' && showTrustModal !== 'api' && (
                  <div className="hidden sm:inline-flex items-center gap-1 p-0.5 rounded-lg bg-white/5 border border-white/10 text-[10px]">
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
                        className={`px-2 py-0.5 rounded-md font-bold cursor-pointer transition-colors ${
                          showTrustModal === tab.id
                            ? 'bg-cyan-500/25 text-cyan-200'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </div>
                )}
                <button
                  onClick={closeTrustModal}
                  className="p-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white cursor-pointer"
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
                  <div className="rounded-xl border border-white/10 bg-[#050811]/85 overflow-hidden">
                    <div className="flex items-center justify-between px-3 py-2 border-b border-white/10 text-[11px] font-mono text-slate-400">
                      <span>POST /api/scan • Web &amp; API Audit</span>
                      <button
                        type="button"
                        onClick={() => {
                          const cmd = `curl -X POST https://checkmyapk.com/api/scan \\\n  -H "Content-Type: application/json" \\\n  -H "Authorization: Bearer YOUR_WORKSPACE_API_TOKEN" \\\n  -d '{"url":"https://api.yourdomain.com"}'`;
                          navigator.clipboard?.writeText(cmd).then(() => {
                            setApiSnippetCopied(true);
                            setTimeout(() => setApiSnippetCopied(false), 1800);
                          }).catch(() => {});
                        }}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-white/10 hover:bg-white/15 text-slate-200 cursor-pointer"
                      >
                        {apiSnippetCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{apiSnippetCopied ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <pre className="p-3.5 text-[11px] font-mono text-cyan-300 overflow-x-auto leading-relaxed">
{`curl -X POST https://checkmyapk.com/api/scan \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_WORKSPACE_API_TOKEN" \\
  -d '{"url":"https://api.yourdomain.com"}'`}
                    </pre>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="p-3.5 rounded-xl bg-[#050811]/80 border border-white/10">
                      <strong className="text-white block mb-1">APK Binary Upload Endpoint</strong>
                      <code className="text-cyan-300 font-mono text-[11px]">POST /api/scan-apk</code>
                      <p className="mt-1 text-slate-400">
                        Accepts <code className="text-slate-200">multipart/form-data</code> (<code className="text-slate-200">apk</code> field) up to 150MB on Team &amp; Agency and returns deterministic OWASP MASVS JSON findings.
                      </p>
                    </div>
                    <div className="p-3.5 rounded-xl bg-[#050811]/80 border border-white/10">
                      <strong className="text-white block mb-1">Workspace Token Access</strong>
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
                        className="h-8 px-3.5 rounded-md text-xs font-semibold bg-white text-slate-950 hover:bg-slate-200 transition-colors cursor-pointer"
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
                        className="h-8 px-3.5 rounded-md text-xs font-semibold bg-white text-slate-950 hover:bg-slate-200 transition-colors cursor-pointer"
                      >
                        View Team &amp; Agency Plan
                      </button>
                    )}
                  </div>
                </div>
              ) : showTrustModal !== 'methodology' ? (
                <>
                  <p className="text-[11px] text-slate-400">
                    Effective: {LEGAL_DOCS_BY_ID[showTrustModal].effectiveDate} •{' '}
                    {LEGAL_DOCS_BY_ID[showTrustModal].subtitle}
                  </p>
                  {LEGAL_DOCS_BY_ID[showTrustModal].sections.map((sec) => (
                    <div key={sec.title} className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 space-y-1.5">
                      <h4 className="font-black text-white">{sec.title}</h4>
                      <p>{sec.body}</p>
                    </div>
                  ))}
                </>
              ) : (
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="p-3.5 rounded-2xl bg-[#050811]/80 border border-white/10">
                      <strong className="text-cyan-300 block mb-1">Stage 1: Binary Manifest & IPC</strong>
                      Parses AndroidBinaryXML (<code className="text-white">AndroidManifest.xml</code> + <code className="text-white">network_security_config</code>) to check debuggable flags, backup rules, SDK targets, and exported Activities/Services/Receivers/Providers.
                    </div>
                    <div className="p-3.5 rounded-2xl bg-[#050811]/80 border border-white/10">
                      <strong className="text-purple-300 block mb-1">Stage 2: DEX, Resources & Secrets</strong>
                      Scans <code className="text-white">classes*.dex</code>, <code className="text-white">resources.arsc</code> &amp; JS assets for hardcoded API keys, SSL TrustAll bypasses, ECB/DES weak crypto, WebView exposure, R8 obfuscation, and embedded trackers/SDKs.
                    </div>
                    <div className="p-3.5 rounded-2xl bg-[#050811]/80 border border-white/10">
                      <strong className="text-emerald-300 block mb-1">Stage 3: Auto Backend API Probes</strong>
                      Extracts backend API &amp; Firebase/Supabase URLs from APK binaries and actively checks live TLS/HSTS, CORS credentials policy, and open anonymous DB reads.
                    </div>
                    <div className="p-3.5 rounded-2xl bg-[#050811]/80 border border-white/10">
                      <strong className="text-amber-300 block mb-1">Web &amp; API Suite</strong>
                      Inspects live JS chunks + HTML for leaked keys, <code className="text-white">.env</code>/<code className="text-white">.git</code>/<code className="text-white">.js.map</code> exposures, CSP/HSTS/Cookie flags, Firebase/Supabase rules, and burst rate limits.
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {authModalMode && (
        <AuthModal
          initialMode={authModalMode}
          onClose={() => {
            setAuthModalMode(null);
            setPendingCheckout(null);
          }}
          onSuccess={(user) => {
            setCurrentUser(user);
            setAuthModalMode(null);
            if (pendingCheckout) {
              const next = pendingCheckout;
              setPendingCheckout(null);
              void startDodoCheckout(next.plan, next.billingCycle);
            }
          }}
        />
      )}

      {/* ── Architectural Footer ── */}
      <footer className="py-6 border-t border-white/[0.08] bg-[#070a09]/90 text-xs text-slate-400 relative z-10 no-print">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-3">
          <span className="font-display font-semibold text-white tracking-[-0.02em]">
            CheckMyAPK <span className="font-sans font-normal text-slate-400">· Android APK &amp; Web Security Scanner</span>
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
