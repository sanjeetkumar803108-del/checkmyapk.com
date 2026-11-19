import React, { useState } from 'react';
import {
  Check,
  Smartphone,
  Globe,
  ChevronDown,
  ArrowRight,
  Mail,
  Clock,
  ShieldCheck,
  Zap,
  Crown,
} from 'lucide-react';
import type { AccountPlan, UserAccount } from '../types/account';
import type { LegalDocId } from '../data/legalDocs';
import { PLAN_DISPLAY_CARDS } from '../data/planPolicy';
import { ContactUsForm } from './ContactUsForm';
import { LiveScanTelemetryBar } from './LiveScanTelemetryBar';

interface HomepageSectionsProps {
  currentUser: UserAccount | null;
  onSelectPlan: (plan: AccountPlan, billingCycle?: 'monthly' | 'annual') => void;
  checkoutBusyPlan?: AccountPlan | null;
  onStartAudit: (mode: 'apk' | 'web') => void;
  onOpenLegal?: (doc: LegalDocId) => void;
  onOpenPricingPage?: () => void;
}

interface DetectionRuleItem {
  id: string;
  title: string;
  token: string;
  detail: string;
}

const APK_ENGINE_RULES: DetectionRuleItem[] = [
  {
    id: 'MASVS-STORAGE-1',
    title: 'DEX Bytecode Secret & Logcat Audit',
    token: 'classes*.dex',
    detail: 'Hardcoded API keys, Log.d credential leaks & Signing SHA-256',
  },
  {
    id: 'MASVS-PLATFORM-1',
    title: 'Manifest, AAB & App Link Audit',
    token: '.apk · .aab · assetlinks',
    detail: 'Exported IPC, FLAG_SECURE, Biometric CryptoObject & deep link hijack checks',
  },
  {
    id: 'MASVS-CODE-2',
    title: 'Native ELF & OSV.dev CVE Audit',
    token: 'lib/*.so · OSV.dev',
    detail: 'NX, PIE, Canary, Full RELRO & real-time Maven dependency CVEs',
  },
  {
    id: 'MASVS-NETWORK-1',
    title: 'TLS Pinning & Cipher Posture',
    token: 'TrustManager',
    detail: 'SSL TrustAll bypasses, cleartext traffic & weak ciphers',
  },
  {
    id: 'MASVS-AUTH-2',
    title: 'Cloud Storage & BaaS Live Probes',
    token: 'S3 · GCS · Firebase',
    detail: 'Embedded DB rules & public cloud storage bucket ACL verification',
  },
  {
    id: 'MASVS-RESILIENCE-1',
    title: 'Integrity, Obfuscation & Trackers',
    token: 'R8 · Play Integrity',
    detail: 'Root/tamper detection signals, R8 minification & third-party SDKs',
  },
];

const WEB_ENGINE_RULES: DetectionRuleItem[] = [
  {
    id: 'OWASP-A02',
    title: 'Client Bundle AST, Secrets & Cloud ACLs',
    token: 'JS AST · S3/GCS',
    detail: 'Leaked cloud keys, public S3/GCS/Azure buckets & DOM XSS sinks',
  },
  {
    id: 'OWASP-A05',
    title: 'Artifacts, Actuator & Sub-Route Crawl',
    token: '.env · .git · /actuator',
    detail: 'Exposed configs, heapdumps, Prometheus metrics & source maps',
  },
  {
    id: 'OWASP-A06',
    title: 'Live OSV.dev CVE & SRI Supply-Chain',
    token: 'OSV.dev · SRI · TLS',
    detail: 'Real-time frontend CVE matching, HSTS, CSP & HttpOnly enforcement',
  },
  {
    id: 'OWASP-A01',
    title: 'Verified Active DAST & Origin Security',
    token: 'CORS · TRACE · Redirect',
    detail: 'Origin reflection, X-Forwarded-Host, Open Redirect & output encoding',
  },
  {
    id: 'OWASP-A04',
    title: 'Denial-of-Wallet Rate-Limit Probe',
    token: '4 / 15 req burst',
    detail: 'Safe non-destructive throttling & quota guard checks',
  },
  {
    id: 'OWASP-A07',
    title: 'Session & Compound Chain Triage',
    token: 'Bearer JWT · AI Chains',
    detail: 'Authenticated route claims & cross-finding attack path correlation',
  },
];

const FAQ_ITEMS = [
  {
    q: 'Are uploaded .apk files saved on your servers?',
    a: 'No. Uploaded APK binaries stay strictly inside volatile server memory buffers during the audit and are discarded immediately once your JSON/PDF report is generated.',
  },
  {
    q: 'What do Confirmed vs Heuristic / Tentative tags mean?',
    a: 'Findings verified through deterministic binary parsing or live HTTP probes carry higher confidence, while pattern-matched discoveries are tagged so engineers can verify runtime protections without false alarm fatigue.',
  },
  {
    q: 'Why does Domain Ownership verification unlock a 15-request burst?',
    a: 'Unverified public domains receive a gentle 4-request rate probe so our scanner never overwhelms third-party sites. Verifying DNS TXT or HTML Meta ownership proves authorization for the full 15-request burst test.',
  },
  {
    q: 'Can I export results for Play Store or GitHub PR reviews?',
    a: 'Yes. Every completed audit includes Print-to-PDF formatting, structured JSON telemetry, downloadable Markdown, and a Copy PR Summary button for Slack or GitHub Pull Requests.',
  },
];

export const HomepageSections: React.FC<HomepageSectionsProps> = ({
  currentUser,
  onSelectPlan,
  checkoutBusyPlan = null,
  onStartAudit,
  onOpenLegal,
  onOpenPricingPage,
}) => {
  const [annualBilling, setAnnualBilling] = useState(true);
  const [openFaq, setOpenFaq] = useState<number | null>(0);

  const plans = PLAN_DISPLAY_CARDS.map((card, idx) => ({
    id: card.id,
    tierIndex: String(idx + 1).padStart(2, '0'),
    tagline: card.tagline,
    name: card.name,
    badge: card.badge,
    priceMonthlyNum: card.priceMonthly,
    priceAnnualNum: card.priceAnnual,
    annualTotalUsd: card.annualTotalUsd,
    slots: card.id === 'free' ? '2 slots/mo' : card.id === 'pro' ? '15 slots/mo' : '60 slots/mo',
    maxApk: card.id === 'free' ? '25 MB APK' : card.id === 'pro' ? '75 MB APK' : '150 MB APK',
    subtitle: card.subtitle,
    features: card.highlights,
    highlighted: card.highlighted,
    cta:
      checkoutBusyPlan === card.id
        ? 'Opening Checkout...'
        : currentUser?.plan === card.id
        ? 'Current Plan'
        : card.id === 'free'
        ? 'Start Free'
        : card.id === 'pro'
        ? 'Upgrade to Pro'
        : 'Get Team & Agency',
  }));

  return (
    <div className="w-full space-y-20 pt-10 pb-8">
      {/* ── Detection Rules Specification Matrix ── */}
      <section id="detection-matrix" className="scroll-mt-20 space-y-6">
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-white/10 pb-5">
          <div className="space-y-1.5 text-left">
            <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold">
              Detection Rules
            </span>
            <h2 className="text-2xl sm:text-[28px] font-display font-semibold tracking-[-0.035em] leading-[1.15]">
              <span className="text-white">Static APK inspection</span>{' '}
              <span className="wb-headline-muted">and live endpoint probes.</span>
            </h2>
          </div>
          <p className="text-xs text-slate-400 max-w-xs text-left md:text-right leading-relaxed">
            Deterministic parsers mapped directly to OWASP MASVS v2 and OWASP Top 10 rule IDs.
          </p>
        </div>

        <div className="wb-bezel p-1.5 rounded-2xl relative">
          {/* Subtle Top Emerald Light-Catch Hairline */}
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
          />

          <div className="wb-surface rounded-xl overflow-hidden text-left">
            <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-white/10">
              {/* Column 1: Android APK Engine */}
              <div className="flex flex-col">
                <div className="wb-ide-chrome px-5 py-4 border-b border-white/10 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center shrink-0">
                      <Smartphone className="w-4 h-4 text-emerald-400" />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="text-sm font-display font-semibold tracking-[-0.015em] text-white">
                          Android APK Engine
                        </h3>
                        <span className="font-mono text-[9.5px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 font-semibold">
                          MASVS v2 · 6 Rules
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 truncate mt-0.5">
                        DEX bytecode, binary XML &amp; native ELF
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => onStartAudit('apk')}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-medium bg-white/[0.04] hover:bg-emerald-500/10 border border-white/10 hover:border-emerald-500/35 text-emerald-400 transition-all cursor-pointer shrink-0"
                  >
                    <span>Scan APK</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>

                <ul className="divide-y divide-white/[0.08] flex-1">
                  {APK_ENGINE_RULES.map((rule, idx) => (
                    <li
                      key={rule.id}
                      className="wb-spec-row group px-5 py-3.5 flex items-start justify-between gap-3 transition-colors"
                    >
                      <div className="flex items-start gap-3 min-w-0">
                        <span className="font-mono text-[10px] tabular-nums text-slate-500 group-hover:text-emerald-400 transition-colors pt-0.5 shrink-0">
                          {String(idx + 1).padStart(2, '0')}
                        </span>
                        <div className="min-w-0 space-y-1">
                          <div className="text-[13px] font-semibold tracking-[-0.01em] text-white leading-snug">
                            {rule.title}
                          </div>
                          <div className="text-[11.5px] text-slate-400 leading-relaxed flex flex-wrap items-center gap-1.5">
                            <code className="wb-spec-code font-mono text-[10px] px-1.5 py-0.5 rounded leading-none">
                              {rule.token}
                            </code>
                            <span>{rule.detail}</span>
                          </div>
                        </div>
                      </div>
                      <span className="font-mono text-[10px] text-slate-400 group-hover:text-emerald-400 bg-white/[0.04] border border-white/10 group-hover:border-emerald-500/35 px-2 py-0.5 rounded shrink-0 transition-colors mt-0.5">
                        {rule.id}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Column 2: Website & API Suite */}
              <div className="flex flex-col">
                <div className="wb-ide-chrome px-5 py-4 border-b border-white/10 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/25 flex items-center justify-center shrink-0">
                      <Globe className="w-4 h-4 text-cyan-400" />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="text-sm font-display font-semibold tracking-[-0.015em] text-white">
                          Website &amp; API Suite
                        </h3>
                        <span className="font-mono text-[9.5px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/25 text-cyan-400 font-semibold">
                          OWASP Top 10 · 6 Rules
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 truncate mt-0.5">
                        Safe DAST, JS bundle AST &amp; network posture
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => onStartAudit('web')}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-medium bg-white/[0.04] hover:bg-cyan-500/10 border border-white/10 hover:border-cyan-500/35 text-cyan-400 transition-all cursor-pointer shrink-0"
                  >
                    <span>Scan URL</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>

                <ul className="divide-y divide-white/[0.08] flex-1">
                  {WEB_ENGINE_RULES.map((rule, idx) => (
                    <li
                      key={rule.id}
                      className="wb-spec-row group px-5 py-3.5 flex items-start justify-between gap-3 transition-colors"
                    >
                      <div className="flex items-start gap-3 min-w-0">
                        <span className="font-mono text-[10px] tabular-nums text-slate-500 group-hover:text-cyan-400 transition-colors pt-0.5 shrink-0">
                          {String(idx + 1).padStart(2, '0')}
                        </span>
                        <div className="min-w-0 space-y-1">
                          <div className="text-[13px] font-semibold tracking-[-0.01em] text-white leading-snug">
                            {rule.title}
                          </div>
                          <div className="text-[11.5px] text-slate-400 leading-relaxed flex flex-wrap items-center gap-1.5">
                            <code className="wb-spec-code font-mono text-[10px] px-1.5 py-0.5 rounded leading-none">
                              {rule.token}
                            </code>
                            <span>{rule.detail}</span>
                          </div>
                        </div>
                      </div>
                      <span className="font-mono text-[10px] text-slate-400 group-hover:text-cyan-400 bg-white/[0.04] border border-white/10 group-hover:border-cyan-500/35 px-2 py-0.5 rounded shrink-0 transition-colors mt-0.5">
                        {rule.id}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Bottom Spec Footer Strip */}
            <div className="wb-ide-chrome px-5 py-2.5 border-t border-white/10 flex flex-wrap items-center justify-between gap-2 font-mono text-[10.5px] text-slate-400">
              <span className="inline-flex items-center gap-2">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Zero cloud retention · In-memory AST &amp; DEX parsing</span>
              </span>
              <span className="text-slate-500">
                Mapped to OWASP MASVS v2 &amp; OWASP Top 10
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* ── Live Real-Time Scan Telemetry Counter ── */}
      <LiveScanTelemetryBar />

      {/* ── Pricing Preview (Architectural Double-Bezel Workbench) ── */}
      <section id="pricing" className="scroll-mt-20 space-y-6">
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-white/10 pb-5">
          <div className="space-y-1.5 text-left">
            <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold">
              Pricing &amp; Quotas
            </span>
            <h2 className="text-2xl sm:text-[28px] font-display font-semibold tracking-[-0.035em] leading-[1.15]">
              <span className="text-white">Start free.</span>{' '}
              <span className="wb-headline-muted">Scale when your release pipeline grows.</span>
            </h2>
          </div>

          {/* Compact Segmented Billing Toggle */}
          <div className="inline-flex items-center p-1 rounded-md wb-surface-muted self-start md:self-auto">
            <button
              type="button"
              onClick={() => setAnnualBilling(false)}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
                !annualBilling ? 'bg-white/15 text-white font-semibold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Monthly
            </button>
            <button
              type="button"
              onClick={() => setAnnualBilling(true)}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors cursor-pointer inline-flex items-center gap-1.5 ${
                annualBilling ? 'bg-white/15 text-white font-semibold' : 'text-slate-400 hover:text-white'
              }`}
            >
              <span>Annual</span>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold">
                Save 38%
              </span>
            </button>
          </div>
        </div>

        <div className="wb-bezel p-1.5 rounded-2xl relative">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
          />

          <div className="wb-surface rounded-xl overflow-hidden text-left">
            <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-white/10 items-stretch">
              {plans.map((plan) => {
                const isActive = currentUser?.plan === plan.id;
                const displayPrice = annualBilling ? plan.priceAnnualNum : plan.priceMonthlyNum;
                const isAgency = plan.id === 'agency';
                return (
                  <div
                    key={plan.id}
                    className={`p-6 flex flex-col justify-between relative overflow-hidden ${
                      plan.highlighted ? 'bg-emerald-500/[0.03]' : ''
                    }`}
                  >
                    {plan.highlighted && (
                      <>
                        <div
                          aria-hidden="true"
                          className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-emerald-500/40 via-emerald-400 to-emerald-500/40"
                        />
                        <div
                          aria-hidden="true"
                          className="pointer-events-none absolute -top-24 -right-24 w-56 h-56 rounded-full bg-emerald-500/[0.08] blur-3xl"
                        />
                      </>
                    )}

                    <div className="relative z-10 space-y-4">
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-3">
                          <div
                            className={`w-9 h-9 rounded-lg flex items-center justify-center border shrink-0 ${
                              plan.highlighted
                                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                                : isAgency
                                ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                                : 'bg-white/[0.04] border-white/10 text-slate-300'
                            }`}
                          >
                            {plan.id === 'free' ? (
                              <ShieldCheck className="w-4 h-4" />
                            ) : plan.highlighted ? (
                              <Zap className="w-4 h-4" />
                            ) : (
                              <Crown className="w-4 h-4" />
                            )}
                          </div>
                          <div>
                            <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">
                              Tier {plan.tierIndex}
                            </div>
                            <h3 className="text-sm font-display font-semibold tracking-[-0.015em] text-white">
                              {plan.name}
                            </h3>
                          </div>
                        </div>

                        {plan.badge && (
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[9.5px] font-semibold uppercase tracking-wider shrink-0 border ${
                              plan.highlighted
                                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                                : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                            }`}
                          >
                            {plan.badge}
                          </span>
                        )}
                      </div>

                      <div className="space-y-1">
                        <div className="flex items-baseline gap-2 flex-wrap">
                          <span className="text-3xl sm:text-[34px] font-display font-semibold tabular-nums text-white tracking-[-0.04em]">
                            ${displayPrice}
                          </span>
                          <span className="font-mono text-[11px] text-slate-400">/ month</span>
                          {plan.id !== 'free' && annualBilling && (
                            <span className="font-mono text-xs text-slate-500 line-through tabular-nums">
                              ${plan.priceMonthlyNum}
                            </span>
                          )}
                        </div>
                        <div className="font-mono text-[10px] text-slate-500">
                          {plan.id === 'free'
                            ? 'Free forever · No card required'
                            : annualBilling
                            ? `Billed $${plan.annualTotalUsd}/yr`
                            : `Or $${plan.priceAnnualNum}/mo billed annually`}
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-1.5">
                        <code className="wb-spec-code font-mono text-[10px] px-2 py-0.5 rounded">
                          {plan.slots}
                        </code>
                        <code className="wb-spec-code font-mono text-[10px] px-2 py-0.5 rounded">
                          {plan.maxApk}
                        </code>
                      </div>

                      <p className="text-xs text-slate-400 leading-relaxed">{plan.subtitle}</p>

                      <ul className="space-y-2.5 pt-4 border-t border-white/10">
                        {plan.features.map((feat) => (
                          <li key={feat} className="flex items-start gap-2.5 text-xs text-slate-300 leading-relaxed">
                            <Check
                              className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${
                                isAgency ? 'text-cyan-400' : 'text-emerald-400'
                              }`}
                            />
                            <span>{feat}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <button
                      type="button"
                      onClick={() => onSelectPlan(plan.id, annualBilling ? 'annual' : 'monthly')}
                      disabled={isActive || checkoutBusyPlan === plan.id}
                      className={`relative z-10 mt-6 w-full h-9 rounded-md text-xs font-semibold transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                        isActive
                          ? 'bg-emerald-500/10 border border-emerald-500/35 text-emerald-400 cursor-default'
                          : plan.highlighted
                          ? 'wb-emerald-btn'
                          : isAgency
                          ? 'wb-primary-btn'
                          : 'bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-white'
                      }`}
                    >
                      <span>{plan.cta}</span>
                      {!isActive && <ArrowRight className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                );
              })}
            </div>

            {/* Bottom Pricing Footer Strip */}
            <div className="wb-ide-chrome px-5 py-3 border-t border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs text-slate-400">
              <div className="flex flex-wrap items-center gap-2 font-mono text-[10.5px]">
                <span>Cancel anytime before renewal · 7-day technical refund guarantee.</span>
                {onOpenLegal && (
                  <button
                    type="button"
                    onClick={() => onOpenLegal('refund')}
                    className="text-emerald-400 hover:underline font-medium cursor-pointer"
                  >
                    Refund Policy
                  </button>
                )}
              </div>
              {onOpenPricingPage && (
                <button
                  type="button"
                  onClick={onOpenPricingPage}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-medium wb-surface hover:border-white/25 text-white transition-colors cursor-pointer shrink-0"
                >
                  <span>Compare all 16 checks &amp; limits</span>
                  <ArrowRight className="w-3 h-3 text-emerald-400" />
                </button>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* ── Minimal Hairline Security FAQ ── */}
      <section id="faq" className="scroll-mt-20 space-y-5">
        <div className="space-y-1.5 text-left">
          <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold">
            FAQ
          </span>
          <h2 className="text-2xl sm:text-[28px] font-display font-semibold tracking-[-0.035em] leading-[1.15]">
            <span className="text-white">Security &amp; workflow</span>{' '}
            <span className="wb-headline-muted">questions answered.</span>
          </h2>
        </div>

        <div className="wb-bezel p-1.5 rounded-2xl">
          <div className="wb-surface rounded-xl divide-y divide-white/10 text-left overflow-hidden">
            {FAQ_ITEMS.map((item, idx) => {
              const isOpen = openFaq === idx;
              return (
                <div key={item.q} className="wb-spec-row transition-colors">
                  <button
                    type="button"
                    onClick={() => setOpenFaq(isOpen ? null : idx)}
                    className="w-full px-5 py-4 flex items-center justify-between gap-4 text-left cursor-pointer group"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span className="font-mono text-[10px] tabular-nums text-emerald-400 shrink-0">
                        0{idx + 1}
                      </span>
                      <span className="text-xs sm:text-sm font-display font-semibold text-white group-hover:text-emerald-400 transition-colors">
                        {item.q}
                      </span>
                    </div>
                    <ChevronDown
                      className={`w-4 h-4 text-slate-400 shrink-0 transition-transform duration-200 ${
                        isOpen ? 'rotate-180 text-emerald-400' : ''
                      }`}
                    />
                  </button>
                  {isOpen && (
                    <div className="px-5 pb-4 pl-12 pr-8 text-xs text-slate-400 leading-relaxed max-w-3xl">
                      {item.a}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ── Architectural Double-Bezel Support Desk Section ── */}
      <section id="contact" className="scroll-mt-20">
        <div className="wb-bezel p-1.5 rounded-2xl relative">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
          />
          <div className="wb-surface rounded-xl p-6 sm:p-8 grid grid-cols-1 lg:grid-cols-12 gap-8 items-start text-left">
            <div className="lg:col-span-5 space-y-4">
              <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold block">
                Support Desk
              </span>
              <h2 className="text-2xl font-display font-semibold tracking-[-0.035em] leading-[1.15]">
                <span className="text-white">Need help with</span>{' '}
                <span className="wb-headline-muted">an audit or billing?</span>
              </h2>
              <p className="text-xs sm:text-[13px] text-slate-400 leading-relaxed">
                Reach out to our engineering team for APK scan questions, domain verification, CI/CD tokens, or refund requests.
              </p>

              <div className="space-y-2.5 pt-3 border-t border-white/10">
                <div className="flex items-center gap-2.5 text-xs">
                  <Mail className="w-4 h-4 text-emerald-400 shrink-0" />
                  <a
                    href="mailto:checkmyapk.com@gmail.com"
                    className="font-mono font-medium text-white hover:text-emerald-400 transition-colors"
                  >
                    checkmyapk.com@gmail.com
                  </a>
                </div>
                <div className="flex items-center gap-2.5 text-xs text-slate-400">
                  <Clock className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>Typical response within 12 hours</span>
                </div>
              </div>
            </div>

            <div className="lg:col-span-7">
              <ContactUsForm
                defaultName={currentUser?.name || ''}
                defaultEmail={currentUser?.email || ''}
              />
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
