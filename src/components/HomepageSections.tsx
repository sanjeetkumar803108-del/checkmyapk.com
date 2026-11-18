import React, { useState } from 'react';
import {
  Check,
  Smartphone,
  Globe,
  ChevronDown,
  ArrowRight,
  Mail,
  Clock,
} from 'lucide-react';
import type { AccountPlan, UserAccount } from '../types/account';
import type { LegalDocId } from '../data/legalDocs';
import { PLAN_DISPLAY_CARDS } from '../data/planPolicy';
import { ContactUsForm } from './ContactUsForm';

interface HomepageSectionsProps {
  currentUser: UserAccount | null;
  onSelectPlan: (plan: AccountPlan, billingCycle?: 'monthly' | 'annual') => void;
  checkoutBusyPlan?: AccountPlan | null;
  onStartAudit: (mode: 'apk' | 'web') => void;
  onOpenLegal?: (doc: LegalDocId) => void;
  onOpenPricingPage?: () => void;
}

const APK_ENGINE_RULES = [
  { id: 'MASVS-STORAGE-1', desc: 'Dalvik DEX & classes*.dex bytecode secret & API key extraction' },
  { id: 'MASVS-PLATFORM-1', desc: 'AndroidBinaryXML Manifest, exported IPC & debuggable flags' },
  { id: 'MASVS-CODE-2', desc: 'Native .so ELF hardening (NX, PIE, Stack Canary, Full RELRO)' },
  { id: 'MASVS-NETWORK-1', desc: 'SSL TrustAll bypasses, cleartext config & weak symmetric ciphers' },
  { id: 'MASVS-AUTH-2', desc: 'Embedded Firebase / Supabase URLs & anonymous read probes' },
  { id: 'MASVS-RESILIENCE-1', desc: 'R8/ProGuard obfuscation posture & embedded tracker audit' },
];

const WEB_ENGINE_RULES = [
  { id: 'OWASP-A02', desc: 'JS bundle AST & taint scan for leaked keys and DOM XSS sinks' },
  { id: 'OWASP-A05', desc: 'Exposed .env, .git, .js.map & public build artifact discovery' },
  { id: 'OWASP-A02-TLS', desc: 'TLS protocol, HSTS, CSP, SRI & HttpOnly/SameSite cookie flags' },
  { id: 'OWASP-A01', desc: 'Live CORS Origin reflection & DNS / SPF / DMARC posture checks' },
  { id: 'OWASP-A04', desc: 'Denial-of-Wallet rate-limit burst probe (4 or 15 req profiles)' },
  { id: 'OWASP-A07', desc: 'Optional Bearer JWT / Cookie same-origin protected route audit' },
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

  const plans = PLAN_DISPLAY_CARDS.map((card) => ({
    id: card.id,
    name: card.name,
    badge: card.badge,
    priceMonthly: `$${card.priceMonthly}`,
    priceAnnual: `$${card.priceAnnual}`,
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
      {/* ── Detection Rules Specification Table ── */}
      <section id="detection-matrix" className="scroll-mt-20 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-white/10 pb-5">
          <div className="space-y-1.5 text-left">
            <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold">
              Detection Rules
            </span>
            <h2 className="text-2xl sm:text-[28px] font-display font-semibold tracking-[-0.03em] text-white">
              Static APK bytecode inspection and live endpoint probes.
            </h2>
          </div>
          <p className="text-xs text-slate-400 max-w-sm text-left sm:text-right leading-relaxed">
            Deterministic parsers mapped directly to OWASP MASVS v2 and OWASP Top 10 rule IDs.
          </p>
        </div>

        <div className="wb-surface rounded-xl overflow-hidden grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-white/10 text-left">
          {/* Column 1: Android APK Engine */}
          <div className="flex flex-col">
            <div className="px-5 py-4 border-b border-white/10 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <Smartphone className="w-4 h-4 text-slate-300" />
                <div>
                  <h3 className="text-sm font-semibold text-white">Android APK Engine</h3>
                  <p className="text-[11px] text-slate-400">DEX bytecode, binary XML &amp; native ELF</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => onStartAudit('apk')}
                className="text-xs font-medium text-emerald-400 hover:underline inline-flex items-center gap-1 cursor-pointer shrink-0"
              >
                Scan APK <ArrowRight className="w-3 h-3" />
              </button>
            </div>
            <ul className="divide-y divide-white/[0.08]">
              {APK_ENGINE_RULES.map((rule) => (
                <li
                  key={rule.id}
                  className="px-5 py-3.5 flex items-start justify-between gap-4 text-xs"
                >
                  <span className="text-slate-300 leading-relaxed">{rule.desc}</span>
                  <span className="font-mono text-[10px] text-slate-400 bg-white/[0.04] border border-white/10 px-2 py-0.5 rounded shrink-0">
                    {rule.id}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          {/* Column 2: Web & API Engine */}
          <div className="flex flex-col">
            <div className="px-5 py-4 border-b border-white/10 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <Globe className="w-4 h-4 text-slate-300" />
                <div>
                  <h3 className="text-sm font-semibold text-white">Website &amp; API Suite</h3>
                  <p className="text-[11px] text-slate-400">Safe DAST, JS bundle AST &amp; network posture</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => onStartAudit('web')}
                className="text-xs font-medium text-emerald-400 hover:underline inline-flex items-center gap-1 cursor-pointer shrink-0"
              >
                Scan URL <ArrowRight className="w-3 h-3" />
              </button>
            </div>
            <ul className="divide-y divide-white/[0.08]">
              {WEB_ENGINE_RULES.map((rule) => (
                <li
                  key={rule.id}
                  className="px-5 py-3.5 flex items-start justify-between gap-4 text-xs"
                >
                  <span className="text-slate-300 leading-relaxed">{rule.desc}</span>
                  <span className="font-mono text-[10px] text-slate-400 bg-white/[0.04] border border-white/10 px-2 py-0.5 rounded shrink-0">
                    {rule.id}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      {/* ── Pricing Preview ── */}
      <section id="pricing" className="scroll-mt-20 space-y-6">
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-white/10 pb-5">
          <div className="space-y-1.5 text-left">
            <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold">
              Pricing
            </span>
            <h2 className="text-2xl sm:text-[28px] font-display font-semibold tracking-[-0.03em] text-white">
              Start free. Scale when your release pipeline grows.
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
              <span className="font-mono text-[10px] text-emerald-400">-20%</span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-left items-stretch">
          {plans.map((plan) => {
            const isActive = currentUser?.plan === plan.id;
            return (
              <div
                key={plan.id}
                className={`wb-surface rounded-xl p-6 flex flex-col justify-between relative overflow-hidden ${
                  plan.highlighted ? 'border-emerald-500/45' : ''
                }`}
              >
                {plan.highlighted && (
                  <div
                    aria-hidden="true"
                    className="absolute inset-x-0 top-0 h-[2px] bg-emerald-500"
                  />
                )}

                <div className="space-y-4">
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-sm font-semibold text-white">{plan.name}</h3>
                    {plan.badge && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                        {plan.badge}
                      </span>
                    )}
                  </div>

                  <div className="flex items-baseline gap-1.5">
                    <span className="text-3xl font-display font-semibold text-white tracking-[-0.03em]">
                      {annualBilling ? plan.priceAnnual : plan.priceMonthly}
                    </span>
                    <span className="text-xs text-slate-400">/ month</span>
                  </div>

                  <p className="text-xs text-slate-400 leading-relaxed">{plan.subtitle}</p>

                  <ul className="space-y-2.5 pt-4 border-t border-white/10">
                    {plan.features.map((feat) => (
                      <li key={feat} className="flex items-start gap-2 text-xs text-slate-300">
                        <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                        <span>{feat}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <button
                  type="button"
                  onClick={() => onSelectPlan(plan.id, annualBilling ? 'annual' : 'monthly')}
                  disabled={isActive || checkoutBusyPlan === plan.id}
                  className={`mt-6 w-full h-9 rounded-md text-xs font-semibold transition-colors cursor-pointer flex items-center justify-center gap-1.5 ${
                    isActive
                      ? 'bg-emerald-500/10 border border-emerald-500/35 text-emerald-400 cursor-default'
                      : plan.highlighted
                      ? 'wb-emerald-btn'
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

        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-1 text-xs text-slate-400">
          <div className="flex flex-wrap items-center gap-2">
            <span>Cancel anytime before renewal. 7-day technical refund guarantee.</span>
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
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md text-xs font-medium wb-surface hover:border-white/25 text-white transition-colors cursor-pointer shrink-0"
            >
              <span>Compare all 16 checks &amp; limits</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </section>

      {/* ── Minimal Hairline Security FAQ ── */}
      <section id="faq" className="scroll-mt-20 space-y-5">
        <div className="space-y-1 text-left">
          <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-slate-400 font-semibold">
            FAQ
          </span>
          <h2 className="text-xl sm:text-2xl font-display font-semibold tracking-[-0.03em] text-white">
            Security &amp; workflow questions
          </h2>
        </div>

        <div className="border-y border-white/10 divide-y divide-white/10 text-left">
          {FAQ_ITEMS.map((item, idx) => {
            const isOpen = openFaq === idx;
            return (
              <div key={item.q}>
                <button
                  type="button"
                  onClick={() => setOpenFaq(isOpen ? null : idx)}
                  className="w-full py-4 flex items-center justify-between gap-4 text-left cursor-pointer group"
                >
                  <span className="text-xs sm:text-sm font-semibold text-white group-hover:text-emerald-400 transition-colors">
                    {item.q}
                  </span>
                  <ChevronDown
                    className={`w-4 h-4 text-slate-400 shrink-0 transition-transform duration-200 ${
                      isOpen ? 'rotate-180 text-emerald-400' : ''
                    }`}
                  />
                </button>
                {isOpen && (
                  <div className="pb-4 pr-8 text-xs text-slate-400 leading-relaxed max-w-3xl">
                    {item.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* ── Flat Architectural Contact Section ── */}
      <section id="contact" className="scroll-mt-20">
        <div className="wb-surface rounded-xl p-6 sm:p-8 grid grid-cols-1 lg:grid-cols-12 gap-8 items-start text-left">
          <div className="lg:col-span-5 space-y-4">
            <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold block">
              Support Desk
            </span>
            <h2 className="text-2xl font-display font-semibold tracking-[-0.03em] text-white">
              Need help with an audit or billing?
            </h2>
            <p className="text-xs sm:text-[13px] text-slate-400 leading-relaxed">
              Reach out to our engineering team for APK scan questions, domain verification, CI/CD tokens, or refund requests.
            </p>

            <div className="space-y-2.5 pt-2 border-t border-white/10">
              <div className="flex items-center gap-2.5 text-xs">
                <Mail className="w-4 h-4 text-slate-400 shrink-0" />
                <a
                  href="mailto:checkmyapk.com@gmail.com"
                  className="font-mono font-medium text-white hover:text-emerald-400 transition-colors"
                >
                  checkmyapk.com@gmail.com
                </a>
              </div>
              <div className="flex items-center gap-2.5 text-xs text-slate-400">
                <Clock className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>Typical response within 24 hours</span>
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
      </section>
    </div>
  );
};
