import React, { useState } from 'react';
import {
  CheckCircle2,
  Smartphone,
  Globe,
  ChevronDown,
  Sparkles,
  ArrowRight,
  ShieldCheck,
  Mail,
  Clock,
} from 'lucide-react';
import type { AccountPlan, UserAccount } from '../types/account';
import type { LegalDocId } from '../data/legalDocs';
import { PLAN_DISPLAY_CARDS } from '../data/planPolicy';
import { ContactUsForm } from './ContactUsForm';
import { RevealOnScroll } from './RevealOnScroll';

interface HomepageSectionsProps {
  currentUser: UserAccount | null;
  onSelectPlan: (plan: AccountPlan) => void;
  onStartAudit: (mode: 'apk' | 'web') => void;
  onOpenLegal?: (doc: LegalDocId) => void;
  onOpenPricingPage?: () => void;
}

const APK_ENGINE_CHECKS = [
  'Dalvik DEX & classes*.dex bytecode key extraction',
  'AndroidBinaryXML Manifest, exported IPC & debug flags',
  'Native .so ELF hardening (NX, PIE, Stack Canary, RELRO)',
  'SSL TrustAll bypasses, WebView JS exposure & weak crypto',
  'Embedded Firebase / Supabase URL & anonymous read probes',
  'R8/ProGuard obfuscation check & embedded tracker audit',
];

const WEB_ENGINE_CHECKS = [
  'JS chunk AST & taint scan for secrets and DOM XSS sinks',
  'Exposed .env, .git, .js.map & sensitive artifact discovery',
  'TLS version, HSTS, CSP, SRI & cookie security flags audit',
  'Live CORS Origin reflection & DNS / SPF / DMARC posture',
  'Denial-of-Wallet rate-limit burst probe (4 or 15 req)',
  'Optional Bearer JWT / Cookie same-origin protected route audit',
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
    a: 'Yes. Every completed audit includes one-click Print-to-PDF formatting, structured JSON telemetry, downloadable Markdown, and a Copy PR Summary button for Slack or GitHub Pull Requests.',
  },
];

export const HomepageSections: React.FC<HomepageSectionsProps> = ({
  currentUser,
  onSelectPlan,
  onStartAudit,
  onOpenLegal,
  onOpenPricingPage,
}) => {
  const [annualBilling, setAnnualBilling] = useState(true);
  const [openFaq, setOpenFaq] = useState<number | null>(0);

  const plans = PLAN_DISPLAY_CARDS.map((card) => ({
    id: card.id,
    name: card.name,
    badge: card.id === 'pro' ? 'Public Beta Free' : card.badge,
    priceMonthly: `$${card.priceMonthly}`,
    priceAnnual: `$${card.priceAnnual}`,
    subtitle: card.subtitle,
    features: card.highlights,
    highlighted: card.highlighted,
    cta:
      currentUser?.plan === card.id
        ? card.id === 'free'
          ? 'Current Plan'
          : 'Active Beta Plan'
        : card.id === 'free'
        ? 'Start Free'
        : card.id === 'pro'
        ? 'Activate Pro Beta'
        : 'Activate Team Beta',
  }));

  return (
    <div className="w-full space-y-20 pt-10 pb-8">
      {/* ── Detection Matrix: Real APK + Web Engine Capabilities ── */}
      <section id="detection-matrix" className="scroll-mt-24 space-y-6">
        <RevealOnScroll>
          <div className="text-center space-y-2 max-w-2xl mx-auto">
            <span className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-300/90 font-semibold">
              <ShieldCheck className="w-3.5 h-3.5" />
              Unified Inspection Engine
            </span>
            <h2 className="text-2xl sm:text-3xl font-google font-semibold tracking-[-0.03em] text-white">
              Deep Binary Static Analysis + Live Attack Probes
            </h2>
            <p className="text-xs sm:text-sm text-slate-400">
              One workspace covering both compiled Android builds and production web endpoints.
            </p>
          </div>
        </RevealOnScroll>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-left">
          <RevealOnScroll delayMs={0}>
            <div className="glass-card rounded-3xl p-6 border border-purple-400/20 space-y-4 h-full">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-xl bg-purple-500/15 border border-purple-400/30 flex items-center justify-center text-purple-300">
                    <Smartphone className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-black text-white">Android .APK Deep Engine</h3>
                    <p className="text-[11px] text-slate-400">Static bytecode, binary XML &amp; native ELF</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => onStartAudit('apk')}
                  className="text-[11px] font-bold text-purple-300 hover:text-purple-200 inline-flex items-center gap-1 cursor-pointer"
                >
                  Scan APK <ArrowRight className="w-3 h-3" />
                </button>
              </div>
              <ul className="space-y-2.5">
                {APK_ENGINE_CHECKS.map((item, idx) => (
                  <RevealOnScroll key={item} delayMs={80 + idx * 65}>
                    <li className="flex items-start gap-2.5 text-xs text-slate-300">
                      <CheckCircle2 className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
                      <span>{item}</span>
                    </li>
                  </RevealOnScroll>
                ))}
              </ul>
            </div>
          </RevealOnScroll>

          <RevealOnScroll delayMs={160}>
            <div className="glass-card rounded-3xl p-6 border border-cyan-400/20 space-y-4 h-full">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-xl bg-cyan-500/15 border border-cyan-400/30 flex items-center justify-center text-cyan-300">
                    <Globe className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-black text-white">Live Website &amp; API Suite</h3>
                    <p className="text-[11px] text-slate-400">Safe DAST, JS bundle AST &amp; network posture</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => onStartAudit('web')}
                  className="text-[11px] font-bold text-cyan-300 hover:text-cyan-200 inline-flex items-center gap-1 cursor-pointer"
                >
                  Scan URL <ArrowRight className="w-3 h-3" />
                </button>
              </div>
              <ul className="space-y-2.5">
                {WEB_ENGINE_CHECKS.map((item, idx) => (
                  <RevealOnScroll key={item} delayMs={180 + idx * 65}>
                    <li className="flex items-start gap-2.5 text-xs text-slate-300">
                      <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                      <span>{item}</span>
                    </li>
                  </RevealOnScroll>
                ))}
              </ul>
            </div>
          </RevealOnScroll>
        </div>
      </section>

      {/* ── Pricing Section ── */}
      <section id="pricing" className="scroll-mt-24 space-y-7">
        <RevealOnScroll>
          <div className="text-center space-y-3 max-w-2xl mx-auto">
            <span className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-emerald-300/90 font-semibold">
              <Sparkles className="w-3.5 h-3.5" />
              Simple SaaS Tiers • Free During Public Beta
            </span>
            <h2 className="text-2xl sm:text-4xl font-google font-semibold tracking-[-0.035em] text-white">
              Start Free. Scale With Confidence.
            </h2>
            <p className="text-xs sm:text-sm text-slate-400">
              Start free with 2 apps/month, or unlock 15–60 unique apps with Unlimited Re-scans &amp; AI Fix Doctor.
            </p>

            {/* Billing Toggle */}
            <div className="inline-flex items-center gap-2 p-1 rounded-full bg-white/[0.04] border border-white/10 mt-2">
              <button
                type="button"
                onClick={() => setAnnualBilling(false)}
                className={`px-3.5 py-1 rounded-full text-xs font-bold transition-all cursor-pointer ${
                  !annualBilling ? 'bg-white/15 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Monthly
              </button>
              <button
                type="button"
                onClick={() => setAnnualBilling(true)}
                className={`px-3.5 py-1 rounded-full text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                  annualBilling ? 'bg-cyan-500/20 text-cyan-200 border border-cyan-400/30' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Annual
                <span className="text-[10px] font-mono text-emerald-300">Save up to 38%</span>
              </button>
            </div>
          </div>
        </RevealOnScroll>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5 text-left items-stretch">
          {plans.map((plan, idx) => {
            const isActive = currentUser?.plan === plan.id;
            return (
              <RevealOnScroll key={plan.id} delayMs={idx * 150} className="h-full">
                <div
                  className={`h-full rounded-3xl p-6 flex flex-col justify-between border transition-all duration-300 ${
                    plan.highlighted
                      ? 'glass-panel border-cyan-400/40 shadow-[0_24px_60px_-20px_rgba(6,182,212,0.28)] relative'
                      : 'glass-card border-white/10 hover:border-white/20'
                  }`}
                >
                  <div className="space-y-4">
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="text-base font-black text-white">{plan.name}</h3>
                      {plan.badge && (
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider bg-cyan-500/15 border border-cyan-400/35 text-cyan-300">
                          {plan.badge}
                        </span>
                      )}
                    </div>

                    <div className="flex items-baseline gap-1.5">
                      <span className="text-3xl sm:text-4xl font-google font-bold text-white tracking-tight">
                        {annualBilling ? plan.priceAnnual : plan.priceMonthly}
                      </span>
                      <span className="text-xs text-slate-400">/ month</span>
                      {plan.id !== 'free' && (
                        <span className="ml-2 text-[10px] font-mono text-emerald-300 bg-emerald-500/10 border border-emerald-500/25 px-1.5 py-0.5 rounded">
                          $0 in Beta
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed">{plan.subtitle}</p>

                    <ul className="space-y-2.5 pt-2 border-t border-white/10">
                      {plan.features.map((feat) => (
                        <li key={feat} className="flex items-start gap-2 text-xs text-slate-300">
                          <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                          <span>{feat}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <button
                    type="button"
                    onClick={() => onSelectPlan(plan.id)}
                    disabled={isActive}
                    className={`mt-6 w-full py-2.5 rounded-xl text-xs font-black transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                      isActive
                        ? 'bg-emerald-500/15 border border-emerald-400/35 text-emerald-300 cursor-default'
                        : plan.highlighted
                        ? 'bg-gradient-to-r from-cyan-400 to-emerald-400 hover:from-cyan-300 hover:to-emerald-300 text-slate-950 shadow-lg'
                        : 'bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-white'
                    }`}
                  >
                    <span>{plan.cta}</span>
                    {!isActive && <ArrowRight className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </RevealOnScroll>
            );
          })}
        </div>

        {onOpenPricingPage && (
          <RevealOnScroll delayMs={180}>
            <div className="flex justify-center pt-1">
              <button
                type="button"
                onClick={onOpenPricingPage}
                className="group inline-flex items-center gap-2.5 px-5 py-3 rounded-2xl text-xs font-extrabold bg-white/[0.04] hover:bg-cyan-500/15 text-cyan-200 border border-white/10 hover:border-cyan-400/40 transition-all shadow-lg cursor-pointer"
              >
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <span>Compare All 16 Features, Limits &amp; Exports in Full Table</span>
                <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
              </button>
            </div>
          </RevealOnScroll>
        )}

        <RevealOnScroll delayMs={220}>
          <div className="flex flex-wrap items-center justify-center gap-2 text-[11px] text-slate-400 pt-1">
            <span>Cancel anytime before renewal • 7-day technical refund guarantee.</span>
            {onOpenLegal && (
              <button
                type="button"
                onClick={() => onOpenLegal('refund')}
                className="text-cyan-300 hover:underline font-bold cursor-pointer"
              >
                Read Refund &amp; Cancellation Policy
              </button>
            )}
          </div>
        </RevealOnScroll>
      </section>

      {/* ── Developer Security FAQ ── */}
      <section id="faq" className="scroll-mt-24 max-w-3xl mx-auto space-y-5">
        <RevealOnScroll>
          <div className="text-center space-y-1.5">
            <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-400 font-semibold">
              Security &amp; Workflow FAQ
            </span>
            <h2 className="text-xl sm:text-2xl font-google font-semibold tracking-[-0.03em] text-white">
              Frequently Asked Questions
            </h2>
          </div>
        </RevealOnScroll>

        <div className="space-y-2.5 text-left">
          {FAQ_ITEMS.map((item, idx) => {
            const isOpen = openFaq === idx;
            return (
              <RevealOnScroll key={item.q} delayMs={idx * 105}>
                <div className="glass-card rounded-2xl border border-white/10 overflow-hidden transition-colors">
                  <button
                    type="button"
                    onClick={() => setOpenFaq(isOpen ? null : idx)}
                    className="w-full px-5 py-4 flex items-center justify-between gap-4 text-left cursor-pointer"
                  >
                    <span className="text-xs sm:text-sm font-bold text-white">{item.q}</span>
                    <ChevronDown
                      className={`w-4 h-4 text-slate-400 shrink-0 transition-transform duration-200 ${
                        isOpen ? 'rotate-180 text-cyan-300' : ''
                      }`}
                    />
                  </button>
                  {isOpen && (
                    <div className="px-5 pb-4 text-xs text-slate-400 leading-relaxed border-t border-white/5 pt-3">
                      {item.a}
                    </div>
                  )}
                </div>
              </RevealOnScroll>
            );
          })}
        </div>
      </section>

      {/* ── Contact Us Section (Home Bottom) ── */}
      <section id="contact" className="scroll-mt-24 max-w-4xl mx-auto">
        <RevealOnScroll>
          <div className="glass-panel rounded-3xl p-6 sm:p-8 border border-white/15 grid grid-cols-1 lg:grid-cols-12 gap-7 items-start text-left">
            <RevealOnScroll delayMs={60} className="lg:col-span-5 space-y-4">
              <span className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-300 font-semibold">
                <Mail className="w-3.5 h-3.5" />
                Contact Us
              </span>
              <h2 className="text-2xl sm:text-3xl font-google font-semibold tracking-[-0.03em] text-white">
                Have a Question or Need Help?
              </h2>
              <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
                Reach out to our engineering &amp; security support team for APK audit help, domain verification, billing, or bug reports.
              </p>

              <div className="space-y-2.5 pt-1">
                <div className="p-3 rounded-2xl bg-[#050811]/75 border border-white/10">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 font-bold">
                    Support Email
                  </div>
                  <a
                    href="mailto:checkmyapk.com@gmail.com"
                    className="text-xs font-mono font-bold text-cyan-300 hover:underline"
                  >
                    checkmyapk.com@gmail.com
                  </a>
                </div>
                <div className="p-3 rounded-2xl bg-[#050811]/75 border border-white/10 flex items-center gap-2.5">
                  <Clock className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span className="text-xs text-slate-300 font-medium">
                    Response within 24 hours • OWASP Security Desk
                  </span>
                </div>
              </div>
            </RevealOnScroll>

            <RevealOnScroll delayMs={180} className="lg:col-span-7">
              <ContactUsForm
                defaultName={currentUser?.name || ''}
                defaultEmail={currentUser?.email || ''}
              />
            </RevealOnScroll>
          </div>
        </RevealOnScroll>
      </section>
    </div>
  );
};

