import React, { useEffect, useState } from 'react';
import {
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  Cpu,
  Crown,
  Layers,
  Minus,
  ShieldCheck,
  Sparkles,
  Wrench,
} from 'lucide-react';
import type { AccountPlan, UserAccount } from '../types/account';
import type { LegalDocId } from '../data/legalDocs';
import {
  PLAN_DISPLAY_CARDS,
  PRICING_COMPARISON_GROUPS,
  type ComparisonCell,
  type ComparisonGroup,
} from '../data/planPolicy';

interface PricingPageProps {
  currentUser: UserAccount | null;
  onSelectPlan: (plan: AccountPlan, billingCycle?: 'monthly' | 'annual') => void;
  checkoutBusyPlan?: AccountPlan | null;
  onBack: () => void;
  onOpenLegal?: (doc: LegalDocId) => void;
}

type CategoryFilter = 'all' | ComparisonGroup['id'];

const GROUP_ICONS: Record<ComparisonGroup['id'], typeof Layers> = {
  quotas: Layers,
  engine: ShieldCheck,
  fixes: Wrench,
  automation: Cpu,
};

const PRICING_FAQ = [
  {
    q: 'How do Unique App Slots & Unlimited Re-Scans work?',
    a: 'Each Android packageName (e.g., com.app.demo) or root website domain counts as 1 slot for the billing month. On Pro and Agency, scanning new builds of that same app/domain to verify fixes is completely unlimited (with anti-bot daily burst caps).',
  },
  {
    q: 'Can I upgrade, downgrade, or cancel anytime?',
    a: 'Yes. You can switch tiers anytime, and cancellations stop the next renewal immediately while keeping your active billing period intact.',
  },
  {
    q: 'Are APK binaries or JWT tokens stored on your servers?',
    a: 'No. Uploaded .apk binaries stay strictly in volatile RAM during decompilation and are wiped right after audit completion. Auth headers/cookies are never logged or persisted.',
  },
];

function renderComparisonCell(cell: ComparisonCell) {
  if (cell === true) {
    return (
      <span
        className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500/15 border border-emerald-400/35 text-emerald-300"
        aria-label="Included"
      >
        <Check className="w-3.5 h-3.5 stroke-[2.6]" />
      </span>
    );
  }
  if (cell === false) {
    return (
      <span
        className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-white/[0.03] border border-white/10 text-slate-500"
        aria-label="Not included"
      >
        <Minus className="w-3.5 h-3.5" />
      </span>
    );
  }

  const badgeStyle =
    cell.emphasis === 'emerald'
      ? 'bg-emerald-500/15 border-emerald-400/35 text-emerald-300 font-bold'
      : cell.emphasis === 'cyan'
      ? 'bg-cyan-500/15 border-cyan-400/35 text-cyan-200 font-bold'
      : cell.emphasis === 'purple'
      ? 'bg-purple-500/15 border-purple-400/35 text-purple-200 font-bold'
      : cell.emphasis === 'muted'
      ? 'bg-white/[0.03] border-white/10 text-slate-400 font-medium'
      : 'bg-white/[0.06] border-white/15 text-slate-200 font-semibold';

  return (
    <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-[11px] border whitespace-nowrap ${badgeStyle}`}>
      {cell.text}
    </span>
  );
}

export const PricingPage: React.FC<PricingPageProps> = ({
  currentUser,
  onSelectPlan,
  checkoutBusyPlan = null,
  onBack,
  onOpenLegal,
}) => {
  const [annualBilling, setAnnualBilling] = useState(true);
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [mobileFocusPlan, setMobileFocusPlan] = useState<AccountPlan>('pro');

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, []);

  const visibleGroups =
    categoryFilter === 'all'
      ? PRICING_COMPARISON_GROUPS
      : PRICING_COMPARISON_GROUPS.filter((g) => g.id === categoryFilter);

  const getCtaLabel = (planId: AccountPlan, defaultLabel: string) => {
    if (checkoutBusyPlan === planId) {
      return 'Opening Checkout...';
    }
    if (currentUser?.plan === planId) {
      return 'Current Plan';
    }
    return defaultLabel;
  };

  return (
    <div className="w-full space-y-10 pb-8">
      {/* Top Breadcrumb Navigation */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold bg-white/[0.04] hover:bg-white/[0.09] text-slate-200 border border-white/10 transition-all cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5 text-cyan-400" />
          <span>Back to Security Scanner</span>
        </button>

        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-mono uppercase tracking-[0.16em] bg-emerald-500/10 border border-emerald-400/25 text-emerald-300 font-semibold">
          <Sparkles className="w-3 h-3" />
          Transparent SaaS Plans • Cancel Anytime
        </span>
      </div>

      {/* Pricing Hero + Billing Toggle */}
      <section className="text-center space-y-4 max-w-3xl mx-auto">
        <h1 className="text-3xl sm:text-5xl font-google font-semibold tracking-[-0.04em] text-white leading-tight">
          Simple Pricing. Zero Feature Guesswork.
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">
          Start free with 2 monthly app slots, upgrade to <span className="text-cyan-300 font-semibold">Pro Security</span> for Unlimited Re-scans &amp; AI Fix Doctor, or scale with <span className="text-purple-300 font-semibold">Team &amp; Agency</span> for CI/CD API tokens and 150MB builds.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-3 pt-1">
          <div className="inline-flex items-center gap-1.5 p-1 rounded-full bg-white/[0.04] border border-white/10">
            <button
              type="button"
              onClick={() => setAnnualBilling(false)}
              className={`px-4 py-1.5 rounded-full text-xs font-bold transition-all cursor-pointer ${
                !annualBilling ? 'bg-white/15 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Monthly Billing
            </button>
            <button
              type="button"
              onClick={() => setAnnualBilling(true)}
              className={`px-4 py-1.5 rounded-full text-xs font-bold transition-all cursor-pointer flex items-center gap-2 ${
                annualBilling
                  ? 'bg-cyan-500/20 text-cyan-200 border border-cyan-400/35'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <span>Annual Billing</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300">
                Save up to 38%
              </span>
            </button>
          </div>

          <a
            href="#full-comparison-table"
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-full text-xs font-bold text-cyan-300 hover:text-cyan-200 bg-cyan-500/10 hover:bg-cyan-500/15 border border-cyan-400/25 transition-all"
          >
            <span>Jump to Comparison Table</span>
            <ArrowDown className="w-3.5 h-3.5" />
          </a>
        </div>
      </section>

      {/* 3 Plan Cards */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-5 items-stretch text-left">
        {PLAN_DISPLAY_CARDS.map((plan) => {
          const isActive = currentUser?.plan === plan.id;
          const displayPrice = annualBilling ? plan.priceAnnual : plan.priceMonthly;
          const defaultCta =
            plan.id === 'free'
              ? 'Start Free'
              : plan.id === 'pro'
              ? 'Upgrade to Pro'
              : 'Get Team & Agency';

          return (
            <div
              key={plan.id}
              className={`rounded-3xl p-6 flex flex-col justify-between border transition-all duration-300 ${
                plan.highlighted
                  ? 'glass-panel border-cyan-400/45 shadow-[0_24px_60px_-20px_rgba(6,182,212,0.28)] relative'
                  : 'glass-card border-white/10 hover:border-white/20'
              }`}
            >
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-slate-400">
                      {plan.tagline}
                    </div>
                    <h2 className="text-lg font-black text-white mt-0.5 flex items-center gap-2">
                      {plan.id === 'agency' && <Crown className="w-4 h-4 text-purple-400" />}
                      <span>{plan.name}</span>
                    </h2>
                  </div>
                  {plan.badge && (
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider shrink-0 border ${
                        plan.highlighted
                          ? 'bg-cyan-500/15 border-cyan-400/35 text-cyan-300'
                          : 'bg-purple-500/15 border-purple-400/35 text-purple-300'
                      }`}
                    >
                      {plan.badge}
                    </span>
                  )}
                </div>

                <div className="space-y-1">
                  <div className="flex items-baseline gap-1.5 flex-wrap">
                    <span className="text-4xl font-google font-bold text-white tracking-tight">
                      ${displayPrice}
                    </span>
                    <span className="text-xs text-slate-400">/ month</span>
                  </div>
                  {plan.id !== 'free' && (
                    <div className="text-[11px] text-slate-400">
                      {annualBilling
                        ? `Billed $${plan.annualTotalUsd}/year (normally $${plan.priceMonthly}/mo)`
                        : `Or $${plan.priceAnnual}/mo when billed annually`}
                    </div>
                  )}
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">{plan.subtitle}</p>

                <ul className="space-y-2.5 pt-3 border-t border-white/10">
                  {plan.highlights.map((feat) => (
                    <li key={feat} className="flex items-start gap-2 text-xs text-slate-300">
                      <CheckCircle2
                        className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${
                          plan.id === 'agency' ? 'text-purple-400' : 'text-cyan-400'
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
                className={`mt-6 w-full py-2.5 rounded-xl text-xs font-black transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                  isActive
                    ? 'bg-emerald-500/15 border border-emerald-400/35 text-emerald-300 cursor-default'
                    : plan.highlighted
                    ? 'bg-gradient-to-r from-cyan-400 to-emerald-400 hover:from-cyan-300 hover:to-emerald-300 text-slate-950 shadow-lg'
                    : 'bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-white'
                }`}
              >
                <span>{getCtaLabel(plan.id, defaultCta)}</span>
                {!isActive && <ArrowRight className="w-3.5 h-3.5" />}
              </button>
            </div>
          );
        })}
      </section>

      {/* Full Categorized Comparison Table Section */}
      <section id="full-comparison-table" className="scroll-mt-24 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
          <div className="text-left space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-300 font-semibold">
              Side-by-Side Breakdown
            </span>
            <h2 className="text-2xl sm:text-3xl font-google font-semibold tracking-[-0.03em] text-white">
              Compare Every Plan &amp; Limit
            </h2>
          </div>

          {/* Category Filter Pills */}
          <div className="flex flex-wrap items-center gap-1.5">
            {(
              [
                { id: 'all', label: 'All Features' },
                { id: 'quotas', label: 'Quotas' },
                { id: 'engine', label: 'Scanner Engine' },
                { id: 'fixes', label: 'AI Fixes & Exports' },
                { id: 'automation', label: 'CI/CD & Queue' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setCategoryFilter(tab.id)}
                className={`px-3 py-1.5 rounded-xl text-[11px] font-bold border transition-all cursor-pointer ${
                  categoryFilter === tab.id
                    ? 'bg-cyan-500/20 text-cyan-200 border-cyan-400/35'
                    : 'bg-white/[0.03] text-slate-400 hover:text-white border-white/10'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Desktop & Tablet Full 4-Column Comparison Table */}
        <div className="hidden md:block glass-panel rounded-3xl border border-white/15 overflow-hidden shadow-2xl">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-white/10 bg-[#050811]/90">
                <th className="p-5 w-[40%] align-bottom">
                  <div className="text-xs font-extrabold uppercase tracking-wider text-slate-300">
                    Capability &amp; Enforcement
                  </div>
                  <div className="text-[11px] font-normal text-slate-400 mt-1">
                    Strictly enforced in both UI and backend APIs
                  </div>
                </th>
                {PLAN_DISPLAY_CARDS.map((plan) => {
                  const price = annualBilling ? plan.priceAnnual : plan.priceMonthly;
                  const isActive = currentUser?.plan === plan.id;
                  return (
                    <th
                      key={plan.id}
                      className={`p-5 w-[20%] text-center align-bottom ${
                        plan.highlighted
                          ? 'bg-cyan-500/[0.08] border-x border-cyan-400/25'
                          : ''
                      }`}
                    >
                      <div className="space-y-2">
                        {plan.highlighted && (
                          <div className="inline-block px-2 py-0.5 rounded-full text-[9px] font-mono uppercase tracking-wider bg-cyan-500/20 text-cyan-200 border border-cyan-400/35 font-bold">
                            Most Popular
                          </div>
                        )}
                        <div className="text-sm font-black text-white">{plan.name}</div>
                        <div className="text-lg font-google font-bold text-white">
                          ${price}
                          <span className="text-[11px] font-normal text-slate-400">/mo</span>
                        </div>
                        <button
                          type="button"
                          onClick={() => onSelectPlan(plan.id, annualBilling ? 'annual' : 'monthly')}
                          disabled={isActive || checkoutBusyPlan === plan.id}
                          className={`w-full py-1.5 px-2 rounded-lg text-[11px] font-extrabold transition-all cursor-pointer ${
                            isActive
                              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-400/30 cursor-default'
                              : plan.highlighted
                              ? 'bg-cyan-400 hover:bg-cyan-300 text-slate-950'
                              : 'bg-white/[0.06] hover:bg-white/[0.14] text-white border border-white/10'
                          }`}
                        >
                          {isActive ? 'Current' : `Choose ${plan.name.split(' ')[0]}`}
                        </button>
                      </div>
                    </th>
                  );
                })}
              </tr>
            </thead>

            <tbody>
              {visibleGroups.map((group) => {
                const GroupIcon = GROUP_ICONS[group.id];
                return (
                  <React.Fragment key={group.id}>
                    <tr className="bg-white/[0.03] border-y border-white/10">
                      <td colSpan={4} className="px-5 py-3">
                        <div className="flex items-center gap-2 text-xs font-black uppercase tracking-wider text-slate-200">
                          <GroupIcon className="w-4 h-4 text-cyan-400" />
                          <span>{group.title}</span>
                        </div>
                      </td>
                    </tr>
                    {group.rows.map((row) => (
                      <tr
                        key={row.label}
                        className="border-b border-white/[0.06] last:border-b-0 hover:bg-white/[0.02] transition-colors"
                      >
                        <td className="px-5 py-4 align-middle">
                          <div className="text-xs font-bold text-white">{row.label}</div>
                          <div className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                            {row.detail}
                          </div>
                        </td>
                        <td className="px-4 py-4 text-center align-middle">
                          {renderComparisonCell(row.starter)}
                        </td>
                        <td className="px-4 py-4 text-center align-middle bg-cyan-500/[0.05] border-x border-cyan-400/20">
                          {renderComparisonCell(row.pro)}
                        </td>
                        <td className="px-4 py-4 text-center align-middle">
                          {renderComparisonCell(row.agency)}
                        </td>
                      </tr>
                    ))}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Mobile Clean Single-Plan Inspector (Zero cramped horizontal scrolling) */}
        <div className="md:hidden space-y-4">
          <div className="grid grid-cols-3 gap-1.5 p-1 rounded-2xl bg-white/[0.04] border border-white/10">
            {PLAN_DISPLAY_CARDS.map((plan) => {
              const price = annualBilling ? plan.priceAnnual : plan.priceMonthly;
              const selected = mobileFocusPlan === plan.id;
              return (
                <button
                  key={plan.id}
                  type="button"
                  onClick={() => setMobileFocusPlan(plan.id)}
                  className={`py-2 px-2 rounded-xl text-center transition-all cursor-pointer ${
                    selected
                      ? 'bg-cyan-500/20 border border-cyan-400/40 text-white'
                      : 'text-slate-400 border border-transparent'
                  }`}
                >
                  <div className="text-[11px] font-black truncate">{plan.name}</div>
                  <div className="text-[10px] font-mono text-cyan-300">${price}/mo</div>
                </button>
              );
            })}
          </div>

          <div className="glass-panel rounded-3xl border border-white/15 p-4 space-y-5">
            {visibleGroups.map((group) => {
              const GroupIcon = GROUP_ICONS[group.id];
              return (
                <div key={group.id} className="space-y-2.5">
                  <div className="flex items-center gap-2 text-[11px] font-black uppercase tracking-wider text-cyan-300 border-b border-white/10 pb-2">
                    <GroupIcon className="w-3.5 h-3.5" />
                    <span>{group.title}</span>
                  </div>
                  <div className="space-y-2.5">
                    {group.rows.map((row) => {
                      const val =
                        mobileFocusPlan === 'free'
                          ? row.starter
                          : mobileFocusPlan === 'pro'
                          ? row.pro
                          : row.agency;
                      return (
                        <div
                          key={row.label}
                          className="flex items-center justify-between gap-3 py-1.5 border-b border-white/[0.05] last:border-b-0"
                        >
                          <div className="text-left min-w-0">
                            <div className="text-xs font-bold text-white">{row.label}</div>
                            <div className="text-[10px] text-slate-400 leading-snug">{row.detail}</div>
                          </div>
                          <div className="shrink-0">{renderComparisonCell(val)}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}

            <button
              type="button"
              onClick={() => onSelectPlan(mobileFocusPlan, annualBilling ? 'annual' : 'monthly')}
              disabled={currentUser?.plan === mobileFocusPlan || checkoutBusyPlan === mobileFocusPlan}
              className="w-full py-2.5 rounded-xl text-xs font-black bg-gradient-to-r from-cyan-400 to-emerald-400 text-slate-950 disabled:opacity-50 cursor-pointer"
            >
              {checkoutBusyPlan === mobileFocusPlan
                ? 'Opening Checkout...'
                : currentUser?.plan === mobileFocusPlan
                ? 'Current Plan'
                : `Select ${PLAN_DISPLAY_CARDS.find((p) => p.id === mobileFocusPlan)?.name}`}
            </button>
          </div>
        </div>
      </section>

      {/* Billing & Compliance Mini-FAQ */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4 text-left">
        {PRICING_FAQ.map((item) => (
          <div key={item.q} className="glass-card rounded-2xl p-5 border border-white/10 space-y-2">
            <h3 className="text-xs font-black text-white">{item.q}</h3>
            <p className="text-[11px] text-slate-400 leading-relaxed">{item.a}</p>
          </div>
        ))}
      </section>

      {/* Compliance & Policy Footer Strip */}
      <div className="glass-card rounded-2xl p-4 sm:p-5 border border-white/10 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
        <span>
          Cancel anytime before renewal • 7-day technical refund guarantee on paid subscriptions.
        </span>
        {onOpenLegal && (
          <div className="flex flex-wrap items-center gap-4 text-[11px] font-bold">
            <button
              type="button"
              onClick={() => onOpenLegal('refund')}
              className="text-amber-300 hover:underline cursor-pointer"
            >
              Refund &amp; Cancellation Policy
            </button>
            <button
              type="button"
              onClick={() => onOpenLegal('terms')}
              className="text-cyan-300 hover:underline cursor-pointer"
            >
              Terms of Service
            </button>
            <button
              type="button"
              onClick={() => onOpenLegal('privacy')}
              className="text-emerald-300 hover:underline cursor-pointer"
            >
              Privacy Policy
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

