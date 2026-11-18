import React, { useEffect, useState } from 'react';
import {
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  Check,
  Cpu,
  Crown,
  Layers,
  Minus,
  ShieldCheck,
  Wrench,
  Zap,
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

const TIER_SPEC_META: Record<
  AccountPlan,
  { index: string; slots: string; maxApk: string; accent: 'neutral' | 'emerald' | 'cyan' }
> = {
  free: { index: '01', slots: '2 slots/mo', maxApk: '25 MB APK', accent: 'neutral' },
  pro: { index: '02', slots: '15 slots/mo', maxApk: '75 MB APK', accent: 'emerald' },
  agency: { index: '03', slots: '60 slots/mo', maxApk: '150 MB APK', accent: 'cyan' },
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
        className="inline-flex items-center justify-center w-6 h-6 rounded-md bg-emerald-500/12 border border-emerald-500/30 text-emerald-400"
        aria-label="Included"
      >
        <Check className="w-3.5 h-3.5 stroke-[2.5]" />
      </span>
    );
  }
  if (cell === false) {
    return (
      <span
        className="inline-flex items-center justify-center w-6 h-6 rounded-md bg-white/[0.03] border border-white/10 text-slate-500"
        aria-label="Not included"
      >
        <Minus className="w-3.5 h-3.5" />
      </span>
    );
  }

  const badgeStyle =
    cell.emphasis === 'emerald'
      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 font-semibold'
      : cell.emphasis === 'cyan'
      ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400 font-semibold'
      : cell.emphasis === 'purple'
      ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400 font-semibold'
      : cell.emphasis === 'muted'
      ? 'bg-white/[0.03] border-white/10 text-slate-400 font-medium'
      : 'bg-white/[0.05] border-white/10 text-slate-300 font-medium';

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded font-mono text-[10.5px] border whitespace-nowrap ${badgeStyle}`}
    >
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
    <div className="w-full space-y-12 pb-10">
      {/* Top Breadcrumb Navigation */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-md text-xs font-medium wb-surface hover:border-white/25 text-slate-300 hover:text-white transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5 text-emerald-400" />
          <span>Back to Security Scanner</span>
        </button>

        <span className="wb-eyebrow-pill inline-flex items-center gap-2 px-3 py-1 rounded-md font-mono text-[10.5px] uppercase tracking-[0.12em] font-medium">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0" aria-hidden="true" />
          <span>Transparent Plans · Cancel Anytime</span>
        </span>
      </div>

      {/* Pricing Hero + Billing Toggle */}
      <section className="text-center space-y-5 max-w-3xl mx-auto">
        <div className="space-y-2.5">
          <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold block">
            Pricing &amp; Quotas
          </span>
          <h1 className="text-3xl sm:text-5xl font-display font-bold tracking-[-0.04em] leading-[1.08]">
            <span className="text-white">Simple pricing.</span>{' '}
            <span className="wb-headline-muted">Zero guesswork.</span>
          </h1>
        </div>
        <p className="text-xs sm:text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">
          Start free with 2 monthly app slots, upgrade to{' '}
          <span className="text-emerald-400 font-semibold">Pro Security</span> for unlimited re-scans &amp; AI Fix Doctor, or scale with{' '}
          <span className="text-cyan-400 font-semibold">Team &amp; Agency</span> for CI/CD API tokens and 150 MB builds.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-3 pt-1">
          <div className="inline-flex items-center p-1 rounded-md wb-surface-muted">
            <button
              type="button"
              onClick={() => setAnnualBilling(false)}
              className={`px-3.5 py-1.5 rounded text-xs font-medium transition-colors cursor-pointer ${
                !annualBilling
                  ? 'bg-white/15 text-white font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Monthly
            </button>
            <button
              type="button"
              onClick={() => setAnnualBilling(true)}
              className={`px-3.5 py-1.5 rounded text-xs font-medium transition-colors cursor-pointer inline-flex items-center gap-2 ${
                annualBilling
                  ? 'bg-white/15 text-white font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <span>Annual</span>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold">
                Save 38%
              </span>
            </button>
          </div>

          <button
            type="button"
            onClick={() => {
              document
                .getElementById('full-comparison-table')
                ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md text-xs font-medium wb-surface hover:border-white/25 text-slate-300 hover:text-white transition-colors cursor-pointer"
          >
            <span>Compare all 16 limits</span>
            <ArrowDown className="w-3.5 h-3.5 text-emerald-400" />
          </button>
        </div>
      </section>

      {/* Unified Double-Bezel 3-Tier Architectural Pricing Workbench */}
      <section className="wb-bezel p-1.5 rounded-2xl relative">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
        />

        <div className="wb-surface rounded-xl overflow-hidden text-left">
          {/* Top Workbench Strip */}
          <div className="wb-ide-chrome px-5 py-2.5 border-b border-white/10 flex flex-wrap items-center justify-between gap-2 font-mono text-[10.5px] text-slate-400">
            <span className="inline-flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
              <span className="text-slate-300 font-medium">
                {annualBilling ? 'Annual Billing Active (up to 38% off)' : 'Monthly Flex Billing'}
              </span>
            </span>
            <span className="text-slate-500">
              Instant activation · 7-day technical refund guarantee
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-white/10 items-stretch">
            {PLAN_DISPLAY_CARDS.map((plan) => {
              const isActive = currentUser?.plan === plan.id;
              const displayPrice = annualBilling ? plan.priceAnnual : plan.priceMonthly;
              const spec = TIER_SPEC_META[plan.id];
              const defaultCta =
                plan.id === 'free'
                  ? 'Start Free'
                  : plan.id === 'pro'
                  ? 'Upgrade to Pro'
                  : 'Get Team & Agency';

              return (
                <div
                  key={plan.id}
                  className={`p-6 flex flex-col justify-between relative overflow-hidden transition-colors ${
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

                  <div className="relative z-10 space-y-5">
                    {/* Tier Eyebrow + Badge */}
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-9 h-9 rounded-lg flex items-center justify-center border shrink-0 ${
                            spec.accent === 'emerald'
                              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                              : spec.accent === 'cyan'
                              ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                              : 'bg-white/[0.04] border-white/10 text-slate-300'
                          }`}
                        >
                          {plan.id === 'free' ? (
                            <ShieldCheck className="w-4 h-4" />
                          ) : plan.id === 'pro' ? (
                            <Zap className="w-4 h-4" />
                          ) : (
                            <Crown className="w-4 h-4" />
                          )}
                        </div>
                        <div>
                          <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">
                            Tier {spec.index} · {plan.tagline}
                          </div>
                          <h2 className="text-base font-display font-semibold tracking-[-0.02em] text-white mt-0.5">
                            {plan.name}
                          </h2>
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

                    {/* Price Display */}
                    <div className="space-y-1.5">
                      <div className="flex items-baseline gap-2 flex-wrap">
                        <span className="text-4xl font-display font-semibold tabular-nums tracking-[-0.04em] text-white">
                          ${displayPrice}
                        </span>
                        <span className="font-mono text-[11px] text-slate-400">/ month</span>
                        {plan.id !== 'free' && annualBilling && (
                          <span className="font-mono text-xs text-slate-500 line-through tabular-nums">
                            ${plan.priceMonthly}
                          </span>
                        )}
                      </div>
                      <div className="font-mono text-[10.5px] text-slate-500">
                        {plan.id === 'free'
                          ? 'Free forever · No credit card required'
                          : annualBilling
                          ? `Billed $${plan.annualTotalUsd}/yr (save $${(plan.priceMonthly - plan.priceAnnual) * 12}/yr)`
                          : `Or $${plan.priceAnnual}/mo billed annually`}
                      </div>
                    </div>

                    {/* Quick Spec Chips */}
                    <div className="flex flex-wrap items-center gap-1.5">
                      <code className="wb-spec-code font-mono text-[10px] px-2 py-0.5 rounded">
                        {spec.slots}
                      </code>
                      <code className="wb-spec-code font-mono text-[10px] px-2 py-0.5 rounded">
                        {spec.maxApk}
                      </code>
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed">{plan.subtitle}</p>

                    {/* Feature Checklist */}
                    <ul className="space-y-2.5 pt-4 border-t border-white/10">
                      {plan.highlights.map((feat) => (
                        <li key={feat} className="flex items-start gap-2.5 text-xs text-slate-300 leading-relaxed">
                          <Check
                            className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${
                              spec.accent === 'cyan' ? 'text-cyan-400' : 'text-emerald-400'
                            }`}
                          />
                          <span>{feat}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* CTA Button */}
                  <button
                    type="button"
                    onClick={() => onSelectPlan(plan.id, annualBilling ? 'annual' : 'monthly')}
                    disabled={isActive || checkoutBusyPlan === plan.id}
                    className={`relative z-10 mt-7 w-full h-10 rounded-md text-xs font-semibold transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                      isActive
                        ? 'bg-emerald-500/10 border border-emerald-500/35 text-emerald-400 cursor-default'
                        : plan.highlighted
                        ? 'wb-emerald-btn'
                        : plan.id === 'agency'
                        ? 'wb-primary-btn'
                        : 'bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-white'
                    }`}
                  >
                    <span>{getCtaLabel(plan.id, defaultCta)}</span>
                    {!isActive && <ArrowRight className="w-3.5 h-3.5" />}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Full Categorized Comparison Table Section */}
      <section id="full-comparison-table" className="scroll-mt-24 space-y-6">
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-white/10 pb-5">
          <div className="text-left space-y-1.5">
            <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold">
              Side-by-Side Matrix
            </span>
            <h2 className="text-2xl sm:text-[28px] font-display font-semibold tracking-[-0.035em] leading-[1.15]">
              <span className="text-white">Compare every plan</span>{' '}
              <span className="wb-headline-muted">&amp; enforcement limit.</span>
            </h2>
          </div>

          {/* Category Filter Tabs */}
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
                className={`px-3 py-1.5 rounded-md font-mono text-[10.5px] font-medium border transition-colors cursor-pointer ${
                  categoryFilter === tab.id
                    ? 'bg-emerald-500/12 text-emerald-400 border-emerald-500/35 font-semibold'
                    : 'bg-white/[0.03] text-slate-400 hover:text-white border-white/10'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Desktop & Tablet Full 4-Column Comparison Table */}
        <div className="hidden md:block wb-bezel p-1.5 rounded-2xl relative">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/45 to-transparent"
          />
          <div className="wb-surface rounded-xl overflow-hidden">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/10 wb-ide-chrome">
                  <th className="p-5 w-[40%] align-bottom">
                    <div className="font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-slate-300">
                      Capability &amp; Enforcement
                    </div>
                    <div className="text-[11px] font-normal text-slate-500 mt-1">
                      Strictly enforced across UI &amp; backend APIs
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
                            ? 'bg-emerald-500/[0.05] border-x border-emerald-500/20'
                            : ''
                        }`}
                      >
                        <div className="space-y-2">
                          {plan.highlighted && (
                            <div className="inline-block px-2 py-0.5 rounded font-mono text-[9px] uppercase tracking-wider bg-emerald-500/12 text-emerald-400 border border-emerald-500/30 font-semibold">
                              Most Popular
                            </div>
                          )}
                          <div className="text-sm font-display font-semibold text-white">
                            {plan.name}
                          </div>
                          <div className="text-lg font-display font-semibold tabular-nums text-white">
                            ${price}
                            <span className="font-mono text-[10px] font-normal text-slate-400">/mo</span>
                          </div>
                          <button
                            type="button"
                            onClick={() => onSelectPlan(plan.id, annualBilling ? 'annual' : 'monthly')}
                            disabled={isActive || checkoutBusyPlan === plan.id}
                            className={`w-full h-8 px-2 rounded-md text-[11px] font-semibold transition-colors cursor-pointer ${
                              isActive
                                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 cursor-default'
                                : plan.highlighted
                                ? 'wb-emerald-btn'
                                : 'bg-white/[0.06] hover:bg-white/[0.12] text-white border border-white/10'
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
                      <tr className="wb-ide-chrome border-y border-white/10">
                        <td colSpan={4} className="px-5 py-3">
                          <div className="flex items-center gap-2 font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-slate-300">
                            <GroupIcon className="w-3.5 h-3.5 text-emerald-400" />
                            <span>{group.title}</span>
                          </div>
                        </td>
                      </tr>
                      {group.rows.map((row) => (
                        <tr
                          key={row.label}
                          className="wb-spec-row border-b border-white/[0.06] last:border-b-0 transition-colors"
                        >
                          <td className="px-5 py-3.5 align-middle">
                            <div className="text-[12.5px] font-semibold text-white">{row.label}</div>
                            <div className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                              {row.detail}
                            </div>
                          </td>
                          <td className="px-4 py-3.5 text-center align-middle">
                            {renderComparisonCell(row.starter)}
                          </td>
                          <td className="px-4 py-3.5 text-center align-middle bg-emerald-500/[0.03] border-x border-emerald-500/15">
                            {renderComparisonCell(row.pro)}
                          </td>
                          <td className="px-4 py-3.5 text-center align-middle">
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
        </div>

        {/* Mobile Clean Single-Plan Inspector */}
        <div className="md:hidden space-y-4">
          <div className="grid grid-cols-3 gap-1.5 p-1 rounded-lg wb-surface-muted">
            {PLAN_DISPLAY_CARDS.map((plan) => {
              const price = annualBilling ? plan.priceAnnual : plan.priceMonthly;
              const selected = mobileFocusPlan === plan.id;
              return (
                <button
                  key={plan.id}
                  type="button"
                  onClick={() => setMobileFocusPlan(plan.id)}
                  className={`py-2 px-2 rounded-md text-center transition-colors cursor-pointer ${
                    selected
                      ? 'bg-emerald-500/15 border border-emerald-500/35 text-white'
                      : 'text-slate-400 border border-transparent'
                  }`}
                >
                  <div className="text-[11px] font-display font-semibold truncate">{plan.name}</div>
                  <div className="text-[10px] font-mono text-emerald-400 tabular-nums">${price}/mo</div>
                </button>
              );
            })}
          </div>

          <div className="wb-bezel p-1.5 rounded-2xl">
            <div className="wb-surface rounded-xl p-4 space-y-5">
              {visibleGroups.map((group) => {
                const GroupIcon = GROUP_ICONS[group.id];
                return (
                  <div key={group.id} className="space-y-2.5">
                    <div className="flex items-center gap-2 font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-emerald-400 border-b border-white/10 pb-2">
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
                            className="flex items-center justify-between gap-3 py-1.5 border-b border-white/[0.06] last:border-b-0"
                          >
                            <div className="text-left min-w-0">
                              <div className="text-xs font-semibold text-white">{row.label}</div>
                              <div className="text-[10.5px] text-slate-400 leading-snug">{row.detail}</div>
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
                className="wb-emerald-btn w-full h-10 rounded-md text-xs font-semibold disabled:opacity-50 cursor-pointer"
              >
                {checkoutBusyPlan === mobileFocusPlan
                  ? 'Opening Checkout...'
                  : currentUser?.plan === mobileFocusPlan
                  ? 'Current Plan'
                  : `Select ${PLAN_DISPLAY_CARDS.find((p) => p.id === mobileFocusPlan)?.name}`}
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Billing & Compliance Mini-FAQ */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4 text-left">
        {PRICING_FAQ.map((item, idx) => (
          <div key={item.q} className="wb-surface rounded-xl p-5 space-y-2">
            <span className="font-mono text-[10px] text-emerald-400 tabular-nums">
              0{idx + 1}
            </span>
            <h3 className="text-xs font-display font-semibold text-white leading-snug">
              {item.q}
            </h3>
            <p className="text-[11.5px] text-slate-400 leading-relaxed">{item.a}</p>
          </div>
        ))}
      </section>

      {/* Compliance & Policy Footer Strip */}
      <div className="wb-surface rounded-xl px-5 py-4 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
        <span>
          Cancel anytime before renewal · 7-day technical refund guarantee on paid subscriptions.
        </span>
        {onOpenLegal && (
          <div className="flex flex-wrap items-center gap-4 text-[11px] font-medium">
            <button
              type="button"
              onClick={() => onOpenLegal('refund')}
              className="text-emerald-400 hover:underline cursor-pointer"
            >
              Refund Policy
            </button>
            <button
              type="button"
              onClick={() => onOpenLegal('terms')}
              className="text-slate-300 hover:text-white hover:underline cursor-pointer"
            >
              Terms of Service
            </button>
            <button
              type="button"
              onClick={() => onOpenLegal('privacy')}
              className="text-slate-300 hover:text-white hover:underline cursor-pointer"
            >
              Privacy Policy
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
