import React, { useEffect, useState } from 'react';
import {
  ArrowLeft,
  ArrowUpRight,
  Check,
  Copy,
  Crown,
  Globe,
  History,
  Key,
  Lock,
  LogOut,
  Mail,
  Moon,
  Plus,
  RefreshCw,
  Scale,
  Settings,
  ShieldCheck,
  Smartphone,
  Sun,
  FileText,
} from 'lucide-react';
import type { AccountPlan, SavedScanEntry, UserAccount } from '../types/account';
import { getPlanPolicy } from '../data/planPolicy';
import { LEGAL_DOCS_BY_ID, type LegalDocId } from '../data/legalDocs';
import { ContactUsForm } from './ContactUsForm';

interface AccountPageProps {
  user: UserAccount;
  onBack: () => void;
  onUserUpdated: (user: UserAccount) => void;
  onLogout: () => void;
  onOpenSavedScan: (entry: SavedScanEntry) => void | Promise<void>;
  onRescanWeb: (targetUrl: string) => void;
  onRescanApk?: (targetPackage?: string) => void;
  onOpenPricingPage?: () => void;
  theme?: 'dark' | 'light';
  onToggleTheme?: () => void;
}

type AccountViewTab = 'overview' | 'settings';
type SettingsSection = LegalDocId | 'contact' | 'preferences';

const LEGAL_SETTING_STYLE: Record<
  LegalDocId,
  { icon: typeof ShieldCheck; iconClass: string; badgeClass: string }
> = {
  privacy: {
    icon: Lock,
    iconClass: 'text-emerald-400',
    badgeClass: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
  },
  terms: {
    icon: Scale,
    iconClass: 'text-cyan-400',
    badgeClass: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
  },
  refund: {
    icon: RefreshCw,
    iconClass: 'text-amber-400',
    badgeClass: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
  },
};

export const AccountPage: React.FC<AccountPageProps> = ({
  user,
  onBack,
  onUserUpdated,
  onLogout,
  onOpenSavedScan,
  onRescanWeb,
  onRescanApk,
  onOpenPricingPage,
  theme = 'dark',
  onToggleTheme,
}) => {
  const [activeTab, setActiveTab] = useState<AccountViewTab>('overview');
  const [settingsSection, setSettingsSection] = useState<SettingsSection>('privacy');
  const [tokenCopied, setTokenCopied] = useState(false);
  const [emailCopied, setEmailCopied] = useState<string | null>(null);
  const [showToken, setShowToken] = useState(false);
  const [busyPlan, setBusyPlan] = useState<AccountPlan | null>(null);
  const [billingCycle, setBillingCycle] = useState<'monthly' | 'annual'>('monthly');
  const [billingError, setBillingError] = useState<string | null>(null);
  const [rotatingToken, setRotatingToken] = useState(false);
  const [openingScanId, setOpeningScanId] = useState<string | null>(null);

  const handleCopyEmail = async (address: string) => {
    try {
      await navigator.clipboard.writeText(address);
      setEmailCopied(address);
      setTimeout(() => setEmailCopied(null), 1800);
    } catch {}
  };

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, []);

  const handleCopyToken = async () => {
    try {
      await navigator.clipboard.writeText(user.apiToken);
      setTokenCopied(true);
      setTimeout(() => setTokenCopied(false), 1800);
    } catch {}
  };

  const handlePlanChange = async (plan: AccountPlan) => {
    if (plan === user.plan) return;
    setBusyPlan(plan);
    setBillingError(null);
    try {
      if (plan === 'free' || user.isOwner) {
        const res = await fetch('/api/auth/plan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ plan }),
        });
        const data = await res.json().catch(() => null);
        if (res.ok && data?.user) {
          onUserUpdated(data.user);
        } else {
          setBillingError(data?.error || 'Could not update your plan.');
        }
        return;
      }

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
      setBillingError(data?.error || 'Could not launch Dodo Payments checkout. Please try again shortly.');
    } catch {
      setBillingError('Network error while contacting billing service.');
    } finally {
      setBusyPlan(null);
    }
  };

  const handleRotateToken = async () => {
    setRotatingToken(true);
    try {
      const res = await fetch('/api/auth/token/rotate', {
        method: 'POST',
        credentials: 'same-origin',
      });
      if (res.ok) {
        const data = await res.json();
        if (data.user) onUserUpdated(data.user);
      }
    } finally {
      setRotatingToken(false);
    }
  };

  const planPolicy = getPlanPolicy(user.plan);
  const appsUsed = user.monthlyAppsUsed ?? 0;
  const appLimit = user.monthlyAppLimit ?? planPolicy.monthlyUniqueTargets;
  const quotaPct = Math.min(100, Math.round((appsUsed / Math.max(1, appLimit)) * 100));

  return (
    <section aria-label="Account Workspace" className="w-full py-2 sm:py-4 space-y-6 no-print">
      {/* Top Page Breadcrumb & Actions */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={activeTab === 'settings' ? () => setActiveTab('overview') : onBack}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-md wb-surface hover:border-white/25 text-xs font-medium text-slate-300 hover:text-white transition-colors cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5 text-emerald-400" />
            <span>{activeTab === 'settings' ? 'Back to Profile' : 'Back to Scanner'}</span>
          </button>
          <span className="text-[11px] font-mono text-slate-500 hidden sm:inline">
            {activeTab === 'settings' ? 'Workspace / Settings & Legal' : 'Workspace / Profile & Billing'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setActiveTab((prev) => (prev === 'settings' ? 'overview' : 'settings'))}
            className={`inline-flex items-center gap-1.5 h-9 px-3.5 rounded-md border text-xs font-medium transition-colors cursor-pointer ${
              activeTab === 'settings'
                ? 'bg-emerald-500/15 border-emerald-500/35 text-emerald-400 font-semibold'
                : 'wb-surface hover:border-white/25 text-slate-300 hover:text-white'
            }`}
          >
            <Settings className="w-3.5 h-3.5 text-emerald-400" />
            <span>Settings</span>
          </button>

          <button
            type="button"
            onClick={onBack}
            className="wb-emerald-btn h-9 px-4 rounded-md text-xs font-semibold inline-flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Security Audit</span>
          </button>
        </div>
      </div>

      {activeTab === 'settings' ? (
        <div className="wb-bezel p-1.5 rounded-2xl relative">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
          />
          <div className="wb-surface rounded-xl overflow-hidden grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-white/10 text-left">
            {/* Left Settings Navigation */}
            <div className="lg:col-span-4 p-4 space-y-1.5">
              <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-[0.14em] text-slate-500 font-semibold">
                Legal &amp; Support Settings
              </div>

              {[
                {
                  id: 'privacy' as SettingsSection,
                  label: 'Privacy Policy',
                  sub: 'RAM-only processing & data safety',
                  icon: Lock,
                  accent: 'text-emerald-400',
                },
                {
                  id: 'terms' as SettingsSection,
                  label: 'Terms of Service',
                  sub: 'Authorized use & scanner disclaimer',
                  icon: Scale,
                  accent: 'text-cyan-400',
                },
                {
                  id: 'refund' as SettingsSection,
                  label: 'Refund & Cancellation',
                  sub: 'Cancel anytime & 7-day refund rules',
                  icon: RefreshCw,
                  accent: 'text-amber-400',
                },
                {
                  id: 'contact' as SettingsSection,
                  label: 'Contact Us',
                  sub: 'Support email & direct message',
                  icon: Mail,
                  accent: 'text-emerald-400',
                },
                {
                  id: 'preferences' as SettingsSection,
                  label: 'Appearance & Session',
                  sub: 'Light / Dark theme & sign out',
                  icon: theme === 'dark' ? Moon : Sun,
                  accent: 'text-amber-400',
                },
              ].map((item) => {
                const Icon = item.icon;
                const isSelected = settingsSection === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setSettingsSection(item.id)}
                    className={`w-full text-left flex items-start gap-3 p-3 rounded-lg border transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-emerald-500/10 border-emerald-500/35'
                        : 'bg-transparent border-transparent hover:bg-white/[0.03] hover:border-white/10'
                    }`}
                  >
                    <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${item.accent}`} />
                    <div className="min-w-0">
                      <div className="text-xs font-display font-semibold text-white">{item.label}</div>
                      <div className="text-[11px] text-slate-400 leading-snug">{item.sub}</div>
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Right Settings Content Pane */}
            <div className="lg:col-span-8 p-6 sm:p-7 space-y-5">
              {(settingsSection === 'privacy' || settingsSection === 'terms' || settingsSection === 'refund') &&
                (() => {
                  const doc = LEGAL_DOCS_BY_ID[settingsSection];
                  const style = LEGAL_SETTING_STYLE[settingsSection];
                  const DocIcon = style.icon;
                  return (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-4">
                        <div>
                          <h2 className="text-lg font-display font-semibold text-white flex items-center gap-2 tracking-[-0.02em]">
                            <DocIcon className={`w-4 h-4 ${style.iconClass}`} />
                            <span>{doc.title}</span>
                          </h2>
                          <p className="text-xs text-slate-400 mt-1">
                            Effective {doc.effectiveDate} · {doc.subtitle}
                          </p>
                        </div>
                        <span
                          className={`px-2.5 py-0.5 rounded font-mono text-[10px] font-semibold border shrink-0 ${style.badgeClass}`}
                        >
                          {doc.badge}
                        </span>
                      </div>

                      <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
                        {doc.sections.map((sec) => (
                          <div key={sec.title} className="p-4 rounded-lg wb-surface-muted space-y-1.5">
                            <h3 className="text-xs font-display font-semibold text-white">{sec.title}</h3>
                            <p>{sec.body}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })()}

              {settingsSection === 'contact' && (
                <div className="space-y-5">
                  <div className="border-b border-white/10 pb-4">
                    <h2 className="text-lg font-display font-semibold text-white flex items-center gap-2 tracking-[-0.02em]">
                      <Mail className="w-4 h-4 text-emerald-400" />
                      <span>Contact Us &amp; Security Support</span>
                    </h2>
                    <p className="text-xs text-slate-400 mt-1">
                      Need help with an audit report, billing question, or responsible vulnerability disclosure?
                    </p>
                  </div>

                  {/* Direct Contact Cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {[
                      {
                        label: 'Primary Support Inbox',
                        email: 'checkmyapk.com@gmail.com',
                      },
                      {
                        label: 'Security & Abuse Desk',
                        email: 'checkmyapk.com@gmail.com',
                      },
                    ].map((desk) => (
                      <div
                        key={desk.label}
                        className="p-3.5 rounded-lg wb-surface-muted space-y-2"
                      >
                        <div className="text-[11px] font-medium text-slate-400">{desk.label}</div>
                        <div className="flex items-center justify-between gap-2">
                          <a
                            href={`mailto:${desk.email}`}
                            className="text-xs font-mono font-semibold text-emerald-400 hover:underline truncate"
                          >
                            {desk.email}
                          </a>
                          <button
                            type="button"
                            onClick={() => handleCopyEmail(desk.email)}
                            className="px-2.5 py-1 rounded bg-white/[0.05] hover:bg-white/[0.1] border border-white/10 text-[10.5px] font-mono font-medium text-slate-300 inline-flex items-center gap-1 shrink-0 cursor-pointer"
                          >
                            {emailCopied === desk.email ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                            {emailCopied === desk.email ? 'Copied' : 'Copy'}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="pt-1">
                    <ContactUsForm defaultName={user.name} defaultEmail={user.email} />
                  </div>
                </div>
              )}

              {settingsSection === 'preferences' && (
                <div className="space-y-4">
                  <div className="border-b border-white/10 pb-4">
                    <h2 className="text-lg font-display font-semibold text-white flex items-center gap-2 tracking-[-0.02em]">
                      <Settings className="w-4 h-4 text-emerald-400" />
                      <span>Workspace Appearance &amp; Session</span>
                    </h2>
                    <p className="text-xs text-slate-400 mt-1">
                      Customize visual theme and manage your active signed-in session.
                    </p>
                  </div>

                  {onToggleTheme && (
                    <div className="p-4 rounded-lg wb-surface-muted flex items-center justify-between gap-3">
                      <div>
                        <div className="text-xs font-display font-semibold text-white">Interface Theme</div>
                        <div className="text-[11px] text-slate-400">
                          Currently using {theme === 'dark' ? 'Obsidian Dark (Default)' : 'Clean Light'} theme
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={onToggleTheme}
                        className="px-3.5 py-2 rounded-md wb-surface hover:border-white/25 text-xs font-medium text-white inline-flex items-center gap-2 cursor-pointer"
                      >
                        {theme === 'dark' ? (
                          <>
                            <Sun className="w-3.5 h-3.5 text-amber-400" />
                            <span>Switch to Light Mode</span>
                          </>
                        ) : (
                          <>
                            <Moon className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Switch to Dark Mode</span>
                          </>
                        )}
                      </button>
                    </div>
                  )}

                  <div className="p-4 rounded-lg wb-surface-muted flex items-center justify-between gap-3">
                    <div>
                      <div className="text-xs font-display font-semibold text-white">Signed-In Account</div>
                      <div className="text-[11px] text-slate-400">{user.email}</div>
                    </div>
                    <button
                      type="button"
                      onClick={onLogout}
                      className="px-3.5 py-2 rounded-md bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-400 text-xs font-semibold inline-flex items-center gap-1.5 cursor-pointer"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      <span>Sign Out</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      ) : (
        /* Main Two-Column Obsidian Account Workbench */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start text-left">
          {/* Left Column: Profile Identity, Plan & Quota, Session */}
          <div className="lg:col-span-5 space-y-5">
            {/* Identity Card */}
            <div className="wb-bezel p-1.5 rounded-2xl relative">
              <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
              />
              <div className="wb-surface rounded-xl p-5 space-y-4">
                <div className="flex items-center gap-4">
                  {user.avatarUrl ? (
                    <img
                      src={user.avatarUrl}
                      alt={user.name}
                      referrerPolicy="no-referrer"
                      className="w-14 h-14 rounded-xl border border-emerald-500/35 object-cover shrink-0"
                    />
                  ) : (
                    <div className="w-14 h-14 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-display font-semibold text-lg shrink-0">
                      {user.name.slice(0, 2).toUpperCase()}
                    </div>
                  )}

                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h1 className="text-lg font-display font-semibold tracking-[-0.02em] text-white truncate">
                        {user.name}
                      </h1>
                      <span className="px-2 py-0.5 rounded font-mono text-[10px] uppercase tracking-wider font-semibold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                        {user.plan}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 truncate">{user.email}</p>
                    <div className="flex flex-wrap items-center gap-2 pt-0.5">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded wb-spec-code font-mono text-[10px]">
                        <ShieldCheck className="w-3 h-3 text-emerald-400" />
                        {user.authProvider === 'google' ? 'Google OAuth' : 'Email & Password'}
                      </span>
                      <span className="font-mono text-[10px] text-slate-500">
                        Joined {new Date(user.createdAt).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Plan & Monthly App Slot Quota Card */}
            <div className="wb-bezel p-1.5 rounded-2xl">
              <div className="wb-surface rounded-xl p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-sm font-display font-semibold text-white">
                    <Crown className="w-4 h-4 text-emerald-400" />
                    <span>Monthly App &amp; Website Slots</span>
                  </div>
                  <span className="text-xs font-mono tabular-nums text-slate-300">
                    {appsUsed} / {appLimit} targets
                  </span>
                </div>

                <div className="h-2 rounded-full bg-white/[0.06] overflow-hidden">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-400 transition-all duration-500"
                    style={{ width: `${quotaPct}%` }}
                  />
                </div>

                <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                  <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 font-semibold">
                    {planPolicy.maxRescansPerTarget === null
                      ? 'Unlimited Re-scans on tracked apps'
                      : `Max ${planPolicy.maxRescansPerTarget} scans per app`}
                  </span>
                  <span className="px-2 py-0.5 rounded wb-spec-code">
                    Max APK: {planPolicy.maxApkMb} MB
                  </span>
                  {planPolicy.priorityQueue && (
                    <span className="px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/25 text-cyan-400 font-semibold">
                      Priority Queue
                    </span>
                  )}
                </div>

                {Array.isArray(user.monthlyTargets) && user.monthlyTargets.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-0.5">
                    {user.monthlyTargets.slice(0, 6).map((item) => (
                      <span
                        key={item.target}
                        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded wb-surface-muted text-[10px] font-mono text-slate-300"
                      >
                        <span className="truncate max-w-[140px]">{item.target.replace(/^(apk|web):/, '')}</span>
                        <span className="text-emerald-400 font-semibold">{item.count}x</span>
                      </span>
                    ))}
                  </div>
                )}

                <div className="space-y-2.5 pt-2 border-t border-white/10">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-medium text-slate-400">
                        Plan &amp; Subscription
                      </span>
                      {user.isOwner ? (
                        <span className="px-2 py-0.5 rounded font-mono text-[10px] uppercase bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-semibold">
                          Owner · All Plans Active
                        </span>
                      ) : (
                        user.billingStatus && (
                          <span className="px-2 py-0.5 rounded font-mono text-[10px] uppercase bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                            {user.billingStatus.replace('_', ' ')}
                          </span>
                        )
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="inline-flex rounded-md wb-surface-muted p-0.5 text-[10px] font-mono">
                        <button
                          type="button"
                          onClick={() => setBillingCycle('monthly')}
                          className={`px-2 py-0.5 rounded cursor-pointer transition-colors ${
                            billingCycle === 'monthly' ? 'bg-white/15 text-white font-semibold' : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          Monthly
                        </button>
                        <button
                          type="button"
                          onClick={() => setBillingCycle('annual')}
                          className={`px-2 py-0.5 rounded cursor-pointer transition-colors ${
                            billingCycle === 'annual' ? 'bg-emerald-500/20 text-emerald-400 font-semibold' : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          Annual (-38%)
                        </button>
                      </div>
                      {onOpenPricingPage && (
                        <button
                          type="button"
                          onClick={onOpenPricingPage}
                          className="text-[11px] font-medium text-emerald-400 hover:underline cursor-pointer"
                        >
                          Compare Plans →
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    {(['free', 'pro', 'agency'] as AccountPlan[]).map((tier) => (
                      <button
                        key={tier}
                        type="button"
                        disabled={busyPlan !== null}
                        onClick={() => handlePlanChange(tier)}
                        className={`py-2 px-3 rounded-md font-mono text-xs font-semibold uppercase tracking-wider border transition-colors cursor-pointer ${
                          user.plan === tier
                            ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400'
                            : 'wb-surface-muted text-slate-400 hover:text-white hover:border-white/25'
                        }`}
                      >
                        {busyPlan === tier ? '...' : tier}
                      </button>
                    ))}
                  </div>

                  {billingError && (
                    <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-[11px] text-amber-400">
                      {billingError}
                    </div>
                  )}
                </div>

                <p className="text-[11px] text-slate-500 leading-relaxed">
                  Paid upgrades checkout securely via Dodo Payments. Switch back to Starter Free anytime.
                </p>
              </div>
            </div>

            {/* Session Card */}
            <div className="wb-surface rounded-xl p-4 flex items-center justify-between gap-3">
              <div>
                <div className="text-xs font-display font-semibold text-white">Active Browser Session</div>
                <div className="text-[11px] text-slate-400">Signed with HttpOnly cookie</div>
              </div>
              <button
                type="button"
                onClick={onLogout}
                className="px-3.5 py-2 rounded-md bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-400 text-xs font-semibold inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Sign Out</span>
              </button>
            </div>
          </div>

          {/* Right Column: Personal Workspace API Token & Saved Scan History */}
          <div className="lg:col-span-7 space-y-5">
            {/* CI/CD API Key */}
            <div className="wb-bezel p-1.5 rounded-2xl">
              <div className="wb-surface rounded-xl p-5 space-y-3.5">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-display font-semibold text-white flex items-center gap-2">
                      <Key className="w-4 h-4 text-cyan-400" />
                      <span>Workspace CI/CD API Token</span>
                      <span className="px-2 py-0.5 rounded font-mono text-[9.5px] uppercase font-semibold bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                        Agency Only
                      </span>
                    </h2>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Use this token for CI/CD pipeline triggers and automated multi-client API sweeps.
                    </p>
                  </div>
                  {planPolicy.features.apiTokenAccess && (
                    <button
                      type="button"
                      onClick={handleRotateToken}
                      disabled={rotatingToken}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md wb-surface-muted hover:border-white/25 text-xs font-medium text-slate-300 hover:text-white transition-colors cursor-pointer shrink-0"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${rotatingToken ? 'animate-spin' : ''}`} />
                      <span>Rotate</span>
                    </button>
                  )}
                </div>

                {planPolicy.features.apiTokenAccess ? (
                  <div className="flex flex-wrap sm:flex-nowrap items-center gap-2">
                    <code className="flex-1 min-w-0 px-3.5 py-2 rounded-md wb-surface-muted text-xs font-mono text-cyan-400 truncate">
                      {showToken
                        ? user.apiToken
                        : `${user.apiToken.slice(0, 13)}••••••••••••${user.apiToken.slice(-4)}`}
                    </code>
                    <button
                      type="button"
                      onClick={() => setShowToken((v) => !v)}
                      className="px-3 py-2 rounded-md wb-surface-muted hover:border-white/25 text-xs font-medium text-slate-300 hover:text-white cursor-pointer"
                    >
                      {showToken ? 'Hide' : 'Show'}
                    </button>
                    <button
                      type="button"
                      onClick={handleCopyToken}
                      className="px-3 py-2 rounded-md wb-surface-muted hover:border-white/25 text-xs font-medium text-slate-200 inline-flex items-center gap-1.5 cursor-pointer"
                    >
                      {tokenCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{tokenCopied ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                ) : (
                  <div className="p-3.5 rounded-lg wb-surface-muted flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="text-[11px] text-slate-300 flex items-center gap-2">
                      <Lock className="w-4 h-4 text-cyan-400 shrink-0" />
                      <span>
                        Workspace API tokens &amp; CI/CD automation unlock on <strong className="text-white">Team &amp; Agency</strong>.
                      </span>
                    </div>
                    <button
                      type="button"
                      disabled={busyPlan !== null}
                      onClick={() => handlePlanChange('agency')}
                      className="wb-primary-btn h-8 px-3 rounded-md text-[11px] font-semibold shrink-0 cursor-pointer"
                    >
                      Upgrade to Agency
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Saved Scan History */}
            <div className="wb-bezel p-1.5 rounded-2xl">
              <div className="wb-surface rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between gap-2">
                  <h2 className="text-sm font-display font-semibold text-white flex items-center gap-2">
                    <History className="w-4 h-4 text-emerald-400" />
                    <span>Saved Scan History ({user.scansHistory.length})</span>
                  </h2>
                  <span className="text-[10.5px] font-mono text-slate-500">Latest 20 stored</span>
                </div>

                {user.scansHistory.length === 0 ? (
                  <div className="p-8 rounded-xl wb-surface-muted border-dashed text-center space-y-3">
                    <p className="text-xs text-slate-400">
                      No saved scans yet. Run any APK or Web scan while signed in and your audit scores will appear here.
                    </p>
                    <button
                      type="button"
                      onClick={onBack}
                      className="wb-emerald-btn h-9 px-4 rounded-md text-xs font-semibold inline-flex items-center gap-1.5 cursor-pointer"
                    >
                      <span>Start First Scan</span>
                      <ArrowUpRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
                    {user.scansHistory.map((item) => {
                      const isOpening = openingScanId === item.id;
                      const handleRowOpen = async () => {
                        if (openingScanId) return;
                        setOpeningScanId(item.id);
                        try {
                          await onOpenSavedScan(item);
                        } finally {
                          setOpeningScanId(null);
                        }
                      };
                      return (
                        <div
                          key={item.id}
                          role="button"
                          tabIndex={0}
                          onClick={handleRowOpen}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault();
                              void handleRowOpen();
                            }
                          }}
                          title="Tap to view this past security report"
                          className="group flex items-center justify-between gap-3 p-3.5 rounded-lg wb-surface-muted hover:border-emerald-500/40 transition-colors cursor-pointer text-left"
                        >
                          <div className="flex items-center gap-3 min-w-0">
                            <div
                              className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 border ${
                                item.mode === 'apk'
                                  ? 'bg-emerald-500/10 border-emerald-500/25 text-emerald-400'
                                  : 'bg-cyan-500/10 border-cyan-500/25 text-cyan-400'
                              }`}
                            >
                              {item.mode === 'apk' ? (
                                <Smartphone className="w-4 h-4" />
                              ) : (
                                <Globe className="w-4 h-4" />
                              )}
                            </div>
                            <div className="min-w-0">
                              <div className="text-xs font-display font-semibold text-white group-hover:text-emerald-400 transition-colors truncate flex items-center gap-1.5">
                                <span className="truncate">{item.target}</span>
                                <span className="text-[10px] font-mono text-emerald-400 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                                  {isOpening ? 'Opening…' : 'View Report →'}
                                </span>
                              </div>
                              <div className="font-mono text-[10.5px] text-slate-400">
                                {new Date(item.timestamp).toLocaleString()} · {item.criticalCount} critical
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-2 shrink-0">
                            <span className="px-2 py-1 rounded wb-spec-code font-mono text-[11px] font-semibold tabular-nums">
                              {item.grade} ({item.score})
                            </span>
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                void handleRowOpen();
                              }}
                              title="Open saved report"
                              className="hidden sm:inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md wb-surface hover:border-white/25 text-[11px] font-medium text-slate-200 hover:text-white cursor-pointer"
                            >
                              <FileText className="w-3 h-3 text-emerald-400" />
                              <span>{isOpening ? 'Loading…' : 'Report'}</span>
                            </button>
                            {item.mode === 'web' ? (
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onRescanWeb(item.target);
                                }}
                                title="Re-scan this URL"
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-[11px] font-medium text-cyan-400 cursor-pointer"
                              >
                                <span>Re-scan</span>
                                <ArrowUpRight className="w-3.5 h-3.5" />
                              </button>
                            ) : (
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  if (onRescanApk) {
                                    onRescanApk(item.target);
                                  } else {
                                    onBack();
                                  }
                                }}
                                title="Select APK file to re-scan"
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-[11px] font-medium text-emerald-400 cursor-pointer"
                              >
                                <span>Re-scan</span>
                                <ArrowUpRight className="w-3.5 h-3.5" />
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
