import React, { useEffect, useState } from 'react';
import {
  ArrowLeft,
  ArrowUpRight,
  Check,
  Copy,
  Crown,
  FileText,
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
} from 'lucide-react';
import type { AccountPlan, UserAccount } from '../types/account';
import { LEGAL_DOCS_BY_ID, type LegalDocId } from '../data/legalDocs';
import { getPlanPolicy } from '../data/planPolicy';
import { ContactUsForm } from './ContactUsForm';

interface AccountPageProps {
  user: UserAccount;
  onBack: () => void;
  onUserUpdated: (user: UserAccount) => void;
  onLogout: () => void;
  onRescanWeb: (targetUrl: string) => void;
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
    icon: ShieldCheck,
    iconClass: 'text-emerald-400',
    badgeClass: 'bg-emerald-500/15 border-emerald-400/30 text-emerald-300',
  },
  terms: {
    icon: FileText,
    iconClass: 'text-cyan-400',
    badgeClass: 'bg-cyan-500/15 border-cyan-400/30 text-cyan-300',
  },
  refund: {
    icon: RefreshCw,
    iconClass: 'text-amber-300',
    badgeClass: 'bg-amber-500/15 border-amber-400/30 text-amber-300',
  },
};

export const AccountPage: React.FC<AccountPageProps> = ({
  user,
  onBack,
  onUserUpdated,
  onLogout,
  onRescanWeb,
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
  const [rotatingToken, setRotatingToken] = useState(false);

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
    } catch {
      // Ignore clipboard permission failures cleanly
    }
  };

  const handlePlanChange = async (plan: AccountPlan) => {
    if (plan === user.plan) return;
    setBusyPlan(plan);
    try {
      const res = await fetch('/api/auth/plan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ plan }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.user) onUserUpdated(data.user);
      }
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
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-white/[0.05] hover:bg-white/[0.1] border border-white/15 text-xs font-bold text-slate-200 transition-all cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5 text-cyan-400" />
            {activeTab === 'settings' ? 'Back to Profile' : 'Back to Scanner'}
          </button>
          <span className="text-xs font-mono text-slate-500 hidden sm:inline">
            {activeTab === 'settings' ? 'Workspace / Settings & Legal' : 'Workspace / Profile & Billing'}
          </span>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => setActiveTab((prev) => (prev === 'settings' ? 'overview' : 'settings'))}
            className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer ${
              activeTab === 'settings'
                ? 'bg-cyan-500/20 border-cyan-400/50 text-cyan-200 shadow-sm'
                : 'bg-white/[0.05] hover:bg-white/[0.1] border-white/15 text-slate-200'
            }`}
          >
            <Settings className="w-3.5 h-3.5 text-cyan-400" />
            Settings
          </button>

          <button
            type="button"
            onClick={onBack}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-400 to-emerald-400 hover:brightness-110 text-slate-950 text-xs font-extrabold transition-all shadow-sm cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            New Security Audit
          </button>
        </div>
      </div>

      {activeTab === 'settings' ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Settings Navigation */}
          <div className="lg:col-span-4 glass-panel rounded-3xl p-4 border border-white/15 space-y-1.5">
            <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-[0.18em] text-slate-500 font-bold">
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
                accent: 'text-amber-300',
              },
              {
                id: 'contact' as SettingsSection,
                label: 'Contact Us',
                sub: 'Support email & direct message',
                icon: Mail,
                accent: 'text-purple-400',
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
                  className={`w-full text-left flex items-start gap-3 p-3 rounded-2xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-cyan-500/15 border-cyan-400/40'
                      : 'bg-transparent border-transparent hover:bg-white/[0.04] hover:border-white/10'
                  }`}
                >
                  <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${item.accent}`} />
                  <div className="min-w-0">
                    <div className="text-xs font-bold text-white">{item.label}</div>
                    <div className="text-[11px] text-slate-400 leading-snug">{item.sub}</div>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Right Settings Content Pane */}
          <div className="lg:col-span-8 glass-panel rounded-3xl p-6 sm:p-7 border border-white/15 space-y-5">
            {(settingsSection === 'privacy' || settingsSection === 'terms' || settingsSection === 'refund') &&
              (() => {
                const doc = LEGAL_DOCS_BY_ID[settingsSection];
                const style = LEGAL_SETTING_STYLE[settingsSection];
                const DocIcon = style.icon;
                return (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-4">
                      <div>
                        <h2 className="text-lg font-black text-white flex items-center gap-2">
                          <DocIcon className={`w-5 h-5 ${style.iconClass}`} />
                          {doc.title}
                        </h2>
                        <p className="text-xs text-slate-400 mt-1">
                          Effective {doc.effectiveDate} • {doc.subtitle}
                        </p>
                      </div>
                      <span
                        className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-bold border shrink-0 ${style.badgeClass}`}
                      >
                        {doc.badge}
                      </span>
                    </div>

                    <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
                      {doc.sections.map((sec) => (
                        <div key={sec.title} className="p-4 rounded-2xl bg-[#050811]/75 border border-white/10 space-y-1.5">
                          <h3 className="text-xs font-extrabold text-white">{sec.title}</h3>
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
                  <h2 className="text-lg font-black text-white flex items-center gap-2">
                    <Mail className="w-5 h-5 text-purple-400" />
                    Contact Us &amp; Security Support
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
                      className="p-3.5 rounded-2xl bg-[#050811]/75 border border-white/10 space-y-2"
                    >
                      <div className="text-[11px] font-semibold text-slate-400">{desk.label}</div>
                      <div className="flex items-center justify-between gap-2">
                        <a
                          href={`mailto:${desk.email}`}
                          className="text-xs font-mono font-bold text-cyan-300 hover:underline truncate"
                        >
                          {desk.email}
                        </a>
                        <button
                          type="button"
                          onClick={() => handleCopyEmail(desk.email)}
                          className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-[11px] font-semibold text-slate-200 inline-flex items-center gap-1 shrink-0 cursor-pointer"
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

                {/* 3-Box Contact Inquiry Form (Name, Email, Topic + Send Message) */}
                <div className="pt-1">
                  <ContactUsForm defaultName={user.name} defaultEmail={user.email} />
                </div>
              </div>
            )}

            {settingsSection === 'preferences' && (
              <div className="space-y-5">
                <div className="border-b border-white/10 pb-4">
                  <h2 className="text-lg font-black text-white flex items-center gap-2">
                    <Settings className="w-5 h-5 text-amber-400" />
                    Workspace Appearance &amp; Session
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Customize visual theme and manage your active signed-in session.
                  </p>
                </div>

                {onToggleTheme && (
                  <div className="p-4 rounded-2xl bg-[#050811]/75 border border-white/10 flex items-center justify-between gap-3">
                    <div>
                      <div className="text-xs font-bold text-white">Interface Theme</div>
                      <div className="text-[11px] text-slate-400">
                        Currently using {theme === 'dark' ? 'Dark Cyber' : 'Clean Light'} theme
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={onToggleTheme}
                      className="px-3.5 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/15 text-xs font-bold text-white inline-flex items-center gap-2 cursor-pointer"
                    >
                      {theme === 'dark' ? (
                        <>
                          <Sun className="w-3.5 h-3.5 text-amber-300" />
                          Switch to Light Mode
                        </>
                      ) : (
                        <>
                          <Moon className="w-3.5 h-3.5 text-indigo-600" />
                          Switch to Dark Mode
                        </>
                      )}
                    </button>
                  </div>
                )}

                <div className="p-4 rounded-2xl bg-[#050811]/75 border border-white/10 flex items-center justify-between gap-3">
                  <div>
                    <div className="text-xs font-bold text-white">Signed-In Account</div>
                    <div className="text-[11px] text-slate-400">{user.email}</div>
                  </div>
                  <button
                    type="button"
                    onClick={onLogout}
                    className="px-4 py-2 rounded-xl bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/35 text-rose-200 text-xs font-bold inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    Sign Out
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      ) : (
        /* Main Two-Column SaaS Account Dashboard */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Profile Identity, Plan & Quota, Session */}
        <div className="lg:col-span-5 space-y-5">
          {/* Identity Card */}
          <div className="glass-panel rounded-3xl p-6 border border-white/15 space-y-5">
            <div className="flex items-center gap-4">
              {user.avatarUrl ? (
                <img
                  src={user.avatarUrl}
                  alt={user.name}
                  referrerPolicy="no-referrer"
                  className="w-16 h-16 rounded-2xl border border-cyan-400/40 object-cover shrink-0 shadow-lg"
                />
              ) : (
                <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-400/25 to-purple-500/25 border border-cyan-400/35 flex items-center justify-center text-white font-black text-xl shrink-0">
                  {user.name.slice(0, 2).toUpperCase()}
                </div>
              )}

              <div className="min-w-0 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <h1 className="text-xl font-black text-white truncate">{user.name}</h1>
                  <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono uppercase tracking-wider font-bold bg-cyan-500/15 border border-cyan-400/35 text-cyan-300">
                    {user.plan}
                  </span>
                </div>
                <p className="text-xs text-slate-400 truncate">{user.email}</p>
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-white/[0.04] border border-white/10 text-[10px] font-semibold text-slate-300">
                    <ShieldCheck className="w-3 h-3 text-emerald-400" />
                    {user.authProvider === 'google' ? 'Google OAuth' : 'Email & Password'}
                  </span>
                  <span className="text-[11px] text-slate-500">
                    Joined {new Date(user.createdAt).toLocaleDateString()}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Plan & Monthly App Slot Quota Card */}
          <div className="glass-panel rounded-3xl p-6 border border-white/15 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <Crown className="w-4 h-4 text-amber-400" />
                <span>Monthly App &amp; Website Slots</span>
              </div>
              <span className="text-xs font-mono text-slate-300">
                {appsUsed} / {appLimit} unique targets this month
              </span>
            </div>

            <div className="h-2.5 rounded-full bg-white/5 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyan-400 via-indigo-400 to-emerald-400 transition-all duration-500"
                style={{ width: `${quotaPct}%` }}
              />
            </div>

            <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
              <span className="px-2 py-0.5 rounded-md bg-white/[0.04] border border-white/10 text-cyan-300 font-bold">
                {planPolicy.maxRescansPerTarget === null
                  ? 'Unlimited Re-scans on tracked apps'
                  : `Max ${planPolicy.maxRescansPerTarget} scans per app`}
              </span>
              <span className="px-2 py-0.5 rounded-md bg-white/[0.04] border border-white/10 text-slate-300">
                Max APK: {planPolicy.maxApkMb} MB
              </span>
              {planPolicy.priorityQueue && (
                <span className="px-2 py-0.5 rounded-md bg-purple-500/15 border border-purple-400/30 text-purple-200 font-bold">
                  Priority Queue
                </span>
              )}
            </div>

            {Array.isArray(user.monthlyTargets) && user.monthlyTargets.length > 0 && (
              <div className="flex flex-wrap gap-1.5 pt-0.5">
                {user.monthlyTargets.slice(0, 6).map((item) => (
                  <span
                    key={item.target}
                    className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-[#050811]/70 border border-white/10 text-[10px] font-mono text-slate-300"
                  >
                    <span className="truncate max-w-[140px]">{item.target.replace(/^(apk|web):/, '')}</span>
                    <span className="text-cyan-300 font-bold">{item.count}x</span>
                  </span>
                ))}
              </div>
            )}

            <div className="space-y-2 pt-1">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[11px] font-semibold text-slate-400">
                  Switch Public Beta Tier
                </span>
                {onOpenPricingPage && (
                  <button
                    type="button"
                    onClick={onOpenPricingPage}
                    className="text-[11px] font-bold text-cyan-300 hover:underline cursor-pointer"
                  >
                    Compare All Plans →
                  </button>
                )}
              </div>
              <div className="grid grid-cols-3 gap-2">
                {(['free', 'pro', 'agency'] as AccountPlan[]).map((tier) => (
                  <button
                    key={tier}
                    type="button"
                    disabled={busyPlan !== null}
                    onClick={() => handlePlanChange(tier)}
                    className={`py-2 px-3 rounded-xl text-xs font-bold uppercase tracking-wider border transition-all cursor-pointer ${
                      user.plan === tier
                        ? 'bg-cyan-500/20 border-cyan-400/55 text-cyan-200 shadow-sm'
                        : 'bg-white/[0.03] border-white/10 text-slate-400 hover:text-white hover:bg-white/10'
                    }`}
                  >
                    {busyPlan === tier ? '...' : tier}
                  </button>
                ))}
              </div>
            </div>

            <p className="text-[11px] text-slate-500 leading-relaxed">
              Public Beta: All plan tiers are previewable without billing charges while payment gateway integration is in staging.
            </p>
          </div>

          {/* Session Card */}
          <div className="glass-panel rounded-3xl p-5 border border-white/15 flex items-center justify-between gap-3">
            <div>
              <div className="text-xs font-bold text-white">Active Browser Session</div>
              <div className="text-[11px] text-slate-400">Signed with HttpOnly cookie</div>
            </div>
            <button
              type="button"
              onClick={onLogout}
              className="px-4 py-2 rounded-xl bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/35 text-rose-200 text-xs font-bold inline-flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign Out
            </button>
          </div>
        </div>

        {/* Right Column: Personal Workspace API Token & Saved Scan History */}
        <div className="lg:col-span-7 space-y-5">
          {/* CI/CD API Key (Strictly Team & Agency Exclusive) */}
          <div className="glass-panel rounded-3xl p-6 border border-white/15 space-y-3">
            <div className="flex items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <Key className="w-4 h-4 text-purple-400" />
                  Workspace CI/CD API Token
                  <span className="px-2 py-0.5 rounded-full text-[9px] font-mono uppercase font-bold bg-purple-500/15 border border-purple-400/30 text-purple-300">
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
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.1] border border-white/10 text-xs font-semibold text-slate-300 hover:text-cyan-300 transition-colors cursor-pointer shrink-0"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${rotatingToken ? 'animate-spin' : ''}`} />
                  Rotate
                </button>
              )}
            </div>

            {planPolicy.features.apiTokenAccess ? (
              <div className="flex flex-wrap sm:flex-nowrap items-center gap-2">
                <code className="flex-1 min-w-0 px-3.5 py-2.5 rounded-xl bg-black/60 border border-white/10 text-xs font-mono text-cyan-300 truncate">
                  {showToken
                    ? user.apiToken
                    : `${user.apiToken.slice(0, 13)}••••••••••••${user.apiToken.slice(-4)}`}
                </code>
                <button
                  type="button"
                  onClick={() => setShowToken((v) => !v)}
                  className="px-3.5 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-semibold text-slate-300 cursor-pointer"
                >
                  {showToken ? 'Hide' : 'Show'}
                </button>
                <button
                  type="button"
                  onClick={handleCopyToken}
                  className="px-3.5 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-semibold text-slate-200 inline-flex items-center gap-1.5 cursor-pointer"
                >
                  {tokenCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {tokenCopied ? 'Copied' : 'Copy'}
                </button>
              </div>
            ) : (
              <div className="p-3.5 rounded-2xl bg-[#050811]/75 border border-purple-500/25 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="text-[11px] text-slate-300 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-purple-400 shrink-0" />
                  <span>
                    Workspace API tokens &amp; CI/CD automation are exclusive to <strong className="text-white">Team &amp; Agency ($79/mo)</strong>.
                  </span>
                </div>
                <button
                  type="button"
                  disabled={busyPlan !== null}
                  onClick={() => handlePlanChange('agency')}
                  className="px-3 py-1.5 rounded-xl bg-purple-500/20 hover:bg-purple-500/30 border border-purple-400/40 text-purple-200 text-[11px] font-bold shrink-0 cursor-pointer"
                >
                  Preview Agency Tier
                </button>
              </div>
            )}
          </div>

          {/* Saved Scan History */}
          <div className="glass-panel rounded-3xl p-6 border border-white/15 space-y-4">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <History className="w-4 h-4 text-cyan-400" />
                Saved Scan History ({user.scansHistory.length})
              </h2>
              <span className="text-[11px] font-mono text-slate-500">Latest 20 stored</span>
            </div>

            {user.scansHistory.length === 0 ? (
              <div className="p-8 rounded-2xl bg-white/[0.02] border border-dashed border-white/15 text-center space-y-3">
                <p className="text-xs text-slate-400">
                  No saved scans yet. Run any APK or Web scan while signed in and your audit scores will appear here.
                </p>
                <button
                  type="button"
                  onClick={onBack}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-white/[0.06] hover:bg-white/[0.12] border border-white/15 text-xs font-bold text-white cursor-pointer"
                >
                  Start First Scan
                  <ArrowUpRight className="w-3.5 h-3.5 text-cyan-400" />
                </button>
              </div>
            ) : (
              <div className="space-y-2.5 max-h-[420px] overflow-y-auto pr-1">
                {user.scansHistory.map((item) => (
                  <div
                    key={item.id}
                    className="flex items-center justify-between gap-3 p-3.5 rounded-2xl bg-[#050811]/75 border border-white/10 hover:border-white/20 transition-colors"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div
                        className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 border ${
                          item.mode === 'apk'
                            ? 'bg-purple-500/15 border-purple-400/30 text-purple-300'
                            : 'bg-cyan-500/15 border-cyan-400/30 text-cyan-300'
                        }`}
                      >
                        {item.mode === 'apk' ? (
                          <Smartphone className="w-4 h-4" />
                        ) : (
                          <Globe className="w-4 h-4" />
                        )}
                      </div>
                      <div className="min-w-0">
                        <div className="text-xs font-bold text-white truncate">{item.target}</div>
                        <div className="text-[11px] text-slate-400">
                          {new Date(item.timestamp).toLocaleString()} • {item.criticalCount} critical
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2.5 shrink-0">
                      <span className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-xs font-black text-cyan-300">
                        {item.grade} ({item.score})
                      </span>
                      {item.mode === 'web' && (
                        <button
                          type="button"
                          onClick={() => {
                            onBack();
                            onRescanWeb(item.target);
                          }}
                          title="Re-scan this URL"
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/30 text-[11px] font-bold text-cyan-200 cursor-pointer"
                        >
                          Re-scan
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
        </div>
      )}
    </section>
  );
};

