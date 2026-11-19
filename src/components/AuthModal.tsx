import React, { useState, useEffect } from 'react';
import {
  X,
  Lock,
  Mail,
  User,
  ArrowRight,
  ShieldCheck,
  AlertTriangle,
  ArrowLeft,
  FileText,
} from 'lucide-react';
import type { UserAccount } from '../types/account';
import { isFirebaseGoogleConfigured, signInWithGooglePopup } from '../lib/firebaseAuth';
import { LEGAL_DOCS_BY_ID, type LegalDocId } from '../data/legalDocs';

interface AuthModalProps {
  initialMode: 'login' | 'register';
  notice?: string | null;
  onClose: () => void;
  onSuccess: (user: UserAccount) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({
  initialMode,
  notice = null,
  onClose,
  onSuccess,
}) => {
  const [mode, setMode] = useState<'login' | 'register'>(initialMode);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [setupHint, setSetupHint] = useState<string | null>(null);
  const [acceptedPolicies, setAcceptedPolicies] = useState(false);
  const [viewingDoc, setViewingDoc] = useState<LegalDocId | null>(null);

  useEffect(() => {
    setMode(initialMode);
    setError(null);
    setSetupHint(null);
    setViewingDoc(null);
  }, [initialMode]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  const handleGoogleSignIn = async () => {
    setError(null);
    setSetupHint(null);

    if (!acceptedPolicies) {
      setError('Please check the Privacy Policy & Terms of Service agreement box to continue.');
      return;
    }

    if (!isFirebaseGoogleConfigured()) {
      setSetupHint(
        'Firebase Console is not connected yet. Paste VITE_FIREBASE_API_KEY, VITE_FIREBASE_AUTH_DOMAIN, VITE_FIREBASE_PROJECT_ID, and VITE_FIREBASE_APP_ID into .env and restart the server.'
      );
      return;
    }

    setGoogleLoading(true);
    try {
      const { idToken } = await signInWithGooglePopup();
      const res = await fetch('/api/auth/firebase-google', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ idToken }),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data?.user) {
        setError(data?.error || 'Google authentication failed on server.');
        return;
      }

      onSuccess(data.user as UserAccount);
    } catch (err: any) {
      const code = String(err?.code || '');
      if (code === 'auth/popup-closed-by-user' || code === 'auth/cancelled-popup-request') {
        setError('Google sign-in popup was closed before completing.');
      } else if (code === 'auth/unauthorized-domain') {
        setSetupHint(
          `Add "${window.location.hostname}" to Firebase Console -> Authentication -> Settings -> Authorized domains.`
        );
      } else if (code === 'auth/operation-not-allowed') {
        setSetupHint(
          'Enable Google provider in Firebase Console -> Authentication -> Sign-in method -> Google -> Enable.'
        );
      } else {
        setError(err?.message || 'Google Sign-In failed.');
      }
    } finally {
      setGoogleLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSetupHint(null);

    if (!acceptedPolicies) {
      setError('Please check the Privacy Policy & Terms of Service agreement box to continue.');
      return;
    }

    setSubmitting(true);

    try {
      const endpoint = mode === 'login' ? '/api/auth/login' : '/api/auth/register';
      const payload =
        mode === 'login'
          ? { email: email.trim(), password }
          : { name: name.trim(), email: email.trim(), password };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data?.user) {
        setError(data?.error || 'Authentication failed. Please check your details.');
        return;
      }

      onSuccess(data.user as UserAccount);
    } catch {
      setError('Network error while connecting to authentication service.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 no-print"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="wb-bezel p-1.5 rounded-2xl max-w-md w-full relative">
        {/* Subtle Top Emerald Light-Catch Hairline */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
        />

        <div className="wb-surface rounded-xl overflow-hidden text-left">
          {/* Top Chrome Header */}
          <div className="wb-ide-chrome px-5 py-4 border-b border-white/10 flex items-center justify-between gap-3">
            {viewingDoc ? (
              <div className="flex items-center gap-2.5 min-w-0">
                <button
                  type="button"
                  onClick={() => setViewingDoc(null)}
                  className="p-1.5 rounded-md wb-surface-muted hover:border-white/25 text-slate-300 hover:text-white transition-colors cursor-pointer shrink-0"
                  aria-label="Back to Sign In"
                >
                  <ArrowLeft className="w-4 h-4" />
                </button>
                <div className="min-w-0">
                  <span className="inline-flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-[0.14em] text-emerald-400 font-semibold">
                    <FileText className="w-3 h-3" />
                    Legal Agreement
                  </span>
                  <h3 className="text-sm font-display font-semibold text-white tracking-[-0.015em] truncate mt-0.5">
                    {viewingDoc === 'privacy'
                      ? 'Privacy Policy'
                      : viewingDoc === 'terms'
                      ? 'Terms of Service'
                      : 'Refund & Cancellation Policy'}
                  </h3>
                </div>
              </div>
            ) : (
              <div>
                <span className="inline-flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-[0.14em] text-emerald-400 font-semibold">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  CheckMyAPK Workspace
                </span>
                <h3 className="text-lg font-display font-semibold text-white tracking-[-0.025em] mt-0.5">
                  {mode === 'login' ? 'Sign in to run audit' : 'Create free account'}
                </h3>
              </div>
            )}
            <button
              type="button"
              onClick={onClose}
              aria-label="Close authentication modal"
              className="p-1.5 rounded-md wb-surface-muted hover:border-white/25 text-slate-400 hover:text-white transition-colors cursor-pointer shrink-0"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="p-5 sm:p-6 space-y-4">
            {viewingDoc ? (
              (() => {
                const activeDoc = LEGAL_DOCS_BY_ID[viewingDoc];
                return (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between gap-2 text-[11px] text-slate-400">
                      <span className="font-mono text-[10.5px]">Effective: {activeDoc.effectiveDate}</span>
                      <div className="inline-flex items-center gap-1 p-0.5 rounded-md wb-surface-muted font-mono text-[10px]">
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
                            onClick={() => setViewingDoc(tab.id)}
                            className={`px-2 py-0.5 rounded font-medium cursor-pointer transition-colors ${
                              viewingDoc === tab.id
                                ? 'bg-emerald-500/20 text-emerald-400 font-semibold'
                                : 'text-slate-400 hover:text-white'
                            }`}
                          >
                            {tab.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="max-h-[46vh] overflow-y-auto pr-1 space-y-2.5 text-xs text-slate-300 leading-relaxed">
                      <p className="text-[11px] text-slate-400">{activeDoc.subtitle}</p>
                      {activeDoc.sections.map((sec) => (
                        <div
                          key={sec.title}
                          className="p-3.5 rounded-lg wb-surface-muted space-y-1"
                        >
                          <div className="text-xs font-display font-semibold text-white">{sec.title}</div>
                          <p className="text-[11px] text-slate-300 leading-relaxed">{sec.body}</p>
                        </div>
                      ))}
                    </div>

                    <button
                      type="button"
                      onClick={() => {
                        setAcceptedPolicies(true);
                        setError(null);
                        setViewingDoc(null);
                      }}
                      className="wb-emerald-btn w-full h-10 rounded-md font-semibold text-xs cursor-pointer"
                    >
                      Accept Policy &amp; Return to Sign In
                    </button>
                  </div>
                );
              })()
            ) : (
              <>
                {notice && (
                  <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-medium flex items-start gap-2.5 leading-relaxed">
                    <Lock className="w-4 h-4 shrink-0 mt-0.5" />
                    <span>{notice}</span>
                  </div>
                )}

                {/* Segmented Mode Switcher */}
                <div className="flex items-center p-1 wb-surface-muted rounded-md">
                  <button
                    type="button"
                    onClick={() => {
                      setMode('login');
                      setError(null);
                    }}
                    className={`flex-1 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer ${
                      mode === 'login'
                        ? 'bg-white/15 text-white font-semibold'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Sign In
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setMode('register');
                      setError(null);
                    }}
                    className={`flex-1 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer ${
                      mode === 'register'
                        ? 'bg-emerald-500/20 text-emerald-400 font-semibold'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Create Account
                  </button>
                </div>

                <form onSubmit={handleSubmit} className="space-y-3.5">
                  {mode === 'register' && (
                    <div className="space-y-1">
                      <label className="text-[11px] font-medium text-slate-300 block">Full Name</label>
                      <div className="relative">
                        <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                        <input
                          type="text"
                          required
                          minLength={2}
                          maxLength={60}
                          value={name}
                          onChange={(e) => setName(e.target.value)}
                          placeholder="Alex Sharma"
                          className="w-full pl-10 pr-4 h-10 rounded-md wb-surface-muted focus:border-emerald-500/60 focus:outline-none text-xs sm:text-sm text-white placeholder-slate-500"
                        />
                      </div>
                    </div>
                  )}

                  <div className="space-y-1">
                    <label className="text-[11px] font-medium text-slate-300 block">Work or Personal Email</label>
                    <div className="relative">
                      <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                      <input
                        type="email"
                        required
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="you@company.com"
                        className="w-full pl-10 pr-4 h-10 rounded-md wb-surface-muted focus:border-emerald-500/60 focus:outline-none text-xs sm:text-sm text-white placeholder-slate-500"
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] font-medium text-slate-300 block">Password</label>
                    <div className="relative">
                      <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                      <input
                        type="password"
                        required
                        minLength={8}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Minimum 8 characters"
                        className="w-full pl-10 pr-4 h-10 rounded-md wb-surface-muted focus:border-emerald-500/60 focus:outline-none text-xs sm:text-sm text-white placeholder-slate-500"
                      />
                    </div>
                  </div>

                  {error && (
                    <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-medium flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span>{error}</span>
                    </div>
                  )}

                  {/* Mandatory Privacy Policy & Terms of Service Check */}
                  <label className="flex items-start gap-2.5 p-3 rounded-lg wb-surface-muted hover:border-emerald-500/35 transition-colors cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={acceptedPolicies}
                      onChange={(e) => {
                        setAcceptedPolicies(e.target.checked);
                        if (e.target.checked) setError(null);
                      }}
                      className="mt-0.5 w-4 h-4 rounded accent-emerald-500 shrink-0 cursor-pointer"
                    />
                    <span className="text-[11px] text-slate-300 leading-relaxed">
                      I agree to CheckMyAPK&apos;s{' '}
                      <button
                        type="button"
                        onClick={(e) => {
                          e.preventDefault();
                          setViewingDoc('privacy');
                        }}
                        className="text-emerald-400 hover:underline font-medium cursor-pointer"
                      >
                        Privacy Policy
                      </button>
                      ,{' '}
                      <button
                        type="button"
                        onClick={(e) => {
                          e.preventDefault();
                          setViewingDoc('terms');
                        }}
                        className="text-emerald-400 hover:underline font-medium cursor-pointer"
                      >
                        Terms of Service
                      </button>
                      , and{' '}
                      <button
                        type="button"
                        onClick={(e) => {
                          e.preventDefault();
                          setViewingDoc('refund');
                        }}
                        className="text-emerald-400 hover:underline font-medium cursor-pointer"
                      >
                        Refund Policy
                      </button>
                      .
                    </span>
                  </label>

                  <button
                    type="submit"
                    disabled={submitting || googleLoading}
                    className="wb-emerald-btn w-full h-10 rounded-md font-semibold text-xs sm:text-[13px] flex items-center justify-center gap-2 transition-colors cursor-pointer disabled:opacity-60"
                  >
                    <span>
                      {submitting
                        ? 'Authenticating...'
                        : mode === 'login'
                        ? 'Sign In'
                        : 'Create Free Account'}
                    </span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </form>

                <div className="relative flex items-center justify-center py-0.5">
                  <div className="border-t border-white/10 w-full" />
                  <span className="px-3 text-[10px] font-mono uppercase tracking-[0.14em] text-slate-500 whitespace-nowrap">
                    or continue with
                  </span>
                  <div className="border-t border-white/10 w-full" />
                </div>

                {/* Official Google Sign-In Button */}
                <button
                  type="button"
                  onClick={handleGoogleSignIn}
                  disabled={googleLoading || submitting}
                  className="wb-primary-btn w-full h-10 px-4 rounded-md font-semibold text-xs sm:text-[13px] flex items-center justify-center gap-2.5 transition-colors cursor-pointer disabled:opacity-60"
                >
                  <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24" aria-hidden="true">
                    <path
                      fill="#4285F4"
                      d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z"
                    />
                    <path
                      fill="#34A853"
                      d="M12 24c3.3 0 6.08-1.09 8.1-2.96l-3.88-3.05c-1.09.73-2.49 1.16-4.22 1.16-3.24 0-5.99-2.19-6.97-5.14H1.03v3.14C3.04 21.14 7.21 24 12 24z"
                    />
                    <path
                      fill="#FBBC05"
                      d="M5.03 14.01c-.25-.73-.39-1.52-.39-2.33s.14-1.6.39-2.33V6.21H1.03C.37 7.53 0 9.02 0 11.68s.37 4.15 1.03 5.47l4-3.14z"
                    />
                    <path
                      fill="#EA4335"
                      d="M12 4.75c1.79 0 3.4.62 4.67 1.83l3.5-3.5C18.07 1.19 15.3 0 12 0 7.21 0 3.04 2.86 1.03 7.01l4 3.14c.98-2.95 3.73-5.4 6.97-5.4z"
                    />
                  </svg>
                  <span>{googleLoading ? 'Connecting to Google...' : 'Continue with Google'}</span>
                </button>

                {setupHint && (
                  <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[11px] leading-relaxed">
                    {setupHint}
                  </div>
                )}

                <p className="font-mono text-[10px] text-slate-500 text-center leading-relaxed">
                  Secured via Firebase OAuth &amp; signed <code className="text-slate-400">HttpOnly</code> session cookies
                </p>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
