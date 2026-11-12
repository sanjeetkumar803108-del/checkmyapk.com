import React, { useState, useEffect } from 'react';
import { X, Lock, Mail, User, ArrowRight, ShieldCheck, AlertTriangle, ArrowLeft, FileText } from 'lucide-react';
import type { UserAccount } from '../types/account';
import { isFirebaseGoogleConfigured, signInWithGooglePopup } from '../lib/firebaseAuth';
import { LEGAL_DOCS_BY_ID, type LegalDocId } from '../data/legalDocs';

interface AuthModalProps {
  initialMode: 'login' | 'register';
  onClose: () => void;
  onSuccess: (user: UserAccount) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ initialMode, onClose, onSuccess }) => {
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
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error || 'Could not verify Google sign-in.');
        return;
      }
      onSuccess(data.user);
      onClose();
    } catch (err: any) {
      const code = String(err?.code || '');
      if (code === 'auth/popup-closed-by-user' || code === 'auth/cancelled-popup-request') {
        return;
      }
      if (code === 'auth/unauthorized-domain') {
        setError(
          `Add "${window.location.hostname}" to Firebase Console -> Authentication -> Settings -> Authorized domains.`
        );
        return;
      }
      if (code === 'auth/popup-blocked') {
        setError('Browser blocked the Google sign-in popup. Please allow popups for this site.');
        return;
      }
      setError(err?.message || 'Google Sign-In failed. Please try again.');
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
      const endpoint = mode === 'register' ? '/api/auth/register' : '/api/auth/login';
      const body =
        mode === 'register' ? { name, email, password } : { email, password };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error || 'Authentication failed.');
        setSubmitting(false);
        return;
      }
      onSuccess(data.user);
      onClose();
    } catch {
      setError('Could not reach server. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[110] bg-black/80 backdrop-blur-md flex items-center justify-center p-4 no-print">
      <div className="w-full max-w-md glass-panel rounded-3xl p-6 sm:p-7 border border-white/15 shadow-2xl space-y-5 relative overflow-y-auto max-h-[92vh]">
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-400/60 to-transparent"
          aria-hidden="true"
        />

        <div className="flex items-start justify-between gap-3">
          {viewingDoc ? (
            <div className="flex items-center gap-2.5">
              <button
                type="button"
                onClick={() => setViewingDoc(null)}
                className="p-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white transition-colors cursor-pointer"
                aria-label="Back to Sign In"
              >
                <ArrowLeft className="w-4 h-4" />
              </button>
              <div>
                <span className="inline-flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-[0.16em] text-cyan-300/90 font-semibold">
                  <FileText className="w-3.5 h-3.5" />
                  Legal Agreement
                </span>
                <h3 className="text-base font-black text-white tracking-tight mt-0.5">
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
              <span className="inline-flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-[0.16em] text-cyan-300/90 font-semibold">
                <ShieldCheck className="w-3.5 h-3.5" />
                CheckMyAPK Account
              </span>
              <h3 className="text-xl font-black text-white tracking-tight mt-1">
                {mode === 'login' ? 'Sign In to Workspace' : 'Create Free Account'}
              </h3>
            </div>
          )}
          <button
            type="button"
            onClick={onClose}
            aria-label="Close authentication modal"
            className="p-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {viewingDoc ? (
          (() => {
            const activeDoc = LEGAL_DOCS_BY_ID[viewingDoc];
            return (
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-2 text-[11px] text-slate-400">
                  <span>Effective: {activeDoc.effectiveDate}</span>
                  <div className="inline-flex items-center gap-1 p-0.5 rounded-lg bg-white/5 border border-white/10">
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
                        className={`px-2 py-0.5 rounded-md font-bold cursor-pointer ${
                          viewingDoc === tab.id ? 'bg-cyan-500/20 text-cyan-200' : 'text-slate-400'
                        }`}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="max-h-72 overflow-y-auto pr-1 space-y-2.5 text-xs text-slate-300 leading-relaxed">
                  {activeDoc.sections.map((sec) => (
                    <div
                      key={sec.title}
                      className="p-3 rounded-xl bg-[#050811]/80 border border-white/10 space-y-1"
                    >
                      <h4 className="font-bold text-white">{sec.title}</h4>
                      <p className="text-[11px] text-slate-300">{sec.body}</p>
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
                  className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-emerald-400 hover:brightness-110 text-slate-950 font-black text-xs cursor-pointer"
                >
                  Accept Policy &amp; Return to Sign In
                </button>
              </div>
            );
          })()
        ) : (
          <>
        {/* Mode Switcher */}
        <div className="flex items-center p-1 bg-[#050811]/90 border border-white/10 rounded-xl">
          <button
            type="button"
            onClick={() => {
              setMode('login');
              setError(null);
            }}
            className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all cursor-pointer ${
              mode === 'login'
                ? 'bg-white/10 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
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
            className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all cursor-pointer ${
              mode === 'register'
                ? 'bg-gradient-to-r from-cyan-500/20 to-purple-500/20 border border-cyan-400/25 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Create Account
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3.5">
          {mode === 'register' && (
            <div className="space-y-1">
              <label className="text-[11px] font-bold text-slate-300 block">Full Name</label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  required
                  minLength={2}
                  maxLength={60}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Alex Sharma"
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[#050811]/90 border border-white/10 focus:border-cyan-400/50 focus:outline-none text-sm text-white placeholder-slate-600"
                />
              </div>
            </div>
          )}

          <div className="space-y-1">
            <label className="text-[11px] font-bold text-slate-300 block">Work or Personal Email</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[#050811]/90 border border-white/10 focus:border-cyan-400/50 focus:outline-none text-sm text-white placeholder-slate-600"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-bold text-slate-300 block">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Minimum 8 characters"
                className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[#050811]/90 border border-white/10 focus:border-cyan-400/50 focus:outline-none text-sm text-white placeholder-slate-600"
              />
            </div>
          </div>

          {error && (
            <div className="p-3 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-200 text-xs font-semibold flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{error}</span>
            </div>
          )}

          {/* Mandatory Privacy Policy & Terms of Service Check */}
          <label className="flex items-start gap-2.5 p-3 rounded-xl bg-[#050811]/75 border border-white/10 hover:border-cyan-400/35 transition-colors cursor-pointer select-none">
            <input
              type="checkbox"
              checked={acceptedPolicies}
              onChange={(e) => {
                setAcceptedPolicies(e.target.checked);
                if (e.target.checked) setError(null);
              }}
              className="mt-0.5 w-4 h-4 rounded accent-cyan-400 shrink-0 cursor-pointer"
            />
            <span className="text-[11px] text-slate-300 leading-relaxed">
              I agree to CheckMyAPK&apos;s{' '}
              <button
                type="button"
                onClick={(e) => {
                  e.preventDefault();
                  setViewingDoc('privacy');
                }}
                className="text-cyan-300 hover:underline font-bold cursor-pointer"
              >
                Privacy Policy
              </button>{' '}
              and{' '}
              <button
                type="button"
                onClick={(e) => {
                  e.preventDefault();
                  setViewingDoc('terms');
                }}
                className="text-cyan-300 hover:underline font-bold cursor-pointer"
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
                className="text-cyan-300 hover:underline font-bold cursor-pointer"
              >
                Refund Policy
              </button>{' '}
              (including Authorized Security Testing rules).
            </span>
          </label>

          <button
            type="submit"
            disabled={submitting || googleLoading}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-400 to-emerald-400 hover:from-cyan-300 hover:to-emerald-300 text-slate-950 font-black text-sm flex items-center justify-center gap-2 transition-all cursor-pointer disabled:opacity-60 shadow-lg"
          >
            <span>
              {submitting
                ? 'Authenticating...'
                : mode === 'login'
                ? 'Sign In'
                : 'Create Free Account'}
            </span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        <div className="relative flex items-center justify-center">
          <div className="border-t border-white/10 w-full" />
          <span className="px-3 text-[10px] font-mono uppercase tracking-[0.16em] text-slate-500 bg-[#0b101d] whitespace-nowrap">
            or continue with
          </span>
          <div className="border-t border-white/10 w-full" />
        </div>

        {/* Official Google Sign-In Button */}
        <button
          type="button"
          onClick={handleGoogleSignIn}
          disabled={googleLoading || submitting}
          className="w-full py-2.5 px-4 rounded-xl bg-white hover:bg-slate-100 text-slate-900 font-bold text-sm flex items-center justify-center gap-2.5 shadow-md transition-all cursor-pointer disabled:opacity-60"
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
          <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-400/30 text-amber-200 text-[11px] leading-relaxed">
            {setupHint}
          </div>
        )}

        <p className="text-[11px] text-slate-500 text-center leading-relaxed">
          Secured with Firebase OAuth verification &amp; signed <code className="text-slate-400">HttpOnly</code> sessions.
        </p>
          </>
        )}
      </div>
    </div>
  );
};
