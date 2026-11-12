import React, { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, Mail, MessageSquare, Send, User } from 'lucide-react';

interface ContactUsFormProps {
  defaultName?: string;
  defaultEmail?: string;
  compact?: boolean;
}

export const ContactUsForm: React.FC<ContactUsFormProps> = ({
  defaultName = '',
  defaultEmail = '',
  compact = false,
}) => {
  const [name, setName] = useState(defaultName);
  const [email, setEmail] = useState(defaultEmail);
  const [topic, setTopic] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sentInfo, setSentInfo] = useState<{
    id: string;
    email: string;
    to: string;
    emailDelivered: boolean;
  } | null>(null);

  useEffect(() => {
    if (defaultName && !name) setName(defaultName);
  }, [defaultName]);

  useEffect(() => {
    if (defaultEmail && !email) setEmail(defaultEmail);
  }, [defaultEmail]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSentInfo(null);

    if (name.trim().length < 2) {
      setError('Please enter your name (at least 2 characters).');
      return;
    }
    if (!email.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setError('Please enter a valid email address.');
      return;
    }
    if (topic.trim().length < 4) {
      setError('Please write your topic or message (at least 4 characters).');
      return;
    }

    setSending(true);
    try {
      const res = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          name: name.trim(),
          email: email.trim(),
          topic: topic.trim(),
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data?.error || 'Could not send message. Please try again.');
        return;
      }

      setSentInfo({
        id: data.id || 'received',
        email: email.trim(),
        to: data.to || 'checkmyapk.com@gmail.com',
        emailDelivered: Boolean(data.emailDelivered),
      });
      setTopic('');
    } catch {
      setError('Network error while sending message. Please try again.');
    } finally {
      setSending(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className={compact ? 'space-y-3' : 'space-y-3.5'}>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {/* Box 1: User Name */}
        <div className="space-y-1 text-left">
          <label className="text-[11px] font-bold text-slate-300 block">Your Name</label>
          <div className="relative">
            <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              required
              minLength={2}
              maxLength={80}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Enter your name"
              className="w-full pl-10 pr-3.5 py-2.5 rounded-xl bg-[#050811]/85 border border-white/10 focus:border-cyan-400/55 focus:outline-none text-xs sm:text-sm text-white placeholder-slate-500"
            />
          </div>
        </div>

        {/* Box 2: User Email */}
        <div className="space-y-1 text-left">
          <label className="text-[11px] font-bold text-slate-300 block">Email Address</label>
          <div className="relative">
            <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="email"
              required
              maxLength={120}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              className="w-full pl-10 pr-3.5 py-2.5 rounded-xl bg-[#050811]/85 border border-white/10 focus:border-cyan-400/55 focus:outline-none text-xs sm:text-sm text-white placeholder-slate-500"
            />
          </div>
        </div>
      </div>

      {/* Box 3: Topic / Message */}
      <div className="space-y-1 text-left">
        <label className="text-[11px] font-bold text-slate-300 block">Topic / Message</label>
        <div className="relative">
          <MessageSquare className="w-4 h-4 text-slate-500 absolute left-3.5 top-3 pointer-events-none" />
          <textarea
            rows={compact ? 3 : 4}
            required
            minLength={4}
            maxLength={2000}
            value={topic}
            onChange={(e) => setTopic(e.target.value)}
            placeholder="Write your topic, question, or issue here..."
            className="w-full pl-10 pr-3.5 py-2.5 rounded-xl bg-[#050811]/85 border border-white/10 focus:border-cyan-400/55 focus:outline-none text-xs sm:text-sm text-white placeholder-slate-500 resize-y"
          />
        </div>
      </div>

      {error && (
        <div className="p-2.5 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-200 text-xs font-semibold flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {sentInfo && (
        <div className="p-3 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-200 text-xs font-semibold flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
          <span>
            {sentInfo.emailDelivered ? (
              <>
                Email automatically sent to <strong>{sentInfo.to}</strong> (
                <code className="font-mono">{sentInfo.id}</code>)! We&apos;ll reply to{' '}
                <strong>{sentInfo.email}</strong> shortly.
              </>
            ) : typeof window !== 'undefined' &&
              (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') ? (
              <>
                Saved locally (<code className="font-mono">{sentInfo.id}</code>). Paste your 16-letter{' '}
                <code className="font-mono">GMAIL_APP_PASSWORD</code> in <code className="font-mono">.env</code>{' '}
                &amp; restart server to deliver live to <strong>{sentInfo.to}</strong>.
              </>
            ) : (
              <>
                Message received (<code className="font-mono">{sentInfo.id}</code>) for{' '}
                <strong>{sentInfo.to}</strong>! Our team will reply to <strong>{sentInfo.email}</strong> shortly.
              </>
            )}
          </span>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
        <span className="text-[11px] text-slate-500">
          Auto-routed to: <span className="font-mono text-slate-400">checkmyapk.com@gmail.com</span>
        </span>
        <button
          type="submit"
          disabled={sending}
          className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-emerald-400 hover:brightness-110 text-slate-950 font-black text-xs sm:text-sm inline-flex items-center gap-2 transition-all shadow-md cursor-pointer disabled:opacity-60"
        >
          <Send className="w-3.5 h-3.5" />
          <span>{sending ? 'Sending...' : 'Send Message'}</span>
        </button>
      </div>
    </form>
  );
};

