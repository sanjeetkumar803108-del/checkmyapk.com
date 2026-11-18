import React, { useEffect, useRef, useState } from 'react';
import { Activity, Globe, Radio, Smartphone } from 'lucide-react';

interface LiveScanStats {
  totalScans: number;
  apkScans: number;
  webScans: number;
  lastScanAt: string | null;
  lastScanMode: 'apk' | 'web' | null;
}

function formatRelativeTime(iso: string | null, nowMs: number): string {
  if (!iso) return 'Awaiting first scan';
  const parsed = Date.parse(iso);
  if (Number.isNaN(parsed)) return 'Recently';
  const diffSec = Math.max(0, Math.floor((nowMs - parsed) / 1000));
  if (diffSec < 15) return 'Just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDays = Math.floor(diffHr / 24);
  return `${diffDays}d ago`;
}

export const LiveScanTelemetryBar: React.FC = () => {
  const [stats, setStats] = useState<LiveScanStats | null>(null);
  const [streamLive, setStreamLive] = useState(false);
  const [recentPulse, setRecentPulse] = useState<'apk' | 'web' | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const prevTotalRef = useRef<number | null>(null);
  const pulseTimerRef = useRef<number | null>(null);

  useEffect(() => {
    let active = true;
    let pollTimer: number | null = null;
    let es: EventSource | null = null;

    const applySnapshot = (next: LiveScanStats) => {
      if (!active) return;
      if (
        prevTotalRef.current !== null &&
        next.totalScans > prevTotalRef.current
      ) {
        setRecentPulse(next.lastScanMode || 'web');
        if (pulseTimerRef.current) window.clearTimeout(pulseTimerRef.current);
        pulseTimerRef.current = window.setTimeout(() => {
          setRecentPulse(null);
        }, 3500);
      }
      prevTotalRef.current = next.totalScans;
      setStats(next);
      setNowMs(Date.now());
    };

    const fetchOnce = async () => {
      try {
        const res = await fetch('/api/stats/scans', { cache: 'no-store' });
        if (!res.ok) return;
        const data = (await res.json()) as LiveScanStats;
        if (typeof data?.totalScans === 'number') {
          applySnapshot(data);
        }
      } catch {
        // Ignore transient network hiccups
      }
    };

    fetchOnce();

    if (typeof window !== 'undefined' && 'EventSource' in window) {
      try {
        es = new EventSource('/api/stats/scans/stream');
        es.onopen = () => {
          if (active) setStreamLive(true);
        };
        es.onmessage = (event) => {
          try {
            const parsed = JSON.parse(event.data) as LiveScanStats;
            if (typeof parsed?.totalScans === 'number') {
              applySnapshot(parsed);
            }
          } catch {
            // Ignore malformed SSE payload
          }
        };
        es.onerror = () => {
          if (active) setStreamLive(false);
        };
      } catch {
        setStreamLive(false);
      }
    }

    // Fallback sync every 25s + refresh relative timestamp every 30s
    pollTimer = window.setInterval(() => {
      setNowMs(Date.now());
      if (!es || es.readyState !== EventSource.OPEN) {
        fetchOnce();
      }
    }, 25000);

    return () => {
      active = false;
      if (es) es.close();
      if (pollTimer) window.clearInterval(pollTimer);
      if (pulseTimerRef.current) window.clearTimeout(pulseTimerRef.current);
    };
  }, []);

  const total = stats?.totalScans ?? 0;
  const apkCount = stats?.apkScans ?? 0;
  const webCount = stats?.webScans ?? 0;
  const apkPct = total > 0 ? Math.round((apkCount / total) * 100) : 0;
  const webPct = total > 0 ? Math.round((webCount / total) * 100) : 0;
  const loaded = stats !== null;

  return (
    <section aria-label="Live Scan Telemetry" className="space-y-3">
      <div className="wb-bezel p-1.5 rounded-2xl relative">
        {/* Subtle Top Emerald Light-Catch Hairline */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
        />

        <div className="wb-surface rounded-xl overflow-hidden text-left">
          {/* Top Slim Telemetry Strip */}
          <div className="wb-ide-chrome px-5 py-2.5 border-b border-white/10 flex flex-wrap items-center justify-between gap-2.5">
            <div className="flex items-center gap-2.5">
              <span className="relative flex h-2 w-2 shrink-0" aria-hidden="true">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
              </span>
              <span className="font-mono text-[10.5px] uppercase tracking-[0.14em] text-emerald-400 font-semibold">
                Live Audit Counter
              </span>
              <span className="hidden sm:inline font-mono text-[10px] text-slate-500">
                · Real verified scans recorded by server
              </span>
            </div>

            <div className="flex items-center gap-3 font-mono text-[10px] text-slate-400">
              <span className="inline-flex items-center gap-1.5">
                <Radio className={`w-3 h-3 ${streamLive ? 'text-emerald-400' : 'text-slate-500'}`} />
                <span className={streamLive ? 'text-emerald-400 font-semibold' : 'text-slate-400'}>
                  {streamLive ? 'Live Stream' : 'Synced'}
                </span>
              </span>
              <span className="text-slate-500">·</span>
              <span>
                Last scan:{' '}
                <strong className="text-slate-300 font-medium">
                  {loaded ? formatRelativeTime(stats.lastScanAt, nowMs) : '...'}
                </strong>
              </span>
            </div>
          </div>

          {/* 3 Real-Time Metric Columns */}
          <div className="grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-white/10">
            {/* Total Audits */}
            <div className="p-5 flex flex-col justify-between gap-3">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-white/[0.05] border border-white/10 flex items-center justify-center shrink-0">
                    <Activity className="w-4 h-4 text-emerald-400" />
                  </div>
                  <span className="text-xs font-medium text-slate-400">Total Audits Run</span>
                </div>
                {recentPulse && (
                  <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/35 text-emerald-400 animate-pulse">
                    +1 live
                  </span>
                )}
              </div>

              <div className="space-y-1">
                <div className="font-display tabular-nums text-3xl sm:text-[34px] font-semibold tracking-[-0.035em] text-white leading-none">
                  {loaded ? total.toLocaleString() : '—'}
                </div>
                <p className="font-mono text-[10.5px] text-slate-500">
                  Combined APK + Website URL audits
                </p>
              </div>
            </div>

            {/* Android APK Audits */}
            <div className="p-5 flex flex-col justify-between gap-3">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center shrink-0">
                    <Smartphone className="w-4 h-4 text-emerald-400" />
                  </div>
                  <span className="text-xs font-medium text-slate-400">Android APKs Scanned</span>
                </div>
                {recentPulse === 'apk' ? (
                  <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/35 text-emerald-400 animate-pulse">
                    +1 APK
                  </span>
                ) : (
                  <span className="font-mono text-[10px] text-emerald-400 tabular-nums">
                    {loaded ? `${apkPct}%` : '—'}
                  </span>
                )}
              </div>

              <div className="space-y-2">
                <div className="font-display tabular-nums text-3xl sm:text-[34px] font-semibold tracking-[-0.035em] text-white leading-none">
                  {loaded ? apkCount.toLocaleString() : '—'}
                </div>
                <div className="h-1 w-full rounded-full bg-white/[0.06] overflow-hidden">
                  <div
                    className="h-full rounded-full bg-emerald-400 transition-all duration-500"
                    style={{ width: `${apkPct}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Website URL Audits */}
            <div className="p-5 flex flex-col justify-between gap-3">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/25 flex items-center justify-center shrink-0">
                    <Globe className="w-4 h-4 text-cyan-400" />
                  </div>
                  <span className="text-xs font-medium text-slate-400">Website URLs Scanned</span>
                </div>
                {recentPulse === 'web' ? (
                  <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded bg-cyan-500/15 border border-cyan-500/35 text-cyan-400 animate-pulse">
                    +1 URL
                  </span>
                ) : (
                  <span className="font-mono text-[10px] text-cyan-400 tabular-nums">
                    {loaded ? `${webPct}%` : '—'}
                  </span>
                )}
              </div>

              <div className="space-y-2">
                <div className="font-display tabular-nums text-3xl sm:text-[34px] font-semibold tracking-[-0.035em] text-white leading-none">
                  {loaded ? webCount.toLocaleString() : '—'}
                </div>
                <div className="h-1 w-full rounded-full bg-white/[0.06] overflow-hidden">
                  <div
                    className="h-full rounded-full bg-cyan-400 transition-all duration-500"
                    style={{ width: `${webPct}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
