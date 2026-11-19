import React, { useEffect, useRef, useState } from 'react';
import { Terminal, Check } from 'lucide-react';

interface TerminalProps {
  targetUrl: string;
  isApkMode?: boolean;
}

const BRAILLE_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

const WEB_LOG_MESSAGES = [
  'Initializing CheckMyAPK Phase-1 Deep Audit suite...',
  'Resolving target DNS and verifying SSL/TLS certificate chain...',
  'Crawling HTML DOM tree, multi-route paths & extracting JS bundles...',
  'Mapping robots.txt, sitemap.xml, OpenAPI, GraphQL & Actuator endpoints...',
  'Running Regex Secret Hunter, S3/GCS Cloud Bucket ACLs & DOM XSS sinks...',
  'Querying Google OSV.dev CVE database & JWT/Cookie security claims...',
  'Auditing HTTP headers, CORS reflection & Verified Active DAST checks...',
  'Testing Firebase / Supabase ACLs & Denial-of-Wallet rate limits...',
  'Correlating compound attack chains with Gemini Neural Engine...',
];

const APK_LOG_MESSAGES = [
  'Unpacking Android APK / AAB container in volatile memory sandbox...',
  'Parsing Binary/Protobuf AndroidManifest.xml & exported IPC components...',
  'Auditing debuggable flags, cleartext rules, allowBackup & App Links...',
  'Disassembling classes*.dex for secrets, BiometricPrompt, FLAG_SECURE & taint flows...',
  'Fingerprinting native ELF (.so) mitigations, trackers & Maven dependencies...',
  'Stage 3: Querying Google OSV.dev CVEs & probing Cloud Storage bucket ACLs...',
  'Active Probe: Verifying extracted APIs, Firebase/Supabase & assetlinks.json...',
  'Correlating compound mobile attack chains & OWASP MASVS v2 verdict...',
];

export const LiveTerminalLogs: React.FC<TerminalProps> = ({ targetUrl, isApkMode = false }) => {
  const [logs, setLogs] = useState<string[]>([]);
  const [brailleIdx, setBrailleIdx] = useState(0);
  const [elapsedMs, setElapsedMs] = useState(0);
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);
  const activeMessages = isApkMode ? APK_LOG_MESSAGES : WEB_LOG_MESSAGES;

  useEffect(() => {
    const start = Date.now();
    setElapsedMs(0);
    const brailleTimer = setInterval(() => {
      setBrailleIdx((prev) => (prev + 1) % BRAILLE_FRAMES.length);
      setElapsedMs(Date.now() - start);
    }, 85);
    return () => clearInterval(brailleTimer);
  }, [targetUrl, isApkMode]);

  useEffect(() => {
    setLogs([`[00:00s] Target locked: ${targetUrl}`]);
    let index = 0;

    const interval = setInterval(() => {
      if (index < activeMessages.length) {
        const currentIdx = index;
        const msg = activeMessages[currentIdx];
        const timestamp = String(currentIdx + 1).padStart(2, '0');
        index++;
        setLogs((prev) => [...prev, `[00:${timestamp}s] ${msg}`]);
      } else {
        clearInterval(interval);
      }
    }, 650);

    return () => clearInterval(interval);
  }, [targetUrl, isApkMode]);

  useEffect(() => {
    const el = scrollContainerRef.current;
    if (!el) return;
    el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="wb-surface rounded-xl overflow-hidden font-mono text-xs w-full relative">
      {/* Traveling Top-Border Laser Beam */}
      <div aria-hidden="true" className="wb-top-beam" />

      <div className="wb-ide-chrome px-4 py-2.5 border-b border-white/10 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className={`w-3.5 h-3.5 ${isApkMode ? 'text-emerald-400' : 'text-cyan-400'}`} />
          <span className="text-[11px] font-semibold text-white tracking-tight">
            {isApkMode ? 'CheckMyAPK · Dalvik Bytecode Shell' : 'CheckMyAPK · Live DAST Engine'}
          </span>
        </div>
        <div className="flex items-center gap-2.5" aria-hidden="true">
          <span className="text-[10px] font-mono tabular-nums text-emerald-400/90 bg-emerald-500/10 border border-emerald-500/25 px-1.5 py-0.5 rounded">
            {(elapsedMs / 1000).toFixed(1)}s
          </span>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500/60 border border-rose-400/30 inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400/60 border border-amber-300/30 inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400/80 border border-emerald-300/30 inline-block animate-pulse" />
          </div>
        </div>
      </div>

      <div
        ref={scrollContainerRef}
        className="p-4 space-y-2 text-slate-300 h-52 sm:h-56 overflow-y-auto scroll-smooth wb-surface-muted border-0"
      >
        {logs.map((log, i) => {
          const isLast = i === logs.length - 1;
          return (
            <div key={i} className="flex items-start gap-2.5 leading-relaxed">
              {isLast ? (
                <span
                  className={
                    isApkMode
                      ? 'text-emerald-400 select-none font-bold'
                      : 'text-cyan-400 select-none font-bold'
                  }
                >
                  ❯
                </span>
              ) : (
                <Check className="w-3.5 h-3.5 text-emerald-500/80 mt-0.5 shrink-0" />
              )}
              <span
                className={
                  isLast
                    ? `${isApkMode ? 'text-emerald-400' : 'text-cyan-400'} font-semibold`
                    : 'text-slate-400'
                }
              >
                {log}
                {isLast && (
                  <span
                    aria-hidden="true"
                    className={`wb-cursor-blink inline-block w-1.5 h-3.5 align-middle ml-1.5 ${
                      isApkMode ? 'bg-emerald-400' : 'bg-cyan-400'
                    }`}
                  />
                )}
              </span>
            </div>
          );
        })}
        <div className="flex items-center justify-between gap-2 text-slate-400 pt-2 border-t border-white/5 mt-2">
          <div className="flex items-center gap-2">
            <span className="text-emerald-400 font-bold text-sm leading-none w-3.5 text-center select-none">
              {BRAILLE_FRAMES[brailleIdx]}
            </span>
            <span className="text-[10px] tracking-[0.14em] uppercase text-slate-400">
              {isApkMode
                ? 'Disassembling Dalvik DEX & Native ELF...'
                : 'Executing deterministic payload probes...'}
            </span>
          </div>
          <span className="text-[10px] font-mono text-slate-500 hidden sm:inline">
            LIVE TELEMETRY
          </span>
        </div>
      </div>
    </div>
  );
};
