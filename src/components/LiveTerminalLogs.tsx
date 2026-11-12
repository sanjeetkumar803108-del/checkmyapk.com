import React, { useEffect, useState } from 'react';
import { Terminal, Shield } from 'lucide-react';

interface TerminalProps {
  targetUrl: string;
  isApkMode?: boolean;
}

const WEB_LOG_MESSAGES = [
  'Initializing CheckMyAPK automated penetration suite...',
  'Resolving target DNS and verifying SSL/TLS certificate chain...',
  'Extracting HTML DOM tree and discovering JavaScript bundles...',
  'Mapping robots.txt, sitemap.xml, OpenAPI specs & GraphQL schemas...',
  'Running deep Regex Secret Hunter & Static DOM XSS Sink Analysis...',
  'Auditing JWT claims, Content-Security-Policy, HSTS & CORS headers...',
  'Testing Firebase / Supabase rules & passive API route error leaks...',
  'Firing 15-request burst to test Denial-of-Wallet rate limits...',
  'Synthesizing architectural risk assessment & computing score...'
];

const APK_LOG_MESSAGES = [
  'Unpacking Android APK zip archive in secure memory sandbox...',
  'Parsing AndroidBinaryXML manifest & exported IPC components...',
  'Auditing android:debuggable, usesCleartextTraffic & allowBackup...',
  'Deep-scanning classes*.dex bytecode for secrets, weak crypto & SSL bypass...',
  'Fingerprinting embedded 3rd-party Trackers & telemetry SDKs...',
  'Extracting hardcoded Backend APIs & Firebase/Supabase endpoints...',
  'Stage 3 Active Probe: Testing extracted Backend API headers & DB rules...',
  'Computing OWASP MASVS mobile compliance score & neural brief...'
];

export const LiveTerminalLogs: React.FC<TerminalProps> = ({ targetUrl, isApkMode = false }) => {
  const [logs, setLogs] = useState<string[]>([]);
  const activeMessages = isApkMode ? APK_LOG_MESSAGES : WEB_LOG_MESSAGES;

  useEffect(() => {
    setLogs([`[00:00s] Target locked: ${targetUrl}`]);
    let index = 0;

    const interval = setInterval(() => {
      if (index < activeMessages.length) {
        const timestamp = String(index + 1).padStart(2, '0');
        setLogs(prev => [...prev, `[00:${timestamp}s] ${activeMessages[index]}`]);
        index++;
      } else {
        clearInterval(interval);
      }
    }, 650);

    return () => clearInterval(interval);
  }, [targetUrl, isApkMode]);

  return (
    <div className="glass-panel rounded-2xl overflow-hidden font-mono text-xs shadow-2xl border border-white/10 w-full">
      <div className="bg-[#0b101d]/90 px-4 py-2.5 border-b border-white/10 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className={`w-3.5 h-3.5 ${isApkMode ? 'text-purple-400' : 'text-cyan-400'}`} />
          <span className="text-[11px] font-bold text-slate-200 tracking-wide">
            {isApkMode ? 'CheckMyAPK • Dalvik Decompiler Shell' : 'CheckMyAPK • Active Pentest Engine'}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80 inline-block"></span>
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block"></span>
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block animate-pulse"></span>
        </div>
      </div>

      <div className="p-4 space-y-2 text-slate-300 max-h-60 overflow-y-auto bg-[#050811]/90">
        {logs.map((log, i) => (
          <div key={i} className="flex items-start gap-2.5 leading-relaxed">
            <span className={isApkMode ? 'text-purple-400 select-none font-bold' : 'text-cyan-400 select-none font-bold'}>
              ❯
            </span>
            <span
              className={
                i === logs.length - 1
                  ? `${isApkMode ? 'text-purple-300' : 'text-cyan-300'} font-semibold`
                  : 'text-slate-400'
              }
            >
              {log}
            </span>
          </div>
        ))}
        <div className="flex items-center gap-2 text-slate-500 pt-1">
          <Shield className="w-3 h-3 animate-spin" />
          <span className="text-[10px] tracking-widest uppercase">Executing live payload probes...</span>
        </div>
      </div>
    </div>
  );
};
