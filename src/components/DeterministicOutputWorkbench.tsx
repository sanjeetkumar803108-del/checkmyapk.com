import React, { useState, useRef } from 'react';
import {
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronRight,
  Copy,
  FileCode2,
  ShieldCheck,
  Sparkles,
  Terminal,
  Zap,
} from 'lucide-react';

interface DiffLine {
  type: 'ctx' | 'del' | 'add';
  oldNum?: number;
  newNum?: number;
  text: string;
  highlight?: string;
}

interface SampleFinding {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  rule: string;
  cvss: string;
  scoreGain: number;
  title: string;
  location: string;
  target: string;
  file: string;
  lineRef: string;
  parserLabel: string;
  evidence: {
    source: string;
    match: string;
    impact: string;
  };
  diff: DiffLine[];
}

const SAMPLE_FINDINGS: SampleFinding[] = [
  {
    id: 'stripe-secret',
    severity: 'CRITICAL',
    rule: 'MASVS-STORAGE-1',
    cvss: '9.1',
    scoreGain: 24,
    title: 'Hardcoded Firebase / Stripe Secret in DEX Bytecode',
    location: 'classes2.dex · com/app/Config.class:41',
    target: 'release-v2.4.apk',
    file: 'NetworkClient.kt',
    lineRef: 'L41–42',
    parserLabel: 'Static DEX Bytecode Parser',
    evidence: {
      source: 'classes2.dex → const-string pool (offset 0x004A2C)',
      match: 'Stripe Live key prefix (sk_live_) · Shannon entropy 4.82',
      impact: 'Anyone decompiling the APK can refund payments & dump customer PII',
    },
    diff: [
      {
        type: 'ctx',
        oldNum: 40,
        newNum: 40,
        text: '// Never embed live API secrets inside APK bytecode',
      },
      {
        type: 'del',
        oldNum: 41,
        text: 'val stripeKey = "sk_live_51N9x...REDACTED"',
        highlight: '"sk_live_51N9x...REDACTED"',
      },
      {
        type: 'del',
        oldNum: 42,
        text: 'val auth = "Bearer $stripeKey"',
        highlight: '$stripeKey',
      },
      {
        type: 'add',
        newNum: 41,
        text: 'val checkoutUrl = "https://api.yourapp.com/v1/billing/checkout"',
        highlight: '"https://api.yourapp.com/v1/billing/checkout"',
      },
      {
        type: 'add',
        newNum: 42,
        text: 'val auth = "Bearer ${sessionStore.getUserJwt()}"',
        highlight: '${sessionStore.getUserJwt()}',
      },
    ],
  },
  {
    id: 'debuggable-apk',
    severity: 'HIGH',
    rule: 'MASVS-CODE-2',
    cvss: '7.8',
    scoreGain: 18,
    title: 'Production APK Built With android:debuggable="true"',
    location: 'AndroidManifest.xml · <application>',
    target: 'release-v2.4.apk',
    file: 'app/src/main/AndroidManifest.xml',
    lineRef: 'L18–19',
    parserLabel: 'Binary XML Manifest Parser',
    evidence: {
      source: 'AndroidManifest.xml → <application> flags (resId 0x0101000f)',
      match: 'android:debuggable=true & android:allowBackup=true in release build',
      impact: 'Attackers can attach JDWP / Frida & extract private SQLite / prefs data',
    },
    diff: [
      { type: 'ctx', oldNum: 16, newNum: 16, text: '<application' },
      { type: 'ctx', oldNum: 17, newNum: 17, text: '    android:name=".MainApplication"' },
      {
        type: 'del',
        oldNum: 18,
        text: '    android:debuggable="true"',
        highlight: '"true"',
      },
      {
        type: 'del',
        oldNum: 19,
        text: '    android:allowBackup="true"',
        highlight: '"true"',
      },
      {
        type: 'add',
        newNum: 18,
        text: '    android:debuggable="false"',
        highlight: '"false"',
      },
      {
        type: 'add',
        newNum: 19,
        text: '    android:allowBackup="false"',
        highlight: '"false"',
      },
      {
        type: 'ctx',
        oldNum: 20,
        newNum: 20,
        text: '    android:usesCleartextTraffic="false">',
      },
    ],
  },
  {
    id: 'missing-headers',
    severity: 'MEDIUM',
    rule: 'OWASP-A05',
    cvss: '5.4',
    scoreGain: 12,
    title: 'Missing Strict-Transport-Security & CSP Headers',
    location: 'https://api.yourapp.com · HTTP Response',
    target: 'api.yourapp.com',
    file: 'server.ts (Express Security Middleware)',
    lineRef: 'L88–91',
    parserLabel: 'Live HTTP Header Probe',
    evidence: {
      source: 'GET https://api.yourapp.com → HTTP/2 200 response headers',
      match: 'Strict-Transport-Security & Content-Security-Policy absent',
      impact: 'Allows SSL-strip downgrade & unchecked third-party XSS script execution',
    },
    diff: [
      { type: 'ctx', oldNum: 87, newNum: 87, text: 'app.use((req, res, next) => {' },
      {
        type: 'del',
        oldNum: 88,
        text: '  // Missing HSTS & Content-Security-Policy headers',
        highlight: '// Missing HSTS & Content-Security-Policy headers',
      },
      {
        type: 'add',
        newNum: 88,
        text: '  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");',
        highlight: '"Strict-Transport-Security"',
      },
      {
        type: 'add',
        newNum: 89,
        text: '  res.setHeader("Content-Security-Policy", "default-src \'self\'; object-src \'none\'");',
        highlight: '"Content-Security-Policy"',
      },
      { type: 'ctx', oldNum: 89, newNum: 90, text: '  next();' },
      { type: 'ctx', oldNum: 90, newNum: 91, text: '});' },
    ],
  },
];

const SEVERITY_STYLES = {
  CRITICAL: {
    badge: 'bg-rose-500/15 text-rose-400 border-rose-500/35',
    railBar: 'bg-rose-500 shadow-[0_0_12px_rgba(244,63,94,0.7)]',
    activeRow: 'wb-ide-row-active-critical',
    ambientGlow: 'bg-rose-500/[0.09]',
    cvssPill: 'bg-rose-500/10 text-rose-400 border-rose-500/25',
  },
  HIGH: {
    badge: 'bg-amber-500/15 text-amber-400 border-amber-500/35',
    railBar: 'bg-amber-400 shadow-[0_0_12px_rgba(251,191,36,0.65)]',
    activeRow: 'wb-ide-row-active-high',
    ambientGlow: 'bg-amber-500/[0.09]',
    cvssPill: 'bg-amber-500/10 text-amber-400 border-amber-500/25',
  },
  MEDIUM: {
    badge: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/35',
    railBar: 'bg-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.65)]',
    activeRow: 'wb-ide-row-active-medium',
    ambientGlow: 'bg-cyan-500/[0.09]',
    cvssPill: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/25',
  },
} as const;

const BASE_SCORE = 42;

function renderHighlightedText(text: string, type: DiffLine['type'], highlight?: string) {
  if (!highlight || !text.includes(highlight)) {
    return <span>{text}</span>;
  }
  const idx = text.indexOf(highlight);
  const before = text.slice(0, idx);
  const after = text.slice(idx + highlight.length);
  const tokenClass =
    type === 'del'
      ? 'wb-ide-token-del'
      : type === 'add'
      ? 'wb-ide-token-add'
      : '';

  return (
    <>
      <span>{before}</span>
      <span className={`${tokenClass} px-1 py-0.5 rounded-[3px]`}>{highlight}</span>
      <span>{after}</span>
    </>
  );
}

interface DeterministicOutputWorkbenchProps {
  onOpenSampleDemo: () => void;
}

export const DeterministicOutputWorkbench: React.FC<DeterministicOutputWorkbenchProps> = ({
  onOpenSampleDemo,
}) => {
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [viewMode, setViewMode] = useState<'diff' | 'patch'>('diff');
  const [copied, setCopied] = useState(false);
  const [patchedIds, setPatchedIds] = useState<string[]>([]);
  const workbenchRef = useRef<HTMLDivElement>(null);

  const active = SAMPLE_FINDINGS[selectedIdx] || SAMPLE_FINDINGS[0];
  const sevStyle = SEVERITY_STYLES[active.severity];
  const isCurrentPatched = patchedIds.includes(active.id);

  const totalPossibleGain = SAMPLE_FINDINGS.reduce((sum, f) => sum + f.scoreGain, 0);
  const appliedGain = SAMPLE_FINDINGS.reduce(
    (sum, f) => (patchedIds.includes(f.id) ? sum + f.scoreGain : sum),
    0
  );
  const currentScore = BASE_SCORE + appliedGain;
  const maxProjectedScore = BASE_SCORE + totalPossibleGain;

  const visibleLines =
    viewMode === 'diff'
      ? active.diff
      : active.diff.filter((line) => line.type !== 'del');

  const handleSelectFinding = (idx: number) => {
    setSelectedIdx(idx);
    setCopied(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      handleSelectFinding((selectedIdx + 1) % SAMPLE_FINDINGS.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      handleSelectFinding((selectedIdx - 1 + SAMPLE_FINDINGS.length) % SAMPLE_FINDINGS.length);
    }
  };

  const handleCopyPatch = () => {
    const patchText = active.diff
      .filter((l) => l.type !== 'del')
      .map((l) => l.text)
      .join('\n');
    navigator.clipboard
      ?.writeText(patchText)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
      })
      .catch(() => {});
  };

  const handleToggleSimulatePatch = () => {
    setPatchedIds((prev) =>
      prev.includes(active.id)
        ? prev.filter((id) => id !== active.id)
        : [...prev, active.id]
    );
  };

  return (
    <section id="features" className="scroll-mt-20 space-y-5">
      {/* Section Heading */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-white/10 pb-5">
        <div className="space-y-1.5 text-left">
          <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-400 font-semibold">
            Deterministic Output
          </span>
          <h2 className="text-2xl sm:text-[28px] font-display font-semibold tracking-[-0.03em] text-white">
            Exact file paths and copy-paste patches, not generic alerts.
          </h2>
        </div>
        <button
          type="button"
          onClick={onOpenSampleDemo}
          className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400 hover:underline cursor-pointer self-start sm:self-auto"
        >
          <span>Open full interactive sample report</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* IDE Security Workbench Frame */}
      <div
        ref={workbenchRef}
        tabIndex={0}
        onKeyDown={handleKeyDown}
        aria-label="Interactive security findings and patch diff workbench"
        className="wb-bezel p-1.5 rounded-2xl relative focus:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400/50"
      >
        {/* Subtle Top Emerald Light-Catch Hairline */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
        />

        <div className="wb-surface rounded-xl overflow-hidden text-left">
          {/* ── Top Workbench Chrome Bar ── */}
          <div className="wb-ide-chrome px-4 py-2.5 border-b border-white/10 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <div className="flex items-center gap-1.5 shrink-0" aria-hidden="true">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500/60 border border-rose-400/30" />
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400/60 border border-amber-300/30" />
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400/60 border border-emerald-300/30" />
              </div>
              <div className="h-3.5 w-px bg-white/10 shrink-0 hidden sm:block" />
              <div className="flex items-center gap-2 font-mono text-[11px] text-slate-400 truncate">
                <Terminal className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span className="truncate">
                  <span className="text-slate-500">checkmyapk audit --target </span>
                  <span className="text-white font-medium">{active.target}</span>
                </span>
              </div>
            </div>

            <div className="flex items-center gap-1.5 font-mono text-[10px] shrink-0">
              <span className="px-2 py-0.5 rounded border bg-rose-500/10 border-rose-500/25 text-rose-400 font-semibold">
                1 CRIT
              </span>
              <span className="px-2 py-0.5 rounded border bg-amber-500/10 border-amber-500/25 text-amber-400 font-semibold">
                1 HIGH
              </span>
              <span className="px-2 py-0.5 rounded border bg-cyan-500/10 border-cyan-500/25 text-cyan-400 font-semibold">
                1 MED
              </span>
              <span className="hidden md:inline-flex items-center gap-1 pl-2 ml-1 border-l border-white/10 text-slate-400">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                1.4s · DEX + DAST
              </span>
            </div>
          </div>

          {/* ── Split Workbench Body ── */}
          <div className="grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-white/10">
            {/* Left Rail: Findings List + Projected Score Bar */}
            <div className="lg:col-span-5 flex flex-col justify-between">
              <div role="listbox" aria-label="Parsed security findings" className="divide-y divide-white/[0.08]">
                <div className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-wider text-slate-500 flex items-center justify-between">
                  <span>Parsed Findings ({SAMPLE_FINDINGS.length})</span>
                </div>

                {SAMPLE_FINDINGS.map((item, idx) => {
                  const selected = idx === selectedIdx;
                  const itemStyle = SEVERITY_STYLES[item.severity];
                  const isPatched = patchedIds.includes(item.id);

                  return (
                    <button
                      key={item.id}
                      type="button"
                      role="option"
                      aria-selected={selected}
                      onClick={() => handleSelectFinding(idx)}
                      className={`group relative w-full text-left pl-4 pr-3.5 py-4 transition-all duration-150 cursor-pointer ${
                        selected ? itemStyle.activeRow : 'hover:bg-white/[0.025]'
                      }`}
                    >
                      {/* Active Left Vertical Glow Bar */}
                      <span
                        aria-hidden="true"
                        className={`absolute left-0 inset-y-2 w-[2.5px] rounded-r transition-all duration-200 ${
                          selected ? itemStyle.railBar : 'bg-transparent'
                        }`}
                      />

                      <div className="flex items-start justify-between gap-2.5">
                        <div className="space-y-1.5 min-w-0 flex-1">
                          <div className="flex items-center flex-wrap gap-1.5">
                            <span
                              className={`font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border ${itemStyle.badge}`}
                            >
                              {item.severity}
                            </span>
                            <span className="font-mono text-[10px] text-slate-400">
                              {item.rule}
                            </span>
                            {isPatched ? (
                              <span className="inline-flex items-center gap-1 font-mono text-[10px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/25 px-1.5 py-0.5 rounded">
                                <Check className="w-2.5 h-2.5" />
                                Patched
                              </span>
                            ) : (
                              <span className="font-mono text-[10px] text-emerald-400/90 ml-auto">
                                +{item.scoreGain} pts
                              </span>
                            )}
                          </div>

                          <div
                            className={`text-xs sm:text-[13px] font-semibold leading-snug transition-colors ${
                              isPatched
                                ? 'text-slate-400 line-through decoration-emerald-500/60'
                                : 'text-white'
                            }`}
                          >
                            {item.title}
                          </div>

                          <div className="font-mono text-[11px] text-slate-400 truncate">
                            {item.location}
                          </div>
                        </div>

                        <ChevronRight
                          className={`w-4 h-4 shrink-0 mt-1 transition-all duration-150 ${
                            selected
                              ? 'text-white translate-x-0.5 opacity-100'
                              : 'text-slate-500 opacity-40 group-hover:opacity-80'
                          }`}
                        />
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Left Rail Footer: Live Projected Score Uplift */}
              <div className="px-4 py-3.5 border-t border-white/10 wb-ide-chrome space-y-2">
                <div className="flex items-center justify-between gap-2 font-mono text-[11px]">
                  <span className="inline-flex items-center gap-1.5 text-slate-400">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span>{appliedGain > 0 ? 'Simulated Score' : 'Projected Score'}</span>
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="text-rose-400 font-semibold">{BASE_SCORE}</span>
                    <ArrowRight className="w-3 h-3 text-slate-500" />
                    <span className="text-emerald-400 font-bold">
                      {appliedGain > 0 ? currentScore : maxProjectedScore}
                    </span>
                    <span className="text-[10px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/25 px-1.5 py-0.5 rounded">
                      +{appliedGain > 0 ? appliedGain : totalPossibleGain} pts
                    </span>
                  </span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-white/[0.07] overflow-hidden relative">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-rose-500 via-amber-400 to-emerald-400 transition-all duration-500 ease-out"
                    style={{
                      width: `${appliedGain > 0 ? currentScore : maxProjectedScore}%`,
                    }}
                  />
                </div>
              </div>
            </div>

            {/* Right Pane: IDE Diff Viewer + Deterministic Evidence Drawer */}
            <div className="lg:col-span-7 flex flex-col wb-surface-muted border-0 relative overflow-hidden">
              {/* Dynamic Subtle Severity Ambient Glow */}
              <div
                aria-hidden="true"
                className={`pointer-events-none absolute -top-24 -right-24 w-72 h-72 rounded-full blur-3xl transition-colors duration-500 ${sevStyle.ambientGlow}`}
              />

              {/* IDE File & Mode Toolbar */}
              <div className="relative z-10 px-4 py-2.5 border-b border-white/10 flex flex-wrap items-center justify-between gap-2.5 font-mono text-[11px]">
                <div className="flex items-center gap-2 min-w-0">
                  <FileCode2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span className="text-white font-medium truncate">{active.file}</span>
                  <span className="text-[10px] text-slate-400 bg-white/[0.05] border border-white/10 px-1.5 py-0.5 rounded shrink-0">
                    {active.lineRef}
                  </span>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {/* Unified Diff vs Clean Patch Segmented Toggle */}
                  <div className="inline-flex items-center p-0.5 rounded-md bg-white/[0.05] border border-white/10 text-[10px]">
                    <button
                      type="button"
                      onClick={() => setViewMode('diff')}
                      className={`px-2 py-0.5 rounded transition-colors cursor-pointer ${
                        viewMode === 'diff'
                          ? 'bg-white/15 text-white font-semibold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Unified Diff
                    </button>
                    <button
                      type="button"
                      onClick={() => setViewMode('patch')}
                      className={`px-2 py-0.5 rounded transition-colors cursor-pointer ${
                        viewMode === 'patch'
                          ? 'bg-emerald-500/20 text-emerald-400 font-semibold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Clean Patch
                    </button>
                  </div>

                  {/* Copy Patch Button */}
                  <button
                    type="button"
                    onClick={handleCopyPatch}
                    className={`inline-flex items-center gap-1 px-2.5 py-1 rounded border text-[10px] font-medium transition-all cursor-pointer ${
                      copied
                        ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400'
                        : 'bg-white/[0.06] hover:bg-white/[0.12] border-white/10 text-slate-300 hover:text-white'
                    }`}
                  >
                    {copied ? (
                      <Check className="w-3 h-3 text-emerald-400" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                    <span>{copied ? 'Copied' : 'Copy Patch'}</span>
                  </button>
                </div>
              </div>

              {/* Dual-Gutter Code Diff / Clean Patch Canvas */}
              <div className="relative z-10 py-3 font-mono text-[11.5px] leading-6 overflow-x-auto flex-1">
                <div className="min-w-max">
                  {visibleLines.map((line, lineIdx) => {
                    const isDel = line.type === 'del';
                    const isAdd = line.type === 'add';
                    const prefix =
                      viewMode === 'patch' ? ' ' : isDel ? '-' : isAdd ? '+' : ' ';

                    const rowClass =
                      viewMode === 'patch'
                        ? isAdd
                          ? 'wb-diff-add border-l-2 border-emerald-400/75'
                          : 'text-slate-300 border-l-2 border-transparent'
                        : isDel
                        ? 'wb-diff-del border-l-2 border-rose-500/80'
                        : isAdd
                        ? 'wb-diff-add border-l-2 border-emerald-400/80'
                        : 'text-slate-400 border-l-2 border-transparent';

                    return (
                      <div
                        key={`${active.id}-${viewMode}-${lineIdx}`}
                        className={`flex items-stretch px-3 transition-colors ${rowClass}`}
                      >
                        {/* Dual Line-Number Gutter */}
                        {viewMode === 'diff' ? (
                          <span
                            aria-hidden="true"
                            className="wb-ide-gutter select-none inline-flex items-center gap-2 pr-3 mr-2 text-[10px] shrink-0"
                          >
                            <span className="w-5 text-right">{line.oldNum ?? ''}</span>
                            <span className="w-5 text-right">{line.newNum ?? ''}</span>
                          </span>
                        ) : (
                          <span
                            aria-hidden="true"
                            className="wb-ide-gutter select-none inline-flex items-center pr-3 mr-2 text-[10px] shrink-0"
                          >
                            <span className="w-5 text-right">{line.newNum ?? lineIdx + 1}</span>
                          </span>
                        )}

                        {/* Diff Sign Column */}
                        <span
                          aria-hidden="true"
                          className={`select-none w-4 shrink-0 font-bold ${
                            isDel
                              ? 'text-rose-400'
                              : isAdd
                              ? 'text-emerald-400'
                              : 'text-slate-500'
                          }`}
                        >
                          {prefix}
                        </span>

                        {/* Code Text with Inline Token Highlight */}
                        <span className="whitespace-pre pr-4">
                          {renderHighlightedText(line.text, line.type, line.highlight)}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* ── Deterministic Evidence Drawer (Replaces Empty Dead Space) ── */}
              <div className="relative z-10 wb-ide-evidence px-4 py-3.5 border-t border-white/10 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.12em] font-semibold text-emerald-400">
                    <Zap className="w-3 h-3" />
                    <span>Deterministic Evidence</span>
                  </span>
                  <div className="flex items-center gap-1.5 font-mono text-[10px]">
                    <span className={`px-1.5 py-0.5 rounded border font-semibold ${sevStyle.cvssPill}`}>
                      CVSS {active.cvss}
                    </span>
                    <span className="px-1.5 py-0.5 rounded border bg-emerald-500/10 border-emerald-500/25 text-emerald-400 font-semibold">
                      +{active.scoreGain} pts on fix
                    </span>
                  </div>
                </div>

                <dl className="grid grid-cols-1 gap-1.5 text-[11px] leading-relaxed">
                  <div className="flex flex-col sm:flex-row sm:items-baseline gap-0.5 sm:gap-2">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-slate-500 w-16 shrink-0">
                      Source
                    </dt>
                    <dd className="font-mono text-[11px] text-slate-300 break-all">
                      {active.evidence.source}
                    </dd>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:items-baseline gap-0.5 sm:gap-2">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-slate-500 w-16 shrink-0">
                      Match
                    </dt>
                    <dd className="text-slate-300">{active.evidence.match}</dd>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:items-baseline gap-0.5 sm:gap-2">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-slate-500 w-16 shrink-0">
                      Impact
                    </dt>
                    <dd className="text-slate-400">{active.evidence.impact}</dd>
                  </div>
                </dl>
              </div>

              {/* Footer Status & Interactive Action Bar */}
              <div className="relative z-10 px-4 py-2.5 border-t border-white/10 flex flex-wrap items-center justify-between gap-2 text-[11px]">
                <div className="flex items-center gap-2 text-slate-400">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span className="font-mono text-[10.5px]">
                    <span className="text-emerald-400 font-semibold">Confirmed</span>
                    <span className="text-slate-500"> · </span>
                    <span>{active.parserLabel}</span>
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleToggleSimulatePatch}
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md font-mono text-[10.5px] font-semibold transition-all cursor-pointer border ${
                      isCurrentPatched
                        ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400'
                        : 'bg-white/[0.06] hover:bg-emerald-500/15 border-white/10 hover:border-emerald-500/35 text-white hover:text-emerald-400'
                    }`}
                  >
                    {isCurrentPatched ? (
                      <>
                        <Check className="w-3 h-3" />
                        <span>Patch Verified</span>
                      </>
                    ) : (
                      <>
                        <Sparkles className="w-3 h-3 text-emerald-400" />
                        <span>Simulate Fix</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
