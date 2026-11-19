import React, { useEffect, useRef, useState } from 'react';
import {
  Activity,
  ArrowRight,
  Binary,
  Check,
  ChevronDown,
  ChevronUp,
  Code2,
  Copy,
  Download,
  FileJson,
  FileText,
  Globe,
  Lock,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldCheck,
  Smartphone,
  Sparkles,
  Terminal,
  TrendingUp,
  Wrench,
  X,
  Zap,
} from 'lucide-react';
import { ScoreGauge } from './ScoreGauge';
import { FindingCard } from './FindingCard';
import type { PlanPolicy } from '../data/planPolicy';

export type ReportTab = 'findings' | 'quickfix' | 'surface' | 'logs';
export type FindingFilter = 'vulns' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'pass' | 'all';

interface MasterSnippet {
  filename: string;
  desc: string;
  code: string;
}

interface SummaryRow {
  num: string;
  label: string;
  text: string;
  accent: string;
}

function parseExecutiveSummary(summaryText?: string): SummaryRow[] {
  if (!summaryText) return [];
  const rawLines = summaryText.split('\n').map((l) => l.trim()).filter(Boolean);
  const rows: SummaryRow[] = [];

  const roleMeta = [
    { label: 'Threat Posture', accent: 'border-emerald-500/35 text-emerald-400 bg-emerald-500/10' },
    { label: 'Primary Attack Vector', accent: 'border-rose-500/35 text-rose-400 bg-rose-500/10' },
    { label: '24-Hour Remediation', accent: 'border-cyan-500/35 text-cyan-400 bg-cyan-500/10' },
  ];

  for (let i = 0; i < rawLines.length && rows.length < 3; i++) {
    const line = rawLines[i];
    const cleaned = line
      .replace(/^[0-9]+[.)]\s*/, '')
      .replace(/^[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F600}-\u{1F64F}\u{1F680}-\u{1F6FF}]\s*/u, '')
      .replace(/^(THREAT LANDSCAPE|PRIMARY ATTACK VECTOR|24-HOUR REMEDIATION ROADMAP|VULNERABILITY STATUS|REMEDIATION|ARCHIVED [A-Z ]+|ZERO-RETENTION [A-Z ]+|PRIMARY EXPOSURE|ACTION):\s*/i, '')
      .trim();

    if (!cleaned) continue;
    const meta = roleMeta[rows.length] || {
      label: `Point 0${rows.length + 1}`,
      accent: 'border-white/20 text-slate-300 bg-white/5',
    };
    rows.push({
      num: `0${rows.length + 1}`,
      label: meta.label,
      text: cleaned,
      accent: meta.accent,
    });
  }

  if (rows.length === 0 && summaryText) {
    rows.push({
      num: '01',
      label: 'Security Overview',
      text: summaryText,
      accent: 'border-emerald-500/35 text-emerald-400 bg-emerald-500/10',
    });
  }

  return rows;
}

interface SecurityReportDashboardProps {
  report: any;
  scoreDelta: {
    previousScore: number;
    delta: number;
    fixedIssues: string[];
    newIssues: string[];
  } | null;
  activePlanPolicy: PlanPolicy;
  masterCodes: Record<'vercel' | 'nextjs' | 'express', MasterSnippet>;
  domainChallenge: {
    host: string;
    token: string;
    txtRecord: string;
    metaTag: string;
  } | null;
  onLoadDomainChallenge: () => void;
  onNewAudit: () => void;
  onRescanWeb?: (targetUrl: string) => void;
  onRescanApk?: () => void;
  onExportJson: () => void;
  onExportMarkdown: () => void;
  onCopyMarkdown: () => void;
  mdCopied: boolean;
  onRequestUpgrade: () => void;
}

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
  PASS: 5,
};

export const SecurityReportDashboard: React.FC<SecurityReportDashboardProps> = ({
  report,
  scoreDelta,
  activePlanPolicy,
  masterCodes,
  domainChallenge,
  onLoadDomainChallenge,
  onNewAudit,
  onRescanWeb,
  onRescanApk,
  onExportJson,
  onExportMarkdown,
  onCopyMarkdown,
  mdCopied,
  onRequestUpgrade,
}) => {
  const [activeTab, setActiveTab] = useState<ReportTab>('findings');
  const [findingFilter, setFindingFilter] = useState<FindingFilter>(() => {
    const hasVulns = report?.findings?.some(
      (f: any) => f.severity !== 'PASS' && f.severity !== 'INFO'
    );
    return hasVulns ? 'vulns' : 'all';
  });
  const [findingSearch, setFindingSearch] = useState('');
  const [allExpanded, setAllExpanded] = useState<boolean | undefined>(undefined);
  const [masterTab, setMasterTab] = useState<'vercel' | 'nextjs' | 'express'>('vercel');
  const [masterCopied, setMasterCopied] = useState(false);
  const [hashCopied, setHashCopied] = useState(false);
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const exportMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setActiveTab('findings');
    const hasVulns = report?.findings?.some(
      (f: any) => f.severity !== 'PASS' && f.severity !== 'INFO'
    );
    setFindingFilter(hasVulns ? 'vulns' : 'all');
  }, [report?.scanTimestamp, report?.targetUrl]);

  useEffect(() => {
    const onOutsideClick = (e: MouseEvent) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Node)) {
        setExportMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', onOutsideClick);
    return () => document.removeEventListener('mousedown', onOutsideClick);
  }, []);

  const allFindings: any[] = Array.isArray(report?.findings) ? report.findings : [];
  const vulnFindings = allFindings.filter(
    (f) => f.severity !== 'PASS' && f.severity !== 'INFO'
  );
  const passAndInfoFindings = allFindings.filter(
    (f) => f.severity === 'PASS' || f.severity === 'INFO'
  );
  const hasInfo = allFindings.some((f) => f.severity === 'INFO');

  const hasWebHeaderGaps =
    !report.isApkAudit &&
    vulnFindings.some((f) => /header|cors/i.test(f.category || ''));

  const filteredFindings = [...allFindings]
    .filter((f) => {
      if (findingFilter === 'vulns' && (f.severity === 'PASS' || f.severity === 'INFO')) return false;
      if (findingFilter === 'pass' && f.severity !== 'PASS' && f.severity !== 'INFO') return false;
      if (findingFilter !== 'all' && findingFilter !== 'vulns' && findingFilter !== 'pass' && f.severity !== findingFilter) {
        return false;
      }
      if (findingSearch.trim()) {
        const q = findingSearch.toLowerCase().trim();
        const text = `${f.title || ''} ${f.type || ''} ${f.owaspRef || ''} ${f.category || ''} ${f.description || ''} ${f.proof || ''}`.toLowerCase();
        if (!text.includes(q)) return false;
      }
      return true;
    })
    .sort(
      (a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
    );

  const summaryRows = parseExecutiveSummary(report.aiExecutiveSummary);

  const critCount = report.summaryCounts?.critical ?? 0;
  const highCount = report.summaryCounts?.high ?? 0;
  const medCount = report.summaryCounts?.medium ?? 0;
  const lowCount = report.summaryCounts?.low ?? 0;
  const passCount = report.summaryCounts?.pass ?? 0;
  const totalFindingsCount = critCount + highCount + medCount + lowCount + passCount;

  // Realistic projected score if Critical & High issues are resolved
  const potentialGain = (critCount * 28) + (highCount * 16) + (medCount * 6);
  const estUpliftScore = Math.min(100, Math.max(report.score, report.score + potentialGain));
  const upliftDelta = estUpliftScore - report.score;

  const logsCount = report.telemetry?.realTimeLogs?.length || 0;

  const targetDisplay = report.isApkAudit
    ? report.apkMeta?.packageName || report.targetUrl
    : report.targetUrl;

  const gaugeSubtitle = report.isApkAudit && report.apkMeta
    ? `${report.apkMeta.dexCount} DEX · ${report.apkMeta.permissions.length} perms${
        report.telemetry?.durationSeconds ? ` · ${report.telemetry.durationSeconds}s` : ''
      }`
    : report.telemetry
    ? `${report.telemetry.latencyMs || 0} ms · ${report.telemetry.scriptsCount} bundles · ${(
        (report.telemetry.totalBytesScanned || 0) / 1024
      ).toFixed(0)} KB`
    : undefined;

  const handleCopyMaster = (code: string) => {
    navigator.clipboard.writeText(code);
    setMasterCopied(true);
    setTimeout(() => setMasterCopied(false), 1800);
  };

  const jumpToSeverity = (sev: FindingFilter) => {
    setActiveTab('findings');
    setFindingFilter(sev);
  };

  const severityTiles: Array<{
    key: FindingFilter;
    label: string;
    count: number;
    activeClass: string;
    numberClass: string;
  }> = [
    {
      key: 'CRITICAL',
      label: 'Critical',
      count: report.summaryCounts?.critical ?? 0,
      activeClass: 'bg-rose-500/10 border-rose-500/30 hover:border-rose-500/50',
      numberClass: 'text-rose-400',
    },
    {
      key: 'HIGH',
      label: 'High',
      count: report.summaryCounts?.high ?? 0,
      activeClass: 'bg-orange-500/10 border-orange-500/30 hover:border-orange-500/50',
      numberClass: 'text-orange-400',
    },
    {
      key: 'MEDIUM',
      label: 'Medium',
      count: report.summaryCounts?.medium ?? 0,
      activeClass: 'bg-amber-500/10 border-amber-500/30 hover:border-amber-500/50',
      numberClass: 'text-amber-400',
    },
    {
      key: 'LOW',
      label: 'Low',
      count: report.summaryCounts?.low ?? 0,
      activeClass: 'bg-cyan-500/10 border-cyan-500/30 hover:border-cyan-500/50',
      numberClass: 'text-cyan-400',
    },
    {
      key: 'pass',
      label: 'Passed',
      count: report.summaryCounts?.pass ?? 0,
      activeClass: 'bg-emerald-500/10 border-emerald-500/30 hover:border-emerald-500/50',
      numberClass: 'text-emerald-400',
    },
  ];

  return (
    <div className="flex flex-col gap-6 pb-10">
      {/* Sample Demo Preview Banner */}
      {report.isDemoPreview && (
        <div className="wb-surface border-amber-500/35 rounded-xl px-4 py-3 text-xs flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2.5 text-amber-400">
            <Sparkles className="w-4 h-4 shrink-0" />
            <span className="font-medium text-slate-300">
              <strong className="text-amber-400 font-semibold">Sample Demo Report</strong> — Interactive showcase of a vulnerable test APK. Upload your own <code className="wb-spec-code px-1.5 py-0.5 rounded font-mono text-[10px]">.apk</code> for a real audit.
            </span>
          </div>
          <button
            type="button"
            onClick={onNewAudit}
            className="wb-emerald-btn h-8 px-3 rounded-md font-semibold text-[11px] cursor-pointer shrink-0"
          >
            Scan Real APK
          </button>
        </div>
      )}

      {/* ── ZONE 1: Slim Action Header Bar ── */}
      <div className="wb-bezel p-1.5 rounded-2xl relative">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
        />
        <div className="wb-surface rounded-xl px-4 sm:px-5 py-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4 text-left">
          <div className="flex items-start gap-3.5 min-w-0">
            <div
              className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 border ${
                report.isApkAudit
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                  : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
              }`}
            >
              {report.isApkAudit ? <Smartphone className="w-5 h-5" /> : <Shield className="w-5 h-5" />}
            </div>

            <div className="min-w-0 space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-base sm:text-lg font-display font-semibold tracking-[-0.02em] text-white break-all">
                  {targetDisplay}
                </h1>
                <span className="font-mono text-[10px] uppercase tracking-wider px-2 py-0.5 rounded wb-spec-code">
                  {report.isApkAudit ? 'APK Audit' : 'Web Audit'}
                </span>
                {activePlanPolicy.features.scoreDelta && scoreDelta && scoreDelta.delta !== 0 && (
                  <span
                    className={`font-mono text-[10px] font-semibold px-2 py-0.5 rounded border inline-flex items-center gap-1 ${
                      scoreDelta.delta > 0
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                    }`}
                  >
                    <TrendingUp className="w-3 h-3" />
                    {scoreDelta.delta > 0 ? `+${scoreDelta.delta}` : scoreDelta.delta} pts vs prev
                  </span>
                )}
              </div>

              {/* Compact Inline Telemetry + Tech Stack */}
              <div className="flex items-center gap-2 flex-wrap font-mono text-[10.5px] text-slate-400">
                {report.isApkAudit && report.apkMeta ? (
                  <>
                    <span>{report.apkMeta.fileName}</span>
                    <span className="text-slate-600">·</span>
                    <span>{report.apkMeta.sizeMb} MB</span>
                    <span className="text-slate-600">·</span>
                    <span>{report.apkMeta.frameworkDetected}</span>
                    <span className="text-slate-600">·</span>
                    <span>SDK {report.apkMeta.targetSdkVersion} (Min {report.apkMeta.minSdkVersion})</span>
                    {report.apkMeta.sha256 && (
                      <>
                        <span className="text-slate-600">·</span>
                        <button
                          type="button"
                          onClick={() => {
                            navigator.clipboard.writeText(report.apkMeta.sha256);
                            setHashCopied(true);
                            setTimeout(() => setHashCopied(false), 1800);
                          }}
                          className="inline-flex items-center gap-1 text-cyan-400 hover:underline cursor-pointer"
                          title="Copy full SHA-256 fingerprint"
                        >
                          <span>SHA-256: {report.apkMeta.sha256.slice(0, 12)}…</span>
                          {hashCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </>
                    )}
                  </>
                ) : (
                  <>
                    {report.telemetry?.detectedTech?.slice(0, 4).map((tech: string, idx: number) => (
                      <span key={idx} className="wb-spec-code px-1.5 py-0.5 rounded text-[10px]">
                        {tech}
                      </span>
                    ))}
                    {report.domainVerification && (
                      <span className="text-slate-500">
                        · {report.domainVerification.verified ? 'Verified Owner' : `Safe Mode (${report.domainVerification.burstProfile})`}
                      </span>
                    )}
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Right Action Group: Export Dropdown + Re-scan + New Audit */}
          <div className="flex items-center gap-2 shrink-0 flex-wrap no-print">
            {/* Export Dropdown */}
            <div ref={exportMenuRef} className="relative">
              <button
                type="button"
                onClick={() => setExportMenuOpen((v) => !v)}
                className="h-9 px-3 rounded-md text-xs font-medium wb-surface-muted hover:border-white/25 text-slate-300 hover:text-white inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-emerald-400" />
                <span>Export</span>
                <ChevronDown className="w-3 h-3 text-slate-400" />
              </button>

              {exportMenuOpen && (
                <div className="absolute right-0 mt-1.5 w-48 wb-surface rounded-lg shadow-2xl border border-white/15 py-1 z-40 text-left text-xs">
                  <button
                    type="button"
                    onClick={() => {
                      setExportMenuOpen(false);
                      window.print();
                    }}
                    className="w-full px-3 py-2 text-left text-slate-300 hover:text-white wb-spec-row flex items-center gap-2 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Print / Save PDF</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setExportMenuOpen(false);
                      onExportJson();
                    }}
                    className="w-full px-3 py-2 text-left text-slate-300 hover:text-white wb-spec-row flex items-center gap-2 cursor-pointer"
                  >
                    <FileJson className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Download JSON</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setExportMenuOpen(false);
                      onExportMarkdown();
                    }}
                    className="w-full px-3 py-2 text-left text-slate-300 hover:text-white wb-spec-row flex items-center gap-2 cursor-pointer"
                  >
                    <FileText className="w-3.5 h-3.5 text-slate-400" />
                    <span>Download Markdown</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      onCopyMarkdown();
                    }}
                    className="w-full px-3 py-2 text-left text-slate-300 hover:text-white wb-spec-row flex items-center gap-2 cursor-pointer border-t border-white/10 mt-1 pt-2"
                  >
                    {mdCopied ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5 text-slate-400" />
                    )}
                    <span>{mdCopied ? 'PR Summary Copied!' : 'Copy PR Summary'}</span>
                  </button>
                </div>
              )}
            </div>

            {!report.isApkAudit && onRescanWeb && (
              <button
                type="button"
                onClick={() => onRescanWeb(report.targetUrl)}
                className="h-9 px-3 rounded-md text-xs font-medium wb-surface-muted hover:border-white/25 text-slate-300 hover:text-white inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
                <span>Re-scan</span>
              </button>
            )}

            {report.isApkAudit && onRescanApk && (
              <button
                type="button"
                onClick={onRescanApk}
                className="h-9 px-3 rounded-md text-xs font-medium wb-surface-muted hover:border-white/25 text-slate-300 hover:text-white inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5 text-emerald-400" />
                <span>Re-scan APK</span>
              </button>
            )}

            <button
              type="button"
              onClick={onNewAudit}
              className="wb-primary-btn h-9 px-3.5 rounded-md text-xs font-semibold inline-flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <span>New Audit</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* ── ZONE 2: Above-the-Fold Executive Verdict (Score + Severity Strip + Priority Brief) ── */}
      <div className="wb-bezel p-1.5 rounded-2xl">
        <div className="wb-surface rounded-xl overflow-hidden grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-white/10 text-left">
          {/* Left: Score Ring */}
          <div className="lg:col-span-4">
            <ScoreGauge
              score={report.score}
              grade={report.grade}
              riskLevel={report.riskLevel}
              embedded
              subtitle={gaugeSubtitle}
            />
          </div>

          {/* Right: Severity Strip + Remediation Uplift + Priority Action Brief */}
          <div className="lg:col-span-8 p-5 flex flex-col justify-between gap-4">
            {/* Clickable Severity Strip (0 counts dimmed so real issues stand out!) */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
              {severityTiles.map((tile) => {
                const isZero = tile.count === 0;
                return (
                  <button
                    key={tile.label}
                    type="button"
                    disabled={isZero}
                    onClick={() => jumpToSeverity(tile.key)}
                    className={`p-3 rounded-lg border text-center transition-all flex flex-col items-center justify-center ${
                      isZero
                        ? 'bg-white/[0.02] border-white/[0.06] opacity-45 cursor-default'
                        : `${tile.activeClass} cursor-pointer`
                    }`}
                  >
                    <span
                      className={`text-2xl font-display font-semibold tabular-nums leading-none ${
                        isZero ? 'text-slate-500' : tile.numberClass
                      }`}
                    >
                      {tile.count}
                    </span>
                    <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-slate-400 mt-1.5">
                      {tile.label}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Severity Distribution Bar & Remediation Uplift Simulator */}
            {totalFindingsCount > 0 && (
              <div className="p-2.5 rounded-lg bg-black/30 border border-white/5 space-y-2">
                <div className="flex items-center justify-between text-[11px] font-mono flex-wrap gap-2">
                  <span className="text-slate-400 text-[10px] uppercase tracking-wider">
                    Severity Distribution ({totalFindingsCount} items)
                  </span>
                  {upliftDelta > 0 ? (
                    <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10.5px]">
                      <Zap className="w-3 h-3 text-emerald-400 shrink-0" />
                      <span>
                        Projected: <strong className="text-white">{report.score}</strong> → <strong className="text-emerald-300">{estUpliftScore}</strong> (+{upliftDelta} pts uplift)
                      </span>
                    </div>
                  ) : (
                    <div className="inline-flex items-center gap-1 text-emerald-400 text-[10.5px]">
                      <Check className="w-3 h-3" />
                      <span>Zero High/Critical Vulnerabilities</span>
                    </div>
                  )}
                </div>

                {/* Segmented Progress Bar */}
                <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden flex gap-0.5">
                  {critCount > 0 && (
                    <div
                      style={{ width: `${(critCount / totalFindingsCount) * 100}%` }}
                      className="bg-rose-500 h-full rounded-sm"
                      title={`Critical: ${critCount}`}
                    />
                  )}
                  {highCount > 0 && (
                    <div
                      style={{ width: `${(highCount / totalFindingsCount) * 100}%` }}
                      className="bg-orange-500 h-full rounded-sm"
                      title={`High: ${highCount}`}
                    />
                  )}
                  {medCount > 0 && (
                    <div
                      style={{ width: `${(medCount / totalFindingsCount) * 100}%` }}
                      className="bg-amber-400 h-full rounded-sm"
                      title={`Medium: ${medCount}`}
                    />
                  )}
                  {lowCount > 0 && (
                    <div
                      style={{ width: `${(lowCount / totalFindingsCount) * 100}%` }}
                      className="bg-cyan-400 h-full rounded-sm"
                      title={`Low: ${lowCount}`}
                    />
                  )}
                  {passCount > 0 && (
                    <div
                      style={{ width: `${(passCount / totalFindingsCount) * 100}%` }}
                      className="bg-emerald-500 h-full rounded-sm"
                      title={`Passed: ${passCount}`}
                    />
                  )}
                </div>
              </div>
            )}

            {/* Clean Executive Action Brief (Structured 3-Row Spec Format) */}
            {summaryRows.length > 0 && (
              <div className="wb-ide-evidence rounded-xl border border-white/10 p-4 space-y-3 flex-1">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-2">
                  <span className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.14em] font-semibold text-emerald-400">
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Priority Action Brief · Strategic Triage</span>
                  </span>
                  {hasWebHeaderGaps && (
                    <button
                      type="button"
                      onClick={() => setActiveTab('quickfix')}
                      className="font-mono text-[10px] font-semibold text-emerald-400 hover:underline inline-flex items-center gap-1 cursor-pointer no-print"
                    >
                      <span>Open 60s 1-File Fix</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  )}
                </div>

                <div className="space-y-2">
                  {summaryRows.map((row) => (
                    <div
                      key={row.num}
                      className="flex items-start gap-2.5 p-2 rounded-lg bg-black/25 border border-white/5 text-xs leading-relaxed"
                    >
                      <span className={`font-mono text-[9.5px] font-semibold px-2 py-0.5 rounded border shrink-0 mt-0.5 ${row.accent}`}>
                        {row.num} · {row.label}
                      </span>
                      <p className="text-slate-300 min-w-0 flex-1 break-words">
                        {row.text}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── ZONE 3: 4-Tab Security Workbench ── */}
      <div className="space-y-4">
        {/* Sticky Workbench Tab Navigation */}
        <div className="sticky top-14 z-30 bg-[#070a09]/95 backdrop-blur-md pt-2 pb-2 border-b border-white/10 flex items-center justify-between gap-3 overflow-x-auto no-print">
          <div className="flex items-center gap-1 min-w-max">
            <button
              type="button"
              onClick={() => setActiveTab('findings')}
              className={`relative px-4 py-2.5 text-xs font-medium inline-flex items-center gap-2 transition-colors cursor-pointer ${
                activeTab === 'findings'
                  ? 'text-white font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Shield className="w-3.5 h-3.5 text-emerald-400" />
              <span>Findings</span>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded wb-spec-code tabular-nums">
                {vulnFindings.length}
              </span>
              {activeTab === 'findings' && (
                <span className="absolute inset-x-3 -bottom-2 h-[2px] bg-emerald-400" />
              )}
            </button>

            {(hasWebHeaderGaps || report.isApkAudit) && (
              <button
                type="button"
                onClick={() => setActiveTab('quickfix')}
                className={`relative px-4 py-2.5 text-xs font-medium inline-flex items-center gap-2 transition-colors cursor-pointer ${
                  activeTab === 'quickfix'
                    ? 'text-white font-semibold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {report.isApkAudit ? (
                  <>
                    <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
                    <span>APK Internals</span>
                  </>
                ) : (
                  <>
                    <Wrench className="w-3.5 h-3.5 text-emerald-400" />
                    <span>60s Quick Fix</span>
                    <span className="font-mono text-[9.5px] px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                      1-File
                    </span>
                  </>
                )}
                {activeTab === 'quickfix' && (
                  <span className="absolute inset-x-3 -bottom-2 h-[2px] bg-emerald-400" />
                )}
              </button>
            )}

            <button
              type="button"
              onClick={() => setActiveTab('surface')}
              className={`relative px-4 py-2.5 text-xs font-medium inline-flex items-center gap-2 transition-colors cursor-pointer ${
                activeTab === 'surface'
                  ? 'text-white font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {report.isApkAudit ? (
                <Binary className="w-3.5 h-3.5 text-cyan-400" />
              ) : (
                <Globe className="w-3.5 h-3.5 text-cyan-400" />
              )}
              <span>Attack Surface</span>
              {activeTab === 'surface' && (
                <span className="absolute inset-x-3 -bottom-2 h-[2px] bg-emerald-400" />
              )}
            </button>

            {logsCount > 0 && (
              <button
                type="button"
                onClick={() => setActiveTab('logs')}
                className={`relative px-4 py-2.5 text-xs font-medium inline-flex items-center gap-2 transition-colors cursor-pointer ${
                  activeTab === 'logs'
                    ? 'text-white font-semibold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Terminal className="w-3.5 h-3.5 text-slate-400" />
                <span>Scan Logs</span>
                <span className="font-mono text-[10px] px-1.5 py-0.5 rounded wb-spec-code tabular-nums">
                  {logsCount}
                </span>
                {activeTab === 'logs' && (
                  <span className="absolute inset-x-3 -bottom-2 h-[2px] bg-emerald-400" />
                )}
              </button>
            )}
          </div>

          {/* Right Compact Target Context Badge in Sticky Bar */}
          <div className="hidden sm:flex items-center gap-2 pr-2 shrink-0 font-mono text-[10.5px]">
            <span className="text-slate-400 truncate max-w-[200px]" title={targetDisplay}>
              {targetDisplay}
            </span>
            <span className="text-slate-600">·</span>
            <span
              className={`px-2 py-0.5 rounded font-semibold border ${
                report.score >= 80
                  ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
                  : report.score >= 50
                  ? 'text-amber-400 bg-amber-500/10 border-amber-500/30'
                  : 'text-rose-400 bg-rose-500/10 border-rose-500/30'
              }`}
            >
              Score {report.score}/100
            </span>
          </div>
        </div>

        {/* ── TAB 1: FINDINGS (Always visible in Print/PDF too) ── */}
        <div className={activeTab === 'findings' ? 'space-y-4' : 'hidden print:block space-y-4'}>
          {/* Findings Toolbar: Severity Filter Pills + Search Input + Expand/Collapse All */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 no-print">
            {/* Filter Pills */}
            <div className="flex items-center gap-1.5 flex-wrap">
              {(
                [
                  { id: 'vulns' as FindingFilter, label: `Issues (${vulnFindings.length})`, show: true },
                  { id: 'CRITICAL' as FindingFilter, label: `Critical (${report.summaryCounts?.critical ?? 0})`, show: (report.summaryCounts?.critical ?? 0) > 0 },
                  { id: 'HIGH' as FindingFilter, label: `High (${report.summaryCounts?.high ?? 0})`, show: (report.summaryCounts?.high ?? 0) > 0 },
                  { id: 'MEDIUM' as FindingFilter, label: `Medium (${report.summaryCounts?.medium ?? 0})`, show: (report.summaryCounts?.medium ?? 0) > 0 },
                  { id: 'LOW' as FindingFilter, label: `Low (${report.summaryCounts?.low ?? 0})`, show: (report.summaryCounts?.low ?? 0) > 0 },
                  {
                    id: 'pass' as FindingFilter,
                    label: `${hasInfo ? 'Passed & Info' : 'Passed'} (${passAndInfoFindings.length})`,
                    show: passAndInfoFindings.length > 0,
                  },
                  { id: 'all' as FindingFilter, label: `All (${allFindings.length})`, show: true },
                ]
              )
                .filter((p) => p.show)
                .map((pill) => (
                  <button
                    key={pill.id}
                    type="button"
                    onClick={() => setFindingFilter(pill.id)}
                    className={`px-3 py-1.5 rounded-md font-mono text-[11px] font-medium border transition-colors cursor-pointer ${
                      findingFilter === pill.id
                        ? 'bg-emerald-500/12 border-emerald-500/35 text-emerald-400 font-semibold'
                        : 'bg-white/[0.03] border-white/10 text-slate-400 hover:text-white'
                    }`}
                  >
                    {pill.label}
                  </button>
                ))}
            </div>

            {/* Search Input & Expand/Collapse All Button */}
            <div className="flex items-center gap-2 shrink-0">
              <div className="relative min-w-[190px] flex-1 sm:w-56">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                <input
                  type="text"
                  value={findingSearch}
                  onChange={(e) => setFindingSearch(e.target.value)}
                  placeholder="Filter findings..."
                  className="w-full h-8 pl-8 pr-7 rounded-md font-mono text-xs bg-black/40 border border-white/15 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/30"
                />
                {findingSearch && (
                  <button
                    type="button"
                    onClick={() => setFindingSearch('')}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white cursor-pointer"
                    title="Clear filter"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              <button
                type="button"
                onClick={() => setAllExpanded((prev) => (prev === true ? false : true))}
                className="h-8 px-2.5 rounded-md font-mono text-[11px] font-medium border border-white/10 bg-white/[0.03] text-slate-300 hover:text-white inline-flex items-center gap-1.5 cursor-pointer shrink-0 transition-colors"
                title={allExpanded ? 'Collapse all finding cards' : 'Expand all finding cards'}
              >
                {allExpanded ? <ChevronUp className="w-3.5 h-3.5 text-emerald-400" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-400" />}
                <span className="hidden sm:inline">{allExpanded ? 'Collapse All' : 'Expand All'}</span>
              </button>
            </div>
          </div>

          {/* Findings Cards */}
          <div className="flex flex-col gap-3">
            {filteredFindings.length === 0 ? (
              <div className="wb-surface rounded-xl p-10 text-center text-slate-400 text-xs">
                {findingSearch ? (
                  <span>No findings matching &quot;{findingSearch}&quot;. Try a different keyword or clear the search.</span>
                ) : (
                  <span>No findings match this filter. Switch to <strong>All</strong> or <strong>Passed</strong> to view full results.</span>
                )}
              </div>
            ) : (
              filteredFindings.map((finding, idx) => (
                <FindingCard
                  key={`${finding.type}-${idx}`}
                  finding={finding}
                  detectedTech={report.telemetry?.detectedTech}
                  targetUrl={report.targetUrl}
                  defaultExpanded={idx === 0}
                  forceExpanded={allExpanded}
                  canUseAiFixDoctor={activePlanPolicy.features.aiFixDoctor}
                  onRequestUpgrade={onRequestUpgrade}
                />
              ))
            )}
          </div>
        </div>

        {/* ── TAB 2: 60s QUICK FIX (Web) OR APK INTERNALS (APK) ── */}
        {activeTab === 'quickfix' && (
          <div className="space-y-4 text-left">
            {!report.isApkAudit && hasWebHeaderGaps && (
              <div className="wb-bezel p-1.5 rounded-2xl">
                <div className="wb-surface rounded-xl p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
                        <Wrench className="w-4 h-4" />
                      </div>
                      <div>
                        <h3 className="text-sm font-display font-semibold text-white flex items-center gap-2 flex-wrap">
                          <span>60-Second Master Fix: Harden All Headers in 1 File</span>
                          <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                            {activePlanPolicy.features.aiFixDoctor ? 'Recommended' : 'Pro Security'}
                          </span>
                        </h3>
                        <p className="text-xs text-slate-400 mt-0.5">
                          {activePlanPolicy.features.aiFixDoctor
                            ? 'Paste this single config into your repo to resolve CSP, HSTS, X-Frame-Options & MIME sniffing together.'
                            : 'Unlock copy-paste Master Header packs for Vercel, Next.js & Express on Pro Security.'}
                        </p>
                      </div>
                    </div>

                    {activePlanPolicy.features.aiFixDoctor ? (
                      <div className="inline-flex items-center gap-1 wb-surface-muted p-1 rounded-md text-xs font-mono shrink-0">
                        {(['vercel', 'nextjs', 'express'] as const).map((tab) => (
                          <button
                            key={tab}
                            type="button"
                            onClick={() => setMasterTab(tab)}
                            className={`px-3 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                              masterTab === tab
                                ? 'bg-emerald-500/20 text-emerald-400 font-semibold'
                                : 'text-slate-400 hover:text-white'
                            }`}
                          >
                            {tab === 'vercel' ? 'Vercel' : tab === 'nextjs' ? 'Next.js' : 'Node/Express'}
                          </button>
                        ))}
                      </div>
                    ) : (
                      <button
                        type="button"
                        onClick={onRequestUpgrade}
                        className="wb-emerald-btn h-9 px-3.5 rounded-md text-xs font-semibold inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
                      >
                        <Lock className="w-3.5 h-3.5" />
                        <span>Unlock Master Fix</span>
                      </button>
                    )}
                  </div>

                  {activePlanPolicy.features.aiFixDoctor && (
                    <div className="rounded-lg border border-white/10 wb-surface-muted overflow-hidden text-xs">
                      <div className="wb-ide-chrome flex items-center justify-between px-4 py-2 border-b border-white/10">
                        <div className="flex items-center gap-2 text-slate-300 font-mono text-[11px]">
                          <Code2 className="w-3.5 h-3.5 text-emerald-400" />
                          <span>{masterCodes[masterTab].filename}</span>
                        </div>
                        <button
                          type="button"
                          onClick={() => handleCopyMaster(masterCodes[masterTab].code)}
                          className="inline-flex items-center gap-1.5 font-mono text-[10.5px] font-medium text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/15 px-2.5 py-1 rounded border border-emerald-500/30 cursor-pointer"
                        >
                          {masterCopied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                          <span>{masterCopied ? 'Copied' : 'Copy Config'}</span>
                        </button>
                      </div>
                      <pre className="p-4 text-[11.5px] font-mono text-emerald-300 overflow-x-auto leading-relaxed select-all">
                        {masterCodes[masterTab].code}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            )}

            {report.isApkAudit && report.apkMeta && (
              <div className="wb-bezel p-1.5 rounded-2xl relative">
                <div
                  aria-hidden="true"
                  className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
                />
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {/* Exported IPC Surface */}
                {report.apkMeta.exportedComponents && (
                  <div className="wb-surface rounded-xl p-5 space-y-3.5">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-emerald-400" />
                        <h3 className="font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-white">
                          Exported IPC Surface
                        </h3>
                      </div>
                      <span
                        className={`font-mono text-[10px] font-semibold px-2 py-0.5 rounded border ${
                          report.apkMeta.exportedComponents.unprotectedCount > 0
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        }`}
                      >
                        {report.apkMeta.exportedComponents.unprotectedCount > 0
                          ? `${report.apkMeta.exportedComponents.unprotectedCount} Unprotected`
                          : `${report.apkMeta.exportedComponents.totalExported} Audited`}
                      </span>
                    </div>

                    <div className="grid grid-cols-4 gap-2 text-center">
                      {[
                        { label: 'Activities', count: report.apkMeta.exportedComponents.activities.length },
                        { label: 'Services', count: report.apkMeta.exportedComponents.services.length },
                        { label: 'Receivers', count: report.apkMeta.exportedComponents.receivers.length },
                        { label: 'Providers', count: report.apkMeta.exportedComponents.providers.length },
                      ].map((box) => (
                        <div key={box.label} className="p-2.5 rounded-lg wb-surface-muted">
                          <span className="text-base font-display font-semibold tabular-nums text-white block">
                            {box.count}
                          </span>
                          <span className="font-mono text-[9px] uppercase text-slate-400">{box.label}</span>
                        </div>
                      ))}
                    </div>

                    <div className="space-y-1.5 max-h-52 overflow-y-auto pr-1 text-[11px] font-mono">
                      {[
                        ...report.apkMeta.exportedComponents.activities,
                        ...report.apkMeta.exportedComponents.services,
                        ...report.apkMeta.exportedComponents.receivers,
                        ...report.apkMeta.exportedComponents.providers,
                      ]
                        .slice(0, 12)
                        .map((c: any, idx: number) => (
                          <div
                            key={idx}
                            className="flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-md wb-surface-muted"
                          >
                            <span className="truncate text-slate-300" title={c.name}>
                              <span className="text-cyan-400">[{c.componentType[0].toUpperCase()}]</span>{' '}
                              {c.name.split('.').slice(-2).join('.')}
                            </span>
                            <span
                              className={`text-[9.5px] font-semibold px-1.5 py-0.5 rounded shrink-0 ${
                                c.risky
                                  ? 'bg-rose-500/15 text-rose-400'
                                  : c.isLauncher
                                  ? 'bg-cyan-500/15 text-cyan-400'
                                  : 'bg-emerald-500/15 text-emerald-400'
                              }`}
                            >
                              {c.risky ? 'UNPROTECTED' : c.isLauncher ? 'LAUNCHER' : 'GUARDED'}
                            </span>
                          </div>
                        ))}
                    </div>
                  </div>
                )}

                {/* Trackers, SDKs & Permissions */}
                <div className="wb-surface rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Radio className="w-4 h-4 text-cyan-400" />
                      <h3 className="font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-white">
                        Trackers, SDKs &amp; Permissions
                      </h3>
                    </div>
                    <span className="font-mono text-[10px] px-2 py-0.5 rounded wb-spec-code">
                      {report.apkMeta.permissions?.length || 0} Perms
                    </span>
                  </div>

                  <div className="space-y-3 text-xs">
                    <div>
                      <span className="font-mono text-[10px] uppercase text-amber-400 block mb-1.5">
                        Trackers ({report.apkMeta.trackers?.length || 0})
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {report.apkMeta.trackers?.length > 0 ? (
                          report.apkMeta.trackers.map((t: string, i: number) => (
                            <span key={i} className="font-mono text-[10px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/25">
                              {t}
                            </span>
                          ))
                        ) : (
                          <span className="text-[11px] text-slate-500">No ad/analytics trackers detected.</span>
                        )}
                      </div>
                    </div>

                    <div>
                      <span className="font-mono text-[10px] uppercase text-cyan-400 block mb-1.5">
                        Embedded SDKs ({report.apkMeta.sdks?.length || 0})
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {report.apkMeta.sdks?.length > 0 ? (
                          report.apkMeta.sdks.map((s: string, i: number) => (
                            <span key={i} className="font-mono text-[10px] px-2 py-0.5 rounded wb-spec-code">
                              {s}
                            </span>
                          ))
                        ) : (
                          <span className="text-[11px] text-slate-500">No external SDK footprints detected.</span>
                        )}
                      </div>
                    </div>

                    {report.apkMeta.permissions?.length > 0 && (
                      <div>
                        <span className="font-mono text-[10px] uppercase text-slate-400 block mb-1.5">
                          Declared Android Permissions
                        </span>
                        <div className="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto pr-1">
                          {report.apkMeta.permissions.map((perm: string, i: number) => (
                            <code key={i} className="font-mono text-[9.5px] px-1.5 py-0.5 rounded wb-spec-code">
                              {perm.replace('android.permission.', '')}
                            </code>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
            )}
          </div>
        )}

        {/* ── TAB 3: ATTACK SURFACE (Replaces "STAGE 2.5" Jargon) ── */}
        {activeTab === 'surface' && (
          <div className="space-y-4 text-left">
            {/* Web Attack Surface */}
            {!report.isApkAudit && report.webDeepSurface && (
              <div className="wb-bezel p-1.5 rounded-2xl">
                <div className="wb-surface rounded-xl overflow-hidden">
                  {/* Compact Posture Summary Strip */}
                  <div className="wb-ide-chrome px-5 py-3 border-b border-white/10 flex flex-wrap items-center justify-between gap-2 font-mono text-[10.5px]">
                    <span className="text-white font-semibold uppercase tracking-[0.12em] inline-flex items-center gap-2">
                      <Activity className="w-3.5 h-3.5 text-emerald-400" />
                      Web Attack Surface &amp; Network Posture
                    </span>
                    <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
                      <span className="px-2 py-0.5 rounded wb-spec-code">
                        {report.webDeepSurface.discoveredRoutes.length} Routes · {report.webDeepSurface.apiEndpoints.length} APIs
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded border font-semibold ${
                          report.webDeepSurface.domSinks.length > 0
                            ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                            : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        }`}
                      >
                        {report.webDeepSurface.domSinks.length} DOM Sink(s)
                      </span>
                      {report.networkPosture && (
                        <>
                          <span
                            className={`px-2 py-0.5 rounded border font-semibold ${
                              report.networkPosture.corsReflection === 'Strict'
                                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                                : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                            }`}
                          >
                            CORS: {report.networkPosture.corsReflection}
                          </span>
                          {report.networkPosture.tlsProtocol && (
                            <span className="px-2 py-0.5 rounded wb-spec-code">
                              {report.networkPosture.tlsProtocol}
                              {report.networkPosture.certDaysRemaining !== null
                                ? ` (${report.networkPosture.certDaysRemaining}d)`
                                : ''}
                            </span>
                          )}
                          {report.networkPosture.spfPresent !== null && (
                            <span className="px-2 py-0.5 rounded wb-spec-code">
                              SPF:{report.networkPosture.spfPresent ? 'Yes' : 'No'} · DMARC:{report.networkPosture.dmarcPolicy || 'none'}
                            </span>
                          )}
                        </>
                      )}
                    </div>
                  </div>

                  {/* 3 Clean Columns */}
                  <div className="grid grid-cols-1 lg:grid-cols-3 divide-y lg:divide-y-0 lg:divide-x divide-white/10 font-mono text-[11px]">
                    {/* Routes & OpenAPI */}
                    <div className="p-4 space-y-2">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-cyan-400">
                        Routes &amp; APIs ({report.webDeepSurface.openApiSpecs.length} OpenAPI)
                      </div>
                      <div className="max-h-44 overflow-y-auto space-y-1 pr-1 text-slate-300">
                        {report.webDeepSurface.openApiSpecs.map((sp: any, i: number) => (
                          <div key={i} className="text-amber-400 truncate" title={sp.url}>
                            OpenAPI: {sp.url.replace(/^https?:\/\/[^/]+/, '')} ({sp.pathsCount})
                          </div>
                        ))}
                        {report.webDeepSurface.apiEndpoints.slice(0, 10).map((ep: string, i: number) => (
                          <div key={`ep-${i}`} className="text-emerald-400 truncate" title={ep}>
                            API: {ep}
                          </div>
                        ))}
                        {report.webDeepSurface.discoveredRoutes.slice(0, 10).map((rt: string, i: number) => (
                          <div key={`rt-${i}`} className="text-slate-400 truncate" title={rt}>
                            Route: {rt}
                          </div>
                        ))}
                        {report.webDeepSurface.apiEndpoints.length === 0 &&
                          report.webDeepSurface.discoveredRoutes.length === 0 &&
                          report.webDeepSurface.openApiSpecs.length === 0 && (
                            <div className="text-slate-500">No extra routes or OpenAPI docs exposed.</div>
                          )}
                      </div>
                    </div>

                    {/* DOM XSS Sinks */}
                    <div className="p-4 space-y-2">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-rose-400">
                        Static DOM XSS Sinks ({report.webDeepSurface.domSinks.length})
                      </div>
                      <div className="max-h-44 overflow-y-auto space-y-1.5 pr-1">
                        {report.webDeepSurface.domSinks.length > 0 ? (
                          report.webDeepSurface.domSinks.slice(0, 8).map((sink: any, i: number) => (
                            <div key={i} className="p-2 rounded-md bg-rose-500/[0.08] border border-rose-500/20">
                              <div className="flex items-center justify-between gap-1 text-[10px]">
                                <span className="font-semibold text-rose-400">{sink.type}</span>
                                {sink.taintedByInput && (
                                  <span className="px-1.5 py-0.5 rounded bg-rose-500/25 text-white text-[9px]">TAINT</span>
                                )}
                              </div>
                              <div className="text-slate-300 text-[10px] truncate mt-0.5" title={sink.snippet}>
                                {sink.snippet}
                              </div>
                            </div>
                          ))
                        ) : (
                          <div className="text-emerald-400">0 unsafe eval / innerHTML / postMessage sinks matched.</div>
                        )}
                      </div>
                    </div>

                    {/* JWT & Auth Audit */}
                    <div className="p-4 space-y-2">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-emerald-400">
                        JWT &amp; Session Audit ({report.webDeepSurface.jwtAudits.length})
                      </div>
                      <div className="max-h-44 overflow-y-auto space-y-1.5 pr-1">
                        {report.webDeepSurface.jwtAudits.map((jt: any, i: number) => (
                          <div key={i} className="p-2 rounded-md wb-surface-muted space-y-0.5">
                            <div className="flex items-center justify-between text-[10px]">
                              <span className="text-white font-semibold">alg: {jt.alg}</span>
                              <span className={jt.hasExp ? 'text-emerald-400' : 'text-amber-400'}>
                                {jt.hasExp ? (jt.expired ? 'Expired' : 'Valid exp') : 'No exp'}
                              </span>
                            </div>
                            <div className="text-[10px] text-slate-400 truncate">
                              Claims: {jt.claims.join(', ')}
                            </div>
                            {jt.issues.length > 0 && (
                              <div className="text-[10px] text-rose-400 truncate">{jt.issues.join(' · ')}</div>
                            )}
                          </div>
                        ))}
                        {report.webDeepSurface.jwtAudits.length === 0 && (
                          <div className="text-slate-500">
                            No client JWTs detected. Attach an optional Bearer JWT in Scanner Auth Headers to audit protected routes.
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Optional Domain Verification Footer */}
                  <div className="wb-ide-chrome px-5 py-3 border-t border-white/10 space-y-2">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={onLoadDomainChallenge}
                        className="text-[11px] font-medium text-emerald-400 hover:underline inline-flex items-center gap-1.5 cursor-pointer"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Verify Domain Ownership (Unlock 15-Request Rate Burst)</span>
                      </button>
                      <span className="font-mono text-[10px] text-slate-500">
                        Unverified public targets run a safe 4-request profile
                      </span>
                    </div>

                    {domainChallenge && (
                      <div className="p-3 rounded-lg wb-surface-muted border border-emerald-500/25 text-[10.5px] font-mono space-y-1.5 text-slate-300">
                        <div className="text-emerald-400 font-semibold">
                          Add TXT record or HTML Meta Tag to verify &quot;{domainChallenge.host}&quot;:
                        </div>
                        <div className="p-1.5 rounded bg-black/40 break-all select-all text-cyan-400">
                          DNS TXT: {domainChallenge.txtRecord}
                        </div>
                        <div className="p-1.5 rounded bg-black/40 break-all select-all text-emerald-400">
                          HTML Meta: {domainChallenge.metaTag}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* APK Deep Attack Surface (Backend APIs + Dalvik CFG + Native ELF) */}
            {report.isApkAudit && report.apkMeta && (
              <div className="wb-bezel p-1.5 rounded-2xl relative">
                <div
                  aria-hidden="true"
                  className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent"
                />
                <div className="space-y-4">
                  {/* Extracted Backend APIs */}
                <div className="wb-surface rounded-xl p-5 space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Server className="w-4 h-4 text-emerald-400" />
                      <h3 className="font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-white">
                        Extracted Backend APIs &amp; Live Probes
                      </h3>
                    </div>
                    <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/25">
                      {report.apkMeta.probedApis?.length || 0} Probed
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono">
                    {report.apkMeta.probedApis?.length > 0 ? (
                      report.apkMeta.probedApis.map((api: any, idx: number) => (
                        <div key={idx} className="p-2.5 rounded-lg wb-surface-muted space-y-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="truncate text-cyan-400 font-medium" title={api.url}>
                              {api.url.replace(/^https?:\/\//, '')}
                            </span>
                            <span className="text-[9.5px] px-1.5 py-0.5 rounded wb-spec-code shrink-0">
                              {api.reachable ? `HTTP ${api.status} · ${api.latencyMs}ms` : String(api.status)}
                            </span>
                          </div>
                          <div className="text-[10px] text-slate-400 flex items-center gap-2">
                            <span>HSTS: {api.hsts ? 'Yes' : 'No'}</span>
                            <span>·</span>
                            <span className="truncate">CORS: {api.cors}</span>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-slate-500 text-xs">
                        No custom external API origins were hardcoded in DEX/JS bundles.
                      </div>
                    )}
                  </div>
                </div>

                {/* Dalvik Bytecode CFG + Native ELF */}
                {report.apkMeta.dexBytecodeGraph && (
                  <div className="wb-surface rounded-xl p-5 space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Binary className="w-4 h-4 text-cyan-400" />
                        <h3 className="font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-white">
                          Dalvik Bytecode CFG &amp; Native ELF Hardening
                        </h3>
                      </div>
                      <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
                        <span className="px-2 py-0.5 rounded wb-spec-code">
                          {report.apkMeta.dexBytecodeGraph.methodsAnalyzed.toLocaleString()} Methods · {report.apkMeta.dexBytecodeGraph.instructionsScanned.toLocaleString()} Opcodes
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded border font-semibold ${
                            report.apkMeta.dexBytecodeGraph.taintPaths.length > 0
                              ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                              : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          }`}
                        >
                          {report.apkMeta.dexBytecodeGraph.taintPaths.length} Taint Flow(s)
                        </span>
                      </div>
                    </div>

                    {report.apkMeta.dexBytecodeGraph.taintPaths.length > 0 && (
                      <div className="space-y-1.5">
                        {report.apkMeta.dexBytecodeGraph.taintPaths.slice(0, 6).map((tp: any, idx: number) => (
                          <div key={idx} className="p-2.5 rounded-lg bg-rose-500/[0.08] border border-rose-500/25 text-[11px] font-mono">
                            <div className="flex items-center justify-between gap-2 text-rose-400 font-semibold">
                              <span>{tp.source} → {tp.sink}</span>
                              <span className="text-[9.5px] px-1.5 py-0.5 rounded bg-rose-500/15">{tp.owaspRef}</span>
                            </div>
                            <div className="text-slate-300 mt-1 break-all text-[10.5px]">
                              {tp.callChain?.length >= 2 ? tp.callChain.join(' → ') : tp.methodSignature}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {report.apkMeta.nativeElfSummary?.uniqueLibrariesCount > 0 && (
                      <div className="pt-3 border-t border-white/10 space-y-2.5">
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <span className="font-mono text-[10.5px] font-semibold uppercase tracking-wider text-cyan-400">
                            Native ELF (.so) Binaries ({report.apkMeta.nativeElfSummary.uniqueLibrariesCount})
                          </span>
                          <span className="font-mono text-[10px] px-2 py-0.5 rounded wb-spec-code">
                            {report.apkMeta.nativeElfSummary.hardeningWeakCount > 0
                              ? `${report.apkMeta.nativeElfSummary.hardeningWeakCount} Weak Flags`
                              : 'PIE / NX / RELRO Hardened'}
                          </span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 font-mono text-[10px]">
                          {report.apkMeta.nativeElfSummary.libraries.slice(0, 9).map((lib: any, idx: number) => (
                            <div key={idx} className="p-2.5 rounded-lg wb-surface-muted space-y-1.5">
                              <div className="flex items-center justify-between gap-2">
                                <span className="truncate font-semibold text-white">{lib.baseName}</span>
                                <span className="text-[9px] text-slate-400 shrink-0">{lib.archBits}b {lib.abi}</span>
                              </div>
                              <div className="flex flex-wrap gap-1 text-[9px]">
                                <span className={`px-1.5 rounded ${lib.pie ? 'bg-emerald-500/15 text-emerald-400' : 'bg-rose-500/15 text-rose-400'}`}>PIE</span>
                                <span className={`px-1.5 rounded ${lib.nx ? 'bg-emerald-500/15 text-emerald-400' : 'bg-rose-500/15 text-rose-400'}`}>NX</span>
                                <span className={`px-1.5 rounded ${lib.stackCanary ? 'bg-emerald-500/15 text-emerald-400' : 'bg-amber-500/15 text-amber-400'}`}>Canary</span>
                                <span className={`px-1.5 rounded ${lib.relro !== 'NONE' ? 'bg-emerald-500/15 text-emerald-400' : 'bg-rose-500/15 text-rose-400'}`}>RELRO:{lib.relro}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
            )}
          </div>
        )}

        {/* ── TAB 4: SCAN LOGS ── */}
        {activeTab === 'logs' && report.telemetry?.realTimeLogs && (
          <div className="wb-bezel p-1.5 rounded-2xl text-left">
            <div className="wb-surface rounded-xl overflow-hidden">
              <div className="wb-ide-chrome px-4 py-2.5 border-b border-white/10 flex items-center justify-between font-mono text-[10.5px]">
                <span className="inline-flex items-center gap-2 text-slate-300 font-semibold">
                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                  Engine Telemetry Log ({logsCount} events)
                </span>
                <span className="text-slate-500">{report.scanTimestamp}</span>
              </div>
              <div className="p-4 font-mono text-[11.5px] text-slate-300 space-y-2 max-h-[420px] overflow-y-auto wb-surface-muted border-0">
                {report.telemetry.realTimeLogs.map((item: any, idx: number) => (
                  <div key={idx} className="flex gap-3 leading-relaxed">
                    <span className="text-emerald-400 shrink-0 tabular-nums">{item.time}</span>
                    <span>{item.msg}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── ZONE 4: Clean Automated Audit Disclaimer ── */}
      <div className="wb-surface rounded-xl p-4 sm:p-5 text-[11px] text-slate-400 leading-relaxed space-y-1.5 text-left print:break-inside-avoid">
        <div className="flex items-center gap-2 text-slate-300 font-mono font-semibold uppercase tracking-[0.12em] text-[10px]">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          <span>Automated Point-in-Time Security Assessment Disclaimer</span>
        </div>
        <p>
          This report reflects automated static analysis and non-destructive passive/safe dynamic checks performed by{' '}
          <strong className="text-white">CheckMyAPK.com</strong> at{' '}
          <span className="font-mono text-slate-300">{report.scanTimestamp}</span>. Items labeled{' '}
          <span className="text-emerald-400 font-semibold">Confirmed</span> were verified via live HTTP/TLS/DNS telemetry or binary/manifest structure;{' '}
          <span className="text-amber-400 font-semibold">Heuristic</span> items should be reviewed in runtime context.
        </p>
      </div>
    </div>
  );
};
