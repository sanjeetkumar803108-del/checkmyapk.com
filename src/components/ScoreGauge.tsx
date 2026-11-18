import React, { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';

interface ScoreGaugeProps {
  score: number;
  grade: string;
  riskLevel: string;
  embedded?: boolean;
  subtitle?: string;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  score,
  grade,
  riskLevel,
  embedded = false,
  subtitle,
}) => {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let rafId = 0;
    const duration = 850;
    const startTime = performance.now();

    const step = (now: number) => {
      const progress = Math.min((now - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setAnimatedScore(Math.round(eased * score));
      if (progress < 1) {
        rafId = requestAnimationFrame(step);
      }
    };

    rafId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(rafId);
  }, [score]);

  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  let strokeColor = '#10b981';
  let glowColor = 'rgba(16, 185, 129, 0.35)';
  let textColor = 'text-emerald-400';
  let badgeColor = 'bg-emerald-500/12 text-emerald-400 border-emerald-500/30';
  let ringAura = 'from-emerald-500/[0.08] via-transparent to-transparent';

  if (score < 60) {
    strokeColor = '#f43f5e';
    glowColor = 'rgba(244, 63, 94, 0.35)';
    textColor = 'text-rose-400';
    badgeColor = 'bg-rose-500/12 text-rose-400 border-rose-500/30';
    ringAura = 'from-rose-500/[0.08] via-transparent to-transparent';
  } else if (score < 75) {
    strokeColor = '#f59e0b';
    glowColor = 'rgba(245, 158, 11, 0.35)';
    textColor = 'text-amber-400';
    badgeColor = 'bg-amber-500/12 text-amber-400 border-amber-500/30';
    ringAura = 'from-amber-500/[0.08] via-transparent to-transparent';
  } else if (score < 90) {
    strokeColor = '#06b6d4';
    glowColor = 'rgba(6, 182, 212, 0.35)';
    textColor = 'text-cyan-400';
    badgeColor = 'bg-cyan-500/12 text-cyan-400 border-cyan-500/30';
    ringAura = 'from-cyan-500/[0.08] via-transparent to-transparent';
  }

  return (
    <div
      className={`flex flex-col items-center justify-center p-6 relative overflow-hidden ${
        embedded ? 'h-full' : 'wb-surface rounded-xl'
      }`}
    >
      <div className={`absolute inset-0 bg-gradient-to-b ${ringAura} pointer-events-none`} />

      <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-400 mb-3 relative z-10">
        Security Score
      </span>

      <div className="relative w-40 h-40 flex items-center justify-center z-10">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
          <circle
            cx="80"
            cy="80"
            r={radius + 9}
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="1.5"
            strokeDasharray="3 6"
            fill="transparent"
          />
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="10"
            fill="transparent"
          />
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke={strokeColor}
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            style={{
              filter: `drop-shadow(0 0 8px ${glowColor})`,
              transition: 'stroke-dashoffset 0.15s linear',
            }}
          />
        </svg>

        <div className="absolute flex flex-col items-center">
          <span
            className={`text-[44px] font-display font-semibold tabular-nums ${textColor} tracking-[-0.04em] leading-none`}
          >
            {animatedScore}
          </span>
          <span className="font-mono text-[10px] font-medium text-slate-400 uppercase tracking-[0.14em] mt-1.5">
            / 100 pts
          </span>
        </div>
      </div>

      <div className="mt-4 flex items-center gap-2 relative z-10 flex-wrap justify-center">
        <span
          className={`px-2.5 py-1 rounded-md font-mono text-[11px] font-semibold border inline-flex items-center gap-1.5 ${badgeColor}`}
        >
          {score >= 75 ? (
            <ShieldCheck className="w-3.5 h-3.5" />
          ) : (
            <ShieldAlert className="w-3.5 h-3.5" />
          )}
          Grade {grade}
        </span>
        <span className="px-2.5 py-1 rounded-md font-mono text-[11px] font-medium bg-white/[0.04] text-slate-400 border border-white/10">
          Risk: <span className="text-white font-semibold">{riskLevel}</span>
        </span>
      </div>

      {subtitle && (
        <p className="mt-3 font-mono text-[10px] text-slate-500 text-center relative z-10">
          {subtitle}
        </p>
      )}
    </div>
  );
};
