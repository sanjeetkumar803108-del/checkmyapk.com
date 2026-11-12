import React, { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';

interface ScoreGaugeProps {
  score: number;
  grade: string;
  riskLevel: string;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({ score, grade, riskLevel }) => {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let start = 0;
    const duration = 900;
    const startTime = performance.now();

    const step = (now: number) => {
      const progress = Math.min((now - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      start = Math.round(eased * score);
      setAnimatedScore(start);
      if (progress < 1) {
        requestAnimationFrame(step);
      }
    };

    requestAnimationFrame(step);
  }, [score]);

  const radius = 72;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  let strokeColor = '#10b981'; // Emerald
  let glowColor = 'rgba(16, 185, 129, 0.5)';
  let textColor = 'text-emerald-400';
  let badgeColor = 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
  let ringAura = 'from-emerald-500/15 via-transparent to-transparent';

  if (score < 60) {
    strokeColor = '#f43f5e';
    glowColor = 'rgba(244, 63, 94, 0.5)';
    textColor = 'text-rose-400';
    badgeColor = 'bg-rose-500/15 text-rose-300 border-rose-500/30';
    ringAura = 'from-rose-500/15 via-transparent to-transparent';
  } else if (score < 75) {
    strokeColor = '#f59e0b';
    glowColor = 'rgba(245, 158, 11, 0.5)';
    textColor = 'text-amber-400';
    badgeColor = 'bg-amber-500/15 text-amber-300 border-amber-500/30';
    ringAura = 'from-amber-500/15 via-transparent to-transparent';
  } else if (score < 90) {
    strokeColor = '#06b6d4';
    glowColor = 'rgba(6, 182, 212, 0.5)';
    textColor = 'text-cyan-400';
    badgeColor = 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30';
    ringAura = 'from-cyan-500/15 via-transparent to-transparent';
  }

  return (
    <div className="flex flex-col items-center justify-center p-6 glass-panel rounded-3xl relative overflow-hidden group">
      {/* Subtle Background Radial Aura */}
      <div className={`absolute inset-0 bg-gradient-to-b ${ringAura} pointer-events-none`} />

      <span className="text-[10px] font-extrabold uppercase tracking-[0.2em] text-slate-400 mb-3 relative z-10">
        OWASP Security Score
      </span>

      <div className="relative w-44 h-44 flex items-center justify-center z-10">
        <svg className="w-full h-full transform -rotate-90 drop-shadow-2xl">
          {/* Outer dashed calibration ticks */}
          <circle
            cx="88"
            cy="88"
            r={radius + 10}
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="2"
            strokeDasharray="3 7"
            fill="transparent"
          />

          {/* Track Circle */}
          <circle
            cx="88"
            cy="88"
            r={radius}
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="11"
            fill="transparent"
          />

          {/* Progress Circle with Glow */}
          <circle
            cx="88"
            cy="88"
            r={radius}
            stroke={strokeColor}
            strokeWidth="11"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            style={{
              filter: `drop-shadow(0 0 10px ${glowColor})`,
              transition: 'stroke-dashoffset 0.15s linear'
            }}
          />
        </svg>

        <div className="absolute flex flex-col items-center">
          <span className={`text-5xl font-black ${textColor} tracking-tighter leading-none`}>
            {animatedScore}
          </span>
          <span className="text-[11px] font-bold text-slate-400 uppercase tracking-widest mt-1.5 font-mono">
            / 100 PTS
          </span>
        </div>
      </div>

      <div className="mt-5 flex items-center gap-2 relative z-10 flex-wrap justify-center">
        <span className={`px-3.5 py-1 rounded-full text-xs font-black border flex items-center gap-1.5 shadow-lg ${badgeColor}`}>
          {score >= 75 ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldAlert className="w-3.5 h-3.5" />}
          Grade {grade}
        </span>
        <span className="px-3 py-1 rounded-full text-xs font-bold bg-white/5 text-slate-300 border border-white/10">
          Risk: <span className="text-white">{riskLevel}</span>
        </span>
      </div>
    </div>
  );
};
