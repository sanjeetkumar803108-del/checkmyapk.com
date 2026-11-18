import React, { useEffect, useState } from 'react';

interface WordSegment {
  text: string;
  cls: string;
}

const LINE_ONE_WORDS: WordSegment[] = [
  { text: 'Find', cls: 'text-white' },
  { text: 'leaked', cls: 'wb-accent-ink' },
  { text: 'secrets', cls: 'wb-accent-ink' },
  { text: 'and', cls: 'text-white' },
  { text: 'flaws', cls: 'text-white' },
];

const LINE_TWO_WORDS: WordSegment[] = [
  { text: 'in', cls: 'wb-headline-muted' },
  { text: 'your', cls: 'wb-headline-muted' },
  { text: 'APK', cls: 'text-white' },
  { text: 'or', cls: 'wb-headline-muted' },
  { text: 'Web', cls: 'text-white' },
  { text: 'App.', cls: 'text-white' },
];

const LINE_TWO_TOTAL_LETTERS = LINE_TWO_WORDS.reduce(
  (sum, word) => sum + Array.from(word.text).length,
  0
);

interface HeroKineticHeadlineProps {
  introDone: boolean;
}

export const HeroKineticHeadline: React.FC<HeroKineticHeadlineProps> = ({ introDone }) => {
  // Precompute sequential letter index across Line 1 (Left -> Right) and Line 2 (Right -> Left)
  let lineOneIdx = 0;
  let lineTwoIdx = 0;

  return (
    <h1
      aria-label="Find leaked secrets and flaws in your APK or Web App."
      className="wb-hero-perspective font-display font-bold text-4xl sm:text-6xl lg:text-[66px] leading-[1.09] tracking-[-0.045em] text-white"
    >
      {/* Line 1: 3D Flying Letter Wave (Left -> Right) */}
      <span
        aria-hidden="true"
        className="inline-flex flex-wrap items-baseline justify-center gap-x-[0.26em] gap-y-1"
      >
        {LINE_ONE_WORDS.map((word) => {
          const letters = Array.from(word.text);
          return (
            <span key={word.text} className={`inline-flex items-baseline whitespace-nowrap ${word.cls}`}>
              {letters.map((ch, i) => {
                const delayMs = 80 + lineOneIdx * 28;
                lineOneIdx += 1;
                return (
                  <span
                    key={`${word.text}-${i}`}
                    className={introDone ? 'inline-block' : 'wb-char-fly'}
                    style={introDone ? undefined : { animationDelay: `${delayMs}ms` }}
                  >
                    {ch}
                  </span>
                );
              })}
            </span>
          );
        })}
      </span>

      <br className="hidden sm:block" />{' '}

      {/* Line 2: Mirrored Opposite 3D Flying Letter Wave (Right -> Left) */}
      <span
        aria-hidden="true"
        className="inline-flex flex-wrap items-baseline justify-center gap-x-[0.26em] gap-y-1"
      >
        {LINE_TWO_WORDS.map((word, wIdx) => {
          const letters = Array.from(word.text);
          return (
            <span
              key={`${word.text}-${wIdx}`}
              className={`inline-flex items-baseline whitespace-nowrap ${word.cls}`}
            >
              {letters.map((ch, i) => {
                const reverseOrder = LINE_TWO_TOTAL_LETTERS - 1 - lineTwoIdx;
                const delayMs = 680 + reverseOrder * 30;
                lineTwoIdx += 1;
                return (
                  <span
                    key={`${word.text}-${i}`}
                    className={introDone ? 'inline-block' : 'wb-char-fly-reverse'}
                    style={introDone ? undefined : { animationDelay: `${delayMs}ms` }}
                  >
                    {ch}
                  </span>
                );
              })}
            </span>
          );
        })}
      </span>
    </h1>
  );
};

interface HeroRulesCountUpProps {
  target?: number;
  startDelayMs?: number;
  durationMs?: number;
  introDone: boolean;
}

export const HeroRulesCountUp: React.FC<HeroRulesCountUpProps> = ({
  target = 35,
  startDelayMs = 1580,
  durationMs = 1150,
  introDone,
}) => {
  const [count, setCount] = useState<number>(() => (introDone ? target : 0));
  const [finished, setFinished] = useState<boolean>(introDone);

  useEffect(() => {
    if (introDone) {
      setCount(target);
      setFinished(true);
      return;
    }

    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

    if (prefersReduced) {
      setCount(target);
      setFinished(true);
      return;
    }

    let rafId = 0;
    const delayTimer = window.setTimeout(() => {
      const startTime = performance.now();
      const tick = (now: number) => {
        const elapsed = now - startTime;
        const progress = Math.min(1, elapsed / durationMs);
        // Smooth ease-out cubic deceleration (fast start, crisp landing on 35)
        const eased = 1 - Math.pow(1 - progress, 3);
        const nextVal = Math.round(eased * target);
        setCount(nextVal);
        if (progress < 1) {
          rafId = window.requestAnimationFrame(tick);
        } else {
          setCount(target);
          setFinished(true);
        }
      };
      rafId = window.requestAnimationFrame(tick);
    }, startDelayMs);

    return () => {
      window.clearTimeout(delayTimer);
      if (rafId) window.cancelAnimationFrame(rafId);
    };
  }, [target, startDelayMs, durationMs, introDone]);

  return (
    <span className="inline-flex items-baseline tabular-nums">
      <span>{count}</span>
      <span
        className={`text-emerald-400 transition-all duration-300 ${
          finished ? 'opacity-100 scale-100' : 'opacity-0 scale-75'
        }`}
      >
        +
      </span>
    </span>
  );
};
