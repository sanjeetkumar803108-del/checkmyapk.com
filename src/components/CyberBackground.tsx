import React, { useEffect, useRef } from 'react';

interface CyberBackgroundProps {
  accentMode?: 'web' | 'apk';
  theme?: 'dark' | 'light';
}

interface Joint {
  x: number;
  y: number;
}

interface RibbonTentacle {
  joints: Joint[];
  segLen: number;
  baseAngleOffset: number;
  anchorRadius: number;
  waveFreq: number;
  waveAmp: number;
  phase: number;
  thickness: number;
  colorStop: number;
}

interface PlanktonSpore {
  x: number;
  y: number;
  vx: number;
  vy: number;
  size: number;
  phase: number;
  wake: number; // 0..1 excitation when touched by cursor or creature
}

interface CoreNode {
  orbitR: number;
  angle: number;
  speed: number;
  wobblePhase: number;
  x: number;
  y: number;
}

const APK_PALETTE: ReadonlyArray<[number, number, number]> = [
  [34, 211, 238],  // Electric Cyan
  [129, 140, 248], // Neon Indigo
  [192, 132, 252], // Bioluminescent Violet
  [244, 114, 182], // Plasma Magenta
  [52, 211, 153],  // Cyber Emerald
];

const WEB_PALETTE: ReadonlyArray<[number, number, number]> = [
  [34, 211, 238],  // Electric Cyan
  [16, 185, 129],  // Emerald
  [56, 189, 248],  // Cerulean Sky
  [45, 212, 191],  // Teal Mint
  [167, 139, 250], // Soft Violet
];

const LIGHT_APK_PALETTE: ReadonlyArray<[number, number, number]> = [
  [2, 132, 199],   // Deep Sky Cyan
  [79, 70, 229],   // Crisp Indigo
  [124, 58, 237],  // Royal Violet
  [219, 39, 119],  // Rich Magenta
  [5, 150, 105],   // Deep Emerald
];

const LIGHT_WEB_PALETTE: ReadonlyArray<[number, number, number]> = [
  [2, 132, 199],   // Deep Sky Cyan
  [5, 150, 105],   // Deep Emerald
  [37, 99, 235],   // Cobalt Blue
  [13, 148, 136],  // Rich Teal
  [109, 40, 217],  // Crisp Violet
];

function samplePalette(
  palette: ReadonlyArray<[number, number, number]>,
  tNorm: number
): [number, number, number] {
  const wrapped = ((tNorm % 1) + 1) % 1;
  const scaled = wrapped * palette.length;
  const idx = Math.floor(scaled) % palette.length;
  const nextIdx = (idx + 1) % palette.length;
  const frac = scaled - Math.floor(scaled);
  const c1 = palette[idx];
  const c2 = palette[nextIdx];
  return [
    Math.round(c1[0] + (c2[0] - c1[0]) * frac),
    Math.round(c1[1] + (c2[1] - c1[1]) * frac),
    Math.round(c1[2] + (c2[2] - c1[2]) * frac),
  ];
}

/**
 * Unique Living Neural Medusa / Cyber-Organism Backdrop:
 * 1) Articulated Silk Ribbons: 12 multi-jointed translucent tendrils that flex & swim behind
 *    a steering head following your cursor arrow with organic inertia.
 * 2) Harmonic Morphing Membranes: 3 breathing Fourier-spline shells + rotating neural synapse
 *    constellation inside the living core.
 * 3) Reactive Ecosystem Spores: Floating plankton spores that awaken, streak along the wake,
 *    and link with faint neural filaments as the organism glides past.
 * 4) Click Sonar Pulse: Clicking emits a living sonar wave and ripples energy down every ribbon.
 */
export const CyberBackground: React.FC<CyberBackgroundProps> = ({ accentMode = 'apk', theme = 'dark' }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const accentModeRef = useRef<'web' | 'apk'>(accentMode);
  const themeRef = useRef<'dark' | 'light'>(theme);

  useEffect(() => {
    accentModeRef.current = accentMode;
  }, [accentMode]);

  useEffect(() => {
    themeRef.current = theme;
  }, [theme]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return;

    const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    let prefersReducedMotion = reducedMotionQuery.matches;

    let width = window.innerWidth;
    let height = window.innerHeight;
    let rafId = 0;

    const resizeCanvas = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    resizeCanvas();
    const isCompact = width < 768;

    // Living creature head & cursor tracking state
    const creature = {
      x: width * 0.24,
      y: height * 0.34,
      vx: 0,
      vy: 0,
      heading: 0,
      targetX: width * 0.5,
      targetY: height * 0.36,
      mouseActive: false,
      lastMoveAt: 0,
      pulse: 0,
      pulseX: width * 0.5,
      pulseY: height * 0.36,
      pulseRadius: 0,
      pulseAlpha: 0,
    };

    // 1) Articulated silk tentacle ribbons
    const RIBBON_COUNT = isCompact ? 7 : 12;
    const JOINTS_PER_RIBBON = isCompact ? 16 : 22;
    const ribbons: RibbonTentacle[] = Array.from({ length: RIBBON_COUNT }, (_, i) => {
      const spread = (i / Math.max(1, RIBBON_COUNT - 1)) - 0.5; // -0.5 .. +0.5
      const segLen = (isCompact ? 9.5 : 13) + (i % 3) * 2.2;
      const startAngle = Math.PI + spread * 1.45;
      return {
        joints: Array.from({ length: JOINTS_PER_RIBBON }, (__, j) => ({
          x: creature.x + Math.cos(startAngle) * j * segLen,
          y: creature.y + Math.sin(startAngle) * j * segLen,
        })),
        segLen,
        baseAngleOffset: spread * 1.55,
        anchorRadius: (isCompact ? 16 : 24) + (i % 2) * 8,
        waveFreq: 2.1 + (i % 4) * 0.35,
        waveAmp: 0.22 + Math.abs(spread) * 0.28,
        phase: i * 0.72,
        thickness: 2.2 - Math.abs(spread) * 0.7,
        colorStop: i / RIBBON_COUNT,
      };
    });

    // 2) Rotating internal neural synapse constellation nodes
    const CORE_NODE_COUNT = isCompact ? 10 : 16;
    const coreNodes: CoreNode[] = Array.from({ length: CORE_NODE_COUNT }, (_, i) => ({
      orbitR: 0.35 + ((i * 37) % 100) / 145,
      angle: (i / CORE_NODE_COUNT) * Math.PI * 2,
      speed: (i % 2 === 0 ? 1 : -1) * (0.35 + (i % 5) * 0.12),
      wobblePhase: i * 1.13,
      x: creature.x,
      y: creature.y,
    }));

    // 3) Reactive ecosystem plankton spores
    const SPORE_COUNT = isCompact ? 80 : 170;
    const spores: PlanktonSpore[] = Array.from({ length: SPORE_COUNT }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.32,
      vy: (Math.random() - 0.5) * 0.32,
      size: 0.9 + Math.random() * 1.45,
      phase: Math.random() * Math.PI * 2,
      wake: 0,
    }));

    const handleResize = () => {
      resizeCanvas();
      for (let i = 0; i < spores.length; i++) {
        spores[i].x = Math.min(width, Math.max(0, spores[i].x));
        spores[i].y = Math.min(height, Math.max(0, spores[i].y));
      }
    };

    const handleMouseMove = (e: MouseEvent) => {
      creature.mouseActive = true;
      creature.lastMoveAt = performance.now();
      creature.targetX = e.clientX;
      creature.targetY = e.clientY;
    };

    const handleMouseDown = (e: MouseEvent) => {
      creature.mouseActive = true;
      creature.lastMoveAt = performance.now();
      creature.targetX = e.clientX;
      creature.targetY = e.clientY;
      creature.pulse = 1.0;
      creature.pulseX = creature.x;
      creature.pulseY = creature.y;
      creature.pulseRadius = 18;
      creature.pulseAlpha = 0.55;
    };

    const handleMouseLeave = () => {
      creature.mouseActive = false;
    };

    const handleTouchMove = (e: TouchEvent) => {
      if (e.touches.length > 0) {
        creature.mouseActive = true;
        creature.lastMoveAt = performance.now();
        creature.targetX = e.touches[0].clientX;
        creature.targetY = e.touches[0].clientY;
      }
    };

    const handleReducedMotionChange = (e: MediaQueryListEvent) => {
      prefersReducedMotion = e.matches;
      if (prefersReducedMotion) {
        cancelAnimationFrame(rafId);
        renderFrame(performance.now(), true);
      } else {
        rafId = requestAnimationFrame(loop);
      }
    };

    window.addEventListener('resize', handleResize);
    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    window.addEventListener('mousedown', handleMouseDown, { passive: true });
    document.addEventListener('mouseleave', handleMouseLeave);
    window.addEventListener('touchmove', handleTouchMove, { passive: true });
    reducedMotionQuery.addEventListener('change', handleReducedMotionChange);

    const drawMorphingMembrane = (
      cx: number,
      cy: number,
      baseR: number,
      t: number,
      shellIdx: number,
      strokeStyle: string,
      lineWidth: number
    ) => {
      const steps = 64;
      ctx.beginPath();
      for (let s = 0; s <= steps; s++) {
        const a = (s / steps) * Math.PI * 2;
        const harmonic =
          1 +
          0.11 * Math.sin(a * 3 + t * (1.2 + shellIdx * 0.2) + shellIdx * 1.7) +
          0.065 * Math.cos(a * 5 - t * 0.95 + shellIdx) +
          0.035 * Math.sin(a * 2 + creature.heading);
        const r = baseR * harmonic;
        // Slight teardrop elongation in swimming direction
        const forwardPull = Math.cos(a - creature.heading) * (baseR * 0.12);
        const px = cx + Math.cos(a) * (r + forwardPull);
        const py = cy + Math.sin(a) * (r + forwardPull);
        if (s === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.strokeStyle = strokeStyle;
      ctx.lineWidth = lineWidth;
      ctx.stroke();
    };

    const renderFrame = (nowMs: number, staticOnly = false) => {
      const t = nowMs * 0.001;
      ctx.clearRect(0, 0, width, height);

      const minDim = Math.min(width, height);
      const compact = width < 768;
      const isLight = themeRef.current === 'light';
      const palette = isLight
        ? (accentModeRef.current === 'web' ? LIGHT_WEB_PALETTE : LIGHT_APK_PALETTE)
        : (accentModeRef.current === 'web' ? WEB_PALETTE : APK_PALETTE);

      // Autonomous graceful patrol orbit around hero area when cursor rests > 3.2s
      const isIdle = !creature.mouseActive || nowMs - creature.lastMoveAt > 3200;
      const goalX = isIdle
        ? width * 0.5 + Math.sin(t * 0.42) * Math.min(width * 0.28, 320)
        : creature.targetX;
      const goalY = isIdle
        ? height * 0.36 + Math.sin(t * 0.84) * Math.min(height * 0.14, 110)
        : creature.targetY;

      if (!staticOnly) {
        // Spring-smooth swimming kinematics
        const dx = goalX - creature.x;
        const dy = goalY - creature.y;
        const dist = Math.hypot(dx, dy);

        // Gentle orbital hover right around cursor instead of dead-stopping stiffly
        const hoverOffsetX = isIdle ? 0 : Math.cos(t * 1.4) * 14;
        const hoverOffsetY = isIdle ? 0 : Math.sin(t * 1.4) * 14;

        const pullStrength = dist > 6 ? 0.036 : 0.014;
        creature.vx = creature.vx * 0.86 + (dx + hoverOffsetX) * pullStrength;
        creature.vy = creature.vy * 0.86 + (dy + hoverOffsetY) * pullStrength;
        creature.x += creature.vx;
        creature.y += creature.vy;

        const speed = Math.hypot(creature.vx, creature.vy);
        if (speed > 0.25) {
          const desiredHeading = Math.atan2(creature.vy, creature.vx);
          const angleDiff = Math.atan2(
            Math.sin(desiredHeading - creature.heading),
            Math.cos(desiredHeading - creature.heading)
          );
          creature.heading += angleDiff * 0.14;
        }

        creature.pulse *= 0.94;
        if (creature.pulseAlpha > 0.005) {
          creature.pulseRadius += 5.5;
          creature.pulseAlpha *= 0.94;
        }
      }

      const swimSpeed = Math.hypot(creature.vx, creature.vy);
      const coreR = (compact ? minDim * 0.095 : Math.min(minDim * 0.095, 76)) * (1 + creature.pulse * 0.28);

      // 0) Soft bioluminescent aura halo & click sonar wave
      const [hR, hG, hB] = samplePalette(palette, t * 0.04);
      const auraGrad = ctx.createRadialGradient(
        creature.x,
        creature.y,
        0,
        creature.x,
        creature.y,
        coreR * 3.8
      );
      auraGrad.addColorStop(0, `rgba(${hR}, ${hG}, ${hB}, ${isLight ? '0.09' : '0.11'})`);
      auraGrad.addColorStop(0.45, `rgba(${hR}, ${hG}, ${hB}, 0.04)`);
      auraGrad.addColorStop(1, isLight ? 'rgba(248, 250, 252, 0)' : 'rgba(4, 6, 12, 0)');
      ctx.fillStyle = auraGrad;
      ctx.beginPath();
      ctx.arc(creature.x, creature.y, coreR * 3.8, 0, Math.PI * 2);
      ctx.fill();

      if (creature.pulseAlpha > 0.01) {
        ctx.beginPath();
        ctx.arc(creature.pulseX, creature.pulseY, creature.pulseRadius, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(${hR}, ${hG}, ${hB}, ${(creature.pulseAlpha * 0.5).toFixed(3)})`;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      // 1) Update & render reactive plankton spores + slipstream neural links
      const wakeRadius = coreR * 3.1;
      for (let i = 0; i < spores.length; i++) {
        const s = spores[i];
        const sdx = s.x - creature.x;
        const sdy = s.y - creature.y;
        const sDist = Math.hypot(sdx, sdy);

        if (!staticOnly) {
          // Ambient drift
          s.vx += Math.cos(t * 0.6 + s.phase) * 0.008;
          s.vy += Math.sin(t * 0.5 + s.phase * 1.3) * 0.008;

          // Living slipstream swirl when the creature glides nearby
          if (sDist > 2 && sDist < wakeRadius) {
            const proximity = 1 - sDist / wakeRadius;
            s.wake = Math.min(1, s.wake + proximity * 0.14);
            const nx = sdx / sDist;
            const ny = sdy / sDist;
            // Gentle tangential swirl + outward ripple on click pulse
            const swirlForce = proximity * (0.14 + swimSpeed * 0.02 + creature.pulse * 0.6);
            s.vx += (-ny * 0.8 + nx * (0.25 + creature.pulse)) * swirlForce;
            s.vy += (nx * 0.8 + ny * (0.25 + creature.pulse)) * swirlForce;
          } else {
            s.wake *= 0.96;
          }

          s.vx *= 0.97;
          s.vy *= 0.97;
          s.x += s.vx;
          s.y += s.vy;

          if (s.x < -16) s.x = width + 16;
          if (s.x > width + 16) s.x = -16;
          if (s.y < -16) s.y = height + 16;
          if (s.y > height + 16) s.y = -16;
        }

        const [sR, sG, sB] = samplePalette(palette, s.phase / (Math.PI * 2) + t * 0.03);
        const baseAlpha = 0.14 + s.wake * 0.55;
        ctx.fillStyle = s.wake > 0.15
          ? `rgba(${sR}, ${sG}, ${sB}, ${baseAlpha.toFixed(3)})`
          : isLight
            ? `rgba(71, 85, 105, ${(0.14 + 0.06 * Math.sin(t + s.phase)).toFixed(3)})`
            : `rgba(148, 163, 184, ${(0.12 + 0.06 * Math.sin(t + s.phase)).toFixed(3)})`;

        ctx.beginPath();
        ctx.arc(s.x, s.y, s.size * (1 + s.wake * 0.7), 0, Math.PI * 2);
        ctx.fill();

        // Delicate neural thread connecting awakened spores to creature membrane
        if (s.wake > 0.35 && sDist < coreR * 2.2) {
          ctx.beginPath();
          ctx.moveTo(s.x, s.y);
          ctx.lineTo(
            creature.x + (sdx / sDist) * (coreR * 0.88),
            creature.y + (sdy / sDist) * (coreR * 0.88)
          );
          ctx.strokeStyle = `rgba(${sR}, ${sG}, ${sB}, ${(s.wake * 0.16).toFixed(3)})`;
          ctx.lineWidth = 0.75;
          ctx.stroke();
        }
      }

      // 2) Update & render 12 flowing bioluminescent silk ribbons (articulated tendrils)
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';

      for (let rIdx = 0; rIdx < ribbons.length; rIdx++) {
        const rib = ribbons[rIdx];
        const anchorAngle = creature.heading + Math.PI + rib.baseAngleOffset;
        const anchorX = creature.x + Math.cos(anchorAngle) * (rib.anchorRadius * 0.55);
        const anchorY = creature.y + Math.sin(anchorAngle) * (rib.anchorRadius * 0.55);

        rib.joints[0].x = anchorX;
        rib.joints[0].y = anchorY;

        if (!staticOnly) {
          const pulseTravel = creature.pulse * 0.8;
          for (let j = 1; j < rib.joints.length; j++) {
            const prev = rib.joints[j - 1];
            const curr = rib.joints[j];

            // Swimming lateral undulation propagating from head to tail tip
            const waveRatio = j / rib.joints.length;
            const wavePhase = t * rib.waveFreq - j * 0.42 + rib.phase;
            const waveForce = Math.sin(wavePhase) * (rib.waveAmp + waveRatio * 0.42 + pulseTravel * waveRatio);
            const perpAngle = anchorAngle + Math.PI * 0.5;

            const targetX = curr.x + Math.cos(perpAngle) * waveForce * 2.2 + Math.cos(anchorAngle) * 0.55;
            const targetY = curr.y + Math.sin(perpAngle) * waveForce * 2.2 + Math.sin(anchorAngle) * 0.55;

            let jdx = targetX - prev.x;
            let jdy = targetY - prev.y;
            let jDist = Math.hypot(jdx, jdy);
            if (jDist < 0.001) {
              jdx = Math.cos(anchorAngle);
              jdy = Math.sin(anchorAngle);
              jDist = 1;
            }
            curr.x = prev.x + (jdx / jDist) * rib.segLen;
            curr.y = prev.y + (jdy / jDist) * rib.segLen;
          }
        }

        // Smooth tapered gradient segments along each ribbon
        const [rR, rG, rB] = samplePalette(palette, rib.colorStop + t * 0.045);
        for (let j = 0; j < rib.joints.length - 1; j++) {
          const p0 = rib.joints[j];
          const p1 = rib.joints[j + 1];
          const progress = 1 - j / rib.joints.length;
          const segAlpha = (0.06 + progress * 0.34 + creature.pulse * 0.16) * (0.75 + 0.25 * Math.sin(t * 2 - j * 0.3 + rib.phase));
          ctx.beginPath();
          ctx.moveTo(p0.x, p0.y);
          ctx.lineTo(p1.x, p1.y);
          ctx.strokeStyle = `rgba(${rR}, ${rG}, ${rB}, ${Math.min(0.65, segAlpha).toFixed(3)})`;
          ctx.lineWidth = Math.max(0.45, rib.thickness * progress * 1.15);
          ctx.stroke();
        }

        // Tiny glowing bioluminescent tip orb at each tentacle end
        const tip = rib.joints[rib.joints.length - 1];
        ctx.fillStyle = `rgba(${rR}, ${rG}, ${rB}, 0.55)`;
        ctx.beginPath();
        ctx.arc(tip.x, tip.y, 1.5, 0, Math.PI * 2);
        ctx.fill();
      }

      // 3) Render morphing translucent harmonic core membranes
      for (let shell = 0; shell < 3; shell++) {
        const [mR, mG, mB] = samplePalette(palette, shell * 0.28 + t * 0.04);
        const shellR = coreR * (0.56 + shell * 0.26);
        const shellAlpha = 0.28 - shell * 0.06 + creature.pulse * 0.15;
        drawMorphingMembrane(
          creature.x,
          creature.y,
          shellR,
          t,
          shell,
          `rgba(${mR}, ${mG}, ${mB}, ${Math.min(0.55, shellAlpha).toFixed(3)})`,
          1.45 - shell * 0.25
        );
      }

      // 4) Internal neural synapse constellation inside the living core
      for (let i = 0; i < coreNodes.length; i++) {
        const cn = coreNodes[i];
        const a = cn.angle + t * cn.speed;
        const r = coreR * 0.62 * cn.orbitR * (1 + 0.15 * Math.sin(t * 1.8 + cn.wobblePhase));
        cn.x = creature.x + Math.cos(a) * r;
        cn.y = creature.y + Math.sin(a) * r;
      }

      for (let i = 0; i < coreNodes.length; i++) {
        const n1 = coreNodes[i];
        const [nR, nG, nB] = samplePalette(palette, i / coreNodes.length + t * 0.05);
        for (let j = i + 1; j < coreNodes.length; j++) {
          const n2 = coreNodes[j];
          const nd = Math.hypot(n1.x - n2.x, n1.y - n2.y);
          if (nd < coreR * 0.72) {
            const linkAlpha = (1 - nd / (coreR * 0.72)) * 0.26;
            ctx.beginPath();
            ctx.moveTo(n1.x, n1.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.strokeStyle = `rgba(${nR}, ${nG}, ${nB}, ${linkAlpha.toFixed(3)})`;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
        ctx.fillStyle = `rgba(${nR}, ${nG}, ${nB}, 0.68)`;
        ctx.beginPath();
        ctx.arc(n1.x, n1.y, 1.45, 0, Math.PI * 2);
        ctx.fill();
      }
    };

    const loop = (now: number) => {
      if (document.visibilityState === 'visible') {
        renderFrame(now, false);
      }
      rafId = requestAnimationFrame(loop);
    };

    if (prefersReducedMotion) {
      renderFrame(performance.now(), true);
    } else {
      rafId = requestAnimationFrame(loop);
    }

    return () => {
      cancelAnimationFrame(rafId);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mousedown', handleMouseDown);
      document.removeEventListener('mouseleave', handleMouseLeave);
      window.removeEventListener('touchmove', handleTouchMove);
      reducedMotionQuery.removeEventListener('change', handleReducedMotionChange);
    };
  }, []);

  return (
    <div
      className="fixed inset-0 pointer-events-none z-0 overflow-hidden no-print"
      aria-hidden="true"
    >
      <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" />
    </div>
  );
};
