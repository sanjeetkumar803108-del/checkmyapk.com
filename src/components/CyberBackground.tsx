import React, { useEffect, useRef, useState } from 'react';
import { ArrowUp, ArrowDown, ArrowLeft, ArrowRight, Compass } from 'lucide-react';

interface Particle {
  x: number;
  y: number;
  z: number;
  baseX: number;
  baseY: number;
  size: number;
  hue: 'cyan' | 'purple' | 'emerald';
  pulseOffset: number;
}

interface Shockwave {
  x: number;
  y: number;
  radius: number;
  maxRadius: number;
  alpha: number;
  color: string;
}

interface CyberBackgroundProps {
  accentMode?: 'web' | 'apk';
}

export const CyberBackground: React.FC<CyberBackgroundProps> = ({ accentMode = 'apk' }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Track which arrow keys are currently held down (via keyboard OR on-screen HUD)
  const keysPressedRef = useRef<Record<string, boolean>>({
    ArrowUp: false,
    ArrowDown: false,
    ArrowLeft: false,
    ArrowRight: false,
  });

  const [activeKeys, setActiveKeys] = useState<Record<string, boolean>>({
    ArrowUp: false,
    ArrowDown: false,
    ArrowLeft: false,
    ArrowRight: false,
  });

  const [vectorHud, setVectorHud] = useState<{ speed: string; direction: string }>({
    speed: '1.0x',
    direction: 'CRUISE',
  });

  const accentModeRef = useRef(accentMode);
  useEffect(() => {
    accentModeRef.current = accentMode;
  }, [accentMode]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = window.innerWidth;
    let height = window.innerHeight;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    window.addEventListener('resize', resize);

    // Kinetic physics state controlled by Arrow Keys & Mouse
    const physics = {
      vx: 0,
      vy: 0,
      vz: 1.6, // Ambient forward flow
      targetVx: 0,
      targetVy: 0,
      targetVz: 1.6,
      gridOffsetZ: 0,
      gridOffsetX: 0,
      bankAngle: 0,
      mouseX: width / 2,
      mouseY: height / 2,
      mouseActive: false,
    };

    const shockwaves: Shockwave[] = [];

    const spawnShockwave = (dirKey: string) => {
      const colorMap: Record<string, string> = {
        ArrowUp: '6, 182, 212',     // Cyan
        ArrowDown: '16, 185, 129',  // Emerald
        ArrowLeft: '168, 85, 247',  // Purple
        ArrowRight: '56, 189, 248', // Sky
      };
      shockwaves.push({
        x: width / 2,
        y: height / 2,
        radius: 20,
        maxRadius: Math.max(width, height) * 0.65,
        alpha: 0.42,
        color: colorMap[dirKey] || '6, 182, 212',
      });
    };

    // Create 3D particles
    const PARTICLE_COUNT = 120;
    const DEPTH = 1200;
    const particles: Particle[] = Array.from({ length: PARTICLE_COUNT }, (_, i) => {
      const hues: Array<'cyan' | 'purple' | 'emerald'> = ['cyan', 'cyan', 'purple', 'emerald'];
      const x = (Math.random() - 0.5) * width * 2.2;
      const y = (Math.random() - 0.5) * height * 2.2;
      return {
        x,
        y,
        z: Math.random() * DEPTH + 100,
        baseX: x,
        baseY: y,
        size: Math.random() * 2 + 1.2,
        hue: hues[i % hues.length],
        pulseOffset: Math.random() * Math.PI * 2,
      };
    });

    // Keyboard Arrow Key Handlers
    const updateHudFromKeys = () => {
      const k = keysPressedRef.current;
      setActiveKeys({ ...k });

      const activeDirs: string[] = [];
      if (k.ArrowUp) activeDirs.push('THRUST');
      if (k.ArrowDown) activeDirs.push('REVERSE');
      if (k.ArrowLeft) activeDirs.push('PORT');
      if (k.ArrowRight) activeDirs.push('STARBOARD');

      const boostActive = k.ArrowUp || k.ArrowDown || k.ArrowLeft || k.ArrowRight;
      setVectorHud({
        speed: k.ArrowUp ? '4.8x' : k.ArrowDown ? '-3.2x' : boostActive ? '2.6x' : '1.0x',
        direction: activeDirs.length > 0 ? activeDirs.join(' + ') : 'CRUISE',
      });
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(e.key)) return;
      const activeTag = document.activeElement?.tagName;
      if (activeTag === 'INPUT' || activeTag === 'TEXTAREA' || activeTag === 'SELECT') return;

      if (!keysPressedRef.current[e.key]) {
        keysPressedRef.current[e.key] = true;
        spawnShockwave(e.key);
        updateHudFromKeys();
      }
    };

    const handleKeyUp = (e: KeyboardEvent) => {
      if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(e.key)) return;
      if (keysPressedRef.current[e.key]) {
        keysPressedRef.current[e.key] = false;
        updateHudFromKeys();
      }
    };

    const handleMouseMove = (e: MouseEvent) => {
      physics.mouseX = e.clientX;
      physics.mouseY = e.clientY;
      physics.mouseActive = true;
    };

    const handleMouseLeave = () => {
      physics.mouseActive = false;
    };

    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('keyup', handleKeyUp);
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseleave', handleMouseLeave);

    // Expose global trigger for on-screen D-pad HUD buttons
    (window as any).__triggerArrowKey = (key: string, pressed: boolean) => {
      const prev = keysPressedRef.current[key];
      keysPressedRef.current[key] = pressed;
      if (pressed && !prev) {
        spawnShockwave(key);
      }
      updateHudFromKeys();
    };

    let time = 0;

    const render = () => {
      time += 0.016;
      const k = keysPressedRef.current;

      // Compute target velocities from held Arrow Keys
      physics.targetVz = k.ArrowUp ? 14.5 : k.ArrowDown ? -10.5 : 1.5;
      physics.targetVx = (k.ArrowLeft ? 10.0 : 0) + (k.ArrowRight ? -10.0 : 0);
      physics.targetVy = (k.ArrowUp ? 2.5 : 0) + (k.ArrowDown ? -2.5 : 0);

      // Smooth inertial damping (buttery 60fps easing)
      physics.vz += (physics.targetVz - physics.vz) * 0.08;
      physics.vx += (physics.targetVx - physics.vx) * 0.08;
      physics.vy += (physics.targetVy - physics.vy) * 0.08;

      const targetBank = (k.ArrowLeft ? -0.05 : 0) + (k.ArrowRight ? 0.05 : 0);
      physics.bankAngle += (targetBank - physics.bankAngle) * 0.08;

      // Deep space / obsidian cyber backdrop
      ctx.fillStyle = '#04060c';
      ctx.fillRect(0, 0, width, height);

      // Ambient Aurora Gradient Glows (Subtle cyan & purple/emerald)
      const isApk = accentModeRef.current === 'apk';
      const primaryRgb = isApk ? '168, 85, 247' : '6, 182, 212';
      const secondaryRgb = isApk ? '6, 182, 212' : '16, 185, 129';

      const auraX = physics.mouseActive
        ? width * 0.5 + (physics.mouseX - width * 0.5) * 0.25
        : width * 0.5 + physics.vx * 18;
      const auraY = physics.mouseActive
        ? height * 0.35 + (physics.mouseY - height * 0.35) * 0.25
        : height * 0.35;

      const bgGrad = ctx.createRadialGradient(auraX, auraY, 10, auraX, auraY, Math.max(width, height) * 0.75);
      bgGrad.addColorStop(0, `rgba(${primaryRgb}, 0.14)`);
      bgGrad.addColorStop(0.45, `rgba(${secondaryRgb}, 0.05)`);
      bgGrad.addColorStop(1, 'rgba(4, 6, 12, 0)');
      ctx.fillStyle = bgGrad;
      ctx.fillRect(0, 0, width, height);

      // ── 1. 3D Perspective Cyber Floor Grid ──
      physics.gridOffsetZ = (physics.gridOffsetZ + physics.vz * 1.4) % 80;
      if (physics.gridOffsetZ < 0) physics.gridOffsetZ += 80;
      physics.gridOffsetX = (physics.gridOffsetX + physics.vx * 1.8) % 120;

      const horizonY = height * 0.54 + (physics.vy * 8);
      const fov = 420;

      ctx.save();
      ctx.translate(width / 2, height / 2);
      ctx.rotate(physics.bankAngle);
      ctx.translate(-width / 2, -height / 2);

      // Draw perspective horizon grid lines
      ctx.lineWidth = 1;
      const numVerticalLines = 22;
      for (let i = -numVerticalLines; i <= numVerticalLines; i++) {
        const worldX = i * 160 + physics.gridOffsetX;
        const x1 = width / 2 + (worldX * fov) / 1400;
        const y1 = horizonY;
        const x2 = width / 2 + (worldX * fov) / 120;
        const y2 = height + 180;

        const grad = ctx.createLinearGradient(x1, y1, x2, y2);
        grad.addColorStop(0, `rgba(${primaryRgb}, 0)`);
        grad.addColorStop(0.35, `rgba(${primaryRgb}, 0.14)`);
        grad.addColorStop(1, `rgba(${secondaryRgb}, 0.25)`);
        ctx.strokeStyle = grad;
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();
      }

      // Horizontal depth lines moving toward camera
      for (let zStep = 120; zStep < 1400; zStep += 80) {
        const z = zStep - physics.gridOffsetZ;
        if (z <= 40) continue;
        const scale = fov / z;
        const y = horizonY + 210 * scale;
        if (y > height + 100 || y < horizonY) continue;

        const alpha = Math.min(0.28, (1 - z / 1400) * 0.35);
        ctx.strokeStyle = `rgba(${secondaryRgb}, ${alpha})`;
        ctx.beginPath();
        ctx.moveTo(-200, y);
        ctx.lineTo(width + 200, y);
        ctx.stroke();
      }

      // ── 2. Projected 3D Neural Particles & Warp Trails ──
      const projectedPoints: Array<{ px: number; py: number; z: number; alpha: number; colorRgb: string }> = [];
      const parallaxX = physics.mouseActive ? (physics.mouseX - width / 2) * 0.04 : 0;
      const parallaxY = physics.mouseActive ? (physics.mouseY - height / 2) * 0.04 : 0;

      for (const p of particles) {
        p.z -= physics.vz;
        p.x += physics.vx * (1.2 - p.z / DEPTH);
        p.y += physics.vy * (1.2 - p.z / DEPTH);

        // Wrap Z depth seamlessly
        if (p.z <= 40) {
          p.z = DEPTH;
          p.x = (Math.random() - 0.5) * width * 2.2;
          p.y = (Math.random() - 0.5) * height * 2.2;
        } else if (p.z > DEPTH) {
          p.z = 50;
          p.x = (Math.random() - 0.5) * width * 2.2;
          p.y = (Math.random() - 0.5) * height * 2.2;
        }

        // Wrap lateral X/Y boundaries seamlessly
        const boundX = width * 1.4;
        const boundY = height * 1.4;
        if (p.x > boundX) p.x = -boundX;
        if (p.x < -boundX) p.x = boundX;
        if (p.y > boundY) p.y = -boundY;
        if (p.y < -boundY) p.y = boundY;

        const scale = fov / (fov + p.z);
        const px = width / 2 + (p.x - parallaxX * 4) * scale;
        const py = height / 2 + (p.y - parallaxY * 4) * scale;

        if (px < -100 || px > width + 100 || py < -100 || py > height + 100) continue;

        const pulse = 0.75 + 0.25 * Math.sin(time * 2.5 + p.pulseOffset);
        const alpha = Math.min(0.9, (1 - p.z / DEPTH) * 0.85 * pulse);

        const colorRgb =
          p.hue === 'purple'
            ? '168, 85, 247'
            : p.hue === 'emerald'
            ? '16, 185, 129'
            : '6, 182, 212';

        // Draw warp streak tail when velocity is high (Arrow Up/Down/Left/Right pressed!)
        const speedMagnitude = Math.abs(physics.vz) + Math.abs(physics.vx);
        if (speedMagnitude > 3.5) {
          const prevScale = fov / (fov + p.z + physics.vz * 2.8);
          const prevPx = width / 2 + (p.x - physics.vx * 2.2 - parallaxX * 4) * prevScale;
          const prevPy = height / 2 + (p.y - physics.vy * 2.2 - parallaxY * 4) * prevScale;

          ctx.strokeStyle = `rgba(${colorRgb}, ${alpha * 0.7})`;
          ctx.lineWidth = Math.max(0.8, p.size * scale * 1.3);
          ctx.beginPath();
          ctx.moveTo(prevPx, prevPy);
          ctx.lineTo(px, py);
          ctx.stroke();
        }

        // Draw luminous particle core
        ctx.fillStyle = `rgba(${colorRgb}, ${alpha})`;
        ctx.beginPath();
        ctx.arc(px, py, Math.max(0.9, p.size * scale * 1.6), 0, Math.PI * 2);
        ctx.fill();

        projectedPoints.push({ px, py, z: p.z, alpha, colorRgb });
      }

      // ── 3. Neural Constellation Connections (Nodes & Cursor Magnetic Links) ──
      const maxConnectDist = 140;
      for (let i = 0; i < projectedPoints.length; i++) {
        const a = projectedPoints[i];
        if (a.z > 750) continue;

        // Connect to nearby nodes
        for (let j = i + 1; j < projectedPoints.length; j++) {
          const b = projectedPoints[j];
          if (b.z > 750) continue;
          const dx = a.px - b.px;
          const dy = a.py - b.py;
          const distSq = dx * dx + dy * dy;
          if (distSq < maxConnectDist * maxConnectDist) {
            const lineAlpha = (1 - Math.sqrt(distSq) / maxConnectDist) * Math.min(a.alpha, b.alpha) * 0.25;
            ctx.strokeStyle = `rgba(${a.colorRgb}, ${lineAlpha})`;
            ctx.lineWidth = 0.7;
            ctx.beginPath();
            ctx.moveTo(a.px, a.py);
            ctx.lineTo(b.px, b.py);
            ctx.stroke();
          }
        }

        // Magnetic highlight to cursor
        if (physics.mouseActive) {
          const mdx = a.px - physics.mouseX;
          const mdy = a.py - physics.mouseY;
          const mDistSq = mdx * mdx + mdy * mdy;
          if (mDistSq < 180 * 180) {
            const mAlpha = (1 - Math.sqrt(mDistSq) / 180) * 0.35;
            ctx.strokeStyle = `rgba(${secondaryRgb}, ${mAlpha})`;
            ctx.lineWidth = 0.9;
            ctx.beginPath();
            ctx.moveTo(a.px, a.py);
            ctx.lineTo(physics.mouseX, physics.mouseY);
            ctx.stroke();
          }
        }
      }

      // ── 4. Radial Kinetic Shockwaves on Arrow Press ──
      for (let i = shockwaves.length - 1; i >= 0; i--) {
        const sw = shockwaves[i];
        sw.radius += 16;
        sw.alpha *= 0.94;
        ctx.strokeStyle = `rgba(${sw.color}, ${sw.alpha})`;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(sw.x, sw.y, sw.radius, 0, Math.PI * 2);
        ctx.stroke();
        if (sw.alpha < 0.02 || sw.radius > sw.maxRadius) {
          shockwaves.splice(i, 1);
        }
      }

      ctx.restore();

      // Subtle vignette to keep center UI crisp
      const vignette = ctx.createRadialGradient(
        width / 2,
        height / 2,
        Math.min(width, height) * 0.25,
        width / 2,
        height / 2,
        Math.max(width, height) * 0.85
      );
      vignette.addColorStop(0, 'rgba(4, 6, 12, 0)');
      vignette.addColorStop(1, 'rgba(4, 6, 12, 0.65)');
      ctx.fillStyle = vignette;
      ctx.fillRect(0, 0, width, height);

      animationFrameId = requestAnimationFrame(render);
    };

    animationFrameId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', resize);
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('keyup', handleKeyUp);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseleave', handleMouseLeave);
      delete (window as any).__triggerArrowKey;
    };
  }, []);

  const triggerHudKey = (key: string, pressed: boolean) => {
    if ((window as any).__triggerArrowKey) {
      (window as any).__triggerArrowKey(key, pressed);
    }
  };

  return (
    <>
      <canvas
        ref={canvasRef}
        className="fixed inset-0 pointer-events-none z-0"
        aria-hidden="true"
      />

      {/* Interactive Arrow-Key Kinetic D-Pad HUD (Bottom Right) */}
      <div className="fixed bottom-4 right-4 z-40 hidden sm:flex items-center gap-3 px-3.5 py-2.5 rounded-2xl glass-panel no-print select-none shadow-2xl border border-white/10">
        <div className="flex flex-col text-left pr-2 border-r border-white/10">
          <span className="text-[9px] font-extrabold uppercase tracking-widest text-cyan-400 flex items-center gap-1">
            <Compass className="w-3 h-3 animate-spin" style={{ animationDuration: '8s' }} />
            Matrix Vector
          </span>
          <span className="text-[11px] font-mono font-bold text-white mt-0.5">
            {vectorHud.direction} <span className="text-emerald-400">{vectorHud.speed}</span>
          </span>
          <span className="text-[9px] text-slate-400">Use Arrow Keys ↑↓←→</span>
        </div>

        {/* Interactive Clickable / Keyboard-Synced Arrow Pad */}
        <div className="grid grid-cols-3 gap-1 w-20">
          <div></div>
          <button
            type="button"
            aria-label="Thrust Up"
            onMouseDown={() => triggerHudKey('ArrowUp', true)}
            onMouseUp={() => triggerHudKey('ArrowUp', false)}
            onMouseLeave={() => triggerHudKey('ArrowUp', false)}
            className={`w-6 h-6 rounded-md flex items-center justify-center border transition-all cursor-pointer ${
              activeKeys.ArrowUp
                ? 'bg-cyan-500 text-slate-950 border-cyan-300 shadow-[0_0_12px_rgba(6,182,212,0.8)] scale-110'
                : 'bg-white/5 text-slate-400 border-white/10 hover:text-white hover:bg-white/10'
            }`}
          >
            <ArrowUp className="w-3 h-3" />
          </button>
          <div></div>

          <button
            type="button"
            aria-label="Steer Left"
            onMouseDown={() => triggerHudKey('ArrowLeft', true)}
            onMouseUp={() => triggerHudKey('ArrowLeft', false)}
            onMouseLeave={() => triggerHudKey('ArrowLeft', false)}
            className={`w-6 h-6 rounded-md flex items-center justify-center border transition-all cursor-pointer ${
              activeKeys.ArrowLeft
                ? 'bg-purple-500 text-white border-purple-300 shadow-[0_0_12px_rgba(168,85,247,0.8)] scale-110'
                : 'bg-white/5 text-slate-400 border-white/10 hover:text-white hover:bg-white/10'
            }`}
          >
            <ArrowLeft className="w-3 h-3" />
          </button>
          <button
            type="button"
            aria-label="Reverse Down"
            onMouseDown={() => triggerHudKey('ArrowDown', true)}
            onMouseUp={() => triggerHudKey('ArrowDown', false)}
            onMouseLeave={() => triggerHudKey('ArrowDown', false)}
            className={`w-6 h-6 rounded-md flex items-center justify-center border transition-all cursor-pointer ${
              activeKeys.ArrowDown
                ? 'bg-emerald-500 text-slate-950 border-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.8)] scale-110'
                : 'bg-white/5 text-slate-400 border-white/10 hover:text-white hover:bg-white/10'
            }`}
          >
            <ArrowDown className="w-3 h-3" />
          </button>
          <button
            type="button"
            aria-label="Steer Right"
            onMouseDown={() => triggerHudKey('ArrowRight', true)}
            onMouseUp={() => triggerHudKey('ArrowRight', false)}
            onMouseLeave={() => triggerHudKey('ArrowRight', false)}
            className={`w-6 h-6 rounded-md flex items-center justify-center border transition-all cursor-pointer ${
              activeKeys.ArrowRight
                ? 'bg-cyan-400 text-slate-950 border-cyan-200 shadow-[0_0_12px_rgba(56,189,248,0.8)] scale-110'
                : 'bg-white/5 text-slate-400 border-white/10 hover:text-white hover:bg-white/10'
            }`}
          >
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>
      </div>
    </>
  );
};

