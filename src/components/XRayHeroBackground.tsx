import React, { useEffect, useRef } from 'react';

/**
 * X-Ray Vulnerability Radar — Hero background.
 * A hidden layer of leaked-secret fragments sits under the grid. An emerald radar
 * spotlight auto-sweeps (and follows the cursor on desktop); only inside that circle
 * are the secrets "revealed" and flagged. Zero media download, GPU-cheap CSS masks.
 */

interface Fragment {
  text: string;
  x: number; // % from left
  y: number; // % from top
  sev: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  mobile?: boolean;
}

// Positioned in the outer bands so the centered headline always stays crisp.
const FRAGMENTS: Fragment[] = [
  { text: 'AIzaSyD-9xQ2kLmR7vT0pW3nE8', x: 4, y: 12, sev: 'HIGH', mobile: true },
  { text: 'android:debuggable="true"', x: 6, y: 30, sev: 'CRITICAL' },
  { text: 'sk_live_51MxKq8Ld2pZ...', x: 3, y: 50, sev: 'CRITICAL', mobile: true },
  { text: 'usesCleartextTraffic="true"', x: 7, y: 68, sev: 'HIGH' },
  { text: 'Access-Control-Allow-Origin: *', x: 4, y: 86, sev: 'MEDIUM', mobile: true },
  { text: 'classes2.dex → SecretKeySpec("k3y")', x: 77, y: 10, sev: 'HIGH', mobile: true },
  { text: 'mongodb+srv://admin:p4ss@cl0', x: 80, y: 27, sev: 'CRITICAL' },
  { text: 'AES/ECB/PKCS5Padding', x: 83, y: 45, sev: 'MEDIUM', mobile: true },
  { text: 'X509TrustManager { /* trust all */ }', x: 76, y: 62, sev: 'CRITICAL' },
  { text: '/.env → 200 OK', x: 84, y: 80, sev: 'HIGH', mobile: true },
  { text: 'ghp_7Rk2Lq0Vx9mN3tY8wB1z', x: 24, y: 5, sev: 'HIGH' },
  { text: 'exported="true" · no permission', x: 58, y: 4, sev: 'HIGH' },
  { text: 'jwt alg: "none"', x: 27, y: 93, sev: 'CRITICAL' },
  { text: 'main.js.map exposed', x: 60, y: 94, sev: 'MEDIUM' },
];

const SEV_STYLE: Record<Fragment['sev'], string> = {
  CRITICAL: 'xray-tag-critical',
  HIGH: 'xray-tag-high',
  MEDIUM: 'xray-tag-medium',
};

const RADIUS = 210;

export const XRayHeroBackground: React.FC = () => {
  const rootRef = useRef<HTMLDivElement | null>(null);
  const fragRefs = useRef<Array<HTMLDivElement | null>>([]);

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const finePointer = window.matchMedia('(pointer: fine)').matches;

    let rafId = 0;
    let lastMouseAt = 0;
    let mouseX = 0;
    let mouseY = 0;
    let curX = -9999;
    let curY = -9999;
    const start = performance.now();

    const onMove = (e: MouseEvent) => {
      const rect = root.getBoundingClientRect();
      if (e.clientY < rect.top || e.clientY > rect.bottom) return;
      mouseX = e.clientX - rect.left;
      mouseY = e.clientY - rect.top;
      lastMouseAt = performance.now();
    };
    if (finePointer && !reduceMotion) {
      window.addEventListener('mousemove', onMove, { passive: true });
    }

    const tick = (now: number) => {
      const w = root.clientWidth;
      const h = root.clientHeight;
      const t = (now - start) / 1000;

      // Auto radar path (slow Lissajous sweep covering the outer bands)
      const autoX = w * (0.5 + 0.42 * Math.sin(t * 0.32));
      const autoY = h * (0.5 + 0.38 * Math.sin(t * 0.51 + 1.2));

      const followingMouse = finePointer && now - lastMouseAt < 2600;
      const targetX = reduceMotion ? w * 0.14 : followingMouse ? mouseX : autoX;
      const targetY = reduceMotion ? h * 0.3 : followingMouse ? mouseY : autoY;

      if (curX < -1000) {
        curX = targetX;
        curY = targetY;
      } else {
        const ease = followingMouse ? 0.14 : 0.05;
        curX += (targetX - curX) * ease;
        curY += (targetY - curY) * ease;
      }

      root.style.setProperty('--xr-x', `${curX.toFixed(1)}px`);
      root.style.setProperty('--xr-y', `${curY.toFixed(1)}px`);

      // Flag fragments currently inside the radar circle
      for (let i = 0; i < FRAGMENTS.length; i++) {
        const el = fragRefs.current[i];
        if (!el) continue;
        const fx = (FRAGMENTS[i].x / 100) * w + 60;
        const fy = (FRAGMENTS[i].y / 100) * h;
        const dist = Math.hypot(fx - curX, fy - curY);
        const inside = dist < RADIUS * 0.72;
        if (inside !== el.classList.contains('is-flagged')) {
          el.classList.toggle('is-flagged', inside);
        }
      }

      if (!reduceMotion) rafId = requestAnimationFrame(tick);
    };

    rafId = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(rafId);
      window.removeEventListener('mousemove', onMove);
    };
  }, []);

  const renderFragments = (revealed: boolean) =>
    FRAGMENTS.map((f, i) => (
      <div
        key={`${revealed ? 'r' : 'd'}-${i}`}
        ref={revealed ? (el) => { fragRefs.current[i] = el; } : undefined}
        className={`xray-frag absolute font-mono whitespace-nowrap ${f.mobile ? '' : 'hidden md:block'}`}
        style={{ left: `${f.x}%`, top: `${f.y}%` }}
      >
        <span className="xray-frag-text">{f.text}</span>
        {revealed && (
          <span className={`xray-tag ${SEV_STYLE[f.sev]}`}>⚠ {f.sev}</span>
        )}
      </div>
    ));

  return (
    <div
      ref={rootRef}
      aria-hidden="true"
      className="xray-root pointer-events-none absolute inset-y-0 left-1/2 -translate-x-1/2 w-screen overflow-hidden select-none"
    >
      {/* Layer 1: barely-visible "dark" secrets */}
      <div className="xray-layer-dim absolute inset-0">{renderFragments(false)}</div>

      {/* Layer 2: revealed secrets + bright grid, masked to the radar circle */}
      <div className="xray-layer-reveal absolute inset-0">
        <div className="xray-grid-bright absolute inset-0" />
        {renderFragments(true)}
      </div>

      {/* Radar spotlight: glow + rotating sweep + rings */}
      <div className="xray-spot">
        <div className="xray-spot-glow" />
        <div className="xray-spot-sweep" />
        <div className="xray-spot-ring" />
        <div className="xray-spot-ring xray-spot-ring-inner" />
        <div className="xray-spot-cross" />
      </div>

      {/* Keep headline zone readable + fade edges into page background */}
      <div className="xray-center-veil absolute inset-0" />
      <div className="xray-edge-fade absolute inset-0" />
    </div>
  );
};
