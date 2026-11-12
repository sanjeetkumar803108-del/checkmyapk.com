import React, { useEffect, useRef, useState } from 'react';

interface RevealOnScrollProps {
  children: React.ReactNode;
  delayMs?: number;
  className?: string;
}

/**
 * Staggered scroll-triggered reveal wrapper (uses IntersectionObserver + GPU transform/blur)
 * so lower sections and cards glide in smoothly line-by-line as the visitor scrolls.
 */
export const RevealOnScroll: React.FC<RevealOnScrollProps> = ({
  children,
  delayMs = 0,
  className = '',
}) => {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (prefersReduced || typeof IntersectionObserver === 'undefined') {
      setVisible(true);
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setVisible(true);
            observer.unobserve(entry.target);
          }
        }
      },
      { threshold: 0.08, rootMargin: '0px 0px -28px 0px' }
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return (
    <div
      ref={ref}
      style={{
        transitionDelay: visible ? `${delayMs}ms` : '0ms',
      }}
      className={`bento-reveal-item ${visible ? 'is-visible' : ''} ${className}`}
    >
      {children}
    </div>
  );
};

