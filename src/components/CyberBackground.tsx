import React from 'react';

interface CyberBackgroundProps {
  accentMode?: 'web' | 'apk';
  theme?: 'dark' | 'light';
}

/**
 * Architectural micro-grid backdrop — calm, zero visual noise behind typography,
 * and instant dark/light sync during directional curtain transitions.
 */
export const CyberBackground: React.FC<CyberBackgroundProps> = () => {
  return (
    <div
      className="wb-grid-bg fixed inset-0 pointer-events-none z-0 overflow-hidden no-print"
      aria-hidden="true"
    />
  );
};
