import React from 'react';
import orbitalImage from '../assets/orbital_composite_2x.png';

export const OrbitalCenterpiece: React.FC = () => {
  return (
    <div className="relative w-full max-w-[330px] lg:max-w-[370px] xl:max-w-[410px] mx-auto select-none pointer-events-auto group">
      {/* Natural In-Flow Composition Asset ensuring solid dimensions */}
      <img
        src={orbitalImage}
        alt="VETO Deterministic Security Orbital Core"
        className="w-full h-auto block object-contain pointer-events-none select-none z-10"
      />

      {/* SVG Vector Precision Overlay (Crisp Wireframe Accents & Living Telemetry) */}
      <svg
        viewBox="0 0 347 435"
        className="absolute inset-0 w-full h-full overflow-visible z-20 pointer-events-none"
        aria-hidden="true"
      >
        <defs>
          <filter id="glowSubtle" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="2.5" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Dynamic Rotating Slow Wireframe Ring for subtle motion */}
        <g className="origin-[212px_193px] animate-orbit-slow opacity-40">
          <ellipse
            cx="212"
            cy="193"
            rx="130"
            ry="48"
            fill="none"
            stroke="#D0DEC7"
            strokeWidth="0.8"
            strokeDasharray="4 8"
            transform="rotate(-28 212 193)"
          />
        </g>

        {/* Counter-rotating wireframe ring */}
        <g className="origin-[212px_193px] animate-orbit-reverse opacity-30">
          <ellipse
            cx="212"
            cy="193"
            rx="118"
            ry="42"
            fill="none"
            stroke="#A2B89A"
            strokeWidth="0.6"
            strokeDasharray="2 6"
            transform="rotate(42 212 193)"
          />
        </g>

        {/* Interactive Pulsing Star Reticle Node (Bottom Left at x: 88, y: 395 in crop space) */}
        <g className="pointer-events-auto cursor-crosshair">
          <circle
            cx="87"
            cy="395"
            r="12"
            fill="none"
            stroke="#A2B89A"
            strokeWidth="0.8"
            opacity="0.6"
            className="animate-ping origin-[87px_395px]"
            style={{ animationDuration: '3s' }}
          />
        </g>
      </svg>
    </div>
  );
};