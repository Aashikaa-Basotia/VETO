import React, { useEffect, useState } from 'react';

export const CustomCursor: React.FC = () => {
  const [position, setPosition] = useState({ x: -100, y: -100 });
  const [isHovered, setIsHovered] = useState(false);
  const [isVisible, setIsVisible] = useState(false);
  const [isFinePointer, setIsFinePointer] = useState<boolean>(() => {
    if (typeof window !== 'undefined' && window.matchMedia) {
      return window.matchMedia('(pointer: fine)').matches;
    }
    return false;
  });

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;

    const mediaQuery = window.matchMedia('(pointer: fine)');
    const handleMediaChange = (e: MediaQueryListEvent) => {
      setIsFinePointer(e.matches);
    };

    mediaQuery.addEventListener('change', handleMediaChange);

    const onMouseMove = (e: MouseEvent) => {
      setPosition({ x: e.clientX, y: e.clientY });
      if (!isVisible) setIsVisible(true);

      const target = e.target as HTMLElement | null;
      if (target) {
        const interactive = target.closest('button, a, input, select, textarea, [role="button"], tr[class*="cursor-pointer"]');
        setIsHovered(!!interactive);
      }
    };

    const onMouseLeave = () => {
      setIsVisible(false);
    };

    window.addEventListener('mousemove', onMouseMove, { passive: true });
    document.addEventListener('mouseleave', onMouseLeave);

    return () => {
      mediaQuery.removeEventListener('change', handleMediaChange);
      window.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseleave', onMouseLeave);
    };
  }, [isVisible]);

  if (!isFinePointer || !isVisible) {
    return null;
  }

  return (
    <>
      {/* Center Reticle Dot */}
      <div
        className="fixed top-0 left-0 w-1.5 h-1.5 bg-[#A2B89A] rounded-full pointer-events-none z-50 transition-transform duration-75 ease-out -translate-x-1/2 -translate-y-1/2 shadow-[0_0_8px_rgba(162,184,154,0.6)]"
        style={{
          transform: `translate3d(${position.x}px, ${position.y}px, 0) scale(${isHovered ? 1.5 : 1})`,
        }}
      />
      {/* Outer Subtle Aura Ring */}
      <div
        className={`fixed top-0 left-0 rounded-full pointer-events-none z-50 border border-[#A2B89A]/30 transition-all duration-200 ease-out -translate-x-1/2 -translate-y-1/2 ${
          isHovered
            ? 'w-7 h-7 bg-[#A2B89A]/10 border-[#A2B89A]/50 scale-100'
            : 'w-5 h-5 scale-90 opacity-40'
        }`}
        style={{
          transform: `translate3d(${position.x}px, ${position.y}px, 0) translate(-50%, -50%)`,
        }}
      />
    </>
  );
};
