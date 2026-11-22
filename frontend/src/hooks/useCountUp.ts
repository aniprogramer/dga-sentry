import { useState, useEffect } from "react";

export function useCountUp(target: number, duration: number = 500, decimals: number = 1): string {
  const isReduced = typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const [displayValue, setDisplayValue] = useState<number>(() => {
    return isReduced || typeof window === "undefined" ? target : 0;
  });

  useEffect(() => {
    if (typeof window === "undefined" || isReduced) {
      return;
    }

    let startTime: number | null = null;
    let animId: number;
    const startVal = 0;

    const easeOutCubic = (t: number): number => {
      return 1 - Math.pow(1 - t, 3);
    };

    const step = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const elapsed = timestamp - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const easedProgress = easeOutCubic(progress);
      const current = startVal + (target - startVal) * easedProgress;

      setDisplayValue(current);

      if (progress < 1) {
        animId = requestAnimationFrame(step);
      } else {
        setDisplayValue(target);
      }
    };

    animId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(animId);
  }, [target, duration, isReduced]);

  return (isReduced ? target : displayValue).toFixed(decimals);
}
