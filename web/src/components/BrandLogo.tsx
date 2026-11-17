import { useId } from "react";

type BrandLogoProps = { size?: number; className?: string };

export function BrandLogo({ size = 42, className = "" }: BrandLogoProps) {
  const id = useId().replaceAll(":", "");
  const gradientId = `${id}-gradient`;
  const glowId = `${id}-glow`;
  return (
    <svg
      aria-hidden="true"
      className={className}
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
    >
      <defs>
        <linearGradient id={gradientId} x1="7" y1="5" x2="42" y2="44" gradientUnits="userSpaceOnUse">
          <stop stopColor="#E6D9FF" />
          <stop offset=".55" stopColor="#AF8BFF" />
          <stop offset="1" stopColor="#7444D8" />
        </linearGradient>
        <filter id={glowId} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="2.4" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>
      <rect x="2" y="2" width="44" height="44" rx="14" fill={`url(#${gradientId})`} />
      <path d="M11 25h6l3.5-8 7 15 3.5-7h6" stroke="#211136" strokeWidth="2.8" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="11" cy="25" r="2" fill="#F3ECFF" filter={`url(#${glowId})`} />
      <circle cx="37" cy="25" r="2" fill="#F3ECFF" filter={`url(#${glowId})`} />
      <circle cx="24" cy="24" r="2.3" fill="#F3ECFF" />
    </svg>
  );
}
