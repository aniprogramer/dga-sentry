interface BrandMarkProps {
  className?: string;
  size?: number;
  "aria-hidden"?: boolean | "true" | "false";
  "aria-label"?: string;
}

export default function BrandMark({
  className = "soc-brand-mark",
  size,
  "aria-hidden": ariaHidden = true,
  "aria-label": ariaLabel,
}: BrandMarkProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 64 64"
      width={size}
      height={size}
      className={className}
      aria-hidden={ariaLabel ? undefined : ariaHidden}
      aria-label={ariaLabel}
      role={ariaLabel ? "img" : undefined}
      fill="none"
    >
      <polygon
        points="32.00,3.50 7.32,17.75 7.32,46.25 32.00,60.50 56.68,46.25 56.68,17.75"
        fill="var(--surface-card)"
        stroke="var(--color-safe)"
        strokeWidth="3"
        strokeLinejoin="miter"
      />
      <path d="M32 32 L32.00 15.00" stroke="var(--color-safe)" strokeOpacity="0.55" strokeWidth="1.8" />
      <path d="M32 32 L17.28 23.50" stroke="var(--color-safe)" strokeOpacity="0.55" strokeWidth="1.8" />
      <path d="M32 32 L17.28 40.50" stroke="var(--color-safe)" strokeOpacity="0.55" strokeWidth="1.8" />
      <path d="M32 32 L32.00 49.00" stroke="var(--color-safe)" strokeOpacity="0.55" strokeWidth="1.8" />
      <path d="M32 32 L46.72 40.50" stroke="var(--color-safe)" strokeOpacity="0.55" strokeWidth="1.8" />
      <path d="M32 32 L46.72 23.50" stroke="var(--color-safe)" strokeOpacity="0.55" strokeWidth="1.8" />
      <rect x="29.00" y="12.00" width="6.00" height="6.00" fill="var(--color-safe)" />
      <rect x="14.28" y="20.50" width="6.00" height="6.00" fill="var(--color-safe)" />
      <rect x="14.28" y="37.50" width="6.00" height="6.00" fill="var(--color-safe)" />
      <rect x="29.00" y="46.00" width="6.00" height="6.00" fill="var(--color-malicious)" />
      <rect x="43.72" y="37.50" width="6.00" height="6.00" fill="var(--color-safe)" />
      <rect x="43.72" y="20.50" width="6.00" height="6.00" fill="var(--color-safe)" />
      <rect x="27.00" y="27.00" width="10.00" height="10.00" fill="var(--color-safe)" />
    </svg>
  );
}
