import React from "react";

export default function Sparkline({ data, color }) {
  const series = data && data.length ? data : [0, 0];
  const w = 200, h = 30, max = Math.max(...series, 1);
  const n = series.length;
  const pts = series
    .map((val, i) => `${n === 1 ? 0 : (i / (n - 1)) * w},${h - (val / max) * (h - 3) - 1}`)
    .join(" ");
  const id = "g" + color.replace(/[^a-z0-9]/gi, "");
  return (
    <svg className="spark" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <defs>
        <linearGradient id={id} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.28" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={`0,${h} ${pts} ${w},${h}`} fill={`url(#${id})`} />
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  );
}
