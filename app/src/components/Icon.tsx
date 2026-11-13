import type { ReactNode } from 'react';

const P: Record<string, ReactNode> = {
  overview: (<><rect x="3.5" y="3.5" width="7" height="9" rx="1.6" /><rect x="13.5" y="3.5" width="7" height="5" rx="1.6" /><rect x="13.5" y="11.5" width="7" height="9" rx="1.6" /><rect x="3.5" y="15.5" width="7" height="5" rx="1.6" /></>),
  policies: (<><circle cx="6" cy="6" r="2.4" /><circle cx="6" cy="18" r="2.4" /><circle cx="18" cy="12" r="2.4" /><path d="M6 8.4v7.2M8.2 7.1l7.6 3.8M8.2 16.9l7.6-3.8" /></>),
  nodes: (<><circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17M12 3.5c2.4 2.6 3.5 5.4 3.5 8.5s-1.1 5.9-3.5 8.5c-2.4-2.6-3.5-5.4-3.5-8.5s1.1-5.9 3.5-8.5z" /></>),
  rules: (<><path d="M10 6h10M10 12h10M10 18h10" /><path d="M4.5 6h1.5M4.5 12h1.5M4.5 18h1.5" /></>),
  config: (<><path d="M14 3.5H7a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8.5z" /><path d="M14 3.5v5h5" /><path d="M10 12.5l-2 2 2 2M14 12.5l2 2-2 2" /></>),
  kernel: (<><rect x="6" y="6" width="12" height="12" rx="2" /><rect x="9.5" y="9.5" width="5" height="5" rx="1" /><path d="M9 2.5v3M15 2.5v3M9 18.5v3M15 18.5v3M2.5 9h3M2.5 15h3M18.5 9h3M18.5 15h3" /></>),
  connections: (<><path d="M4 8h14M14 4l4 4-4 4" /><path d="M20 16H6M10 12l-4 4 4 4" /></>),
  logs: (<><rect x="4.5" y="3.5" width="15" height="17" rx="2" /><path d="M8 8h8M8 12h8M8 16h5" /></>),
  settings: (<><path d="M4 7h9M17 7h3M4 17h3M11 17h9" /><circle cx="15" cy="7" r="2" /><circle cx="9" cy="17" r="2" /></>),
  down: <path d="M12 4.5v14M6.5 13l5.5 5.5 5.5-5.5" />,
  up: <path d="M12 19.5v-14M6.5 11L12 5.5l5.5 5.5" />,
  link: (<><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1" /><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" /></>),
  traffic: <path d="M5 20V11M10 20V5M15 20v-7M20 20v-4" />,
  plus: <path d="M12 5v14M5 12h14" />,
  edit: (<><path d="M4 20h4L19 9l-4-4L4 16z" /><path d="M13.5 6.5l4 4" /></>),
  trash: <path d="M4 7h16M9.5 7V4.5h5V7M6.5 7l1 13h9l1-13" />,
  grip: (<><circle cx="9" cy="6" r=".9" /><circle cx="15" cy="6" r=".9" /><circle cx="9" cy="12" r=".9" /><circle cx="15" cy="12" r=".9" /><circle cx="9" cy="18" r=".9" /><circle cx="15" cy="18" r=".9" /></>),
  search: (<><circle cx="11" cy="11" r="6.5" /><path d="M16 16l4 4" /></>),
  check: <path d="M5 12.5l4.5 4.5L19 7.5" />,
  bolt: <path d="M13 3L5 13.5h6L10 21l8-10.5h-6z" />,
  refresh: (<><path d="M20 11a8 8 0 0 0-14.6-4.5M4.5 3.5v3.5H8" /><path d="M4 13a8 8 0 0 0 14.6 4.5M19.5 20.5V17H16" /></>),
  chevUp: <path d="M6.5 14.5L12 9l5.5 5.5" />,
  chevDown: <path d="M6.5 9.5L12 15l5.5-5.5" />,
  chevRight: <path d="M9.5 6.5L15 12l-5.5 5.5" />,
  shield: <path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6z" />,
  monitor: (<><rect x="3" y="4.5" width="18" height="12" rx="2" /><path d="M9 20h6M12 16.5V20" /></>),
  x: <path d="M6.5 6.5l11 11M17.5 6.5l-11 11" />,
  alert: (<><path d="M10.3 4.8a2 2 0 0 1 3.4 0l7 12.2a2 2 0 0 1-1.7 3H5a2 2 0 0 1-1.7-3z" /><path d="M12 9v4M12 16h.01" /></>),
  info: (<><circle cx="12" cy="12" r="8.5" /><path d="M12 11v5M12 8h.01" /></>),
  route: (<><circle cx="6" cy="18" r="2.2" /><circle cx="18" cy="6" r="2.2" /><path d="M8.2 18H15a3 3 0 0 0 0-6H9a3 3 0 0 1 0-6h6.8" /></>),
  layers: (<><path d="M12 4l8.5 4.5L12 13 3.5 8.5z" /><path d="M3.5 12.5L12 17l8.5-4.5M3.5 16.5L12 21l8.5-4.5" /></>),
  download: (<><path d="M12 4v11M7.5 10.5L12 15l4.5-4.5" /><path d="M5 19.5h14" /></>),
  upload: (<><path d="M12 15V4M7.5 8.5L12 4l4.5 4.5" /><path d="M5 19.5h14" /></>),
  folder: (<path d="M3.5 6.5a2 2 0 0 1 2-2h4l2 2.2h7a2 2 0 0 1 2 2v8.8a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z" />),
  clock: (<><circle cx="12" cy="12" r="8.5" /><path d="M12 7.5V12l3 2" /></>),
  play: <path d="M8 5.5v13l10-6.5z" />,
  stop: <rect x="6.5" y="6.5" width="11" height="11" rx="1.5" />,
  doc: (<><path d="M7 3.5h7l5 5V19a1.5 1.5 0 0 1-1.5 1.5h-10.5A1.5 1.5 0 0 1 5.5 19V5A1.5 1.5 0 0 1 7 3.5z" /><path d="M9 12.5h6M9 16h6" /></>),
  direct: (<><path d="M4 12h14" /><path d="M13.5 7.5L18 12l-4.5 4.5" /><path d="M20.5 6v12" /></>),
  pin: (<><path d="M9.5 3.5h5l-.8 5.2 3.3 3.3v1.6H7v-1.6l3.3-3.3z" /><path d="M12 13.6v6.9" /></>),
  eye: (<><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></>),
  eyeOff: (<><path d="m3 3 18 18M8 5.6A12 12 0 0 1 12 5c7 0 10 7 10 7a17 17 0 0 1-4 4M6 6C3 8 2 12 2 12s3 7 10 7a12 12 0 0 0 5-1"/></>),
  copy: (<><rect x="8.5" y="8.5" width="11" height="11" rx="2" /><path d="M15.5 8.5V6.5a2 2 0 0 0-2-2h-7a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2" /></>),
  target: (<><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3.5" /></>),
};

export type IconName = keyof typeof P;

export function Icon({ name, size = 18, stroke = 1.7 }: { name: IconName | string; size?: number; stroke?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {P[name]}
    </svg>
  );
}
