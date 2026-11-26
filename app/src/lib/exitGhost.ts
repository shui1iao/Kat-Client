// Exit transitions for portal overlays (dialogs, popovers, toasts, tooltips).
// React unmounts these nodes immediately, so the close used to be a hard cut.
// When one of them leaves <body>, an inert, non-interactive visual clone is put
// back for the length of its exit animation and then removed. The real node is
// gone at once, so focus, events and state never see the ghost.
const LEAVING: { selector: string; ms: number }[] = [
  { selector: '.modal-mask', ms: 150 },
  { selector: '.kat-pop, .rule-judge-pop', ms: 120 },
  { selector: '.toast', ms: 170 },
  { selector: '.kat-tip', ms: 90 },
];
const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');

function ghost(node: HTMLElement) {
  const rule = LEAVING.find((r) => node.matches(r.selector));
  if (!rule || reduced.matches || document.documentElement.dataset.katWindowHidden === 'true') return;
  const g = node.cloneNode(true) as HTMLElement;
  // cloneNode copies attributes, not live form state: carry current values over
  // so the fading copy shows exactly what the user last saw.
  const live = node.querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>('input, textarea, select');
  const copy = g.querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>('input, textarea, select');
  live.forEach((el, i) => {
    const c = copy[i];
    if (!c) return;
    if (el instanceof HTMLSelectElement) (c as HTMLSelectElement).selectedIndex = el.selectedIndex;
    else if (el instanceof HTMLInputElement && (el.type === 'checkbox' || el.type === 'radio')) (c as HTMLInputElement).checked = el.checked;
    else c.value = el.value;
  });
  g.removeAttribute('id');
  g.querySelectorAll('[id]').forEach((n) => n.removeAttribute('id'));
  g.setAttribute('aria-hidden', 'true');
  g.inert = true;
  g.style.pointerEvents = 'none';
  g.classList.add('kat-leaving');
  document.body.appendChild(g);
  window.setTimeout(() => g.remove(), rule.ms + 30);
}

export function installExitGhosts() {
  const mo = new MutationObserver((records) => {
    for (const r of records)
      for (const n of r.removedNodes)
        if (n instanceof HTMLElement && !n.classList.contains('kat-leaving')) ghost(n);
  });
  mo.observe(document.body, { childList: true });
  return () => mo.disconnect();
}
