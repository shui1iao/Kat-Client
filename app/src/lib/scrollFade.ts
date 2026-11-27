/* Overflow-aware edge fades:
   - Short containers that fit without scrolling get NO top or bottom fade.
   - Long (scrollable) containers at their default top position get ONLY the
     bottom fade; once scrolled away from the top ("not at the default position"),
     the top fade appears too, and once scrolled to the very bottom the bottom
     fade disappears so the last row is completely sharp.
   - Sticky-header tables keep their header crisp and fade rows scrolling under
     the header via [data-scrolled-top="1"] only when scrollTop > 2. */

const STICKY_HEAD_SCROLL =
  '.node-table-scroll, .rule-table-scroll, .res-list, .conn-table-wrap, .log-scroll, .kernel-log-scroll, .safe-log-list';

const FADE_SCROLL =
  STICKY_HEAD_SCROLL +
  ', .nav-list, .modal > .form, .overview-bento, .pol-stream, .settings-scroll, .dns-addr-pop-list' +
  ', .dns-settings-unified, .cfg-tools' +
  ', .policy-editor-v2 .pe-form-body, .sparkle-notes-box, .pe-candidates, .diag-body';

function updateOne(el: HTMLElement) {
  const sticky = el.matches(STICKY_HEAD_SCROLL);
  const overflow = el.scrollHeight - el.clientHeight > 2;
  const hasTop = overflow && el.scrollTop > 2;
  const hasBottom = overflow && el.scrollTop + el.clientHeight < el.scrollHeight - 2;

  const maskMode = !sticky && hasTop && hasBottom
    ? 'both'
    : !sticky && hasTop
      ? 'top'
      : hasBottom
        ? 'bottom'
        : '';

  if (maskMode) {
    if (el.dataset.scrollFade !== maskMode) el.dataset.scrollFade = maskMode;
  } else if (el.dataset.scrollFade !== undefined) {
    delete el.dataset.scrollFade;
  }

  if (sticky) {
    if (hasTop) {
      if (el.dataset.scrolledTop !== '1') el.dataset.scrolledTop = '1';
    } else if (el.dataset.scrolledTop !== undefined) {
      delete el.dataset.scrolledTop;
    }
  }
}

export function installScrollFade(): () => void {
  let raf = 0;
  const observed = new WeakSet<HTMLElement>();
  const ro = new ResizeObserver(() => scheduleSync());

  const syncAll = () => {
    raf = 0;
    const nodes = document.querySelectorAll<HTMLElement>(FADE_SCROLL);
    for (const el of nodes) {
      if (!observed.has(el)) {
        observed.add(el);
        ro.observe(el);
      }
      updateOne(el);
    }
  };

  const scheduleSync = () => {
    if (!raf) raf = window.requestAnimationFrame(syncAll);
  };

  const onScroll = (e: Event) => {
    const el = e.target;
    if (el instanceof HTMLElement && el.matches(FADE_SCROLL)) {
      updateOne(el);
    }
  };

  const mo = new MutationObserver((records) => {
    for (const r of records) {
      for (const n of r.addedNodes) if (n.nodeType === 1) { scheduleSync(); return; }
      for (const n of r.removedNodes) if (n.nodeType === 1) { scheduleSync(); return; }
    }
  });
  mo.observe(document.body, { childList: true, subtree: true });

  document.addEventListener('scroll', onScroll, { capture: true, passive: true });
  document.addEventListener('transitionend', scheduleSync, true);
  window.addEventListener('resize', scheduleSync);
  scheduleSync();

  return () => {
    if (raf) window.cancelAnimationFrame(raf);
    ro.disconnect();
    mo.disconnect();
    document.removeEventListener('scroll', onScroll, true);
    document.removeEventListener('transitionend', scheduleSync, true);
    window.removeEventListener('resize', scheduleSync);
  };
}
