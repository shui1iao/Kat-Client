// Presentation only: do not blur a control or prevent native input events.
export function installInputModality() {
  const root = document.documentElement;
  const pointer = () => { root.dataset.input = 'pointer'; };
  const keyboard = (e: KeyboardEvent) => {
    const target = e.target;
    const searchEditing = target instanceof HTMLInputElement &&
      (target.closest('.search') !== null || target.type === 'search' ||
       (target.getAttribute('aria-label') ?? '').startsWith('搜索'));
    // Editing/submitting a pointer-focused search does not navigate focus.
    // Keep Tab navigation and keyboard activation of other controls unchanged.
    if (searchEditing && e.key !== 'Tab') return;
    if (!e.metaKey && !e.ctrlKey && ['Tab','ArrowUp','ArrowDown','ArrowLeft','ArrowRight','Home','End','Enter',' '].includes(e.key)) root.dataset.input = 'keyboard';
  };
  document.addEventListener('pointerdown', pointer, true);
  document.addEventListener('keydown', keyboard, true);
  return () => { document.removeEventListener('pointerdown', pointer, true); document.removeEventListener('keydown', keyboard, true); };
}
