// This script runs in page context to detect SPA navigation
// It must be a self-contained IIFE with no imports

(function () {
  const win = window as Window & { __vulnersHistoryHookInstalled?: boolean };

  if (win.__vulnersHistoryHookInstalled) {
    return;
  }
  win.__vulnersHistoryHookInstalled = true;

  const notify = (): void => {
    window.dispatchEvent(new CustomEvent('vulners:navigation'));
  };

  const wrap = (method: 'pushState' | 'replaceState'): void => {
    const original = history[method].bind(history);
    history[method] = function (
      data: unknown,
      unused: string,
      url?: string | URL | null
    ): void {
      original(data, unused, url);
      notify();
    };
  };

  wrap('pushState');
  wrap('replaceState');
})();
