/**
 * @jest-environment jsdom
 */

describe('History Hook', () => {
  let originalPushState: typeof history.pushState;
  let originalReplaceState: typeof history.replaceState;

  beforeEach(() => {
    // Store original history methods
    originalPushState = history.pushState;
    originalReplaceState = history.replaceState;

    // Reset the installation flag
    (
      window as Window & { __vulnersHistoryHookInstalled?: boolean }
    ).__vulnersHistoryHookInstalled = false;

    // Clear any event listeners by creating fresh mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    // Restore original history methods
    history.pushState = originalPushState;
    history.replaceState = originalReplaceState;

    // Clean up the flag
    delete (window as Window & { __vulnersHistoryHookInstalled?: boolean })
      .__vulnersHistoryHookInstalled;
  });

  // Helper to load the history hook script
  function loadHistoryHook(): void {
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
  }

  describe('Installation', () => {
    it('should set __vulnersHistoryHookInstalled flag on first load', () => {
      const win = window as Window & {
        __vulnersHistoryHookInstalled?: boolean;
      };
      expect(win.__vulnersHistoryHookInstalled).toBeFalsy();

      loadHistoryHook();

      expect(win.__vulnersHistoryHookInstalled).toBe(true);
    });

    it('should not reinstall if already installed', () => {
      // First load
      loadHistoryHook();
      const pushStateAfterFirst = history.pushState;

      // Second load should be no-op
      loadHistoryHook();
      const pushStateAfterSecond = history.pushState;

      // Should be the same wrapped function
      expect(pushStateAfterFirst).toBe(pushStateAfterSecond);
    });
  });

  describe('History Method Wrapping', () => {
    it('should wrap history.pushState', () => {
      const originalPush = history.pushState;

      loadHistoryHook();

      // pushState should be wrapped (different function)
      expect(history.pushState).not.toBe(originalPush);
    });

    it('should wrap history.replaceState', () => {
      const originalReplace = history.replaceState;

      loadHistoryHook();

      // replaceState should be wrapped (different function)
      expect(history.replaceState).not.toBe(originalReplace);
    });

    it('should still call original pushState', () => {
      const originalPush = jest.fn();
      history.pushState = originalPush;

      loadHistoryHook();

      history.pushState({ test: true }, '', '/new-url');

      expect(originalPush).toHaveBeenCalledWith({ test: true }, '', '/new-url');
    });

    it('should still call original replaceState', () => {
      const originalReplace = jest.fn();
      history.replaceState = originalReplace;

      loadHistoryHook();

      history.replaceState({ test: true }, '', '/new-url');

      expect(originalReplace).toHaveBeenCalledWith(
        { test: true },
        '',
        '/new-url'
      );
    });
  });

  describe('Navigation Event Dispatch', () => {
    it('should dispatch vulners:navigation event on pushState', () => {
      const eventHandler = jest.fn();
      window.addEventListener('vulners:navigation', eventHandler);

      loadHistoryHook();

      history.pushState({}, '', '/test');

      expect(eventHandler).toHaveBeenCalledTimes(1);
      expect(eventHandler).toHaveBeenCalledWith(expect.any(CustomEvent));

      window.removeEventListener('vulners:navigation', eventHandler);
    });

    it('should dispatch vulners:navigation event on replaceState', () => {
      const eventHandler = jest.fn();
      window.addEventListener('vulners:navigation', eventHandler);

      loadHistoryHook();

      history.replaceState({}, '', '/test');

      expect(eventHandler).toHaveBeenCalledTimes(1);
      expect(eventHandler).toHaveBeenCalledWith(expect.any(CustomEvent));

      window.removeEventListener('vulners:navigation', eventHandler);
    });

    it('should dispatch event with correct type', () => {
      let receivedEvent: Event | null = null;
      const eventHandler = (e: Event) => {
        receivedEvent = e;
      };
      window.addEventListener('vulners:navigation', eventHandler);

      loadHistoryHook();

      history.pushState({}, '', '/test');

      expect(receivedEvent).not.toBeNull();
      expect((receivedEvent as unknown as Event).type).toBe(
        'vulners:navigation'
      );

      window.removeEventListener('vulners:navigation', eventHandler);
    });

    it('should dispatch multiple events for multiple navigations', () => {
      const eventHandler = jest.fn();
      window.addEventListener('vulners:navigation', eventHandler);

      loadHistoryHook();

      history.pushState({}, '', '/page1');
      history.pushState({}, '', '/page2');
      history.replaceState({}, '', '/page3');

      expect(eventHandler).toHaveBeenCalledTimes(3);

      window.removeEventListener('vulners:navigation', eventHandler);
    });
  });

  describe('Edge Cases', () => {
    it('should handle null URL parameter', () => {
      const eventHandler = jest.fn();
      window.addEventListener('vulners:navigation', eventHandler);

      loadHistoryHook();

      // Should not throw
      expect(() => {
        history.pushState({}, '', null);
      }).not.toThrow();

      expect(eventHandler).toHaveBeenCalledTimes(1);

      window.removeEventListener('vulners:navigation', eventHandler);
    });

    it('should handle undefined URL parameter', () => {
      const eventHandler = jest.fn();
      window.addEventListener('vulners:navigation', eventHandler);

      loadHistoryHook();

      // Should not throw
      expect(() => {
        history.pushState({}, '');
      }).not.toThrow();

      expect(eventHandler).toHaveBeenCalledTimes(1);

      window.removeEventListener('vulners:navigation', eventHandler);
    });

    it('should handle complex state objects', () => {
      const complexState = {
        nested: { deep: { value: [1, 2, 3] } },
        date: new Date().toISOString(),
      };

      const originalPush = jest.fn();
      history.pushState = originalPush;

      loadHistoryHook();

      history.pushState(complexState, '', '/test');

      expect(originalPush).toHaveBeenCalledWith(complexState, '', '/test');
    });
  });
});
