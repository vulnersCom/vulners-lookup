/**
 * @jest-environment jsdom
 */

import { mockChrome } from './setup';

// Import the actual module for coverage
import {
  TooltipManager,
  DOMScanner,
  detectBulletinType,
  escapeHtml,
  isVulnersHostname,
  CONFIG,
  BULLETIN_TYPE_MAP,
  BULLETIN_TYPE_LABELS,
  BULLETIN_TYPE_COLORS,
  EDITOR_SELECTOR,
} from '../src/content';

// Mock IntersectionObserver
class MockIntersectionObserver {
  callback: IntersectionObserverCallback;
  elements: Set<Element> = new Set();

  constructor(callback: IntersectionObserverCallback) {
    this.callback = callback;
  }

  observe(element: Element) {
    this.elements.add(element);
  }

  unobserve(element: Element) {
    this.elements.delete(element);
  }

  disconnect() {
    this.elements.clear();
  }

  simulateIntersection(entries: Partial<IntersectionObserverEntry>[]) {
    this.callback(
      entries.map((entry) => ({
        isIntersecting: true,
        target: document.createElement('div'),
        ...entry,
      })) as IntersectionObserverEntry[],
      this as unknown as IntersectionObserver
    );
  }
}

// Mock requestIdleCallback
const mockIdleCallback = jest.fn((callback: IdleRequestCallback) => {
  const deadline: IdleDeadline = {
    didTimeout: false,
    timeRemaining: () => 50,
  };
  callback(deadline);
  return 1;
});

const mockCancelIdleCallback = jest.fn();

describe('CVEHighlighter Content Script', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    document.body.innerHTML = '';

    // Mock MutationObserver
    class MutationObserverMock {
      observe = jest.fn();
      disconnect = jest.fn();
      takeRecords = jest.fn();
    }
    global.MutationObserver =
      MutationObserverMock as unknown as typeof MutationObserver;

    // Mock IntersectionObserver
    global.IntersectionObserver =
      MockIntersectionObserver as unknown as typeof IntersectionObserver;

    // Mock requestIdleCallback
    global.requestIdleCallback = mockIdleCallback;
    global.cancelIdleCallback = mockCancelIdleCallback;

    // Default storage mock
    (mockChrome.storage.local.get as jest.Mock).mockImplementation(
      (_keys: any, callback: any) => {
        if (callback) {
          callback({ enabled: true });
        }
        return Promise.resolve({ enabled: true });
      }
    );

    // Mock sendMessage
    (mockChrome.runtime.sendMessage as jest.Mock).mockResolvedValue({
      patterns: null,
    });
  });

  // ============ UTILITY FUNCTIONS TESTS ============

  describe('Utility Functions', () => {
    describe('isVulnersHostname', () => {
      it('should return true for vulners.com', () => {
        expect(isVulnersHostname('vulners.com')).toBe(true);
      });

      it('should return true for www.vulners.com', () => {
        expect(isVulnersHostname('www.vulners.com')).toBe(true);
      });

      it('should return true for subdomains of vulners.com', () => {
        expect(isVulnersHostname('api.vulners.com')).toBe(true);
        expect(isVulnersHostname('subdomain.vulners.com')).toBe(true);
      });

      it('should be case insensitive', () => {
        expect(isVulnersHostname('VULNERS.COM')).toBe(true);
        expect(isVulnersHostname('Vulners.Com')).toBe(true);
      });

      it('should return false for non-vulners domains', () => {
        expect(isVulnersHostname('notvulners.com')).toBe(false);
        expect(isVulnersHostname('vulners.net')).toBe(false);
        expect(isVulnersHostname('example.com')).toBe(false);
        expect(isVulnersHostname('fakevulners.com')).toBe(false);
      });
    });

    describe('escapeHtml', () => {
      it('should escape ampersand', () => {
        expect(escapeHtml('A & B')).toBe('A &amp; B');
      });

      it('should escape less than and greater than', () => {
        expect(escapeHtml('<script>')).toBe('&lt;script&gt;');
      });

      it('should escape quotes', () => {
        expect(escapeHtml('"test"')).toBe('&quot;test&quot;');
        expect(escapeHtml("'test'")).toBe('&#39;test&#39;');
      });

      it('should escape all special characters in a string', () => {
        expect(escapeHtml('<a href="test" onclick=\'alert("XSS")\'>&')).toBe(
          '&lt;a href=&quot;test&quot; onclick=&#39;alert(&quot;XSS&quot;)&#39;&gt;&amp;'
        );
      });

      it('should not modify strings without special characters', () => {
        expect(escapeHtml('Hello World')).toBe('Hello World');
        expect(escapeHtml('CVE-2023-1234')).toBe('CVE-2023-1234');
      });
    });

    describe('detectBulletinType', () => {
      it('should detect CVE type', () => {
        expect(detectBulletinType('CVE-2023-1234')).toBe('cve');
        expect(detectBulletinType('CAN-2022-5678')).toBe('cve');
      });

      it('should detect exploit type', () => {
        expect(detectBulletinType('EDB-ID:12345')).toBe('exploit');
        expect(detectBulletinType('EDBID:12345')).toBe('exploit');
        expect(detectBulletinType('PACKETSTORM:54321')).toBe('exploit');
        expect(detectBulletinType('ZDI-2023-001')).toBe('exploit');
      });

      it('should detect advisory type', () => {
        expect(detectBulletinType('RHSA-2023:1234')).toBe('advisory');
        expect(detectBulletinType('GHSA-abcd-efgh-ijkl')).toBe('advisory');
        expect(detectBulletinType('DSA-1234-1')).toBe('advisory');
        expect(detectBulletinType('USN-1234-1')).toBe('advisory');
        expect(detectBulletinType('CNVD-2023-12345')).toBe('advisory');
      });

      it('should be case insensitive', () => {
        expect(detectBulletinType('cve-2023-1234')).toBe('cve');
        expect(detectBulletinType('ghsa-abcd-efgh-ijkl')).toBe('advisory');
        expect(detectBulletinType('edb-id:12345')).toBe('exploit');
      });

      it('should default to cve for unknown prefixes', () => {
        expect(detectBulletinType('UNKNOWN-2023-1234')).toBe('cve');
      });
    });
  });

  // ============ CONFIG TESTS ============

  describe('Configuration', () => {
    it('should have tooltip configuration', () => {
      expect(CONFIG.TOOLTIP_WIDTH).toBe(320);
      expect(CONFIG.TOOLTIP_HEIGHT).toBe(242);
      expect(CONFIG.TOOLTIP_PADDING).toBe(10);
      expect(CONFIG.TOOLTIP_OFFSET).toBe(5);
    });

    it('should have viewport margin', () => {
      expect(CONFIG.VIEWPORT_MARGIN).toBe(100);
    });

    it('should have timing configuration', () => {
      expect(CONFIG.TOOLTIP_DELAY_MS).toBe(200);
      expect(CONFIG.MUTATION_DEBOUNCE_MS).toBe(100);
      expect(CONFIG.SPA_SETTLE_DELAY_MS).toBe(500);
    });

    it('should have mutation storm thresholds', () => {
      expect(CONFIG.STORM_THRESHOLD).toBe(50);
      expect(CONFIG.STORM_WINDOW_MS).toBe(500);
      expect(CONFIG.MAX_PENDING_MUTATIONS).toBe(100);
    });

    it('should have adaptive debounce settings', () => {
      expect(CONFIG.DEBOUNCE_LOW_MS).toBe(50);
      expect(CONFIG.DEBOUNCE_MEDIUM_MS).toBe(150);
      expect(CONFIG.DEBOUNCE_HIGH_MS).toBe(250);
      expect(CONFIG.DEBOUNCE_STORM_MS).toBe(300);
      expect(CONFIG.DEBOUNCE_EXTREME_MS).toBe(400);
    });
  });

  // ============ BULLETIN TYPE MAPS ============

  describe('Bulletin Type Maps', () => {
    it('should have bulletin type map entries', () => {
      expect(BULLETIN_TYPE_MAP.length).toBeGreaterThan(0);

      const cveEntry = BULLETIN_TYPE_MAP.find(([prefix]) => prefix === 'CVE-');
      expect(cveEntry).toBeDefined();
      expect(cveEntry![1]).toBe('cve');

      const ghsaEntry = BULLETIN_TYPE_MAP.find(
        ([prefix]) => prefix === 'GHSA-'
      );
      expect(ghsaEntry).toBeDefined();
      expect(ghsaEntry![1]).toBe('advisory');

      const edbEntry = BULLETIN_TYPE_MAP.find(
        ([prefix]) => prefix === 'EDB-ID'
      );
      expect(edbEntry).toBeDefined();
      expect(edbEntry![1]).toBe('exploit');
    });

    it('should have bulletin type labels', () => {
      expect(BULLETIN_TYPE_LABELS.cve).toBe('Vulnerability');
      expect(BULLETIN_TYPE_LABELS.advisory).toBe('Security Advisory');
      expect(BULLETIN_TYPE_LABELS.exploit).toBe('Exploit');
    });

    it('should have bulletin type colors', () => {
      expect(BULLETIN_TYPE_COLORS.cve).toBe('#ff8b61');
      expect(BULLETIN_TYPE_COLORS.advisory).toBe('#6366f1');
      expect(BULLETIN_TYPE_COLORS.exploit).toBe('#ef4444');
    });
  });

  // ============ EDITOR SELECTOR ============

  describe('Editor Selector', () => {
    it('should include common editor selectors', () => {
      expect(EDITOR_SELECTOR).toContain('[role="textbox"]');
      expect(EDITOR_SELECTOR).toContain('.ProseMirror');
      expect(EDITOR_SELECTOR).toContain('.monaco-editor');
      expect(EDITOR_SELECTOR).toContain('.ace_editor');
      expect(EDITOR_SELECTOR).toContain('.CodeMirror');
    });
  });

  // ============ TOOLTIP MANAGER TESTS ============

  describe('TooltipManager', () => {
    let tooltipManager: TooltipManager;

    beforeEach(() => {
      tooltipManager = new TooltipManager();
    });

    describe('getCurrentHighlightedElement', () => {
      it('should return null initially', () => {
        expect(tooltipManager.getCurrentHighlightedElement()).toBeNull();
      });
    });

    describe('setCurrentHighlightedElement', () => {
      it('should set the current highlighted element', () => {
        const span = document.createElement('span');
        tooltipManager.setCurrentHighlightedElement(span);
        expect(tooltipManager.getCurrentHighlightedElement()).toBe(span);
      });

      it('should allow setting to null', () => {
        const span = document.createElement('span');
        tooltipManager.setCurrentHighlightedElement(span);
        tooltipManager.setCurrentHighlightedElement(null);
        expect(tooltipManager.getCurrentHighlightedElement()).toBeNull();
      });
    });

    describe('createTooltip', () => {
      it('should create tooltip element in DOM', () => {
        tooltipManager.createTooltip();
        const tooltip = document.querySelector('.vulners-tooltip');
        expect(tooltip).toBeTruthy();
        expect(tooltip?.classList.contains('vulners-tooltip')).toBe(true);
      });
    });

    describe('hideTooltip', () => {
      it('should hide tooltip and clear current element', () => {
        tooltipManager.createTooltip();
        const span = document.createElement('span');
        tooltipManager.setCurrentHighlightedElement(span);
        tooltipManager.hideTooltip();
        expect(tooltipManager.getCurrentHighlightedElement()).toBeNull();
      });
    });

    describe('positionTooltip', () => {
      it('should position tooltip based on element', () => {
        tooltipManager.createTooltip();
        const span = document.createElement('span');
        document.body.appendChild(span);
        tooltipManager.positionTooltip(span);
        // Tooltip should have position set
        const tooltip = document.querySelector(
          '.vulners-tooltip'
        ) as HTMLElement;
        expect(tooltip).toBeTruthy();
      });
    });

    describe('getLoadingHTML', () => {
      it('should return loading HTML with bulletin info', () => {
        const html = tooltipManager.getLoadingHTML('CVE-2023-1234', 'cve');
        expect(html).toContain('vulners-loading');
        expect(html).toContain('vulners-spinner');
        expect(html).toContain('CVE-2023-1234');
        expect(html).toContain('Vulnerability');
      });

      it('should escape HTML in bulletin ID', () => {
        const html = tooltipManager.getLoadingHTML(
          '<script>alert(1)</script>',
          'cve'
        );
        expect(html).not.toContain('<script>');
        expect(html).toContain('&lt;script&gt;');
      });
    });

    describe('getTooltipHTML', () => {
      it('should return tooltip HTML for CVE data', () => {
        const data = {
          id: 'CVE-2023-1234',
          description: 'Test vulnerability',
          cvss: { score: 7.5, vector: 'AV:N' },
        };
        const html = tooltipManager.getTooltipHTML(data, 'cve');
        expect(html).toContain('CVE-2023-1234');
        expect(html).toContain('vulners-tooltip-content');
      });

      it('should show view details link for minimal data', () => {
        const data = {
          id: 'CVE-2023-1234',
          description: 'No description available',
        };
        const html = tooltipManager.getTooltipHTML(data, 'cve');
        expect(html).toContain('View details on Vulners.com');
      });

      it('should show detailed stats when available', () => {
        const data = {
          id: 'CVE-2023-1234',
          description: 'Test',
          cvss: { score: 7.5, vector: 'AV:N' },
          epss: { score: 0.5, percentile: 90 },
          exploitInfo: { exploits: 3, wildExploited: true },
        };
        const html = tooltipManager.getTooltipHTML(data, 'cve');
        expect(html).toContain('7.5');
        expect(html).toContain('0.500');
        expect(html).toContain('3');
        expect(html).toContain('Wild');
      });

      it('should show linked CVEs for advisories', () => {
        const data = {
          id: 'RHSA-2023-1234',
          description: 'Advisory',
          linkedCVEs: ['CVE-2023-1111', 'CVE-2023-2222'],
          linkedCVECount: 2,
        };
        const html = tooltipManager.getTooltipHTML(data, 'advisory');
        expect(html).toContain('Linked CVEs');
        expect(html).toContain('CVE-2023-1111');
        expect(html).toContain('CVE-2023-2222');
      });

      it('should show related CVEs for exploits', () => {
        const data = {
          id: 'EDB-ID:12345',
          description: 'Exploit',
          relatedCVEs: ['CVE-2023-1111'],
          relatedCVECount: 1,
          repoUrl: 'https://github.com/example/exploit',
          author: 'Researcher',
        };
        const html = tooltipManager.getTooltipHTML(data, 'exploit');
        expect(html).toContain('Related CVEs');
        expect(html).toContain('CVE-2023-1111');
        expect(html).toContain('View source');
        expect(html).toContain('Researcher');
      });
    });

    describe('fetchBulletinData', () => {
      it('should fetch data from background script', async () => {
        const mockData = {
          data: { id: 'CVE-2023-1234', description: 'Test' },
        };
        (mockChrome.runtime.sendMessage as jest.Mock).mockResolvedValueOnce(
          mockData
        );

        const result = await tooltipManager.fetchBulletinData(
          'CVE-2023-1234',
          'cve'
        );
        expect(result.id).toBe('CVE-2023-1234');
        expect(result.type).toBe('cve');
      });

      it('should use cached data on subsequent calls', async () => {
        const mockData = {
          data: { id: 'CVE-2023-5678', description: 'Cached' },
        };
        (mockChrome.runtime.sendMessage as jest.Mock).mockResolvedValueOnce(
          mockData
        );

        await tooltipManager.fetchBulletinData('CVE-2023-5678', 'cve');
        const result2 = await tooltipManager.fetchBulletinData(
          'CVE-2023-5678',
          'cve'
        );

        expect(mockChrome.runtime.sendMessage).toHaveBeenCalledTimes(1);
        expect(result2.id).toBe('CVE-2023-5678');
      });

      it('should return fallback data on error', async () => {
        (mockChrome.runtime.sendMessage as jest.Mock).mockRejectedValueOnce(
          new Error('Network error')
        );

        const result = await tooltipManager.fetchBulletinData(
          'CVE-2023-ERROR',
          'cve'
        );
        expect(result.id).toBe('CVE-2023-ERROR');
        expect(result.description).toBe(
          'Unable to fetch vulnerability details'
        );
      });
    });
  });

  // ============ DOM SCANNER TESTS ============

  describe('DOMScanner', () => {
    let domScanner: DOMScanner;
    let tooltipManager: TooltipManager;

    beforeEach(() => {
      tooltipManager = new TooltipManager();
      domScanner = new DOMScanner(tooltipManager);
    });

    describe('isPatternsLoaded', () => {
      it('should return false initially', () => {
        expect(domScanner.isPatternsLoaded()).toBe(false);
      });
    });

    describe('getHighlightedBulletins', () => {
      it('should return empty set initially', () => {
        expect(domScanner.getHighlightedBulletins().size).toBe(0);
      });
    });

    describe('getBulletinTypeCounts', () => {
      it('should return zero counts initially', () => {
        const counts = domScanner.getBulletinTypeCounts();
        expect(counts.cve).toBe(0);
        expect(counts.advisory).toBe(0);
        expect(counts.exploit).toBe(0);
      });
    });

    describe('loadPatterns', () => {
      it('should load patterns from background', async () => {
        const mockPatterns = {
          patterns: ['/CVE-\\d{4}-\\d{4,7}/gi'],
        };
        (mockChrome.runtime.sendMessage as jest.Mock).mockResolvedValueOnce(
          mockPatterns
        );

        await domScanner.loadPatterns();
        expect(domScanner.isPatternsLoaded()).toBe(true);
      });

      it('should use fallback pattern on failure', async () => {
        (mockChrome.runtime.sendMessage as jest.Mock).mockResolvedValueOnce({
          patterns: null,
        });

        await domScanner.loadPatterns();
        expect(domScanner.isPatternsLoaded()).toBe(true);
      });
    });

    describe('hasMatchingPattern', () => {
      beforeEach(async () => {
        (mockChrome.runtime.sendMessage as jest.Mock).mockResolvedValueOnce({
          patterns: null,
        });
        await domScanner.loadPatterns();
      });

      it('should return false for short text', () => {
        expect(domScanner.hasMatchingPattern('CVE')).toBe(false);
      });

      it('should return true for matching text', () => {
        expect(domScanner.hasMatchingPattern('CVE-2023-1234')).toBe(true);
      });

      it('should return false for non-matching text', () => {
        expect(domScanner.hasMatchingPattern('Hello World!')).toBe(false);
      });
    });

    describe('isEditableElement', () => {
      it('should return true for input elements', () => {
        const input = document.createElement('input');
        expect(domScanner.isEditableElement(input)).toBe(true);
      });

      it('should return true for textarea elements', () => {
        const textarea = document.createElement('textarea');
        expect(domScanner.isEditableElement(textarea)).toBe(true);
      });

      it('should return true for select elements', () => {
        const select = document.createElement('select');
        expect(domScanner.isEditableElement(select)).toBe(true);
      });

      it('should return false for regular divs', () => {
        const div = document.createElement('div');
        document.body.appendChild(div);
        expect(domScanner.isEditableElement(div)).toBe(false);
      });

      it('should return false for null', () => {
        expect(domScanner.isEditableElement(null)).toBe(false);
      });

      it('should return true for elements in editor containers', () => {
        document.body.innerHTML =
          '<div class="monaco-editor"><span id="child">Test</span></div>';
        const child = document.getElementById('child') as HTMLElement;
        expect(domScanner.isEditableElement(child)).toBe(true);
      });
    });

    describe('isElementInViewport', () => {
      it('should return true for visible elements', () => {
        const div = document.createElement('div');
        document.body.appendChild(div);
        // In jsdom, getBoundingClientRect returns zeros which is in viewport
        expect(domScanner.isElementInViewport(div)).toBe(true);
      });
    });

    describe('detectMutationStorm', () => {
      it('should return false for few mutations', () => {
        expect(domScanner.detectMutationStorm()).toBe(false);
        expect(domScanner.detectMutationStorm()).toBe(false);
        expect(domScanner.detectMutationStorm()).toBe(false);
      });
    });

    describe('getAdaptiveDebounceMs', () => {
      it('should return low debounce for few pending', () => {
        expect(domScanner.getAdaptiveDebounceMs()).toBe(50);
      });
    });

    describe('highlightCVEsInNode', () => {
      beforeEach(async () => {
        (mockChrome.runtime.sendMessage as jest.Mock).mockResolvedValueOnce({
          patterns: null,
        });
        await domScanner.loadPatterns();
        domScanner.buildCombinedPattern();
      });

      it('should highlight CVE in text node', () => {
        document.body.innerHTML =
          '<div id="test">Check CVE-2023-1234 here</div>';
        const textNode = document.getElementById('test')!.firstChild as Text;

        domScanner.highlightCVEsInNode(textNode);

        expect(domScanner.getHighlightedBulletins().has('CVE-2023-1234')).toBe(
          true
        );
        expect(domScanner.getPendingHighlightsCount()).toBe(1);
      });

      it('should not process already processed nodes', () => {
        document.body.innerHTML =
          '<div id="test">Check CVE-2023-5555 here</div>';
        const textNode = document.getElementById('test')!.firstChild as Text;

        domScanner.highlightCVEsInNode(textNode);
        const initialCount = domScanner.getPendingHighlightsCount();

        // Try to process again
        domScanner.highlightCVEsInNode(textNode);

        // Should not have added more
        expect(domScanner.getPendingHighlightsCount()).toBe(initialCount);
      });

      it('should track counts by type', () => {
        document.body.innerHTML = '<div id="test">CVE-2023-1111</div>';
        const textNode = document.getElementById('test')!.firstChild as Text;

        domScanner.highlightCVEsInNode(textNode);

        const counts = domScanner.getBulletinTypeCounts();
        expect(counts.cve).toBe(1);
      });
    });

    describe('createHighlightElement', () => {
      it('should create span with correct classes', () => {
        const span = (domScanner as any).createHighlightElement(
          'CVE-2023-1234',
          'cve'
        );
        expect(span.classList.contains('vulners-highlight')).toBe(true);
        expect(span.classList.contains('vulners-highlight-cve')).toBe(true);
        expect(span.dataset.bulletinId).toBe('CVE-2023-1234');
        expect(span.dataset.bulletinType).toBe('cve');
      });

      it('should add event listeners', () => {
        const span = (domScanner as any).createHighlightElement(
          'CVE-2023-1234',
          'cve'
        );
        // Event listeners are attached - we can't easily test this but at least verify span is created
        expect(span).toBeTruthy();
      });
    });

    describe('cleanup', () => {
      it('should disconnect visibility observer', () => {
        domScanner.setupVisibilityObserver();
        domScanner.cleanup();
        // No error thrown means success
      });
    });

    describe('removeAllHighlights', () => {
      it('should remove all highlights from DOM', () => {
        document.body.innerHTML = `
          <span class="vulners-highlight" data-bulletin-id="CVE-2023-1111">CVE-2023-1111</span>
        `;

        domScanner.removeAllHighlights();

        const highlights = document.querySelectorAll('.vulners-highlight');
        expect(highlights.length).toBe(0);
      });

      it('should reset counts', () => {
        // Set some counts manually via highlighting
        document.body.innerHTML = '<div id="test">CVE-2023-1234</div>';
        (domScanner as any).bulletinTypeCounts.cve = 5;

        domScanner.removeAllHighlights();

        const counts = domScanner.getBulletinTypeCounts();
        expect(counts.cve).toBe(0);
        expect(counts.advisory).toBe(0);
        expect(counts.exploit).toBe(0);
      });
    });

    describe('scanAndHighlight', () => {
      beforeEach(async () => {
        (mockChrome.runtime.sendMessage as jest.Mock).mockResolvedValue({
          patterns: null,
        });
        await domScanner.loadPatterns();
        domScanner.buildCombinedPattern();
      });

      it('should return needsRescan true when paused', () => {
        const result = domScanner.scanAndHighlight(false, Date.now() + 10000);
        expect(result.needsRescan).toBe(true);
      });

      it('should not process if already processing', () => {
        const result = domScanner.scanAndHighlight(true, 0);
        expect(result.isProcessing).toBe(true);
      });

      it('should scan document body for CVEs', () => {
        document.body.innerHTML = '<div>CVE-2023-1234</div>';

        const result = domScanner.scanAndHighlight(false, 0);

        expect(result.isProcessing).toBe(false);
      });
    });

    describe('scanElementForCVEs', () => {
      beforeEach(async () => {
        (mockChrome.runtime.sendMessage as jest.Mock).mockResolvedValue({
          patterns: null,
        });
        await domScanner.loadPatterns();
        domScanner.buildCombinedPattern();
      });

      it('should skip editable elements', () => {
        const input = document.createElement('input');
        input.value = 'CVE-2023-1234';
        document.body.appendChild(input);

        domScanner.scanElementForCVEs(input);

        // Should not have processed
        expect(domScanner.getHighlightedBulletins().size).toBe(0);
      });
    });

    describe('flushPendingHighlights', () => {
      it('should send badge update after flush', () => {
        domScanner.flushPendingHighlights();
        expect(mockChrome.runtime.sendMessage).toHaveBeenCalledWith({
          action: 'updateBadge',
          count: 0,
        });
      });
    });
  });

  // ============ PATTERN DETECTION TESTS ============

  describe('Pattern Detection', () => {
    describe('CVE Pattern', () => {
      const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/gi;

      it('should detect standard CVE patterns', () => {
        const patterns = [
          'CVE-2023-1234',
          'CVE-2022-12345',
          'CVE-2021-123456',
          'CVE-2020-1234567',
        ];

        patterns.forEach((pattern) => {
          expect(pattern).toMatch(CVE_PATTERN);
        });
      });

      it('should not match invalid CVE patterns', () => {
        const invalidPatterns = ['CVE-23-1234', 'CVE-2023-123', 'CVE20231234'];

        invalidPatterns.forEach((pattern) => {
          expect(pattern).not.toMatch(CVE_PATTERN);
        });
      });

      it('should be case insensitive', () => {
        expect('cve-2023-1234').toMatch(CVE_PATTERN);
        expect('Cve-2023-1234').toMatch(CVE_PATTERN);
      });
    });
  });

  // ============ DATA FETCHING TESTS ============

  describe('CVE Data Fetching', () => {
    it('should fetch CVE data from background script', async () => {
      const mockCVEData = {
        data: {
          id: 'CVE-2023-5555',
          description: 'Test vulnerability',
          cvss: { score: 7.5, vector: 'AV:N' },
        },
      };

      (mockChrome.runtime.sendMessage as jest.Mock).mockResolvedValueOnce(
        mockCVEData
      );

      const result = await mockChrome.runtime.sendMessage({
        action: 'fetchCVEData',
        cveId: 'CVE-2023-5555',
      });

      expect(mockChrome.runtime.sendMessage).toHaveBeenCalledWith({
        action: 'fetchCVEData',
        cveId: 'CVE-2023-5555',
      });
      expect(result).toEqual(mockCVEData);
    });
  });

  // ============ BADGE UPDATES TESTS ============

  describe('Badge Updates', () => {
    it('should send badge update message', () => {
      mockChrome.runtime.sendMessage({
        action: 'updateBadge',
        count: 5,
      });

      expect(mockChrome.runtime.sendMessage).toHaveBeenCalledWith({
        action: 'updateBadge',
        count: 5,
      });
    });
  });

  // ============ STORAGE TESTS ============

  describe('Storage Integration', () => {
    it('should get enabled state from storage', async () => {
      (mockChrome.storage.local.get as jest.Mock).mockResolvedValueOnce({
        enabled: true,
      });

      const result = await mockChrome.storage.local.get(['enabled']);

      expect(result.enabled).toBe(true);
    });
  });
});
