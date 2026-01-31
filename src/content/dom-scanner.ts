import type { BulletinType } from './types';
import { CONFIG, EDITOR_SELECTOR } from './constants';
import { detectBulletinType } from './utils';
import { TooltipManager } from './tooltip-manager';

export class DOMScanner {
  private readonly CVE_PATTERN = /CVE-\d{4}-\d{4,7}/gi;
  private patterns: RegExp[] = [];
  private combinedPattern: RegExp | null = null;
  private patternsLoaded = false;

  private processedNodes = new WeakSet<Node>();
  private highlightedBulletins = new Set<string>();
  private bulletinTypeCounts: Record<BulletinType, number> = {
    cve: 0,
    advisory: 0,
    exploit: 0,
  };

  private pendingHighlights: Array<{
    parent: Element;
    oldNode: Text;
    fragment: DocumentFragment;
  }> = [];
  private highlightFlushScheduled = false;

  // Viewport-aware processing
  private visibilityObserver: IntersectionObserver | null = null;
  private pendingOffscreenElements = new Map<Element, Text[]>();

  // Idle callback processing
  private idleCallbackId: number | null = null;

  // Mutation tracking
  private pendingMutations: MutationRecord[] = [];
  private mutationTimestamps: number[] = [];

  // Event handler references for cleanup
  private highlightEventHandlers = new WeakMap<
    HTMLElement,
    { enter: (e: MouseEvent) => void; leave: (e: MouseEvent) => void }
  >();

  private tooltipManager: TooltipManager;

  constructor(tooltipManager: TooltipManager) {
    this.tooltipManager = tooltipManager;
  }

  // Getters for state access
  getHighlightedBulletins(): Set<string> {
    return this.highlightedBulletins;
  }

  getBulletinTypeCounts(): Record<BulletinType, number> {
    return { ...this.bulletinTypeCounts };
  }

  getPendingHighlightsCount(): number {
    return this.pendingHighlights.length;
  }

  getPendingMutations(): MutationRecord[] {
    return this.pendingMutations;
  }

  getMutationTimestamps(): number[] {
    return this.mutationTimestamps;
  }

  isPatternsLoaded(): boolean {
    return this.patternsLoaded;
  }

  // Pattern management
  async loadPatterns(): Promise<void> {
    try {
      // Use background script to fetch patterns (avoids CORS issues)
      const response = await chrome.runtime.sendMessage({
        action: 'fetchPatterns',
      });

      if (response && response.patterns && Array.isArray(response.patterns)) {
        this.patterns = response.patterns
          .map((patternStr: string) => {
            try {
              // Parse pattern string like "/CVE-\\d{4}-\\d{4,7}/gi"
              const match = patternStr.match(/^\/(.+)\/([gimuy]*)$/);
              if (match) {
                return new RegExp(match[1], match[2]);
              } else {
                // Fallback: treat as plain pattern with 'gi' flags
                return new RegExp(patternStr, 'gi');
              }
            } catch (error) {
              console.warn(`Invalid pattern: ${patternStr}`, error);
              return null;
            }
          })
          .filter(Boolean);
        this.patternsLoaded = true;
        console.log(`Loaded ${this.patterns.length} patterns from API`);
        return;
      }
    } catch (error) {
      console.warn('Failed to load patterns from background script:', error);
    }

    // Always ensure we have at least the CVE pattern
    if (this.patterns.length === 0) {
      this.patterns = [this.CVE_PATTERN];
      this.patternsLoaded = true;
      console.log('Using fallback CVE pattern');
    }

    // Build combined pattern for efficient one-pass matching
    this.buildCombinedPattern();
  }

  buildCombinedPattern(): void {
    if (this.patterns.length === 0) {
      this.combinedPattern = null;
      return;
    }

    // Combine all patterns into single regex for one-pass matching
    const sources = this.patterns.map((p) => `(?:${p.source})`);
    this.combinedPattern = new RegExp(sources.join('|'), 'gi');
  }

  hasMatchingPattern(text: string): boolean {
    // Fast path: skip regex if text is too short to contain any identifier
    if (text.length < CONFIG.MIN_TEXT_LENGTH) {
      return false;
    }
    return this.patterns.some((pattern) => {
      pattern.lastIndex = 0; // Reset regex state for global patterns
      return pattern.test(text);
    });
  }

  isEditableElement(element: HTMLElement | null): boolean {
    if (!element) {
      return false;
    }

    const tagName = element.tagName.toLowerCase();

    // Skip form inputs and textareas
    if (['input', 'textarea', 'select'].includes(tagName)) {
      return true;
    }

    // Skip contenteditable elements (handles "", "true", "plaintext-only", etc.)
    if (element.isContentEditable) {
      return true;
    }

    // Skip elements inside any contenteditable ancestor
    if (element.closest('[contenteditable]')) {
      return true;
    }

    // Skip known editor containers (Jira, Confluence, etc.) using static combined selector
    return !!element.closest(EDITOR_SELECTOR);
  }

  isElementInViewport(element: Element): boolean {
    const rect = element.getBoundingClientRect();
    return (
      rect.bottom >= -CONFIG.VIEWPORT_MARGIN &&
      rect.right >= -CONFIG.VIEWPORT_MARGIN &&
      rect.top <=
        (window.innerHeight || document.documentElement.clientHeight) +
          CONFIG.VIEWPORT_MARGIN &&
      rect.left <=
        (window.innerWidth || document.documentElement.clientWidth) +
          CONFIG.VIEWPORT_MARGIN
    );
  }

  setupVisibilityObserver(): void {
    if (this.visibilityObserver) {
      return;
    }

    this.visibilityObserver = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            const pending = this.pendingOffscreenElements.get(entry.target);
            if (pending) {
              pending.forEach((node) => {
                if (node.isConnected && !this.processedNodes.has(node)) {
                  this.highlightCVEsInNode(node);
                }
              });
              this.pendingOffscreenElements.delete(entry.target);
              this.visibilityObserver?.unobserve(entry.target);
            }
          }
        }
        if (this.pendingHighlights.length > 0) {
          this.scheduleHighlightFlush();
        }
      },
      { rootMargin: `${CONFIG.VIEWPORT_MARGIN}px` }
    );
  }

  scheduleIdleProcessing(nodes: Text[]): void {
    if (nodes.length === 0) {
      return;
    }

    const processChunk = (deadline: IdleDeadline) => {
      while (
        nodes.length > 0 &&
        deadline.timeRemaining() > CONFIG.MIN_IDLE_TIME_MS
      ) {
        const node = nodes.shift();
        if (node && node.isConnected && !this.processedNodes.has(node)) {
          this.highlightCVEsInNode(node);
        }
      }

      if (nodes.length > 0) {
        this.idleCallbackId = requestIdleCallback(processChunk, {
          timeout: CONFIG.IDLE_CALLBACK_TIMEOUT_MS,
        });
      } else if (this.pendingHighlights.length > 0) {
        this.scheduleHighlightFlush();
      }
    };

    if ('requestIdleCallback' in window) {
      this.idleCallbackId = requestIdleCallback(processChunk, {
        timeout: CONFIG.IDLE_CALLBACK_TIMEOUT_MS,
      });
    } else {
      // Fallback: process all immediately
      nodes.forEach((n) => {
        if (n.isConnected && !this.processedNodes.has(n)) {
          this.highlightCVEsInNode(n);
        }
      });
      this.scheduleHighlightFlush();
    }
  }

  scheduleHighlightFlush(): void {
    if (this.highlightFlushScheduled) {
      return;
    }
    this.highlightFlushScheduled = true;

    requestAnimationFrame(() => {
      this.flushPendingHighlights();
      this.highlightFlushScheduled = false;
    });
  }

  flushPendingHighlights(): void {
    for (const { parent, oldNode, fragment } of this.pendingHighlights) {
      // Verify node is still attached and has the expected parent
      if (oldNode.parentNode === parent) {
        parent.replaceChild(fragment, oldNode);
      }
    }
    this.pendingHighlights = [];

    // Single badge update after all changes
    chrome.runtime.sendMessage({
      action: 'updateBadge',
      count: this.highlightedBulletins.size,
    });
  }

  detectMutationStorm(): boolean {
    const now = Date.now();
    this.mutationTimestamps.push(now);
    this.mutationTimestamps = this.mutationTimestamps.filter(
      (t) => now - t < CONFIG.STORM_WINDOW_MS
    );
    return this.mutationTimestamps.length > CONFIG.STORM_THRESHOLD;
  }

  getAdaptiveDebounceMs(): number {
    const count = this.pendingMutations.length;
    const recentActivity = this.mutationTimestamps.length;

    // Heavy storm detected
    if (recentActivity > CONFIG.DEBOUNCE_RECENT_EXTREME) {
      return CONFIG.DEBOUNCE_EXTREME_MS;
    }
    if (recentActivity > CONFIG.DEBOUNCE_RECENT_HIGH) {
      return CONFIG.DEBOUNCE_HIGH_MS;
    }

    // Based on pending mutations
    if (count < CONFIG.DEBOUNCE_RECENT_LOW) {
      return CONFIG.DEBOUNCE_LOW_MS;
    }
    if (count < CONFIG.DEBOUNCE_RECENT_MEDIUM) {
      return CONFIG.DEBOUNCE_MEDIUM_MS;
    }
    return CONFIG.DEBOUNCE_STORM_MS;
  }

  highlightCVEsInNode(textNode: Text): void {
    // Skip if already processed
    if (this.processedNodes.has(textNode)) {
      return;
    }

    const text = textNode.textContent || '';
    const parent = textNode.parentElement;
    if (!parent) {
      return;
    }

    // Mark as processed before doing work
    this.processedNodes.add(textNode);

    const fragment = document.createDocumentFragment();
    let processedOffset = 0;

    // Find all matches using combined pattern for efficiency
    const allMatches: Array<{ match: RegExpExecArray }> = [];

    if (this.combinedPattern) {
      this.combinedPattern.lastIndex = 0;
      let match;
      while ((match = this.combinedPattern.exec(text)) !== null) {
        allMatches.push({ match });
      }
    } else {
      // Fallback to iterating patterns if combined pattern not available
      this.patterns.forEach((pattern) => {
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(text)) !== null) {
          allMatches.push({ match });
          if (!pattern.global) {
            break;
          } // Prevent infinite loop for non-global patterns
        }
      });

      // Sort matches by position (only needed for fallback since combined pattern returns in order)
      allMatches.sort((a, b) => a.match.index - b.match.index);
    }

    // Process matches in order, avoiding overlaps
    allMatches.forEach(({ match }) => {
      const matchStart = match.index;
      const matchEnd = matchStart + match[0].length;

      // Skip overlapping matches
      if (matchStart < processedOffset) {
        return;
      }

      const bulletinId = match[0].toUpperCase();
      const bulletinType = detectBulletinType(bulletinId);

      // Add text before match
      if (matchStart > processedOffset) {
        fragment.appendChild(
          document.createTextNode(text.substring(processedOffset, matchStart))
        );
      }

      // Add highlighted match
      const highlightSpan = this.createHighlightElement(
        bulletinId,
        bulletinType
      );
      fragment.appendChild(highlightSpan);

      // Track counts by type (only count new bulletins)
      if (!this.highlightedBulletins.has(bulletinId)) {
        this.bulletinTypeCounts[bulletinType]++;
      }
      this.highlightedBulletins.add(bulletinId);
      processedOffset = matchEnd;
    });

    // Add remaining text
    if (processedOffset < text.length) {
      fragment.appendChild(
        document.createTextNode(text.substring(processedOffset))
      );
    }

    if (fragment.childNodes.length > 0) {
      // Collect for batched DOM update
      this.pendingHighlights.push({
        parent,
        oldNode: textNode,
        fragment,
      });
    }
  }

  createHighlightElement(
    bulletinId: string,
    bulletinType: BulletinType
  ): HTMLElement {
    const span = document.createElement('span');
    span.className = `vulners-highlight vulners-highlight-${bulletinType}`;
    span.textContent = bulletinId;
    span.dataset.bulletinId = bulletinId;
    span.dataset.bulletinType = bulletinType;

    // Create bound handlers that we can remove later
    const enterHandler = (e: MouseEvent) =>
      this.tooltipManager.handleMouseEnter(e);
    const leaveHandler = (e: MouseEvent) =>
      this.tooltipManager.handleMouseLeave(e);

    span.addEventListener('mouseenter', enterHandler);
    span.addEventListener('mouseleave', leaveHandler);

    // Store references for cleanup
    this.highlightEventHandlers.set(span, {
      enter: enterHandler,
      leave: leaveHandler,
    });

    return span;
  }

  scanAndHighlight(
    isProcessing: boolean,
    pauseUntilMs: number
  ): { isProcessing: boolean; needsRescan: boolean } {
    // Prevent recursive processing
    if (isProcessing) {
      return { isProcessing, needsRescan: false };
    }
    if (Date.now() < pauseUntilMs) {
      return { isProcessing, needsRescan: true };
    }

    // Ensure visibility observer is set up
    this.setupVisibilityObserver();

    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode: (node) => {
          // Skip already processed nodes
          if (this.processedNodes.has(node)) {
            return NodeFilter.FILTER_REJECT;
          }

          const parent = node.parentElement;
          if (!parent) {
            return NodeFilter.FILTER_REJECT;
          }

          const tagName = parent.tagName.toLowerCase();
          if (
            ['script', 'style', 'noscript', 'iframe', 'object'].includes(
              tagName
            )
          ) {
            return NodeFilter.FILTER_REJECT;
          }

          if (parent.classList.contains('vulners-highlight')) {
            return NodeFilter.FILTER_REJECT;
          }

          // Don't highlight inside tooltip
          if (parent.closest('.vulners-tooltip')) {
            return NodeFilter.FILTER_REJECT;
          }

          // Don't highlight inside editable areas (prevents Jira/editor crashes)
          if (this.isEditableElement(parent)) {
            return NodeFilter.FILTER_REJECT;
          }

          return NodeFilter.FILTER_ACCEPT;
        },
      }
    );

    const visibleNodes: Text[] = [];
    const offscreenNodes: Text[] = [];
    let node: Text | null;

    while ((node = walker.nextNode() as Text)) {
      if (this.hasMatchingPattern(node.textContent || '')) {
        const parent = node.parentElement;
        if (parent && this.isElementInViewport(parent)) {
          visibleNodes.push(node);
        } else {
          offscreenNodes.push(node);
        }
      }
    }

    // Process visible nodes immediately via requestAnimationFrame
    if (visibleNodes.length > 0) {
      requestAnimationFrame(() => {
        visibleNodes.forEach((n) => {
          if (n.isConnected && !this.processedNodes.has(n)) {
            this.highlightCVEsInNode(n);
          }
        });
        if (this.pendingHighlights.length > 0) {
          this.scheduleHighlightFlush();
        }
      });
    }

    // Queue off-screen nodes for idle processing or IntersectionObserver
    if (offscreenNodes.length > 0) {
      // Group by parent element for IntersectionObserver
      const offscreenByParent = new Map<Element, Text[]>();
      offscreenNodes.forEach((n) => {
        const parent = n.parentElement;
        if (parent) {
          const existing = offscreenByParent.get(parent) || [];
          existing.push(n);
          offscreenByParent.set(parent, existing);
        }
      });

      // If few off-screen nodes, use idle callback for immediate background processing
      if (offscreenNodes.length <= CONFIG.MAX_IMMEDIATE_OFFSCREEN) {
        this.scheduleIdleProcessing([...offscreenNodes]);
      } else {
        // Use IntersectionObserver for larger sets
        offscreenByParent.forEach((nodes, parent) => {
          const existing = this.pendingOffscreenElements.get(parent) || [];
          this.pendingOffscreenElements.set(parent, [...existing, ...nodes]);
          this.visibilityObserver?.observe(parent);
        });

        // Also schedule some for immediate idle processing to cover hidden elements
        const immediateNodes = offscreenNodes.slice(
          0,
          CONFIG.IMMEDIATE_OFFSCREEN_SLICE
        );
        this.scheduleIdleProcessing(immediateNodes);
      }
    }

    // Update badge
    if (this.pendingHighlights.length === 0 && visibleNodes.length === 0) {
      chrome.runtime.sendMessage({
        action: 'updateBadge',
        count: this.highlightedBulletins.size,
      });
    }

    return { isProcessing: false, needsRescan: false };
  }

  scanElementForCVEs(element: HTMLElement): void {
    // Skip editable elements entirely
    if (this.isEditableElement(element)) {
      return;
    }

    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, {
      acceptNode: (node) => {
        const parent = node.parentElement;
        if (!parent) {
          return NodeFilter.FILTER_REJECT;
        }

        const tagName = parent.tagName.toLowerCase();
        if (
          ['script', 'style', 'noscript', 'iframe', 'object'].includes(tagName)
        ) {
          return NodeFilter.FILTER_REJECT;
        }

        if (parent.classList.contains('vulners-highlight')) {
          return NodeFilter.FILTER_REJECT;
        }

        // Don't highlight inside tooltip
        if (parent.closest('.vulners-tooltip')) {
          return NodeFilter.FILTER_REJECT;
        }

        // Don't highlight inside editable areas
        if (this.isEditableElement(parent)) {
          return NodeFilter.FILTER_REJECT;
        }

        return NodeFilter.FILTER_ACCEPT;
      },
    });

    let node: Text | null;
    while ((node = walker.nextNode() as Text)) {
      if (this.hasMatchingPattern(node.textContent || '')) {
        this.highlightCVEsInNode(node);
      }
    }
  }

  addPendingMutations(mutations: MutationRecord[]): void {
    this.pendingMutations.push(...mutations);
  }

  clearPendingMutations(): void {
    this.pendingMutations = [];
  }

  cleanup(): void {
    if (this.idleCallbackId !== null) {
      cancelIdleCallback(this.idleCallbackId);
      this.idleCallbackId = null;
    }
    this.visibilityObserver?.disconnect();
    this.visibilityObserver = null;
    this.pendingOffscreenElements.clear();
    this.processedNodes = new WeakSet<Node>();
  }

  removeAllHighlights(): void {
    // Clean up observers and pending processing
    this.cleanup();

    document.querySelectorAll('.vulners-highlight').forEach((element) => {
      const htmlElement = element as HTMLElement;

      // Remove event listeners before removing element
      const handlers = this.highlightEventHandlers.get(htmlElement);
      if (handlers) {
        htmlElement.removeEventListener('mouseenter', handlers.enter);
        htmlElement.removeEventListener('mouseleave', handlers.leave);
        this.highlightEventHandlers.delete(htmlElement);
      }

      const parent = element.parentElement;
      if (parent) {
        const textNode = document.createTextNode(element.textContent || '');
        parent.replaceChild(textNode, element);
        parent.normalize();
      }
    });

    this.highlightedBulletins.clear();
    this.bulletinTypeCounts = { cve: 0, advisory: 0, exploit: 0 };

    chrome.runtime.sendMessage({
      action: 'updateBadge',
      count: 0,
    });
  }
}
