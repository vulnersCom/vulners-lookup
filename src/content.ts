interface CVEData {
  id: string;
  title?: string;
  cvss?: {
    score: number;
    vector: string;
  };
  cvss4?: {
    score: number;
    vector: string;
  };
  epss?: {
    score: number;
    percentile: number;
  };
  description?: string;
  shortDescription?: string;
  published?: string;
  modified?: string;
  status?: string;
  isCandidate?: boolean;
  cwe?: string;
  exploitInfo?: {
    maxMaturity?: string;
    exploits?: number;
    available?: string;
    wildExploited?: boolean;
  };
  vulnerabilityIntelligence?: {
    score?: number;
    uncertainty?: number;
    twitterMentions?: number;
    webApplicable?: boolean;
  };
  sources?: string[];
}

class CVEHighlighter {
  private readonly CVE_PATTERN = /CVE-\d{4}-\d{4,7}/gi;
  private patterns: RegExp[] = [];
  private patternsLoaded = false;
  private highlightedCVEs = new Set<string>();
  private cveDataCache = new Map<string, CVEData>();
  private tooltip: HTMLDivElement | null = null;
  private currentHighlightedElement: HTMLElement | null = null;
  private enabled = true;
  private hideTooltipTimeout: number = NaN;
  public static readonly TOOLTIP_DELAY_MS = 200;

  constructor() {
    this.waitForPageLoad();
  }

  private waitForPageLoad() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        this.init();
      });
    } else {
      // DOM is ready or page is fully loaded - start immediately
      this.init();
    }
  }

  private isVulnersSite(): boolean {
    const hostname = window.location.hostname.toLowerCase();
    return (
      hostname === 'vulners.com' ||
      hostname.endsWith('.vulners.com') ||
      hostname === 'www.vulners.com'
    );
  }

  private async loadPatterns() {
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
  }

  private async init() {
    const settings = await chrome.storage.local.get(['enabled']);
    this.enabled = settings.enabled !== false;

    // Don't highlight on vulners.com domain
    if (this.isVulnersSite()) {
      this.enabled = false;
    }

    if (this.enabled) {
      await this.loadPatterns();

      // Try initial scan
      this.scanAndHighlight();

      // Set up periodic rescanning for dynamic content
      this.setupPeriodicScan();
      this.observePageChanges();
    }

    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === 'toggleHighlighting') {
        // Don't allow enabling on vulners.com
        if (this.isVulnersSite()) {
          this.enabled = false;
        } else {
          this.enabled = request.enabled;
        }

        if (this.enabled) {
          if (!this.patternsLoaded) {
            this.loadPatterns().then(() => this.scanAndHighlight());
          } else {
            this.scanAndHighlight();
          }
        } else {
          this.removeAllHighlights();
        }
      } else if (request.action === 'getStats') {
        sendResponse({ count: this.highlightedCVEs.size });
      }
    });
  }

  private setupPeriodicScan() {
    // Fast rescanning for dynamically loaded content
    let scanCount = 0;
    let currentInterval = 500; // Start with 500ms
    const maxScans = 10; // More scan attempts

    const scheduleNextScan = () => {
      if (scanCount >= maxScans || !this.enabled) {
        return;
      }

      setTimeout(() => {
        scanCount++;

        if (!this.enabled) {
          return;
        }

        const previousCount = this.highlightedCVEs.size;
        console.log(
          `Vulners: Fast rescan ${scanCount}/${maxScans} (found: ${previousCount})`
        );

        this.scanAndHighlight();

        const newCount = this.highlightedCVEs.size;

        if (newCount > previousCount) {
          // Found new CVEs, keep scanning quickly
          currentInterval = Math.min(currentInterval, 500);
        } else if (newCount >= 5) {
          // Found plenty of CVEs, slow down
          currentInterval = 2000;
        } else {
          // No new CVEs found, gradually slow down
          currentInterval = Math.min(currentInterval * 1.5, 2000);
        }

        scheduleNextScan();
      }, currentInterval);
    };

    // Start the scanning cycle
    scheduleNextScan();
  }

  private hasMatchingPattern(text: string): boolean {
    return this.patterns.some((pattern) => {
      pattern.lastIndex = 0; // Reset regex state for global patterns
      return pattern.test(text);
    });
  }

  private scanAndHighlight() {
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode: (node) => {
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

          if (parent.classList.contains('vulners-cve-highlight')) {
            return NodeFilter.FILTER_REJECT;
          }

          // Don't highlight inside tooltip
          if (parent.closest('.vulners-tooltip')) {
            return NodeFilter.FILTER_REJECT;
          }

          return NodeFilter.FILTER_ACCEPT;
        },
      }
    );

    const nodesToProcess: Text[] = [];
    let node: Text | null;

    while ((node = walker.nextNode() as Text)) {
      if (this.hasMatchingPattern(node.textContent || '')) {
        nodesToProcess.push(node);
      }
    }

    nodesToProcess.forEach((node) => this.highlightCVEsInNode(node));

    chrome.runtime.sendMessage({
      action: 'updateBadge',
      count: this.highlightedCVEs.size,
    });
  }

  private highlightCVEsInNode(textNode: Text) {
    const text = textNode.textContent || '';
    const parent = textNode.parentElement;
    if (!parent) {
      return;
    }

    const fragment = document.createDocumentFragment();
    let processedOffset = 0;

    // Find all matches from all patterns
    const allMatches: Array<{ match: RegExpExecArray }> = [];

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

    // Sort matches by position
    allMatches.sort((a, b) => a.match.index - b.match.index);

    // Process matches in order, avoiding overlaps
    allMatches.forEach(({ match }) => {
      const matchStart = match.index;
      const matchEnd = matchStart + match[0].length;

      // Skip overlapping matches
      if (matchStart < processedOffset) {
        return;
      }

      const cveId = match[0].toUpperCase();

      // Add text before match
      if (matchStart > processedOffset) {
        fragment.appendChild(
          document.createTextNode(text.substring(processedOffset, matchStart))
        );
      }

      // Add highlighted match
      const highlightSpan = this.createHighlightElement(cveId);
      fragment.appendChild(highlightSpan);

      this.highlightedCVEs.add(cveId);
      processedOffset = matchEnd;
    });

    // Add remaining text
    if (processedOffset < text.length) {
      fragment.appendChild(
        document.createTextNode(text.substring(processedOffset))
      );
    }

    if (fragment.childNodes.length > 0) {
      parent.replaceChild(fragment, textNode);
    }
  }

  private createHighlightElement(cveId: string): HTMLElement {
    const span = document.createElement('span');
    span.className = 'vulners-cve-highlight';
    span.textContent = cveId;
    span.dataset.cveId = cveId;

    span.addEventListener('mouseenter', (e) => this.handleMouseEnter(e));
    span.addEventListener('mouseleave', (e) => this.handleMouseLeave(e));

    return span;
  }

  private async handleMouseEnter(event: MouseEvent) {
    const target = event.currentTarget as HTMLElement;
    const cveId = target.dataset.cveId;

    if (!cveId) {
      return;
    }

    this.currentHighlightedElement = target;

    await this.showTooltip(target, cveId);
  }

  private handleMouseLeave(event: MouseEvent) {
    const relatedTarget = event.relatedTarget as HTMLElement;

    if (relatedTarget && this.tooltip &&
      (this.tooltip.contains(relatedTarget) || relatedTarget === this.tooltip)
    ) {
      return;
    }

    this.hideTooltipTimeout = window.setTimeout(() => {
      this.hideTooltip();
    }, CVEHighlighter.TOOLTIP_DELAY_MS);
  }

  private handleClick(event: MouseEvent) {
    const target = event.currentTarget as HTMLElement;
    const cveId = target.dataset.cveId;

    if (cveId) {
      const url = new URL(`https://vulners.com/cve/${cveId}`);
      url.searchParams.set('utm_source', 'vulners-lookup');
      url.searchParams.set('utm_medium', 'chrome-extension');
      window.open(url.toString(), '_blank');
    }
  }

  private async showTooltip(element: HTMLElement, cveId: string) {
    if (!this.tooltip) {
      this.createTooltip();
    }

    if (!this.tooltip) {
      return;
    }

    this.tooltip.innerHTML = this.getLoadingHTML(cveId);
    this.positionTooltip(element);
    this.tooltip.style.display = 'block';

    const data = await this.fetchCVEData(cveId);

    if (this.currentHighlightedElement === element && this.tooltip) {
      this.tooltip.innerHTML = this.getTooltipHTML(data);

      const titleEl = this.tooltip.querySelector('.vulners-cve-title');
      if (titleEl instanceof HTMLElement) {
        titleEl.addEventListener('click', (e) => this.handleClick(e));
      }
    }
  }

  private createTooltip() {
    this.tooltip = document.createElement('div');
    this.tooltip.className = 'vulners-tooltip';
    this.tooltip.style.display = 'none';

    this.tooltip.addEventListener('mouseenter', () => {
      clearTimeout(this.hideTooltipTimeout);
    });

    this.tooltip.addEventListener('mouseleave', () => {
      this.hideTooltip();
    });

    document.body.appendChild(this.tooltip);
  }

  private hideTooltip() {
    clearTimeout(this.hideTooltipTimeout);

    if (this.tooltip) {
      this.tooltip.style.display = 'none';
    }
    this.currentHighlightedElement = null;
  }

  private positionTooltip(element: HTMLElement) {
    if (!this.tooltip) {
      return;
    }

    const rect = element.getBoundingClientRect();
    const tooltipWidth = 320;
    const tooltipHeight = 242;
    const padding = 10;

    let left = rect.left + window.scrollX;
    let top = rect.bottom + window.scrollY + 5;

    if (left + tooltipWidth > window.innerWidth - padding) {
      left = window.innerWidth - tooltipWidth - padding + window.scrollX;
    }

    if (top + tooltipHeight > window.innerHeight + window.scrollY - padding) {
      top = rect.top + window.scrollY - tooltipHeight - 5;
    }

    this.tooltip.style.left = `${left}px`;
    this.tooltip.style.top = `${top}px`;
  }

  private async fetchCVEData(cveId: string): Promise<CVEData> {
    if (this.cveDataCache.has(cveId)) {
      return this.cveDataCache.get(cveId)!;
    }

    try {
      const response = await chrome.runtime.sendMessage({
        action: 'fetchCVEData',
        cveId: cveId,
      });

      if (response && response.data) {
        this.cveDataCache.set(cveId, response.data);
        return response.data;
      }
    } catch (error) {
      console.error(`Failed to fetch CVE data for ${cveId}:`, error);
    }

    return {
      id: cveId,
      description: 'Unable to fetch vulnerability details',
      status: 'Unknown',
    };
  }

  private getLoadingHTML(cveId: string): string {
    return `
      <div class="vulners-tooltip-content">
        <div class="vulners-header">
          <img class="vulners-logo" src="${chrome.runtime.getURL('assets/icon-48.png')}" alt="Vulners Lookup Logo" />
          <span class="vulners-title">Vulners Lookup</span>
        </div>
        <div class="vulners-cve-id">${cveId}</div>
        <div class="vulners-loading">
          <div class="vulners-spinner"></div>
          <span>Loading vulnerability data...</span>
        </div>
      </div>
    `;
  }

  private normalizeDateUTC(dateStr: string = ''): string {
    if (dateStr.endsWith("Z") || dateStr.endsWith("z")) {
      return dateStr;
    }

    return dateStr + "Z";
  }

  private getTooltipHTML(data: CVEData): string {
    const cvssScore = data.cvss?.score || 0;
    const aiScore = data.vulnerabilityIntelligence?.score || 0;
    const epssScore = data.epss?.score || 0;
    const exploitCount = data.exploitInfo?.exploits || 0;
    const referenceCount = data.sources?.length || 3;
    const affectedCount = 3; // This would need to come from the API
    const {title, id, shortDescription, description, published} = data;

    const date = new Date(this.normalizeDateUTC(published));
    const formattedDate = `🗓 Published: ${date.getDate().toString().padStart(2, "0")} ${
      date.toLocaleString(undefined, { month: "short" })
    } ${date.getFullYear()} ${date.toTimeString().slice(0, 8)}`;

    return `
      <div class="vulners-tooltip-content">
        <div class="vulners-header">
          <img class="vulners-logo" src="${chrome.runtime.getURL('assets/icon-48.png')}" alt="Vulners" />
          <span class="vulners-title">Vulners Lookup</span>
        </div>
        
        <div class="vulners-main-card">
          <div class="vulners-cve-title-wrapper">
            <div class="vulners-cve-title" data-cve-id="${id}">${title ?? id}</div>
            <div class="vulners-published">${formattedDate}</div>
          </div>
          
          <div class="vulners-description">
            ${shortDescription || description || 'No description available'}
          </div>
          
          <div class="vulners-chips">
            ${
              cvssScore > 0
                ? `
              <div class="vulners-chip">
                <span class="vulners-chip-value">${cvssScore.toFixed(1)}</span>
                <span class="vulners-chip-label">CVSS</span>
              </div>
            `
                : ''
            }
            
            ${
              aiScore > 0
                ? `
              <div class="vulners-chip">
                <span class="vulners-chip-value">${aiScore.toFixed(1)}</span>
                <span class="vulners-chip-label">AI score</span>
              </div>
            `
                : ''
            }
            
            ${
              epssScore > 0
                ? `
              <div class="vulners-chip">
                <span class="vulners-chip-value">${epssScore.toFixed(3)}</span>
                <span class="vulners-chip-label">EPSS</span>
              </div>
            `
                : ''
            }
          </div>
        </div>
        
        <div class="vulners-stats">
          ${
            data.exploitInfo?.wildExploited
              ? `
            <div class="vulners-stat-card vulners-wild">
              <div class="vulners-stat-label">Wild</div>
            </div>
          `
              : ''
          }
          
          <div class="vulners-stat-card">
            <div class="vulners-stat-count">${exploitCount}</div>
            <div class="vulners-stat-label">Exploits</div>
          </div>
          
          <div class="vulners-stat-card">
            <div class="vulners-stat-count">${referenceCount}</div>
            <div class="vulners-stat-label">References</div>
          </div>
          
          <div class="vulners-stat-card">
            <div class="vulners-stat-count">${affectedCount}</div>
            <div class="vulners-stat-label">Affected</div>
          </div>
        </div>
      </div>
    `;
  }

  private observePageChanges() {
    const observer = new MutationObserver((mutations) => {
      if (!this.enabled) {
        return;
      }

      for (const mutation of mutations) {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.TEXT_NODE) {
              const textNode = node as Text;
              if (this.hasMatchingPattern(textNode.textContent || '')) {
                this.highlightCVEsInNode(textNode);
              }
            } else if (node.nodeType === Node.ELEMENT_NODE) {
              const element = node as HTMLElement;
              if (
                !element.classList.contains('vulners-cve-highlight') &&
                !element.classList.contains('vulners-tooltip')
              ) {
                this.scanElementForCVEs(element);
              }
            }
          });
        }
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  private scanElementForCVEs(element: HTMLElement) {
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

        if (parent.classList.contains('vulners-cve-highlight')) {
          return NodeFilter.FILTER_REJECT;
        }

        // Don't highlight inside tooltip
        if (parent.closest('.vulners-tooltip')) {
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

  private removeAllHighlights() {
    document.querySelectorAll('.vulners-cve-highlight').forEach((element) => {
      const parent = element.parentElement;
      if (parent) {
        const textNode = document.createTextNode(element.textContent || '');
        parent.replaceChild(textNode, element);
        parent.normalize();
      }
    });

    this.highlightedCVEs.clear();

    chrome.runtime.sendMessage({
      action: 'updateBadge',
      count: 0,
    });
  }
}

new CVEHighlighter();
