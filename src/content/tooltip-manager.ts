import type { BulletinType, CVEData } from './types';
import {
  CONFIG,
  BULLETIN_TYPE_LABELS,
  BULLETIN_TYPE_COLORS,
} from './constants';
import { escapeHtml } from './utils';

export class TooltipManager {
  private tooltip: HTMLDivElement | null = null;
  private currentHighlightedElement: HTMLElement | null = null;
  private hideTooltipTimeout: number = NaN;
  private cveDataCache = new Map<string, CVEData>();

  constructor() {}

  getCurrentHighlightedElement(): HTMLElement | null {
    return this.currentHighlightedElement;
  }

  setCurrentHighlightedElement(element: HTMLElement | null): void {
    this.currentHighlightedElement = element;
  }

  clearHideTimeout(): void {
    clearTimeout(this.hideTooltipTimeout);
  }

  async handleMouseEnter(event: MouseEvent): Promise<void> {
    const target = event.currentTarget as HTMLElement;
    const bulletinId = target.dataset.bulletinId;
    const bulletinType = (target.dataset.bulletinType as BulletinType) || 'cve';

    if (!bulletinId) {
      return;
    }

    this.currentHighlightedElement = target;

    await this.showTooltip(target, bulletinId, bulletinType);
  }

  handleMouseLeave(event: MouseEvent): void {
    const relatedTarget = event.relatedTarget as HTMLElement;

    if (
      relatedTarget &&
      this.tooltip &&
      (this.tooltip.contains(relatedTarget) || relatedTarget === this.tooltip)
    ) {
      return;
    }

    this.hideTooltipTimeout = window.setTimeout(() => {
      this.hideTooltip();
    }, CONFIG.TOOLTIP_DELAY_MS);
  }

  async showTooltip(
    element: HTMLElement,
    bulletinId: string,
    bulletinType: BulletinType
  ): Promise<void> {
    if (!this.tooltip) {
      this.createTooltip();
    }

    if (!this.tooltip) {
      return;
    }

    this.tooltip.innerHTML = this.getLoadingHTML(bulletinId, bulletinType);
    this.positionTooltip(element);
    this.tooltip.style.display = 'block';

    const data = await this.fetchBulletinData(bulletinId, bulletinType);

    if (this.currentHighlightedElement === element && this.tooltip) {
      this.tooltip.innerHTML = this.getTooltipHTML(data, bulletinType);
    }
  }

  createTooltip(): void {
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

  hideTooltip(): void {
    clearTimeout(this.hideTooltipTimeout);

    if (this.tooltip) {
      this.tooltip.style.display = 'none';
    }
    this.currentHighlightedElement = null;
  }

  positionTooltip(element: HTMLElement): void {
    if (!this.tooltip) {
      return;
    }

    const rect = element.getBoundingClientRect();

    let left = rect.left + window.scrollX;
    let top = rect.bottom + window.scrollY + CONFIG.TOOLTIP_OFFSET;

    if (
      left + CONFIG.TOOLTIP_WIDTH >
      window.innerWidth - CONFIG.TOOLTIP_PADDING
    ) {
      left =
        window.innerWidth -
        CONFIG.TOOLTIP_WIDTH -
        CONFIG.TOOLTIP_PADDING +
        window.scrollX;
    }

    if (
      top + CONFIG.TOOLTIP_HEIGHT >
      window.innerHeight + window.scrollY - CONFIG.TOOLTIP_PADDING
    ) {
      top =
        rect.top +
        window.scrollY -
        CONFIG.TOOLTIP_HEIGHT -
        CONFIG.TOOLTIP_OFFSET;
    }

    this.tooltip.style.left = `${left}px`;
    this.tooltip.style.top = `${top}px`;
  }

  async fetchBulletinData(
    bulletinId: string,
    bulletinType: BulletinType
  ): Promise<CVEData> {
    const cached = this.cveDataCache.get(bulletinId);
    if (cached) {
      return cached;
    }

    try {
      const response = await chrome.runtime.sendMessage({
        action: 'fetchCVEData',
        cveId: bulletinId,
      });

      if (response && response.data) {
        const data = { ...response.data, type: bulletinType };
        this.cveDataCache.set(bulletinId, data);
        return data;
      }
    } catch (error) {
      console.error(`Failed to fetch data for ${bulletinId}:`, error);
    }

    // Return minimal data for non-CVE types or on error
    return {
      id: bulletinId,
      type: bulletinType,
      description:
        bulletinType === 'cve'
          ? 'Unable to fetch vulnerability details'
          : 'Click to view details on Vulners.com',
      status: 'Unknown',
    };
  }

  getLoadingHTML(bulletinId: string, bulletinType: BulletinType): string {
    const typeLabel = BULLETIN_TYPE_LABELS[bulletinType];
    const typeColor = BULLETIN_TYPE_COLORS[bulletinType];
    const safeBulletinId = escapeHtml(bulletinId);

    return `
      <div class="vulners-tooltip-content">
        <div class="vulners-header">
          <img class="vulners-logo" src="${chrome.runtime.getURL('assets/icon-48.png')}" alt="Vulners Lookup Logo" />
          <span class="vulners-title">Vulners Lookup</span>
          <span class="vulners-type-badge" style="background:${typeColor}">${typeLabel}</span>
        </div>
        <div class="vulners-bulletin-id">${safeBulletinId}</div>
        <div class="vulners-loading">
          <div class="vulners-spinner"></div>
          <span>Loading data...</span>
        </div>
      </div>
    `;
  }

  private normalizeDateUTC(dateStr: string = ''): string {
    if (dateStr.endsWith('Z') || dateStr.endsWith('z')) {
      return dateStr;
    }

    return dateStr + 'Z';
  }

  private getVulnersUrl(id: string): string {
    const url = new URL(`https://vulners.com/cve/${encodeURIComponent(id)}`);
    url.searchParams.set('utm_source', 'vulners-lookup');
    url.searchParams.set('utm_medium', 'chrome-extension');
    return url.toString();
  }

  private formatPublishedDate(published?: string): string {
    if (!published) {
      return '';
    }

    try {
      const date = new Date(this.normalizeDateUTC(published));
      if (isNaN(date.getTime())) {
        return '';
      }
      return `🗓 Published: ${date.getDate().toString().padStart(2, '0')} ${date.toLocaleString(
        undefined,
        { month: 'short' }
      )} ${date.getFullYear()} ${date.toTimeString().slice(0, 8)}`;
    } catch {
      return '';
    }
  }

  getTooltipHTML(data: CVEData, bulletinType: BulletinType): string {
    const cvssScore = data.cvss?.score || 0;
    const aiScore = data.vulnerabilityIntelligence?.score || 0;
    const epssScore = data.epss?.score || 0;
    const exploitCount = data.exploitInfo?.exploits || 0;
    const referenceCount = data.sources?.length || 0;
    const {
      title,
      id,
      shortDescription,
      description,
      published,
      linkedCVEs,
      linkedCVECount,
      relatedCVEs,
      relatedCVECount,
      repoUrl,
      platform,
      maturity,
      author,
    } = data;

    const formattedDate = this.formatPublishedDate(published);
    const hasTitle = title && title !== id;
    const vulnersUrl = this.getVulnersUrl(id);
    const typeLabel = BULLETIN_TYPE_LABELS[bulletinType];
    const typeColor = BULLETIN_TYPE_COLORS[bulletinType];

    // Escape all dynamic values for XSS protection
    const safeId = escapeHtml(id);
    const safeTitle = title ? escapeHtml(title) : '';
    const safeDescription = escapeHtml(
      shortDescription || description || 'No description available'
    );
    const safeAuthor = author ? escapeHtml(author) : '';
    const safePlatform = platform ? escapeHtml(platform) : '';
    const safeMaturity = maturity ? escapeHtml(maturity) : '';

    // Check if we have detailed data (from API) or just basic info
    const hasDetailedData =
      cvssScore > 0 ||
      aiScore > 0 ||
      epssScore > 0 ||
      exploitCount > 0 ||
      linkedCVEs?.length ||
      relatedCVEs?.length ||
      repoUrl ||
      author;

    // Build linked CVEs section for advisories (with "more" indicator)
    const linkedTotal = linkedCVECount || linkedCVEs?.length || 0;
    const linkedMore =
      linkedTotal > (linkedCVEs?.length || 0)
        ? linkedTotal - (linkedCVEs?.length || 0)
        : 0;
    const linkedCVEsHTML =
      linkedCVEs && linkedCVEs.length > 0
        ? `
        <div class="vulners-linked-cves">
          <div class="vulners-linked-label">🔗 Linked CVEs (${linkedTotal}):</div>
          <div class="vulners-linked-list">
            ${linkedCVEs.map((cve) => `<a href="${this.getVulnersUrl(cve)}" target="_blank" rel="noopener noreferrer" class="vulners-linked-cve">${escapeHtml(cve)}</a>`).join('')}
            ${linkedMore > 0 ? `<a href="${vulnersUrl}" target="_blank" rel="noopener noreferrer" class="vulners-linked-cve vulners-more">+${linkedMore} more</a>` : ''}
          </div>
        </div>
      `
        : '';

    // Build related CVEs section for exploits (with "more" indicator)
    const relatedTotal = relatedCVECount || relatedCVEs?.length || 0;
    const relatedMore =
      relatedTotal > (relatedCVEs?.length || 0)
        ? relatedTotal - (relatedCVEs?.length || 0)
        : 0;
    const relatedCVEsHTML =
      relatedCVEs && relatedCVEs.length > 0
        ? `
        <div class="vulners-linked-cves">
          <div class="vulners-linked-label">🎯 Related CVEs (${relatedTotal}):</div>
          <div class="vulners-linked-list">
            ${relatedCVEs.map((cve) => `<a href="${this.getVulnersUrl(cve)}" target="_blank" rel="noopener noreferrer" class="vulners-linked-cve">${escapeHtml(cve)}</a>`).join('')}
            ${relatedMore > 0 ? `<a href="${vulnersUrl}" target="_blank" rel="noopener noreferrer" class="vulners-linked-cve vulners-more">+${relatedMore} more</a>` : ''}
          </div>
        </div>
      `
        : '';

    // Build exploit info section (repoUrl, platform, maturity, author)
    // repoUrl is validated as URL via getVulnersUrl pattern - only allow known safe URLs
    const safeRepoUrl =
      repoUrl && /^https?:\/\/[a-zA-Z0-9.-]+/.test(repoUrl)
        ? escapeHtml(repoUrl)
        : '';
    const exploitInfoHTML =
      safeRepoUrl || safeAuthor || safePlatform || safeMaturity
        ? `
        <div class="vulners-exploit-info">
          ${
            safeRepoUrl
              ? `
          <a href="${safeRepoUrl}" target="_blank" rel="noopener noreferrer" class="vulners-repo-link">
            📁 View source →
          </a>
          `
              : ''
          }
          ${safeAuthor ? `<div class="vulners-author">👤 Author: ${safeAuthor}</div>` : ''}
          ${
            safePlatform || safeMaturity
              ? `
            <div class="vulners-exploit-meta">
              ${safePlatform ? `<span class="vulners-exploit-tag">📦 ${safePlatform}</span>` : ''}
              ${safeMaturity ? `<span class="vulners-exploit-tag vulners-maturity-${safeMaturity}">⚡ ${safeMaturity}</span>` : ''}
            </div>
          `
              : ''
          }
        </div>
      `
        : '';

    return `
      <div class="vulners-tooltip-content">
        <div class="vulners-header">
          <img class="vulners-logo" src="${chrome.runtime.getURL('assets/icon-48.png')}" alt="Vulners" />
          <span class="vulners-title">Vulners Lookup</span>
          <span class="vulners-type-badge" style="background:${typeColor}">${typeLabel}</span>
        </div>

        <div class="vulners-main-card">
          <div class="vulners-cve-title-wrapper">
            <a href="${vulnersUrl}" target="_blank" rel="noopener noreferrer" class="vulners-cve-id-link" style="color:${typeColor}">${safeId}</a>
            ${formattedDate ? `<div class="vulners-published">${formattedDate}</div>` : ''}
          </div>

          ${hasTitle ? `<div class="vulners-bulletin-title">${safeTitle}</div>` : ''}

          <div class="vulners-description">
            ${safeDescription}
          </div>

          ${
            hasDetailedData
              ? `
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

          ${linkedCVEsHTML}
          ${relatedCVEsHTML}
          ${exploitInfoHTML}

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

          ${
            referenceCount > 0
              ? `
          <div class="vulners-stat-card">
            <div class="vulners-stat-count">${referenceCount}</div>
            <div class="vulners-stat-label">References</div>
          </div>
          `
              : ''
          }
        </div>
          `
              : `
        </div>
        <div class="vulners-view-details">
          <a href="${vulnersUrl}" target="_blank" rel="noopener noreferrer" class="vulners-view-link">
            View details on Vulners.com →
          </a>
        </div>
          `
          }
      </div>
    `;
  }
}
