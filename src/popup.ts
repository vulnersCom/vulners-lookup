class PopupController {
  private toggleHighlighting: HTMLInputElement;
  private cveCountElement: HTMLElement;
  private statusElement: HTMLElement;

  constructor() {
    this.toggleHighlighting = document.getElementById(
      'toggle-highlighting'
    ) as HTMLInputElement;
    this.cveCountElement = document.getElementById('cve-count') as HTMLElement;
    this.statusElement = document.getElementById('status') as HTMLElement;

    this.init();
  }

  private async init() {
    await this.loadSettings();
    await this.updateStats();
    this.setupEventListeners();
  }

  private async loadSettings() {
    const settings = await chrome.storage.local.get(['enabled']);
    this.toggleHighlighting.checked = settings.enabled !== false;
    this.updateStatus(settings.enabled !== false);
  }

  private setupEventListeners() {
    this.toggleHighlighting.addEventListener('change', async () => {
      const [tab] = await chrome.tabs.query({
        active: true,
        currentWindow: true,
      });

      // Prevent enabling on vulners.com
      if (tab.url && this.isVulnersSite(tab.url)) {
        this.toggleHighlighting.checked = false;
        return;
      }

      const enabled = this.toggleHighlighting.checked;

      await chrome.storage.local.set({ enabled });

      if (tab.id) {
        chrome.tabs.sendMessage(tab.id, {
          action: 'toggleHighlighting',
          enabled,
        });
      }

      this.updateStatus(enabled);

      if (!enabled) {
        this.cveCountElement.textContent = '0';
        chrome.action.setBadgeText({ text: '' });
      } else {
        await this.updateStats();
      }
    });
  }

  private async updateStats() {
    try {
      const [tab] = await chrome.tabs.query({
        active: true,
        currentWindow: true,
      });

      // Check if we're on vulners.com
      if (tab.url && this.isVulnersSite(tab.url)) {
        this.cveCountElement.textContent = '—';
        this.statusElement.textContent = 'Disabled on Vulners';
        this.statusElement.className = 'stat-value status-inactive';
        this.toggleHighlighting.checked = false;
        this.toggleHighlighting.disabled = true;
        return;
      }

      if (tab.id) {
        chrome.tabs.sendMessage(tab.id, { action: 'getStats' }, (response) => {
          if (response && response.count !== undefined) {
            this.cveCountElement.textContent = response.count.toString();
          }
        });
      }
    } catch (error) {
      console.error('Error updating stats:', error);
    }
  }

  private isVulnersSite(url: string): boolean {
    try {
      const hostname = new URL(url).hostname.toLowerCase();
      return (
        hostname === 'vulners.com' ||
        hostname.endsWith('.vulners.com') ||
        hostname === 'www.vulners.com'
      );
    } catch {
      return false;
    }
  }

  private updateStatus(enabled: boolean) {
    if (enabled) {
      this.statusElement.textContent = 'Active';
      this.statusElement.className = 'stat-value status-active';
    } else {
      this.statusElement.textContent = 'Inactive';
      this.statusElement.className = 'stat-value status-inactive';
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  new PopupController();
});
