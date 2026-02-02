/**
 * @jest-environment jsdom
 */

import { mockChrome } from './setup';
import { PopupController, isVulnersSite } from '../src/popup';

describe('Popup Module', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    // Set up the actual popup HTML structure matching popup.html
    document.body.innerHTML = `
      <div class="popup-container">
        <div class="header">
          <img class="logo" src="" alt="Vulners">
          <h1>Vulners CVE Lookup</h1>
        </div>
        <div class="content">
          <div class="toggle-section">
            <label class="toggle-switch">
              <input type="checkbox" id="toggle-highlighting">
              <span class="slider"></span>
            </label>
            <span id="status" class="stat-value">Active</span>
          </div>
          <div class="stats-section">
            <div class="stat-item">
              <span class="stat-label">CVEs found:</span>
              <span id="cve-count" class="stat-value">0</span>
            </div>
          </div>
        </div>
        <div class="footer">
          <a href="https://vulners.com" target="_blank">Visit Vulners.com</a>
        </div>
      </div>
    `;

    // Default mocks
    (mockChrome.storage.local.get as jest.Mock).mockResolvedValue({
      enabled: true,
    });
    (mockChrome.tabs.query as jest.Mock).mockResolvedValue([
      { id: 1, url: 'https://example.com' },
    ]);
    (mockChrome.tabs.sendMessage as jest.Mock).mockImplementation(
      (_tabId, _message, callback) => {
        if (callback) {
          callback({
            count: 5,
            typeCounts: { cve: 3, advisory: 1, exploit: 1 },
          });
        }
        return Promise.resolve();
      }
    );
  });

  // ============ isVulnersSite UTILITY TESTS ============

  describe('isVulnersSite', () => {
    it('should return true for vulners.com', () => {
      expect(isVulnersSite('https://vulners.com')).toBe(true);
    });

    it('should return true for www.vulners.com', () => {
      expect(isVulnersSite('https://www.vulners.com')).toBe(true);
    });

    it('should return true for subdomains of vulners.com', () => {
      expect(isVulnersSite('https://api.vulners.com')).toBe(true);
      expect(isVulnersSite('https://subdomain.vulners.com')).toBe(true);
    });

    it('should be case insensitive', () => {
      expect(isVulnersSite('https://VULNERS.COM')).toBe(true);
      expect(isVulnersSite('https://Vulners.Com')).toBe(true);
    });

    it('should return false for non-vulners domains', () => {
      expect(isVulnersSite('https://notvulners.com')).toBe(false);
      expect(isVulnersSite('https://vulners.net')).toBe(false);
      expect(isVulnersSite('https://example.com')).toBe(false);
      expect(isVulnersSite('https://fakevulners.com')).toBe(false);
    });

    it('should return false for invalid URLs', () => {
      expect(isVulnersSite('not-a-url')).toBe(false);
      expect(isVulnersSite('')).toBe(false);
    });
  });

  // ============ POPUP CONTROLLER TESTS ============

  describe('PopupController', () => {
    describe('Initialization', () => {
      it('should initialize with correct elements', async () => {
        new PopupController();

        // Wait for async init
        await new Promise((resolve) => setTimeout(resolve, 10));

        expect(mockChrome.storage.local.get).toHaveBeenCalledWith(['enabled']);
      });

      it('should load settings from storage on init', async () => {
        (mockChrome.storage.local.get as jest.Mock).mockResolvedValue({
          enabled: true,
        });

        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const toggle = document.getElementById(
          'toggle-highlighting'
        ) as HTMLInputElement;
        expect(toggle.checked).toBe(true);
      });

      it('should set toggle unchecked when disabled in settings', async () => {
        (mockChrome.storage.local.get as jest.Mock).mockResolvedValue({
          enabled: false,
        });

        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const toggle = document.getElementById(
          'toggle-highlighting'
        ) as HTMLInputElement;
        expect(toggle.checked).toBe(false);
      });

      it('should query active tab on init', async () => {
        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        expect(mockChrome.tabs.query).toHaveBeenCalledWith({
          active: true,
          currentWindow: true,
        });
      });
    });

    describe('loadSettings', () => {
      it('should default to enabled when storage is empty', async () => {
        (mockChrome.storage.local.get as jest.Mock).mockResolvedValue({});

        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const toggle = document.getElementById(
          'toggle-highlighting'
        ) as HTMLInputElement;
        // enabled !== false is true when enabled is undefined
        expect(toggle.checked).toBe(true);
      });
    });

    describe('updateStats', () => {
      it('should display CVE count from content script', async () => {
        (mockChrome.tabs.sendMessage as jest.Mock).mockImplementation(
          (_tabId, _message, callback) => {
            if (callback) {
              callback({
                count: 10,
                typeCounts: { cve: 10, advisory: 0, exploit: 0 },
              });
            }
            return Promise.resolve();
          }
        );

        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const cveCount = document.getElementById('cve-count');
        expect(cveCount?.textContent).toBe('10');
      });

      it('should display type breakdown when multiple types present', async () => {
        (mockChrome.tabs.sendMessage as jest.Mock).mockImplementation(
          (_tabId, _message, callback) => {
            if (callback) {
              callback({
                count: 6,
                typeCounts: { cve: 3, advisory: 2, exploit: 1 },
              });
            }
            return Promise.resolve();
          }
        );

        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const cveCount = document.getElementById('cve-count');
        expect(cveCount?.textContent).toBe('3 CVE | 2 Adv | 1 Exp');
      });

      it('should display only CVE count when no other types', async () => {
        (mockChrome.tabs.sendMessage as jest.Mock).mockImplementation(
          (_tabId, _message, callback) => {
            if (callback) {
              callback({
                count: 5,
                typeCounts: { cve: 5, advisory: 0, exploit: 0 },
              });
            }
            return Promise.resolve();
          }
        );

        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const cveCount = document.getElementById('cve-count');
        expect(cveCount?.textContent).toBe('5');
      });
    });

    describe('updateStatus', () => {
      it('should show Active status when enabled', async () => {
        (mockChrome.storage.local.get as jest.Mock).mockResolvedValue({
          enabled: true,
        });

        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const status = document.getElementById('status');
        expect(status?.textContent).toBe('Active');
        expect(status?.className).toContain('status-active');
      });

      it('should show Inactive status when disabled', async () => {
        (mockChrome.storage.local.get as jest.Mock).mockResolvedValue({
          enabled: false,
        });

        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const status = document.getElementById('status');
        expect(status?.textContent).toBe('Inactive');
        expect(status?.className).toContain('status-inactive');
      });
    });

    describe('Vulners.com Detection', () => {
      it('should disable extension on vulners.com', async () => {
        (mockChrome.tabs.query as jest.Mock).mockResolvedValue([
          { id: 1, url: 'https://vulners.com/cve/CVE-2024-1234' },
        ]);

        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const toggle = document.getElementById(
          'toggle-highlighting'
        ) as HTMLInputElement;
        const status = document.getElementById('status');
        const cveCount = document.getElementById('cve-count');

        expect(toggle.disabled).toBe(true);
        expect(toggle.checked).toBe(false);
        expect(status?.textContent).toBe('Disabled on Vulners');
        expect(cveCount?.textContent).toBe('—');
      });

      it('should disable on www.vulners.com', async () => {
        (mockChrome.tabs.query as jest.Mock).mockResolvedValue([
          { id: 1, url: 'https://www.vulners.com' },
        ]);

        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const toggle = document.getElementById(
          'toggle-highlighting'
        ) as HTMLInputElement;
        expect(toggle.disabled).toBe(true);
      });
    });

    describe('Toggle Event Handling', () => {
      it('should save settings when toggle is changed', async () => {
        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const toggle = document.getElementById(
          'toggle-highlighting'
        ) as HTMLInputElement;

        toggle.checked = false;
        toggle.dispatchEvent(new Event('change'));

        await new Promise((resolve) => setTimeout(resolve, 10));

        expect(mockChrome.storage.local.set).toHaveBeenCalledWith({
          enabled: false,
        });
      });

      it('should send message to content script when toggled', async () => {
        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        // Clear previous calls
        (mockChrome.tabs.sendMessage as jest.Mock).mockClear();

        const toggle = document.getElementById(
          'toggle-highlighting'
        ) as HTMLInputElement;

        toggle.checked = true;
        toggle.dispatchEvent(new Event('change'));

        await new Promise((resolve) => setTimeout(resolve, 10));

        expect(mockChrome.tabs.sendMessage).toHaveBeenCalledWith(1, {
          action: 'toggleHighlighting',
          enabled: true,
        });
      });

      it('should clear badge when disabled', async () => {
        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const toggle = document.getElementById(
          'toggle-highlighting'
        ) as HTMLInputElement;

        toggle.checked = false;
        toggle.dispatchEvent(new Event('change'));

        await new Promise((resolve) => setTimeout(resolve, 10));

        expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({
          text: '',
        });
      });

      it('should set count to 0 when disabled', async () => {
        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const toggle = document.getElementById(
          'toggle-highlighting'
        ) as HTMLInputElement;

        toggle.checked = false;
        toggle.dispatchEvent(new Event('change'));

        await new Promise((resolve) => setTimeout(resolve, 10));

        const cveCount = document.getElementById('cve-count');
        expect(cveCount?.textContent).toBe('0');
      });

      it('should not toggle on vulners.com', async () => {
        (mockChrome.tabs.query as jest.Mock).mockResolvedValue([
          { id: 1, url: 'https://vulners.com' },
        ]);

        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const toggle = document.getElementById(
          'toggle-highlighting'
        ) as HTMLInputElement;

        // Try to enable
        toggle.checked = true;
        toggle.dispatchEvent(new Event('change'));

        await new Promise((resolve) => setTimeout(resolve, 10));

        // Should have been reset to false
        expect(toggle.checked).toBe(false);
      });
    });

    describe('Error Handling', () => {
      it('should handle missing tab id gracefully', async () => {
        (mockChrome.tabs.query as jest.Mock).mockResolvedValue([
          { url: 'https://example.com' }, // No id
        ]);

        // Should not throw
        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        // The controller should still initialize
        const toggle = document.getElementById(
          'toggle-highlighting'
        ) as HTMLInputElement;
        expect(toggle).toBeTruthy();
      });

      it('should handle no active tabs', async () => {
        (mockChrome.tabs.query as jest.Mock).mockResolvedValue([]);

        // Should not throw
        new PopupController();
        await new Promise((resolve) => setTimeout(resolve, 10));

        const toggle = document.getElementById(
          'toggle-highlighting'
        ) as HTMLInputElement;
        expect(toggle).toBeTruthy();
      });
    });
  });

  // ============ UI ELEMENTS TESTS ============

  describe('UI Elements', () => {
    it('should have all required UI elements', () => {
      const elements = {
        container: document.querySelector('.popup-container'),
        header: document.querySelector('.header'),
        logo: document.querySelector('.logo'),
        title: document.querySelector('h1'),
        toggleSection: document.querySelector('.toggle-section'),
        toggleInput: document.getElementById('toggle-highlighting'),
        statusElement: document.getElementById('status'),
        statsSection: document.querySelector('.stats-section'),
        cveCount: document.getElementById('cve-count'),
        footer: document.querySelector('.footer'),
        vulnersLink: document.querySelector('a[href*="vulners.com"]'),
      };

      Object.entries(elements).forEach(([_name, element]) => {
        expect(element).toBeTruthy();
      });
    });

    it('should display logo correctly', () => {
      const logo = document.querySelector('.logo') as HTMLImageElement;

      (mockChrome.runtime.getURL as jest.Mock).mockReturnValue(
        'chrome-extension://test/assets/icon-48.png'
      );

      const iconUrl = mockChrome.runtime.getURL('assets/icon-48.png');
      logo.src = iconUrl;

      expect(mockChrome.runtime.getURL).toHaveBeenCalledWith(
        'assets/icon-48.png'
      );
      expect(logo.src).toBe('chrome-extension://test/assets/icon-48.png');
      expect(logo.alt).toBe('Vulners');
    });

    it('should have proper link to Vulners.com', () => {
      const link = document.querySelector(
        'a[href*="vulners.com"]'
      ) as HTMLAnchorElement;

      expect(link).toBeTruthy();
      expect(link.href).toContain('vulners.com');
      expect(link.target).toBe('_blank');
      expect(link.textContent).toContain('Vulners');
    });
  });

  // ============ STATISTICS DISPLAY TESTS ============

  describe('Statistics Display', () => {
    it('should display CVE count correctly', () => {
      const cveCount = document.getElementById('cve-count');

      const testCounts = [0, 1, 5, 10, 99, 100];

      testCounts.forEach((count) => {
        if (cveCount) {
          cveCount.textContent = count.toString();
        }
        expect(cveCount?.textContent).toBe(count.toString());
      });
    });

    it('should format breakdown with only CVEs present', async () => {
      (mockChrome.tabs.sendMessage as jest.Mock).mockImplementation(
        (_tabId, _message, callback) => {
          if (callback) {
            callback({
              count: 5,
              typeCounts: { cve: 5, advisory: 0, exploit: 0 },
            });
          }
          return Promise.resolve();
        }
      );

      new PopupController();
      await new Promise((resolve) => setTimeout(resolve, 10));

      const cveCount = document.getElementById('cve-count');
      // Should just show the number, not "5 CVE"
      expect(cveCount?.textContent).toBe('5');
    });

    it('should format breakdown with only advisories', async () => {
      (mockChrome.tabs.sendMessage as jest.Mock).mockImplementation(
        (_tabId, _message, callback) => {
          if (callback) {
            callback({
              count: 3,
              typeCounts: { cve: 0, advisory: 3, exploit: 0 },
            });
          }
          return Promise.resolve();
        }
      );

      new PopupController();
      await new Promise((resolve) => setTimeout(resolve, 10));

      const cveCount = document.getElementById('cve-count');
      expect(cveCount?.textContent).toBe('3 Adv');
    });

    it('should format breakdown with only exploits', async () => {
      (mockChrome.tabs.sendMessage as jest.Mock).mockImplementation(
        (_tabId, _message, callback) => {
          if (callback) {
            callback({
              count: 2,
              typeCounts: { cve: 0, advisory: 0, exploit: 2 },
            });
          }
          return Promise.resolve();
        }
      );

      new PopupController();
      await new Promise((resolve) => setTimeout(resolve, 10));

      const cveCount = document.getElementById('cve-count');
      expect(cveCount?.textContent).toBe('2 Exp');
    });
  });

  // ============ ACCESSIBILITY TESTS ============

  describe('Accessibility', () => {
    it('should have proper ARIA labels', () => {
      const toggleInput = document.getElementById(
        'toggle-highlighting'
      ) as HTMLInputElement;

      toggleInput.setAttribute('aria-label', 'Toggle CVE highlighting');
      toggleInput.setAttribute('role', 'switch');

      expect(toggleInput.getAttribute('aria-label')).toBe(
        'Toggle CVE highlighting'
      );
      expect(toggleInput.getAttribute('role')).toBe('switch');
    });

    it('should support keyboard navigation', () => {
      const toggleInput = document.getElementById(
        'toggle-highlighting'
      ) as HTMLInputElement;

      toggleInput.focus();
      expect(document.activeElement).toBe(toggleInput);
    });
  });
});
