/**
 * @jest-environment jsdom
 */

import { isVulnersSite, isVulnersHostname, escapeHtml } from '../src/utils';

describe('Utils Module', () => {
  // ============ isVulnersSite TESTS ============

  describe('isVulnersSite', () => {
    describe('Valid Vulners domains', () => {
      it('should return true for vulners.com', () => {
        expect(isVulnersSite('https://vulners.com')).toBe(true);
        expect(isVulnersSite('http://vulners.com')).toBe(true);
      });

      it('should return true for www.vulners.com', () => {
        expect(isVulnersSite('https://www.vulners.com')).toBe(true);
        expect(isVulnersSite('http://www.vulners.com')).toBe(true);
      });

      it('should return true for subdomains of vulners.com', () => {
        expect(isVulnersSite('https://api.vulners.com')).toBe(true);
        expect(isVulnersSite('https://docs.vulners.com')).toBe(true);
        expect(isVulnersSite('https://subdomain.vulners.com')).toBe(true);
      });

      it('should handle paths after domain', () => {
        expect(isVulnersSite('https://vulners.com/cve/CVE-2024-1234')).toBe(
          true
        );
        expect(isVulnersSite('https://vulners.com/search?query=test')).toBe(
          true
        );
      });
    });

    describe('Case sensitivity', () => {
      it('should be case insensitive', () => {
        expect(isVulnersSite('https://VULNERS.COM')).toBe(true);
        expect(isVulnersSite('https://Vulners.Com')).toBe(true);
        expect(isVulnersSite('https://WWW.VULNERS.COM')).toBe(true);
      });
    });

    describe('Invalid domains', () => {
      it('should return false for non-vulners domains', () => {
        expect(isVulnersSite('https://notvulners.com')).toBe(false);
        expect(isVulnersSite('https://vulners.net')).toBe(false);
        expect(isVulnersSite('https://example.com')).toBe(false);
        expect(isVulnersSite('https://fakevulners.com')).toBe(false);
        expect(isVulnersSite('https://myvulners.com')).toBe(false);
      });

      it('should return false for similar but different domains', () => {
        expect(isVulnersSite('https://vulners.org')).toBe(false);
        expect(isVulnersSite('https://vulners.io')).toBe(false);
        expect(isVulnersSite('https://vulnners.com')).toBe(false);
      });
    });

    describe('Invalid URLs', () => {
      it('should return false for invalid URLs', () => {
        expect(isVulnersSite('not-a-url')).toBe(false);
        expect(isVulnersSite('')).toBe(false);
        expect(isVulnersSite('vulners.com')).toBe(false); // Missing protocol
        expect(isVulnersSite('://vulners.com')).toBe(false);
      });
    });
  });

  // ============ isVulnersHostname TESTS ============

  describe('isVulnersHostname', () => {
    describe('Valid Vulners hostnames', () => {
      it('should return true for vulners.com', () => {
        expect(isVulnersHostname('vulners.com')).toBe(true);
      });

      it('should return true for www.vulners.com', () => {
        expect(isVulnersHostname('www.vulners.com')).toBe(true);
      });

      it('should return true for subdomains of vulners.com', () => {
        expect(isVulnersHostname('api.vulners.com')).toBe(true);
        expect(isVulnersHostname('docs.vulners.com')).toBe(true);
        expect(isVulnersHostname('subdomain.vulners.com')).toBe(true);
        expect(isVulnersHostname('deep.subdomain.vulners.com')).toBe(true);
      });
    });

    describe('Case sensitivity', () => {
      it('should be case insensitive', () => {
        expect(isVulnersHostname('VULNERS.COM')).toBe(true);
        expect(isVulnersHostname('Vulners.Com')).toBe(true);
        expect(isVulnersHostname('WWW.VULNERS.COM')).toBe(true);
        expect(isVulnersHostname('API.VULNERS.COM')).toBe(true);
      });
    });

    describe('Invalid hostnames', () => {
      it('should return false for non-vulners domains', () => {
        expect(isVulnersHostname('notvulners.com')).toBe(false);
        expect(isVulnersHostname('vulners.net')).toBe(false);
        expect(isVulnersHostname('example.com')).toBe(false);
        expect(isVulnersHostname('fakevulners.com')).toBe(false);
        expect(isVulnersHostname('myvulners.com')).toBe(false);
      });

      it('should return false for empty string', () => {
        expect(isVulnersHostname('')).toBe(false);
      });
    });
  });

  // ============ escapeHtml TESTS ============

  describe('escapeHtml', () => {
    describe('Individual characters', () => {
      it('should escape ampersand', () => {
        expect(escapeHtml('A & B')).toBe('A &amp; B');
        expect(escapeHtml('&&&&')).toBe('&amp;&amp;&amp;&amp;');
      });

      it('should escape less than sign', () => {
        expect(escapeHtml('A < B')).toBe('A &lt; B');
        expect(escapeHtml('<<')).toBe('&lt;&lt;');
      });

      it('should escape greater than sign', () => {
        expect(escapeHtml('A > B')).toBe('A &gt; B');
        expect(escapeHtml('>>')).toBe('&gt;&gt;');
      });

      it('should escape double quotes', () => {
        expect(escapeHtml('"test"')).toBe('&quot;test&quot;');
        expect(escapeHtml('a "b" c')).toBe('a &quot;b&quot; c');
      });

      it('should escape single quotes', () => {
        expect(escapeHtml("'test'")).toBe('&#39;test&#39;');
        expect(escapeHtml("a 'b' c")).toBe('a &#39;b&#39; c');
      });
    });

    describe('Combined escaping', () => {
      it('should escape all special characters in a string', () => {
        expect(escapeHtml('<a href="test" onclick=\'alert("XSS")\'>&')).toBe(
          '&lt;a href=&quot;test&quot; onclick=&#39;alert(&quot;XSS&quot;)&#39;&gt;&amp;'
        );
      });

      it('should escape HTML tags', () => {
        expect(escapeHtml('<script>alert(1)</script>')).toBe(
          '&lt;script&gt;alert(1)&lt;/script&gt;'
        );
        expect(escapeHtml('<img src="x" onerror="alert(1)">')).toBe(
          '&lt;img src=&quot;x&quot; onerror=&quot;alert(1)&quot;&gt;'
        );
      });

      it('should handle typical CVE strings correctly', () => {
        expect(escapeHtml('CVE-2023-1234')).toBe('CVE-2023-1234');
        expect(escapeHtml('RHSA-2023:1234')).toBe('RHSA-2023:1234');
        expect(escapeHtml('EDB-ID:12345')).toBe('EDB-ID:12345');
      });
    });

    describe('No modification cases', () => {
      it('should not modify strings without special characters', () => {
        expect(escapeHtml('Hello World')).toBe('Hello World');
        expect(escapeHtml('CVE-2023-1234')).toBe('CVE-2023-1234');
        expect(escapeHtml('Simple text 123')).toBe('Simple text 123');
        expect(escapeHtml('')).toBe('');
      });

      it('should preserve spaces and newlines', () => {
        expect(escapeHtml('Hello\nWorld')).toBe('Hello\nWorld');
        expect(escapeHtml('Hello\tWorld')).toBe('Hello\tWorld');
        expect(escapeHtml('  spaced  ')).toBe('  spaced  ');
      });

      it('should preserve unicode characters', () => {
        expect(escapeHtml('Hëllö Wørld')).toBe('Hëllö Wørld');
        expect(escapeHtml('日本語')).toBe('日本語');
        expect(escapeHtml('🔒 Security')).toBe('🔒 Security');
      });
    });

    describe('XSS prevention', () => {
      it('should prevent script injection', () => {
        const malicious = '<script>document.cookie</script>';
        const escaped = escapeHtml(malicious);
        expect(escaped).not.toContain('<script>');
        expect(escaped).toContain('&lt;script&gt;');
      });

      it('should prevent event handler injection', () => {
        const malicious = '<img onerror="alert(1)" src="x">';
        const escaped = escapeHtml(malicious);
        expect(escaped).not.toContain('<img');
        expect(escaped).toContain('&lt;img');
        expect(escaped).toContain('&quot;');
      });

      it('should prevent href injection', () => {
        const malicious = '<a href="javascript:alert(1)">Click</a>';
        const escaped = escapeHtml(malicious);
        expect(escaped).not.toContain('<a');
        expect(escaped).toContain('&lt;a');
      });
    });
  });
});
