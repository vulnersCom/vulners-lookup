// Shared utilities for Vulners Lookup extension

/**
 * Check if the current URL is on the Vulners.com domain.
 * Used to disable highlighting on the Vulners website itself.
 */
export function isVulnersSite(url: string): boolean {
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

/**
 * Check if hostname (without protocol) is a Vulners domain.
 * Used in content scripts where window.location.hostname is available.
 */
export function isVulnersHostname(hostname: string): boolean {
  const lowerHostname = hostname.toLowerCase();
  return (
    lowerHostname === 'vulners.com' ||
    lowerHostname.endsWith('.vulners.com') ||
    lowerHostname === 'www.vulners.com'
  );
}

/**
 * Escape HTML special characters to prevent XSS attacks.
 * Used for sanitizing dynamic values before inserting into HTML templates.
 */
export function escapeHtml(str: string): string {
  const htmlEscapeMap: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };
  return str.replace(/[&<>"']/g, (char) => htmlEscapeMap[char]);
}
