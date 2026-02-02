// Shared constants for Vulners Lookup extension

// API Configuration
export const VULNERS_HOST = 'https://vulners.com' as const;
export const VULNERS_CVE_API_PATH = '/api/misc/chrome/cve' as const;
export const VULNERS_PATTERNS_API_PATH = '/api/misc/chrome/patterns' as const;

// Cache Configuration
export const CACHE_EXPIRY_MS = 3600000 as const; // 1 hour

// Network Configuration
export const MAX_RETRIES = 3 as const;
export const FETCH_TIMEOUT_MS = 10000 as const; // 10 seconds

// Badge Colors
export const BADGE_BACKGROUND_COLOR = '#6366f1' as const; // Indigo
export const BADGE_TEXT_COLOR = '#ffffff' as const;
