// Content script entry point
// Re-exports from content module for backwards compatibility and testing

export {
  CVEHighlighter,
  TooltipManager,
  DOMScanner,
  CONFIG,
  BULLETIN_TYPE_MAP,
  BULLETIN_TYPE_LABELS,
  BULLETIN_TYPE_COLORS,
  EDITOR_SELECTOR,
  detectBulletinType,
  escapeHtml,
  isVulnersHostname,
} from './content/index';

export type { BulletinType, CVEData } from './content/index';

// Import for initialization
import { CVEHighlighter } from './content/index';

// Initialize the highlighter only in browser context (not during Jest tests)
// Check for document.body to ensure we're in a real browser environment
if (
  typeof document !== 'undefined' &&
  document.body !== null &&
  typeof jest === 'undefined'
) {
  new CVEHighlighter();
}
