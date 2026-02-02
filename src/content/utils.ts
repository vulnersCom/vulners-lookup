// Re-export shared utilities from main utils module
export { isVulnersHostname, escapeHtml } from '../utils';

// Content-specific utilities
import type { BulletinType } from './types';
import { BULLETIN_TYPE_MAP } from './constants';

export function detectBulletinType(id: string): BulletinType {
  const upperId = id.toUpperCase();

  // Special handling for EDB-ID variants to ensure proper detection
  // API pattern /\bEDB-?ID:\s*\d+\b/gi matches both "EDB-ID:" and "EDBID:"
  if (upperId.startsWith('EDB') && upperId.includes('ID')) {
    return 'exploit';
  }

  for (const [prefix, type] of BULLETIN_TYPE_MAP) {
    if (upperId.startsWith(prefix.toUpperCase())) {
      return type;
    }
  }
  return 'cve'; // default fallback
}
