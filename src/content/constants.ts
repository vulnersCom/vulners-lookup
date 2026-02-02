import type { BulletinType } from './types';

// Configuration constants
export const CONFIG = {
  // Tooltip dimensions
  TOOLTIP_WIDTH: 320,
  TOOLTIP_HEIGHT: 242,
  TOOLTIP_PADDING: 10,
  TOOLTIP_OFFSET: 5,

  // Viewport processing
  VIEWPORT_MARGIN: 100,

  // Timing
  TOOLTIP_DELAY_MS: 200,
  MUTATION_DEBOUNCE_MS: 100,
  SPA_SETTLE_DELAY_MS: 500,
  INITIAL_SETTLE_DELAY_MS: 200,
  IDLE_CALLBACK_TIMEOUT_MS: 2000,

  // Scanning
  MAX_SCAN_ATTEMPTS: 10,
  INITIAL_SCAN_INTERVAL_MS: 500,
  MAX_SCAN_INTERVAL_MS: 2000,
  MIN_CVES_FOR_SLOWDOWN: 5,
  SCAN_INTERVAL_MULTIPLIER: 1.5,

  // Mutation storm detection
  STORM_THRESHOLD: 50,
  STORM_WINDOW_MS: 500,
  MAX_PENDING_MUTATIONS: 100,

  // Adaptive debounce thresholds
  DEBOUNCE_LOW_MS: 50,
  DEBOUNCE_MEDIUM_MS: 150,
  DEBOUNCE_HIGH_MS: 250,
  DEBOUNCE_STORM_MS: 300,
  DEBOUNCE_EXTREME_MS: 400,
  DEBOUNCE_RECENT_LOW: 5,
  DEBOUNCE_RECENT_MEDIUM: 20,
  DEBOUNCE_RECENT_HIGH: 15,
  DEBOUNCE_RECENT_EXTREME: 30,

  // Offscreen processing
  MAX_IMMEDIATE_OFFSCREEN: 20,
  IMMEDIATE_OFFSCREEN_SLICE: 10,
  MIN_IDLE_TIME_MS: 2,

  // Text length
  MIN_TEXT_LENGTH: 5,
} as const;

// Custom navigation event name
export const NAVIGATION_EVENT = 'vulners:navigation';

// Static selector for editor detection
export const EDITOR_SELECTOR = [
  '[role="textbox"]',
  '[data-testid*="editor"]',
  '.ProseMirror',
  '.tox-edit-area',
  '.mce-content-body',
  '.ak-editor-content-area',
  '[data-slate-editor]',
  '.ql-editor',
  '.CodeMirror',
  '.monaco-editor',
  '.ace_editor',
  '.cm-editor',
  '[data-lexical-editor]',
  '.cke_editable',
  '.fr-element',
  '.note-editable',
  '.jodit-wysiwyg',
].join(',');

// Pattern prefix to bulletin type mapping
export const BULLETIN_TYPE_MAP: Array<[string, BulletinType]> = [
  // CVE
  ['CVE-', 'cve'],
  ['CAN-', 'cve'],
  // Exploits
  ['EDB-ID', 'exploit'],
  ['EDBID', 'exploit'],
  ['PACKETSTORM:', 'exploit'],
  ['ZDI-', 'exploit'],
  // Advisories
  ['RHSA-', 'advisory'],
  ['RHBA-', 'advisory'],
  ['CESA-', 'advisory'],
  ['ELSA-', 'advisory'],
  ['ALAS-', 'advisory'],
  ['DSA-', 'advisory'],
  ['DLA-', 'advisory'],
  ['USN-', 'advisory'],
  ['FEDORA-', 'advisory'],
  ['GLSA-', 'advisory'],
  ['GHSA-', 'advisory'],
  ['ICSA-', 'advisory'],
  ['ICS-ALERT-', 'advisory'],
  ['VMSA-', 'advisory'],
  ['APPLE-SA-', 'advisory'],
  ['APSB', 'advisory'],
  ['TALOS-', 'advisory'],
  ['JVNDB-', 'advisory'],
  ['JVN#', 'advisory'],
  ['JSA', 'advisory'],
  ['VU#', 'advisory'],
  ['AA', 'advisory'],
  ['TA', 'advisory'],
  ['CNVD-', 'advisory'],
  ['CNNVD-', 'advisory'],
  ['EUVU-', 'advisory'],
  ['EUVD-', 'advisory'],
  ['KB', 'advisory'],
  ['MS', 'advisory'],
];

export const BULLETIN_TYPE_LABELS: Record<BulletinType, string> = {
  cve: 'Vulnerability',
  advisory: 'Security Advisory',
  exploit: 'Exploit',
};

export const BULLETIN_TYPE_COLORS: Record<BulletinType, string> = {
  cve: '#ff8b61',
  advisory: '#6366f1',
  exploit: '#ef4444',
};
