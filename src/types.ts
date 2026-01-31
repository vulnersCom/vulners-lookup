// Shared types for Vulners Lookup extension

// Bulletin type for multi-pattern support
export type BulletinType = 'cve' | 'advisory' | 'exploit';

// CVE/Bulletin data structure returned by Vulners API
export interface CVEData {
  id: string;
  type?: BulletinType;
  title?: string;
  description?: string;
  shortDescription?: string;
  isCandidate?: boolean;
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
  published?: string;
  modified?: string;
  status?: string;
  cwes?: string[]; // Array of CWE IDs, e.g. ["CWE-79", "CWE-89"] (max 5)
  cweCount?: number; // Total count of CWEs
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
  // Advisory-specific fields
  linkedCVEs?: string[];
  linkedCVECount?: number;
  vendor?: string;
  // Exploit-specific fields
  relatedCVEs?: string[];
  relatedCVECount?: number;
  repoUrl?: string;
  platform?: string;
  maturity?: string;
  exploitType?: string;
  verified?: boolean;
  author?: string;
}

// Cached CVE data with timestamp
export interface CachedCVEData {
  data: CVEData;
  timestamp: number;
}

// Message types for communication between scripts
export interface MessageRequest {
  action: 'fetchCVEData' | 'fetchPatterns' | 'updateBadge';
  cveId?: string;
  count?: number;
}

export interface PatternsResponse {
  patterns: string[] | null;
}

export interface CVEResponse {
  data: CVEData;
}

// Vulners API response format for beta API
export interface VulnersAPIResponse {
  id?: string;
  description?: string;
  shortDescription?: string;
  isCandidate?: boolean;
  title?: string;
  published?: string;
  modified?: string;
  status?: string;
  cacheExpiry?: number;
  severity?: {
    cvss?: {
      score: number;
      vector?: string;
    };
    cvss4?: {
      score: number;
      vector?: string;
    };
    epss?: {
      score: number;
      percentile?: number;
    };
  };
  classification?: {
    cwes?: string[];
    cweCount?: number;
  };
  exploitation?: {
    maxMaturity?: string;
    exploitCount?: number;
    availability?: string;
    wildExploited?: boolean;
  };
  intelligence?: {
    aiScore?: number;
    confidence?: number;
    socialMentions?: number;
    webApplicable?: boolean;
  };
  sources?: string[];
  // Advisory-specific
  linkedCves?: string[];
  linkedCveCount?: number;
  vendor?: string;
  // Exploit-specific
  relatedCves?: string[];
  relatedCveCount?: number;
  repoUrl?: string;
  platform?: string;
  maturity?: string;
  exploitType?: string;
  verified?: boolean;
  author?: string;
}
