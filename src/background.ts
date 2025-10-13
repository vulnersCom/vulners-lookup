// Types and Interfaces
interface CachedCVEData {
  data: CVEData;
  timestamp: number;
}

interface CVEData {
  id: string;
  description: string;
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
  status: string;
  cwe?: string;
  exploitInfo?: {
    maxMaturity: string;
    exploits: number;
    available: string;
    wildExploited: boolean;
  };
  vulnerabilityIntelligence?: {
    score: number;
    uncertainty: number;
    twitterMentions: number;
    webApplicable: boolean;
  };
  sources: string[];
}

interface MessageRequest {
  action: 'fetchCVEData' | 'fetchPatterns' | 'updateBadge';
  cveId?: string;
  count?: number;
}

interface PatternsResponse {
  patterns: string[] | null;
}

interface CVEResponse {
  data: CVEData;
}

class BackgroundService {
  private readonly VULNERS_HOST = 'https://vulners.com' as const;
  private readonly VULNERS_CVE_API_PATH = '/api/misc/chrome/cve' as const;
  private readonly VULNERS_PATTERNS_API_PATH =
    '/api/misc/chrome/patterns' as const;
  private readonly CACHE_EXPIRY_MS = 3600000 as const; // 1 hour
  private readonly MAX_RETRIES = 3 as const;
  private readonly cveCache = new Map<string, CachedCVEData>();

  constructor() {
    this.setupMessageListeners();
    void this.setupBadgeDefaults();
  }

  private setupMessageListeners(): void {
    chrome.runtime.onMessage.addListener(
      (
        request: MessageRequest,
        sender: chrome.runtime.MessageSender,
        sendResponse: (response: any) => void
      ): boolean | undefined => {
        switch (request.action) {
          case 'fetchCVEData':
            if (request.cveId) {
              this.fetchCVEData(request.cveId)
                .then(sendResponse)
                .catch((error) => {
                  console.error('Error in fetchCVEData:', error);
                  sendResponse({ error: error.message });
                });
              return true; // Will respond asynchronously
            }
            break;

          case 'fetchPatterns':
            this.fetchPatterns()
              .then(sendResponse)
              .catch((error) => {
                console.error('Error in fetchPatterns:', error);
                sendResponse({ patterns: null });
              });
            return true; // Will respond asynchronously

          case 'updateBadge':
            if (sender.tab?.id && request.count !== undefined) {
              void this.updateBadge(sender.tab.id, request.count);
            }
            break;

          default:
            console.warn('Unknown action:', request.action);
        }
        return undefined;
      }
    );
  }

  private async setupBadgeDefaults(): Promise<void> {
    try {
      await Promise.all([
        chrome.action.setBadgeBackgroundColor({ color: '#6366f1' }),
        chrome.action.setBadgeTextColor({ color: '#ffffff' }),
      ]);
    } catch (error) {
      console.error('Failed to setup badge defaults:', error);
    }
  }

  private async fetchPatterns(): Promise<PatternsResponse> {
    try {
      const response = await this.fetchWithRetry(
        `${this.VULNERS_HOST}${this.VULNERS_PATTERNS_API_PATH}`,
        {
          method: 'GET',
          headers: {
            Accept: 'application/json',
          },
        },
        this.MAX_RETRIES
      );

      if (response?.ok) {
        const data = (await response.json()) as {
          result?: { patterns?: string[] };
        };
        if (data.result?.patterns) {
          return { patterns: data.result.patterns };
        }
      }

      return { patterns: null };
    } catch (error) {
      console.error('Error fetching patterns:', error);
      return { patterns: null };
    }
  }

  private async fetchCVEData(cveId: string): Promise<CVEResponse> {
    // Check cache with expiration
    const cached = this.cveCache.get(cveId);
    if (cached && Date.now() - cached.timestamp < this.CACHE_EXPIRY_MS) {
      return { data: cached.data };
    }

    try {
      // Try Vulners API
      const apiResult = await this.fetchFromAPI(cveId);
      if (apiResult) {
        this.cveCache.set(cveId, {
          data: apiResult,
          timestamp: Date.now(),
        });
        return { data: apiResult };
      }

      return {
        data: {
          id: cveId,
          description: 'Vulnerability information not available',
          status: 'Unknown',
          sources: [],
        },
      };
    } catch (error) {
      console.error(`Error fetching CVE data for ${cveId}:`, error);

      return {
        data: {
          id: cveId,
          description: 'Unable to fetch vulnerability details',
          status: 'Error',
          sources: [],
        },
      };
    }
  }

  private async fetchWithRetry(
    url: string,
    options: RequestInit,
    maxRetries: number = this.MAX_RETRIES
  ): Promise<Response> {
    let lastError: Error | null = null;

    for (let i = 0; i < maxRetries; i++) {
      try {
        const response = await fetch(url, options);

        // If successful or client error (4xx), return immediately
        if (response.ok || (response.status >= 400 && response.status < 500)) {
          return response;
        }

        // For server errors (5xx), retry
        if (response.status >= 500) {
          lastError = new Error(`Server error: ${response.status}`);
          console.warn(
            `Retry ${i + 1}/${maxRetries} for server error ${response.status}`
          );

          // Exponential backoff: 1s, 2s, 4s
          if (i < maxRetries - 1) {
            await new Promise((resolve) =>
              setTimeout(resolve, Math.pow(2, i) * 1000)
            );
          }
          continue;
        }

        return response;
      } catch (error) {
        lastError = error as Error;
        console.warn(`Retry ${i + 1}/${maxRetries} for network error:`, error);

        // Exponential backoff for network errors
        if (i < maxRetries - 1) {
          await new Promise((resolve) =>
            setTimeout(resolve, Math.pow(2, i) * 1000)
          );
        }
      }
    }

    throw lastError || new Error('Failed to fetch after retries');
  }

  private async fetchFromAPI(cveId: string): Promise<CVEData | null> {
    try {
      const response = await this.fetchWithRetry(
        `${this.VULNERS_HOST}${this.VULNERS_CVE_API_PATH}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            cveId: cveId.toUpperCase(),
          }),
        },
        this.MAX_RETRIES
      );

      if (!response.ok) {
        console.warn(`Beta API failed with status: ${response.status}`);
        return null;
      }

      const result = await response.json();

      if (result.result) {
        const processedData = this.processVulnersData(cveId, result.result);
        console.log(`Successfully fetched ${cveId} from beta API`);
        return processedData;
      }

      return null;
    } catch (error) {
      console.warn(`Beta API error for ${cveId} after retries:`, error);
      return null;
    }
  }

  private processVulnersData(cveId: string, doc: any): CVEData {
    // Handle new beta API format (pre-processed)
    if (doc.cacheExpiry || doc.severity || doc.exploitation) {
      return {
        id: doc.id || cveId,
        description: doc.description || 'No description available',
        shortDescription: doc.shortDescription || doc.description,
        isCandidate: doc.isCandidate || false,
        cvss: doc.severity?.cvss
          ? {
              score: doc.severity.cvss.score,
              vector: doc.severity.cvss.vector || '',
            }
          : undefined,
        cvss4: doc.severity?.cvss4
          ? {
              score: doc.severity.cvss4.score,
              vector: doc.severity.cvss4.vector || '',
            }
          : undefined,
        epss: doc.severity?.epss
          ? {
              score: doc.severity.epss.score,
              percentile: doc.severity.epss.percentile || 0,
            }
          : undefined,
        published: doc.published,
        modified: doc.modified,
        status: doc.status || 'Published',
        cwe: doc.classification?.cwe?.id || undefined,
        exploitInfo: doc.exploitation
          ? {
              maxMaturity: doc.exploitation.maxMaturity,
              exploits: doc.exploitation.exploitCount || 0,
              available: doc.exploitation.availability || 'Unknown',
              wildExploited: doc.exploitation.wildExploited || false,
            }
          : undefined,
        vulnerabilityIntelligence: doc.intelligence
          ? {
              score: doc.intelligence.aiScore,
              uncertainty: doc.intelligence.confidence,
              twitterMentions: doc.intelligence.socialMentions,
              webApplicable: doc.intelligence.webApplicable,
            }
          : undefined,
        sources: doc.sources || ['vulners.com'],
      };
    }

    // If not beta API format, return minimal data structure
    return {
      id: cveId,
      description: doc.description || doc.title || 'No description available',
      status: doc.status || 'Unknown',
      sources: ['vulners.com'],
    };
  }

  private async updateBadge(tabId: number, count: number): Promise<void> {
    try {
      const text = count > 0 ? (count > 99 ? '99+' : count.toString()) : '';
      await chrome.action.setBadgeText({
        text,
        tabId,
      });
    } catch (error) {
      console.error(`Failed to update badge for tab ${tabId}:`, error);
    }
  }
}

// Initialize service
new BackgroundService();

// Export for testing purposes
export { BackgroundService };
