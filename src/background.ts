import {
  CVEData,
  CachedCVEData,
  MessageRequest,
  PatternsResponse,
  CVEResponse,
  VulnersAPIResponse,
} from './types';
import {
  VULNERS_HOST,
  VULNERS_CVE_API_PATH,
  VULNERS_PATTERNS_API_PATH,
  CACHE_EXPIRY_MS,
  MAX_RETRIES,
  FETCH_TIMEOUT_MS,
  BADGE_BACKGROUND_COLOR,
  BADGE_TEXT_COLOR,
} from './constants';

class BackgroundService {
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
        sendResponse: (
          response:
            | CVEResponse
            | PatternsResponse
            | { error: string }
            | undefined
        ) => void
      ): boolean | undefined => {
        switch (request.action) {
          case 'fetchCVEData':
            if (request.cveId) {
              this.fetchCVEData(request.cveId)
                .then(sendResponse)
                .catch((error: Error) => {
                  console.error('Error in fetchCVEData:', error);
                  sendResponse({ error: error.message });
                });
              return true; // Will respond asynchronously
            }
            break;

          case 'fetchPatterns':
            this.fetchPatterns()
              .then(sendResponse)
              .catch((error: Error) => {
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
            console.warn(
              'Unknown action:',
              (request as { action: string }).action
            );
        }
        return undefined;
      }
    );
  }

  private async setupBadgeDefaults(): Promise<void> {
    try {
      await Promise.all([
        chrome.action.setBadgeBackgroundColor({
          color: BADGE_BACKGROUND_COLOR,
        }),
        chrome.action.setBadgeTextColor({ color: BADGE_TEXT_COLOR }),
      ]);
    } catch (error) {
      console.error('Failed to setup badge defaults:', error);
    }
  }

  private async fetchPatterns(): Promise<PatternsResponse> {
    try {
      const response = await this.fetchWithRetry(
        `${VULNERS_HOST}${VULNERS_PATTERNS_API_PATH}`,
        {
          method: 'GET',
          headers: {
            Accept: 'application/json',
          },
        },
        MAX_RETRIES
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
    if (cached && Date.now() - cached.timestamp < CACHE_EXPIRY_MS) {
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
    maxRetries: number = MAX_RETRIES
  ): Promise<Response> {
    let lastError: Error | null = null;

    for (let i = 0; i < maxRetries; i++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

      try {
        const response = await fetch(url, {
          ...options,
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

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
        clearTimeout(timeoutId);

        if (error instanceof Error && error.name === 'AbortError') {
          lastError = new Error(`Request timeout after ${FETCH_TIMEOUT_MS}ms`);
          console.warn(
            `Fetch timeout (attempt ${i + 1}/${maxRetries}): ${url}`
          );
        } else {
          lastError = error as Error;
          console.warn(
            `Retry ${i + 1}/${maxRetries} for network error:`,
            error
          );
        }

        // Exponential backoff for network errors and timeouts
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
        `${VULNERS_HOST}${VULNERS_CVE_API_PATH}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            cveId: cveId.toUpperCase(),
          }),
        },
        MAX_RETRIES
      );

      if (!response.ok) {
        console.warn(`Beta API failed with status: ${response.status}`);
        return null;
      }

      const result = (await response.json()) as { result?: VulnersAPIResponse };

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

  private processVulnersData(cveId: string, doc: VulnersAPIResponse): CVEData {
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
        cwes: doc.classification?.cwes || [],
        cweCount: doc.classification?.cweCount || 0,
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
        // Advisory-specific fields
        linkedCVEs: doc.linkedCves || undefined,
        linkedCVECount: doc.linkedCveCount || undefined,
        vendor: doc.vendor || undefined,
        // Exploit-specific fields
        relatedCVEs: doc.relatedCves || undefined,
        relatedCVECount: doc.relatedCveCount || undefined,
        repoUrl: doc.repoUrl || undefined,
        platform: doc.platform || undefined,
        maturity: doc.maturity || undefined,
        exploitType: doc.exploitType || undefined,
        verified: doc.verified,
        author: doc.author || undefined,
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
