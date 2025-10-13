/**
 * @jest-environment node
 */
import { BackgroundService } from '../src/background';
import { mockChrome } from './setup';
global.fetch = jest.fn();
describe('BackgroundService', () => {
    let messageListener;
    const mockFetch = fetch;
    beforeEach(() => {
        jest.clearAllMocks();
        mockFetch.mockClear();
        // Capture the message listener when service is created
        mockChrome.runtime.onMessage.addListener.mockImplementation((listener) => {
            messageListener = listener;
        });
        new BackgroundService();
    });
    describe('Constructor and Initialization', () => {
        it('should setup message listeners on initialization', () => {
            expect(mockChrome.runtime.onMessage.addListener).toHaveBeenCalledTimes(1);
            expect(mockChrome.runtime.onMessage.addListener).toHaveBeenCalledWith(expect.any(Function));
        });
        it('should setup badge defaults on initialization', () => {
            expect(mockChrome.action.setBadgeBackgroundColor).toHaveBeenCalledWith({
                color: '#6366f1',
            });
            expect(mockChrome.action.setBadgeTextColor).toHaveBeenCalledWith({
                color: '#ffffff',
            });
        });
    });
    describe('Message Handling', () => {
        describe('fetchCVEData action', () => {
            it('should fetch CVE data for valid CVE ID', async () => {
                const mockCVEData = {
                    result: {
                        id: 'CVE-2023-1234',
                        description: 'Test vulnerability',
                        severity: {
                            cvss: {
                                score: 7.5,
                                vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                            },
                        },
                    },
                };
                mockFetch.mockResolvedValueOnce({
                    ok: true,
                    json: async () => mockCVEData,
                });
                const sendResponse = jest.fn();
                const result = messageListener({ action: 'fetchCVEData', cveId: 'CVE-2023-1234' }, {}, sendResponse);
                expect(result).toBe(true); // Should return true for async response
                // Wait for async operation
                await new Promise((resolve) => setTimeout(resolve, 100));
                expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({
                    data: expect.objectContaining({
                        id: 'CVE-2023-1234',
                        description: 'Test vulnerability',
                    }),
                }));
            });
            it('should return cached data for repeated CVE requests', async () => {
                const mockCVEData = {
                    result: {
                        id: 'CVE-2023-5678',
                        description: 'Cached vulnerability',
                        severity: {
                            cvss: { score: 5.0, vector: 'test' },
                        },
                    },
                };
                mockFetch.mockResolvedValueOnce({
                    ok: true,
                    json: async () => mockCVEData,
                });
                const sendResponse1 = jest.fn();
                const sendResponse2 = jest.fn();
                // First request
                messageListener({ action: 'fetchCVEData', cveId: 'CVE-2023-5678' }, {}, sendResponse1);
                await new Promise((resolve) => setTimeout(resolve, 100));
                // Second request (should use cache)
                messageListener({ action: 'fetchCVEData', cveId: 'CVE-2023-5678' }, {}, sendResponse2);
                await new Promise((resolve) => setTimeout(resolve, 100));
                expect(mockFetch).toHaveBeenCalledTimes(1); // Only one fetch call
                expect(sendResponse2).toHaveBeenCalledWith(expect.objectContaining({
                    data: expect.objectContaining({
                        id: 'CVE-2023-5678',
                    }),
                }));
            });
            it('should handle API errors gracefully', async () => {
                mockFetch.mockRejectedValue(new Error('Network error'));
                const sendResponse = jest.fn();
                const promise = messageListener({ action: 'fetchCVEData', cveId: 'CVE-2023-9999' }, {}, sendResponse);
                expect(promise).toBe(true); // Returns true for async handling
                // Wait longer for all retries to complete
                await new Promise((resolve) => setTimeout(resolve, 8000)); // Wait for retries
                expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({
                    data: expect.objectContaining({
                        id: 'CVE-2023-9999',
                        description: 'Vulnerability information not available',
                        status: 'Unknown',
                        sources: [],
                    }),
                }));
            }, 10000);
            it('should handle non-OK responses', async () => {
                mockFetch.mockResolvedValueOnce({
                    ok: false,
                    status: 404,
                });
                const sendResponse = jest.fn();
                messageListener({ action: 'fetchCVEData', cveId: 'CVE-2023-0000' }, {}, sendResponse);
                await new Promise((resolve) => setTimeout(resolve, 100));
                expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({
                    data: expect.objectContaining({
                        id: 'CVE-2023-0000',
                        description: 'Vulnerability information not available',
                        status: 'Unknown',
                    }),
                }));
            });
        });
        describe('fetchPatterns action', () => {
            it('should fetch patterns successfully', async () => {
                const mockPatterns = {
                    result: {
                        patterns: [
                            '/CVE-\\d{4}-\\d{4,7}/gi',
                            '/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/gi',
                        ],
                    },
                };
                mockFetch.mockResolvedValueOnce({
                    ok: true,
                    json: async () => mockPatterns,
                });
                const sendResponse = jest.fn();
                const result = messageListener({ action: 'fetchPatterns' }, {}, sendResponse);
                expect(result).toBe(true); // Should return true for async response
                await new Promise((resolve) => setTimeout(resolve, 100));
                expect(sendResponse).toHaveBeenCalledWith({
                    patterns: mockPatterns.result.patterns,
                });
            });
            it('should return null patterns on API error', async () => {
                mockFetch.mockRejectedValue(new Error('Network error'));
                const sendResponse = jest.fn();
                const promise = messageListener({ action: 'fetchPatterns' }, {}, sendResponse);
                expect(promise).toBe(true);
                // Wait for retries to complete
                await new Promise((resolve) => setTimeout(resolve, 8000));
                expect(sendResponse).toHaveBeenCalledWith({ patterns: null });
            }, 10000);
        });
        describe('updateBadge action', () => {
            it('should update badge with count', () => {
                const sender = { tab: { id: 123 } };
                messageListener({ action: 'updateBadge', count: 5 }, sender, jest.fn());
                expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({
                    text: '5',
                    tabId: 123,
                });
            });
            it('should display 99+ for counts over 99', () => {
                const sender = { tab: { id: 456 } };
                messageListener({ action: 'updateBadge', count: 150 }, sender, jest.fn());
                expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({
                    text: '99+',
                    tabId: 456,
                });
            });
            it('should clear badge for count 0', () => {
                const sender = { tab: { id: 789 } };
                messageListener({ action: 'updateBadge', count: 0 }, sender, jest.fn());
                expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({
                    text: '',
                    tabId: 789,
                });
            });
            it('should not update badge if no tab ID', () => {
                const sender = {}; // No tab property
                messageListener({ action: 'updateBadge', count: 5 }, sender, jest.fn());
                expect(mockChrome.action.setBadgeText).not.toHaveBeenCalled();
            });
        });
        describe('Unknown action', () => {
            it('should warn on unknown action', () => {
                const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
                const result = messageListener({ action: 'unknownAction' }, {}, jest.fn());
                expect(result).toBeUndefined();
                expect(consoleSpy).toHaveBeenCalledWith('Unknown action:', 'unknownAction');
                consoleSpy.mockRestore();
            });
        });
    });
    describe('Retry Logic', () => {
        it('should retry on server error (5xx)', async () => {
            // Reset fetch call count
            mockFetch.mockClear();
            // First two attempts fail with 500, third succeeds
            mockFetch
                .mockResolvedValueOnce({ ok: false, status: 500 })
                .mockResolvedValueOnce({ ok: false, status: 503 })
                .mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    result: {
                        id: 'CVE-2023-RETRY',
                        description: 'Success after retries',
                    },
                }),
            });
            const sendResponse = jest.fn();
            messageListener({ action: 'fetchCVEData', cveId: 'CVE-2023-RETRY' }, {}, sendResponse);
            // Wait for retries with exponential backoff (1s + 2s + success)
            await new Promise((resolve) => setTimeout(resolve, 5000));
            expect(mockFetch).toHaveBeenCalledTimes(3);
            expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({
                data: expect.objectContaining({
                    id: 'CVE-2023-RETRY',
                    description: 'Success after retries',
                }),
            }));
        }, 10000); // Increase timeout for retry test
        it('should not retry on client error (4xx)', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 404,
            });
            const sendResponse = jest.fn();
            messageListener({ action: 'fetchCVEData', cveId: 'CVE-2023-404' }, {}, sendResponse);
            await new Promise((resolve) => setTimeout(resolve, 100));
            expect(mockFetch).toHaveBeenCalledTimes(1); // No retries
        });
        it('should retry on network errors', async () => {
            // First attempt network error, second succeeds
            mockFetch
                .mockRejectedValueOnce(new Error('Network failure'))
                .mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    result: {
                        id: 'CVE-2023-NET',
                        description: 'Success after network retry',
                    },
                }),
            });
            const sendResponse = jest.fn();
            messageListener({ action: 'fetchCVEData', cveId: 'CVE-2023-NET' }, {}, sendResponse);
            await new Promise((resolve) => setTimeout(resolve, 2000));
            expect(mockFetch).toHaveBeenCalledTimes(2);
        }, 5000);
    });
    describe('Cache Management', () => {
        it('should expire cache after TTL', async () => {
            const mockCVEData1 = {
                result: {
                    id: 'CVE-2023-TTL',
                    description: 'First fetch',
                },
            };
            const mockCVEData2 = {
                result: {
                    id: 'CVE-2023-TTL',
                    description: 'Second fetch after expiry',
                },
            };
            // Mock Date.now to control time
            const originalDateNow = Date.now;
            let currentTime = 1000000;
            Date.now = jest.fn(() => currentTime);
            mockFetch
                .mockResolvedValueOnce({
                ok: true,
                json: async () => mockCVEData1,
            })
                .mockResolvedValueOnce({
                ok: true,
                json: async () => mockCVEData2,
            });
            const sendResponse1 = jest.fn();
            const sendResponse2 = jest.fn();
            // First request
            messageListener({ action: 'fetchCVEData', cveId: 'CVE-2023-TTL' }, {}, sendResponse1);
            await new Promise((resolve) => setTimeout(resolve, 100));
            // Advance time beyond cache TTL (1 hour + 1 minute)
            currentTime += 3660000;
            // Second request (should fetch again due to expiry)
            messageListener({ action: 'fetchCVEData', cveId: 'CVE-2023-TTL' }, {}, sendResponse2);
            await new Promise((resolve) => setTimeout(resolve, 100));
            expect(mockFetch).toHaveBeenCalledTimes(2); // Two fetches due to cache expiry
            expect(sendResponse2).toHaveBeenCalledWith(expect.objectContaining({
                data: expect.objectContaining({
                    description: 'Second fetch after expiry',
                }),
            }));
            // Restore Date.now
            Date.now = originalDateNow;
        });
    });
    describe('Data Processing', () => {
        it('should process Vulners API data correctly', async () => {
            const mockAPIResponse = {
                result: {
                    id: 'CVE-2023-PROC',
                    description: 'Detailed vulnerability description',
                    shortDescription: 'Short desc',
                    isCandidate: false,
                    severity: {
                        cvss: {
                            score: 8.5,
                            vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                        },
                        cvss4: {
                            score: 9.0,
                            vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N',
                        },
                        epss: {
                            score: 0.95,
                            percentile: 99,
                        },
                    },
                    exploitation: {
                        maxMaturity: 'weaponized',
                        exploitCount: 5,
                        availability: 'public',
                        wildExploited: true,
                    },
                    intelligence: {
                        aiScore: 85,
                        confidence: 0.9,
                        socialMentions: 150,
                        webApplicable: true,
                    },
                    classification: {
                        cwe: {
                            id: 'CWE-79',
                        },
                    },
                    published: '2023-01-01',
                    modified: '2023-01-15',
                    status: 'Published',
                    sources: ['NVD', 'Vulners'],
                },
            };
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => mockAPIResponse,
            });
            const sendResponse = jest.fn();
            messageListener({ action: 'fetchCVEData', cveId: 'CVE-2023-PROC' }, {}, sendResponse);
            await new Promise((resolve) => setTimeout(resolve, 100));
            expect(sendResponse).toHaveBeenCalledWith({
                data: expect.objectContaining({
                    id: 'CVE-2023-PROC',
                    description: 'Detailed vulnerability description',
                    shortDescription: 'Short desc',
                    isCandidate: false,
                    cvss: {
                        score: 8.5,
                        vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                    },
                    cvss4: {
                        score: 9.0,
                        vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N',
                    },
                    epss: {
                        score: 0.95,
                        percentile: 99,
                    },
                    exploitInfo: {
                        maxMaturity: 'weaponized',
                        exploits: 5,
                        available: 'public',
                        wildExploited: true,
                    },
                    vulnerabilityIntelligence: {
                        score: 85,
                        uncertainty: 0.9,
                        twitterMentions: 150,
                        webApplicable: true,
                    },
                    cwe: 'CWE-79',
                    published: '2023-01-01',
                    modified: '2023-01-15',
                    status: 'Published',
                    sources: ['NVD', 'Vulners'],
                }),
            });
        });
        it('should handle partial data gracefully', async () => {
            const mockPartialData = {
                result: {
                    id: 'CVE-2023-PARTIAL',
                    description: 'Minimal data',
                    severity: {
                        cvss: {
                            score: 5.0,
                            // Missing vector
                        },
                    },
                    // Missing other fields
                },
            };
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => mockPartialData,
            });
            const sendResponse = jest.fn();
            messageListener({ action: 'fetchCVEData', cveId: 'CVE-2023-PARTIAL' }, {}, sendResponse);
            await new Promise((resolve) => setTimeout(resolve, 100));
            expect(sendResponse).toHaveBeenCalledWith({
                data: expect.objectContaining({
                    id: 'CVE-2023-PARTIAL',
                    description: 'Minimal data',
                    cvss: {
                        score: 5.0,
                        vector: '', // Default empty string for missing vector
                    },
                    status: 'Published', // Default status
                    sources: ['vulners.com'], // Default source
                }),
            });
        });
    });
});
//# sourceMappingURL=background.test.js.map