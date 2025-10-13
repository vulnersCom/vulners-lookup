import '@testing-library/jest-dom';
// Complete Chrome API mock for tests
const chromeApiMock = {
    runtime: {
        getURL: jest.fn((path) => `chrome-extension://test/${path}`),
        sendMessage: jest.fn(),
        onMessage: {
            addListener: jest.fn(),
        },
    },
    storage: {
        local: {
            get: jest.fn(),
            set: jest.fn(),
        },
    },
    tabs: {
        query: jest.fn(),
        sendMessage: jest.fn(),
    },
    action: {
        setBadgeText: jest.fn(),
        setBadgeBackgroundColor: jest.fn(),
        setBadgeTextColor: jest.fn(),
    },
};
// Export for easy access in tests
export const mockChrome = chromeApiMock;
// Mock Chrome API for both environments
if (typeof window !== 'undefined') {
    window.chrome = chromeApiMock;
}
if (typeof globalThis !== 'undefined') {
    globalThis.chrome = chromeApiMock;
}
// Mock fetch globally
if (typeof window !== 'undefined') {
    window.fetch = jest.fn();
}
if (typeof globalThis !== 'undefined') {
    globalThis.fetch = jest.fn();
}
// Mock console methods to avoid noise during tests
console.log = jest.fn();
console.warn = jest.fn();
console.error = jest.fn();
//# sourceMappingURL=setup.js.map