# Vulners Lookup - CVE Lookup Chrome Extension

A Chrome extension that automatically detects vulnerability identifiers (CVE, Advisory, Exploit) on web pages, highlights them with color-coded styling, and shows detailed vulnerability information from Vulners.com on hover.

## Features

- 🔍 **Multi-Type Detection**: Supports 38+ vulnerability identifier patterns across 3 types:
  - **CVE** (orange): CVE-2024-1234, CAN-2002-0032
  - **Advisory** (indigo): RHSA, DSA, USN, GHSA, CNVD, and 28 more
  - **Exploit** (red): EDB-ID, PACKETSTORM, ZDI
- 🎨 **Color-Coded Highlights**: Type-specific colors for instant visual recognition
- 📊 **Rich Intelligence**: CVSS scores, EPSS data, AI scoring, exploit maturity, and wild exploitation status
- 🔥 **Exploit Indicators**: Fire icons for vulnerabilities exploited in the wild
- ⚡ **SPA Optimized**: Mutation storm detection, viewport-aware processing, adaptive debouncing
- 🎛️ **Toggle Control**: Enable/disable highlighting via popup interface with type breakdown
- 🚀 **API Integration**: Direct integration with Vulners API for latest vulnerability data
- 📱 **Cross-Platform Fonts**: Optimized typography using system font stacks

## Installation

1. Clone this repository
2. Install dependencies: `npm install`
3. Build the extension: `npm run build`
4. Open Chrome and go to `chrome://extensions/`
5. Enable "Developer mode"
6. Click "Load unpacked" and select this directory

## Development

### Prerequisites
- Node.js 22.6+ (for TypeScript config support)
- npm
- Chrome browser

### Setup
```bash
# Install dependencies
npm install

# Build for development
npm run dev

# Build for production
npm run build

# Build optimized production version
npm run build:prod

# Watch for changes
npm run watch

# Type checking
npm run typecheck

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Lint code
npm run lint

# Format code
npm run format
```

### Code Quality

Pre-commit hooks automatically run on `git commit`:
- ESLint with auto-fix for TypeScript files
- Prettier formatting for TS and CSS files

```bash
# Manual lint check
npm run lint

# Manual format check
npm run format:check
```

### Make Commands
```bash
# Build extension
make build

# Production build and package
make package

# Development with watch
make dev

# Run tests
make test

# Run tests with coverage
make coverage

# Clean build artifacts
make clean
```

### File Structure
```
src/
├── background.ts        # Service worker with API integration
├── content.ts           # Content script entry point
├── content/             # Modular content script components
│   ├── index.ts         # Main exports
│   ├── types.ts         # Re-exports from shared types
│   ├── constants.ts     # CONFIG, BULLETIN_TYPE_MAP
│   ├── utils.ts         # detectBulletinType, escapeHtml
│   ├── tooltip-manager.ts   # TooltipManager class
│   ├── dom-scanner.ts       # DOMScanner class
│   └── cve-highlighter.ts   # CVEHighlighter class
├── popup.ts             # Popup UI controller
├── types.ts             # Shared TypeScript types
├── utils.ts             # Shared utilities
├── history-hook.ts      # SPA navigation detection
└── styles/
    ├── content.css      # Tooltip & highlight styling
    └── popup.css        # Popup interface styles
assets/
├── icon-16.png          # Extension icon (16x16)
├── icon-48.png          # Extension icon (48x48)
└── icon-128.png         # Extension icon (128x128)
dist/                    # Build output (bundled IIFE files)
tests/                   # Unit tests (170 tests)
├── background.test.ts   # Background service tests (70+)
├── content.test.ts      # Content script tests (50+)
├── popup.test.ts        # Popup interface tests (20+)
├── history-hook.test.ts # SPA navigation tests (13)
├── utils.test.ts        # Utility function tests (15+)
└── setup.ts             # Chrome API mocks
.husky/                  # Pre-commit hooks
jest.config.ts           # Jest configuration
docs/                    # Documentation
Makefile                 # Build automation
```

## API Integration

The extension integrates with Vulners API for comprehensive vulnerability intelligence:
- **Primary**: Vulners API (`https://vulners.com`)
- **Pattern Discovery**: Dynamic pattern loading from `/api/misc/chrome/patterns`
- **Bulletin Data**: Detailed vulnerability information from `/api/misc/chrome/cve`
- **Caching**: Intelligent in-memory caching with 1-hour TTL

### Vulnerability Intelligence
- **CVSS v3/v4 Scores**: Base scores with vector strings
- **EPSS Data**: Exploit prediction scoring with percentiles
- **AI Scoring**: Machine learning-based vulnerability assessment
- **Exploit Intelligence**: Maturity levels, availability, and wild exploitation status
- **Social Intelligence**: Twitter mentions and web application relevance
- **CWE Classification**: Common weakness enumeration mapping
- **Timeline Data**: Publication and modification dates

## Design System

The extension implements Vulners.com design language with modern improvements:
- **Colors**: Refined palette with proper contrast ratios
- **Typography**: Optimized system font stack for cross-platform consistency
- **Layout**: Responsive card-based design with 320×242px tooltips
- **Components**: Modular chip system for metrics display
- **Icons**: Vector-based fire indicators for wild exploitation
- **Animations**: Smooth transitions with performance optimization

## Architecture

### Background Service
- **Service Worker**: Manifest v3 compliant background processing
- **API Management**: Centralized vulnerability data fetching
- **Caching Strategy**: In-memory cache with intelligent expiration
- **Badge Updates**: Real-time CVE count display

### Content Scripts
- **Pattern Matching**: Dynamic regex patterns from API
- **DOM Monitoring**: MutationObserver for real-time detection
- **Tooltip Rendering**: Optimized HTML generation with data binding
- **Event Handling**: Efficient hover state management

### Configuration
- **Storage**: Chrome local storage for user preferences
- **Settings**: Toggle highlighting, cache management
- **Constants**: Centralized API endpoints and configuration

## Privacy & Security

- No user data collection
- API calls only for CVE information
- Local storage for caching only
- Secure HTTPS API endpoints

## Browser Compatibility

- **Chrome 88+**: Full feature support
- **Chromium-based browsers**: Edge, Opera, Brave compatibility
- **Manifest v3**: Future-proof extension architecture
- **Cross-platform**: Windows, macOS, Linux support
- **Font Rendering**: Optimized typography across all platforms

## Build & Distribution

### Development Build
```bash
npm run build
# or
make build
```

### Production Package
```bash
npm run build:prod
make package
```

This creates an optimized `vulners-lookup-v1.0.6.zip` ready for Chrome Web Store submission.

### Development Workflow
```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Type checking
npm run typecheck

# Clean and rebuild
make clean && make build
```

## Testing

### Test Suite

The extension includes comprehensive unit testing with Jest and TypeScript (**170 tests**):

#### Test Files
- **`background.test.ts`** - Background service worker tests (70+ tests, 87% coverage)
- **`content.test.ts`** - Content script functionality tests (50+ tests)
- **`popup.test.ts`** - Popup interface tests (20+ tests)
- **`history-hook.test.ts`** - SPA navigation detection tests (13 tests)
- **`utils.test.ts`** - Shared utility function tests (15+ tests)

#### Running Tests
```bash
# Run all tests
npm test
# or
make test

# Watch mode for development
npm run test:watch
# or
make test-watch

# Generate coverage reports
npm run test:coverage  
# or
make coverage
```

#### Test Coverage

Current coverage thresholds (minimum 50% required):
- **Statements**: 50%+
- **Branches**: 50%+
- **Functions**: 50%+
- **Lines**: 50%+

Background service maintains 87%+ coverage across all metrics.

#### Test Categories

**Background Service Tests** - Comprehensive service worker testing:
- Message handling (CVE data, patterns, badge updates)
- API retry logic with exponential backoff (3 retries, 1s/2s/4s delays)
- Cache management with TTL (1-hour expiration)
- Error handling for network failures
- Data processing from Vulners API

**Content Script Tests** - DOM manipulation and detection:
- CVE pattern recognition (CVE-YYYY-NNNNNNN format validation)
- DOM highlighting simulation
- Element exclusion (script, style, noscript tags)
- Dynamic content handling via MutationObserver
- Chrome API message passing integration

**Popup Interface Tests** - Extension UI testing:
- Tab querying and content script communication
- Toggle functionality for highlighting control
- Statistics display (CVE count formatting)
- Error handling for content script failures
- UI element accessibility validation

#### Test Environment

- **Framework**: Jest with TypeScript support (`jest.config.ts`)
- **Environment**: jsdom for DOM testing, Node.js for service worker
- **Coverage**: Istanbul/NYC with LCOV/HTML reports
- **Mocking**: Comprehensive Chrome API mocks (`chrome.runtime`, `chrome.storage`, `chrome.tabs`, `chrome.action`)

#### Mock Strategy

The test setup provides complete Chrome extension API mocking:
```typescript
// Global Chrome API mocks in setup.ts
chrome.runtime.sendMessage
chrome.runtime.onMessage  
chrome.storage.local
chrome.tabs.query
chrome.tabs.sendMessage
chrome.action.setBadgeText
```

Network requests mocked with success/failure scenarios for retry testing.

#### Debugging Tests
```bash
# Run specific test file
npx jest tests/background.test.ts

# Verbose output
npx jest --verbose

# Single test by name
npx jest -t "should retry on server error"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Follow TypeScript and CSS conventions
4. **Write tests** for new functionality
5. **Run test suite**: `make test` and ensure coverage thresholds met
6. Test across multiple browsers
7. Run type checking and builds
8. Submit a pull request

## License

MIT License - see LICENSE file for details

## Acknowledgments

- Powered by [Vulners.com](https://vulners.com)
- Fallback data from [NIST NVD](https://nvd.nist.gov)
- Icons and design inspired by security tooling

## Technical Details

### Performance Optimizations
- **Efficient Pattern Matching**: Optimized regex with overlap prevention
- **Intelligent Caching**: Memory-based cache with automatic expiration
- **Lazy Loading**: On-demand tooltip content generation
- **DOM Optimization**: Minimal DOM manipulation with efficient event handling

### Security Features
- **HTTPS Only**: All API communications over secure connections
- **Content Security Policy**: Strict CSP compliance
- **No Data Collection**: Privacy-focused design with local-only storage
- **API Rate Limiting**: Built-in request throttling

## Troubleshooting

### Extension not detecting CVEs?
1. Check if highlighting is enabled in popup
2. Verify extension permissions in `chrome://extensions/`
3. Refresh the page after installation or updates
4. Check developer console for any error messages

### API connectivity issues?
1. Verify network connectivity to `vulners.com`
2. Check if corporate firewall blocks API requests
3. Monitor background service worker in Chrome DevTools

### Tooltips not displaying correctly?
1. Ensure CVE format matches supported patterns
2. Check if content script loaded properly
3. Verify tooltip positioning on different screen sizes
4. Test with different browser zoom levels