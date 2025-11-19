# Vulners Lookup – Chrome & Firefox builds

This project has been prepared for both Chrome and Firefox Manifest V3.

## Build for Chrome

```bash
npm install
npm run build:chrome
```

This will:
- copy `manifest.chrome.json` to `manifest.json`
- run the normal production build
- create a `build/` directory with the Chrome-ready extension

## Build for Firefox

```bash
npm install
npm run build:firefox
```

This will:
- copy `manifest.firefox.json` to `manifest.json`
- run the normal production build
- create a `build/` directory with the Firefox-ready extension

To load the Firefox build temporarily:

1. Open `about:debugging#/runtime/this-firefox`
2. Click **"Load Temporary Add-on..."**
3. Select the `manifest.json` file from the `build/` folder

## AMO (addons.mozilla.org) signing

To distribute the Firefox build:

1. Make sure `manifest.firefox.json` has a stable, unique `browser_specific_settings.gecko.id`.
2. Build with `npm run build:firefox`.
3. Zip the contents of the `build/` folder:
   ```bash
   cd build
   zip -r ../vulners-lookup-firefox-build.zip .
   ```
4. Upload that ZIP to AMO for signing.

The `src/api.ts` helper provides a cross-browser API object (`api`) that maps to
`browser` in Firefox and to `chrome` in Chrome, if you decide to adopt it in the
codebase.
