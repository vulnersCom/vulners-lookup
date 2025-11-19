// Cross-browser extension API wrapper.
// Firefox supports the `chrome.*` namespace, but also exposes `browser.*`.
// This helper always gives you a Chrome-like API object.
declare const browser: typeof chrome | undefined;

export const api: typeof chrome =
  typeof browser !== "undefined" ? browser : chrome;
