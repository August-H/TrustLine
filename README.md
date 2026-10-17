# TrustLine

Monorepo for the TrustLine Chrome extension, macOS background daemon, and website frontend.

```text
apps/
  chrome-extension/  # Chrome browser extension
  macos-daemon/      # Background service for macOS
  web/               # Website frontend
```

Each app owns its source code, dependencies, and build configuration. Add those files inside the corresponding app directory when choosing its framework and tooling.
