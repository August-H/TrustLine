# TrustLine

The Python macOS background process runs a local HTTP(S) inspection proxy. It checks
an approved-site database before asking TypeSafe's Jev model about URL metadata.
Suspicious pages redirect to a proxy-owned `https://blocked.example.com/` page.
Other unapproved pages stay blocked while GPT-6.1 Sol reviews them in a
Cloudflare-hosted browser using authorized ChatGPT subscription access.

```text
apps/
  chrome-extension/  # Reserved, no extension implementation
  macos-daemon/      # Python inspection proxy and optional LaunchAgent
  web/               # Reserved for the website frontend
```

See [service setup](apps/macos-daemon/README.md) for dependencies, Chrome proxy
routing, HTTPS certificate setup, and running at login. No browser extension is
required.
