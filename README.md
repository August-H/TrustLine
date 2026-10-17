# TrustLine

The Python macOS background process runs a local HTTP(S) inspection proxy. It checks
an approved-site database before asking TypeSafe's Jev model about URL metadata.
Suspicious pages redirect to a proxy-owned `https://blocked.example.com/` page.
Other unapproved pages stay blocked while GPT-6.1 Sol reviews them in a
Cloudflare-hosted browser using authorized ChatGPT subscription access.
Successful page reviews are cached in SQLite for 24 hours and survive restarts.

```text
apps/
  chrome-extension/  # Toolbar scores, cloud Deep scan, and warning page
  macos-daemon/      # Python inspection proxy and optional LaunchAgent
  web/               # Reserved for the website frontend
```

See [service setup](apps/macos-daemon/README.md) for dependencies, Chrome proxy
routing, HTTPS certificate setup, and running at login. No browser extension is
required.

The optional [Chrome extension](apps/chrome-extension/README.md) connects to the daemon
on port 8765. Verified domains show 100; other sites show the inverse Jev
suspiciousness probability as a score out of 100. Deep scan runs the existing
Cloudflare browser review and displays its verdict and evidence.
