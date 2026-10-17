"""Direct, bounded HTTP requests with no ambient proxy or credential redirects."""

import json
from urllib.request import ProxyHandler, Request, build_opener

from .inspection import NoRedirects


def direct_opener():
    return build_opener(ProxyHandler({}), NoRedirects())


def request_json(url, *, data=None, token=None, method=None, form=None, timeout=15):
    headers = {"Accept": "application/json"}
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    if form is not None:
        from urllib.parse import urlencode
        body = urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = Request(url, data=body, headers=headers, method=method)
    with direct_opener().open(request, timeout=timeout) as response:
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("Service response exceeded the size limit")
    return json.loads(raw) if raw else {}
