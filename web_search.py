"""Constrained web search for ARCHANGEL AI. No client-side search credentials."""
from __future__ import annotations

import html
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request

BRAVE_URL = "https://api.search.brave.com/res/v1/web/search"
MAX_WEB_RESPONSE = 512 * 1024


class WebSearchError(Exception):
    """A safe, non-sensitive failure suitable for the UI."""


def public_result_url(raw):
    """Only expose ordinary public HTTP(S) links from the search response."""
    if not isinstance(raw, str) or len(raw) > 1800:
        return ""
    try:
        p = urllib.parse.urlsplit(raw)
        host = (p.hostname or "").lower().rstrip(".")
        if p.scheme not in ("https", "http") or not host or p.username or p.password:
            return ""
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")) or "." not in host:
            return ""
        try:
            if not ipaddress.ip_address(host).is_global:
                return ""
        except ValueError:
            pass
        if p.port and not (1 <= p.port <= 65535):
            return ""
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, p.query, ""))
    except (ValueError, UnicodeError):
        return ""


def clean_excerpt(value, limit=420):
    if not isinstance(value, str):
        return ""
    text = html.unescape(re.sub(r"<[^>]*>", " ", value))
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def search_web(query, api_key, opener=None):
    """Return a small set of cited snippets; never fetch result URLs."""
    if not isinstance(query, str) or not query.strip() or len(query) > 250 or len(query.split()) > 40:
        raise ValueError("Запрос должен содержать от 1 до 250 символов (не более 40 слов).")
    if not api_key:
        raise WebSearchError("Интернет-поиск не настроен: добавь BRAVE_SEARCH_API_KEY в переменные окружения Render.")
    params = urllib.parse.urlencode({
        "q": query.strip(), "count": 6, "safesearch": "strict", "text_decorations": "false",
    })
    req = urllib.request.Request(
        BRAVE_URL + "?" + params,
        headers={"Accept": "application/json", "X-Subscription-Token": api_key, "User-Agent": "ARCHANGEL-AI-Search/1.0"},
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None

    try:
        client = opener or urllib.request.build_opener(NoRedirect())
        with client.open(req, timeout=9) as response:
            if response.status != 200:
                raise WebSearchError("Поисковый сервис временно недоступен.")
            raw = response.read(MAX_WEB_RESPONSE + 1)
            if len(raw) > MAX_WEB_RESPONSE:
                raise WebSearchError("Поисковый сервис вернул слишком большой ответ.")
            data = json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        if code in (401, 403):
            raise WebSearchError("Brave Search отклонил ключ API или тариф.") from None
        if code == 429:
            raise WebSearchError("Лимит Brave Search исчерпан; повтори позже.") from None
        raise WebSearchError("Поисковый сервис временно недоступен.") from None
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        raise WebSearchError("Не удалось получить достоверный ответ от поискового сервиса.") from None
    if not isinstance(data, dict):
        raise WebSearchError("Поисковый сервис вернул некорректный ответ.")
    items = data.get("web", {}).get("results", []) if isinstance(data.get("web"), dict) else []
    results = []
    seen = set()
    for item in items[:12]:
        if not isinstance(item, dict):
            continue
        url = public_result_url(item.get("url"))
        if not url or url in seen:
            continue
        seen.add(url)
        results.append({
            "title": clean_excerpt(item.get("title"), 160) or url,
            "url": url,
            "description": clean_excerpt(item.get("description"), 420),
        })
        if len(results) >= 6:
            break
    return results
