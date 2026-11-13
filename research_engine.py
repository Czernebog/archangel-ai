"""Bounded multi-source research with DNS-checked, pinned HTTPS connections.

Public article text is untrusted evidence, never instructions. No redirects, proxy
inheritance, local networks, credentials, scripts or executable content.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
import http.client
import ipaddress
import re
import socket
import ssl
from urllib.parse import urlsplit

from web_search import search_web, public_result_url, clean_excerpt, WebSearchError

MAX_PAGE_BYTES = 160_000
MAX_PAGE_TEXT = 5500
MAX_RESEARCH_RESULTS = 24
MAX_OPEN_PAGES = 12

class PageReader(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.excluded = 0
        self.title_parts = []
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in ('script', 'style', 'svg', 'noscript', 'form', 'iframe', 'template'):
            self.excluded += 1
        if tag == 'title':
            self.in_title = True
        if tag in ('p', 'h1', 'h2', 'h3', 'h4', 'li', 'article', 'main', 'section', 'br'):
            self.parts.append(' ')

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in ('script', 'style', 'svg', 'noscript', 'form', 'iframe', 'template'):
            self.excluded = max(0, self.excluded - 1)
        if tag == 'title':
            self.in_title = False
        if tag in ('p', 'article', 'li', 'section'):
            self.parts.append(' ')

    def handle_data(self, data):
        if self.excluded:
            return
        if self.in_title:
            self.title_parts.append(data)
        elif sum(map(len, self.parts)) < MAX_PAGE_TEXT * 2:
            self.parts.append(data)

    def result(self):
        text = re.sub(r'\s+', ' ', ''.join(self.parts)).strip()
        return text[:MAX_PAGE_TEXT], clean_excerpt(''.join(self.title_parts), 160)


def verified_public_ips(host):
    """Reject DNS answers with any private, loopback or otherwise non-global IP."""
    if not host or not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', host) or '..' in host:
        raise ValueError('Недопустимое имя сервера.')
    if host == 'localhost' or host.endswith(('.localhost', '.local', '.internal')):
        raise ValueError('Локальные адреса запрещены.')
    try:
        ipaddress.ip_address(host)
        raise ValueError('Прямые IP-адреса не поддерживаются.')
    except ValueError as exc:
        if str(exc) == 'Прямые IP-адреса не поддерживаются.':
            raise
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise ValueError('DNS-имя источника не разрешено.') from None
    addresses = []
    for item in infos:
        ip = ipaddress.ip_address(item[4][0])
        if not ip.is_global:
            raise ValueError('Источник указывает на внутренний или служебный адрес.')
        if str(ip) not in addresses:
            addresses.append(str(ip))
    if not addresses:
        raise ValueError('У источника отсутствует публичный адрес.')
    return addresses


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, ips, timeout=6):
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self.validated_ips = ips

    def connect(self):
        last_error = None
        for ip in self.validated_ips:
            try:
                raw = socket.create_connection((ip, 443), timeout=self.timeout)
                try:
                    self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                except Exception:
                    raw.close()
                    raise
                return
            except (OSError, ssl.SSLError) as exc:
                last_error = exc
        raise OSError('Невозможно соединиться с проверенным сервером.') from last_error


def read_public_page(url):
    """Never follow redirects and never evaluate page code."""
    safe = public_result_url(url)
    if not safe:
        raise ValueError('Небезопасная ссылка.')
    parts = urlsplit(safe)
    if parts.scheme != 'https' or parts.port not in (None, 443):
        raise ValueError('Чтение разрешено только через HTTPS на стандартном порту.')
    host = parts.hostname.lower().rstrip('.')
    ips = verified_public_ips(host)
    target = parts.path or '/'
    if parts.query:
        target += '?' + parts.query
    conn = PinnedHTTPSConnection(host, ips)
    try:
        conn.request('GET', target, headers={
            'Host': host, 'User-Agent': 'ARCHANGEL-Research/1.0 (+read-only)',
            'Accept': 'text/html, text/plain;q=0.8', 'Accept-Encoding': 'identity',
            'Connection': 'close',
        })
        res = conn.getresponse()
        if res.status != 200:
            raise ValueError('Страница не предоставила доступный текст.')
        content_type = res.getheader('Content-Type', '').lower()
        if not (content_type.startswith('text/html') or content_type.startswith('text/plain')):
            raise ValueError('Формат страницы не поддерживается.')
        raw = res.read(MAX_PAGE_BYTES + 1)
        if len(raw) > MAX_PAGE_BYTES:
            raise ValueError('Страница превышает ограничение размера.')
        charset = 'utf-8'
        detected = re.search(r'charset\s*=\s*["\']?([\w-]+)', content_type)
        if detected and detected.group(1).lower() in ('utf-8', 'iso-8859-1', 'windows-1251'):
            charset = detected.group(1)
        text = raw.decode(charset, errors='replace')
        if content_type.startswith('text/plain'):
            return clean_excerpt(text, MAX_PAGE_TEXT), ''
        parser = PageReader()
        parser.feed(text)
        return parser.result()
    finally:
        conn.close()


def research(query, api_key, depth='quick', search=search_web, reader=read_public_page):
    """At most 3 search calls / 24 indexed results / 12 page reads per request."""
    if not isinstance(query, str) or not query.strip() or len(query) > 220:
        raise ValueError('Запрос должен содержать от 1 до 220 символов.')
    if depth not in ('quick', 'deep'):
        raise ValueError('Неизвестная глубина исследования.')
    if not api_key:
        raise WebSearchError('Для исследований нужен BRAVE_SEARCH_API_KEY в Render.')
    clean_query = query.strip()
    queries = [clean_query]
    if depth == 'deep':
        queries += [clean_query + ' официальная документация', clean_query + ' сравнение факты']
    indexed = []
    seen = set()
    for q in queries:
        try:
            matches = search(q[:250], api_key, count=8)
        except (WebSearchError, ValueError):
            if not indexed:
                raise
            break
        for item in matches:
            url = public_result_url(item.get('url'))
            if url and url not in seen:
                seen.add(url)
                indexed.append({
                    'title': clean_excerpt(item.get('title'), 160),
                    'url': url,
                    'description': clean_excerpt(item.get('description'), 420),
                    'text': '',
                    'read': False,
                })
                if len(indexed) >= MAX_RESEARCH_RESULTS:
                    break
        if len(indexed) >= MAX_RESEARCH_RESULTS:
            break
    page_limit = 5 if depth == 'quick' else MAX_OPEN_PAGES
    def load(index):
        try:
            text, title = reader(indexed[index]['url'])
            return index, text, title
        except (OSError, ValueError, UnicodeError, TimeoutError, ssl.SSLError):
            return index, '', ''
    with ThreadPoolExecutor(max_workers=4) as pool:
        for index, text, title in pool.map(load, range(min(page_limit, len(indexed)))):
            if text:
                indexed[index]['text'] = text
                indexed[index]['read'] = True
                if title and not indexed[index]['title']:
                    indexed[index]['title'] = title
    return {
        'query': clean_query,
        'depth': depth,
        'indexedCount': len(indexed),
        'readCount': sum(1 for item in indexed if item['read']),
        'sources': indexed,
    }
