#!/usr/bin/env python3
"""ARCHANGEL AI 4.1 lightweight web gateway with isolated browser sessions."""
from __future__ import annotations
import base64, json, mimetypes, os, re, sys, threading, urllib.request, urllib.error, zipfile, webbrowser, subprocess, ipaddress, shutil, secrets, time, hmac
import hashlib
from io import BytesIO
from pathlib import Path
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from http.cookies import SimpleCookie
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parent

def _approved_inline_script_hashes():
    """Hash allowlist for first-party inline scripts. Fail closed if HTML is unavailable."""
    try:
        html = (ROOT / 'index.html').read_text(encoding='utf-8')
    except OSError:
        return ''
    entries = re.findall(r'<script\b[^>]*>([\s\S]*?)</script\s*>', html, flags=re.IGNORECASE)
    return ' '.join("'sha256-" + base64.b64encode(hashlib.sha256(
        source.encode('utf-8')).digest()).decode('ascii') + "'" for source in entries)

INLINE_SCRIPT_HASHES = _approved_inline_script_hashes()

TUNNEL_MODE = os.environ.get('ARCHANGEL_TUNNEL', '').lower() in ('1', 'true', 'yes')
HOSTED_MODE = os.environ.get('ARCHANGEL_PUBLIC', '').lower() in ('1', 'true', 'yes') or os.environ.get('RENDER', '').lower() == 'true'
PUBLIC_MODE = HOSTED_MODE or TUNNEL_MODE
# Quick Tunnel must reach only loopback; do not expose the app on the whole LAN.
HOST = '0.0.0.0' if HOSTED_MODE else '127.0.0.1'
PORT = int(os.environ.get('PORT', '10000')) if HOSTED_MODE else int(os.environ.get('ARCHANGEL_PORT', '8765' if TUNNEL_MODE else '0'))
MAX_BODY = 16 * 1024 * 1024
MAX_CHAT_TEXT = 260_000
MAX_SINGLE_TEXT = 220_000
SESSION_TTL = 30 * 24 * 60 * 60
MAX_SESSIONS = 3000
# Optional shared-site gate. Set a strong secret in the hosting dashboard; never commit it.
SITE_PASSWORD = os.environ.get('ARCHANGEL_SITE_PASSWORD', '')
MAX_ACTIVE_CHATS = 40
MAX_ACTIVE_CHATS_PER_IP = 4
MAX_UPSTREAM_RESPONSE = 4 * 1024 * 1024  # Reject unbounded provider output.
DEFAULT_CONFIG = {'provider': None, 'model': None, 'api_key': None, 'endpoint': None}
SESSIONS = {}
# Sliding-window request timestamps and in-flight chat guards are RAM-only.
RATE_WINDOWS = {}
ACTIVE_CHATS = set()
ACTIVE_CHAT_IPS = {}
RATE_LAST_CLEAN = 0.0
LOCK = threading.RLock()

PROVIDERS = {
    'gemini': 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions',
    'groq': 'https://api.groq.com/openai/v1/chat/completions',
    'openrouter': 'https://openrouter.ai/api/v1/chat/completions',
    'ollama': 'http://127.0.0.1:11434/v1/chat/completions',
    'openai': 'https://api.openai.com/v1/chat/completions',
}

class Handler(SimpleHTTPRequestHandler):
    server_version = 'ARCHANGEL'
    sys_version = ''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def _ensure_session(self):
        if getattr(self, "session_id", None):
            return
        raw_cookie = self.headers.get('Cookie', '')
        cookies = SimpleCookie()
        try:
            cookies.load(raw_cookie)
            morsel = cookies.get('archangel_session')
            candidate = morsel.value if morsel else ''
        except Exception:
            candidate = ''
        if not re.fullmatch(r'[A-Za-z0-9_-]{40,60}', candidate or ''):
            candidate = ''
        now = time.time()
        with LOCK:
            entry = SESSIONS.get(candidate) if candidate else None
            if entry and now - entry.get('last', now) > SESSION_TTL:
                SESSIONS.pop(candidate, None)
                entry = None
            # A valid-looking but unknown cookie is never accepted as a session ID.
            # This prevents clients from choosing/fixing another visitor's session token.
            if entry is None:
                candidate = secrets.token_urlsafe(32)
                self.new_session_cookie = candidate
                if len(SESSIONS) >= MAX_SESSIONS:
                    expired = [key for key, value in SESSIONS.items()
                               if now - value.get('last', now) > SESSION_TTL]
                    for key in expired:
                        SESSIONS.pop(key, None)
                    if len(SESSIONS) >= MAX_SESSIONS:
                        oldest = min(SESSIONS, key=lambda key: SESSIONS[key].get('last', 0))
                        SESSIONS.pop(oldest, None)
                entry = {'config': dict(DEFAULT_CONFIG), 'last': now}
                SESSIONS[candidate] = entry
            entry['last'] = now
        self.session_id = candidate

    def _session_entry(self):
        self._ensure_session()
        with LOCK:
            entry = SESSIONS.get(self.session_id)
            if entry is None:
                entry = {'config': dict(DEFAULT_CONFIG), 'last': time.time()}
                SESSIONS[self.session_id] = entry
            entry['last'] = time.time()
            return entry

    def _client_identity(self):
        # Behind the host's reverse proxy, X-Forwarded-For is populated by the
        # platform. Use its final address (the nearest proxy-added hop); fall
        # back to the socket peer when the header is absent or malformed.
        peer = self.client_address[0] if self.client_address else 'unknown'
        forwarded = self.headers.get('X-Forwarded-For', '')
        if forwarded:
            candidate = forwarded.split(',')[-1].strip()
            try:
                return ipaddress.ip_address(candidate).compressed
            except ValueError:
                pass
        try:
            return ipaddress.ip_address(peer).compressed
        except ValueError:
            return peer[:80]

    def _require_site_password(self):
        """Optional HTTP Basic gate for private deployments; sessions remain isolated."""
        if not SITE_PASSWORD:
            return True
        supplied = ''
        header = self.headers.get('Authorization', '')
        if header.startswith('Basic '):
            try:
                decoded = base64.b64decode(header[6:], validate=True).decode('utf-8')
                supplied = decoded.split(':', 1)[1] if ':' in decoded else ''
            except Exception:
                supplied = ''
        if supplied and hmac.compare_digest(supplied, SITE_PASSWORD):
            return True
        body = json.dumps({'error': 'Доступ к ARCHANGEL защищён.'}, ensure_ascii=False).encode('utf-8')
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="ARCHANGEL", charset="UTF-8"')
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)
        return False

    def _reject_rate_limit(self, retry_after, message, status=429):
        retry_after = max(1, int(retry_after + 0.999))
        raw = json.dumps({'error': message, 'retryAfter': retry_after}, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Retry-After', str(retry_after))
        self.end_headers()
        self.wfile.write(raw)

    def _check_anti_spam(self, action):
        """RAM-only per-session/per-IP sliding windows and concurrency caps."""
        ip = self._client_identity()
        self.client_identity = ip
        policies = {
            'chat': (('chat-session', self.session_id, 10, 60.0, 2.5),
                     ('chat-ip', ip, 40, 60.0, 0.0)),
            'config': (('config-session', self.session_id, 8, 60.0, 0.0),
                       ('config-ip', ip, 32, 60.0, 0.0)),
            'disconnect': (('disconnect-session', self.session_id, 8, 60.0, 0.0),
                           ('disconnect-ip', ip, 32, 60.0, 0.0)),
            'extract': (('extract-session', self.session_id, 10, 60.0, 0.0),
                        ('extract-ip', ip, 24, 60.0, 0.0)),
            'math': (('math-session', self.session_id, 12, 60.0, 0.4),
                     ('math-ip', ip, 40, 60.0, 0.0)),
        }
        specs = policies[action]
        now = time.monotonic()
        rejected = None
        status = 429
        with LOCK:
            global RATE_LAST_CLEAN
            if action == 'chat':
                if self.session_id in ACTIVE_CHATS:
                    rejected = (2, 'В этой сессии уже выполняется запрос. Дождись ответа или останови текущую генерацию.')
                elif len(ACTIVE_CHATS) >= MAX_ACTIVE_CHATS:
                    rejected = (8, 'Сейчас сервер занят. Подожди немного и повтори запрос.')
                    status = 503
                elif ACTIVE_CHAT_IPS.get(ip, 0) >= MAX_ACTIVE_CHATS_PER_IP:
                    rejected = (5, 'С этого подключения уже выполняется несколько запросов. Дождись освобождения места.')

            # Opportunistic cleanup bounds RAM use on a public instance.
            if now - RATE_LAST_CLEAN > 120 or len(RATE_WINDOWS) > 12000:
                for key, stamps in list(RATE_WINDOWS.items()):
                    kept = [stamp for stamp in stamps if now - stamp < 120]
                    if kept:
                        RATE_WINDOWS[key] = kept
                    else:
                        RATE_WINDOWS.pop(key, None)
                RATE_LAST_CLEAN = now

            if rejected is None:
                retry = 0.0
                for bucket, identity, limit, window, min_interval in specs:
                    key = (bucket, identity)
                    stamps = [stamp for stamp in RATE_WINDOWS.get(key, []) if now - stamp < window]
                    if len(stamps) >= limit:
                        retry = max(retry, window - (now - stamps[0]))
                    if min_interval and stamps and now - stamps[-1] < min_interval:
                        retry = max(retry, min_interval - (now - stamps[-1]))
                if retry > 0:
                    rejected = (retry, 'Слишком частые запросы. Подожди немного и попробуй снова.'
                                if action == 'chat' else
                                'Слишком много действий за короткое время. Подожди немного и попробуй снова.')

            if rejected is None:
                for bucket, identity, limit, window, min_interval in specs:
                    key = (bucket, identity)
                    stamps = [stamp for stamp in RATE_WINDOWS.get(key, []) if now - stamp < window]
                    stamps.append(now)
                    RATE_WINDOWS[key] = stamps
                if action == 'chat':
                    ACTIVE_CHATS.add(self.session_id)
                    ACTIVE_CHAT_IPS[ip] = ACTIVE_CHAT_IPS.get(ip, 0) + 1

        if rejected:
            self._reject_rate_limit(rejected[0], rejected[1], status=status)
            return False
        return True

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Robots-Tag', 'noindex, nofollow, noarchive')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Permissions-Policy', 'microphone=(self), camera=(), geolocation=(), payment=(), usb=()')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('X-Permitted-Cross-Domain-Policies', 'none')
        # Hosted edition calls providers exclusively through this server-side gateway.
        # Local development retains optional direct HTTPS connections.
        connect_sources = "'self'" if PUBLIC_MODE else "'self' https:"
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' " + INLINE_SCRIPT_HASHES + "; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self' data: https:; connect-src " + connect_sources + "; media-src 'self' data: blob:; worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-src 'none'; frame-ancestors 'none'")
        if PUBLIC_MODE or self.headers.get('X-Forwarded-Proto', '').split(',')[0].strip().lower() == 'https':
            self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        if getattr(self, 'new_session_cookie', None):
            secure = PUBLIC_MODE or (self.headers.get('X-Forwarded-Proto', '').split(',')[0].strip().lower() == 'https')
            cookie = f"archangel_session={self.new_session_cookie}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict"
            if secure:
                cookie += '; Secure'
            self.send_header('Set-Cookie', cookie)
            self.new_session_cookie = None
        if self.path.split('?', 1)[0] in ('/', '/index.html', '/index.html', '/api/status'):
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        super().end_headers()

    def _verify_request(self):
        # Browser API calls must be same-origin. SameSite=Strict is an additional CSRF barrier.
        request_host = (self.headers.get('X-Forwarded-Host') or self.headers.get('Host', '')).split(',')[0].strip().lower()
        if not request_host:
            self._json(400, {'error': 'Не удалось определить адрес сайта.'})
            return False
        origin = self.headers.get('Origin')
        if not origin and PUBLIC_MODE:
            origin = self.headers.get('Referer')
        if not origin and PUBLIC_MODE:
            self._json(403, {'error': 'Запрос отклонён: браузер не передал проверяемый источник.'})
            return False
        if origin:
            parsed = urlparse(origin)
            origin_host = (parsed.netloc or '').lower()
            if origin_host != request_host:
                self._json(403, {'error': 'Запрос отклонён: источник не совпадает с адресом ARCHANGEL.'})
                return False
            expected_scheme = (self.headers.get('X-Forwarded-Proto') or 'http').split(',')[0].strip().lower()
            if parsed.scheme and expected_scheme and parsed.scheme.lower() != expected_scheme:
                self._json(403, {'error': 'Запрос отклонён: схема источника не совпадает с сайтом.'})
                return False
        fetch_site = (self.headers.get('Sec-Fetch-Site') or '').lower()
        if fetch_site in ('cross-site', 'same-site'):
            self._json(403, {'error': 'Межсайтовый запрос отклонён.'})
            return False
        return True

    def log_message(self, fmt, *args):
        # Never log request bodies, chat content, query strings, or API credentials.
        try:
            code = args[1] if len(args) > 1 else ''
            path = self.path.split('?', 1)[0]
            sys.stdout.write(f'[ARCHANGEL] {self.command} {path} {code}\n')
        except Exception:
            pass

    def _json(self, code, obj):
        raw = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code); self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw))); self.send_header('Cache-Control', 'no-store')
        self.end_headers(); self.wfile.write(raw)

    def _allowed_static_path(self, path):
        clean = path.split('?', 1)[0]
        if clean in ('/', '/index.html', '/index.html', '/robots.txt', '/manifest.webmanifest', '/sw.js'):
            return True
        if clean.startswith('/icons/') and clean.count('/') == 2:
            candidate = (ROOT / clean.lstrip('/')).resolve()
            icons_root = (ROOT / 'icons').resolve()
            return candidate.is_file() and candidate.parent == icons_root
        if clean.startswith('/assets/') and clean.count('/') == 2:
            candidate = (ROOT / clean.lstrip('/')).resolve()
            assets_root = (ROOT / 'assets').resolve()
            return candidate.is_file() and candidate.parent == assets_root
        return False

    def do_GET(self):
        path = urlparse(self.path).path
        # Hosting health checks must not allocate a visitor session or cookie.
        if path == '/healthz':
            return self._json(200, {'ok': True, 'service': 'archangel'})
        if not self._require_site_password():
            return
        if path == '/api/status':
            self._ensure_session()
            with LOCK:
                cfg = dict(self._session_entry()['config'])
            configured = bool(cfg['provider'] and cfg['model'] and (cfg['provider'] == 'ollama' or cfg['api_key']))
            data = {'ok': True, 'version': '4.15.0', 'gateway': True, 'configured': configured,
                    'provider': cfg['provider'], 'model': cfg['model'], 'keyStored': False,
                    'sessionIsolated': True, 'historyStoredOnServer': False,
                    'antiSpam': {'enabled': True, 'chatPerSessionPerMinute': 10, 'chatCooldownSeconds': 2.5, 'maxConcurrentPerSession': 1, 'maxConcurrentPerIp': MAX_ACTIVE_CHATS_PER_IP, 'oneChatAtATime': True}}
            return self._json(200, data)
        if not self._allowed_static_path(path):
            return self._json(404, {'error': 'Маршрут не найден.'})
        if path in ('/', '/index.html', '/index.html'):
            self._ensure_session()
        if path in ('/', '/index.html'):
            self.path = '/index.html'
        return super().do_GET()

    def do_HEAD(self):
        path = urlparse(self.path).path
        if path == '/healthz':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if not self._require_site_password():
            return
        if path == '/api/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if path in ('/', '/index.html', '/index.html'):
            self._ensure_session()
        if self._allowed_static_path(path):
            if path in ('/', '/index.html'):
                self.path = '/index.html'
            return super().do_HEAD()
        self.send_error(404, 'Not Found')

    def do_POST(self):
        action = {'/api/config': 'config', '/api/disconnect': 'disconnect',
                  '/api/chat': 'chat', '/api/extract': 'extract', '/api/math': 'math'}.get(self.path)
        if not action:
            return self._json(404, {'error': 'Маршрут не найден.'})
        if not self._require_site_password(): return
        self._ensure_session()
        chat_slot_acquired = False
        try:
            if not self._verify_request(): return
            if not self._check_anti_spam(action): return
            chat_slot_acquired = (action == 'chat')
            if action == 'config': return self._configure()
            if action == 'disconnect': return self._disconnect()
            if action == 'chat': return self._chat()
            if action == 'extract': return self._extract()
            if action == 'math': return self._math()
        except (ValueError, json.JSONDecodeError) as e:
            return self._json(400, {'error': str(e)})
        except BrokenPipeError:
            return
        except Exception:
            return self._json(500, {'error': 'Внутренняя ошибка шлюза. Проверь соединение и повтори попытку.'})
        finally:
            if chat_slot_acquired:
                with LOCK:
                    ACTIVE_CHATS.discard(self.session_id)
                    active_ip = getattr(self, 'client_identity', None)
                    if active_ip:
                        remaining = ACTIVE_CHAT_IPS.get(active_ip, 0) - 1
                        if remaining > 0:
                            ACTIVE_CHAT_IPS[active_ip] = remaining
                        else:
                            ACTIVE_CHAT_IPS.pop(active_ip, None)

    def _disconnect(self):
        with LOCK:
            entry = self._session_entry()
            entry['config'].update(provider=None, model=None, api_key=None, endpoint=None)
        return self._json(200, {'ok': True, 'disconnected': True, 'keyStored': False,
                               'message': 'Провайдер отключён; ключ удалён из памяти этой сессии.'})

    def _configure(self):
        data = self._read_json(max_bytes=64 * 1024); provider = str(data.get('provider', '')).lower()
        if provider not in (*PROVIDERS.keys(), 'custom'):
            return self._json(400, {'error': 'Неизвестный провайдер.'})
        if PUBLIC_MODE and provider == 'custom':
            return self._json(400, {'error': 'В публичной версии пользовательские endpoint отключены для защиты от SSRF. Выбери встроенного провайдера.'})
        if PUBLIC_MODE and provider == 'ollama':
            return self._json(400, {'error': 'Ollama доступна только в локальной версии: облачный сервер не может подключиться к Ollama на твоём компьютере.'})
        model = str(data.get('model', '')).strip()
        if not model or len(model) > 180 or any(ord(ch) < 32 or ord(ch) == 127 for ch in model):
            return self._json(400, {'error': 'Укажи корректный идентификатор модели без управляющих символов.'})
        key = str(data.get('api_key', '')).strip()
        endpoint = PROVIDERS.get(provider)
        if provider == 'custom':
            endpoint = str(data.get('endpoint', '')).strip()
            parsed = urlparse(endpoint)
            if parsed.scheme != 'https' or not parsed.netloc or not parsed.hostname:
                return self._json(400, {'error': 'Пользовательский endpoint должен быть корректным HTTPS-адресом.'})
            host = parsed.hostname.lower().rstrip('.')
            if host in ('localhost', 'localhost.localdomain') or host.endswith('.local'):
                return self._json(400, {'error': 'Локальные адреса разрешены только для встроенного провайдера Ollama.'})
            try:
                ip = ipaddress.ip_address(host)
                if not ip.is_global:
                    return self._json(400, {'error': 'Endpoint не должен вести на частный или служебный IP-адрес.'})
            except ValueError:
                pass
            if not endpoint.endswith('/chat/completions'):
                return self._json(400, {'error': 'Для пользовательского endpoint укажи полный путь /v1/chat/completions.'})
            if parsed.username or parsed.password or parsed.fragment:
                return self._json(400, {'error': 'Не помещай логин, пароль или фрагмент в URL endpoint; используй отдельный API-ключ.'})
        if provider != 'ollama' and not key:
            return self._json(400, {'error': 'Для выбранного облачного провайдера нужен API-ключ.'})
        if len(key) > 2048 or '\r' in key or '\n' in key:
            return self._json(400, {'error': 'API-ключ имеет недопустимый формат или слишком длинный.'})
        with LOCK:
            entry = self._session_entry()
            entry['config'].update(provider=provider, model=model, api_key=key or None, endpoint=endpoint)
        return self._json(200, {'ok': True, 'provider': provider, 'model': model, 'keyStored': False,
                               'message': 'Ключ принят шлюзом и хранится только в оперативной памяти этой сессии.'})

    def _read_json(self, max_bytes=MAX_BODY):
        content_type = (self.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
        if content_type != 'application/json':
            raise ValueError('Ожидается JSON-запрос с Content-Type: application/json.')
        raw_length = self.headers.get('Content-Length')
        if raw_length is None: raise ValueError('Не указан размер запроса.')
        try: n = int(raw_length)
        except ValueError: raise ValueError('Некорректный размер запроса.')
        if n < 1 or n > max_bytes:
            limit_mb = max(1, max_bytes // (1024 * 1024))
            raise ValueError(f'Слишком большой или пустой запрос (максимум {limit_mb} МБ).')
        value = json.loads(self.rfile.read(n).decode('utf-8'))
        if not isinstance(value, dict): raise ValueError('Тело запроса должно быть JSON-объектом.')
        return value

    def _chat(self):
        data = self._read_json(max_bytes=MAX_BODY)
        with LOCK:
            cfg = dict(self._session_entry()['config'])
        if not cfg['provider'] or not cfg['model']:
            return self._json(409, {'error': 'Сначала подключи провайдера в разделе «Настройки → ИИ и API».'})
        messages = data.get('messages')
        if not isinstance(messages, list) or not messages or len(messages) > 60:
            return self._json(400, {'error': 'Список сообщений пуст или превышает лимит 60 сообщений.'})
        allowed_roles = {'system', 'user', 'assistant'}
        total_text = 0
        for index, message in enumerate(messages):
            if not isinstance(message, dict) or message.get('role') not in allowed_roles:
                return self._json(400, {'error': f'Некорректное сообщение №{index + 1}.'})
            content = message.get('content')
            if not isinstance(content, (str, list)):
                return self._json(400, {'error': f'Некорректное содержимое сообщения №{index + 1}.'})
            text_parts = []
            if isinstance(content, str):
                text_parts.append(content)
            else:
                for part in content:
                    if not isinstance(part, dict):
                        return self._json(400, {'error': 'Вложение должно быть JSON-объектом.'})
                    kind = part.get('type')
                    if kind == 'text' and isinstance(part.get('text'), str):
                        text_parts.append(part['text'])
                    elif kind == 'image_url' and message['role'] == 'user':
                        image = part.get('image_url')
                        uri = image.get('url') if isinstance(image, dict) else None
                        if not isinstance(uri, str) or len(uri) > 11 * 1024 * 1024 or not re.fullmatch(r'data:image/(png|jpeg|webp|gif);base64,[a-zA-Z0-9+/=]+', uri):
                            return self._json(400, {'error': 'Допустимы изображения PNG/JPEG/WebP/GIF в data URL, до 11 МБ.'})
                    elif kind == 'input_audio' and message['role'] == 'user':
                        if cfg['provider'] != 'openrouter':
                            return self._json(400, {'error': 'Аудиодорожки доступны через OpenRouter с моделью, принимающей звук.'})
                        audio = part.get('input_audio')
                        if not isinstance(audio, dict):
                            return self._json(400, {'error': 'Аудиоданные отсутствуют.'})
                        fmt, encoded = audio.get('format'), audio.get('data')
                        if fmt not in ('mp3','wav','m4a','ogg','webm','flac','aac') or not isinstance(encoded,str) or len(encoded)>7*1024*1024 or not re.fullmatch(r'[a-zA-Z0-9+/=]+',encoded):
                            return self._json(400, {'error': 'Неверный формат или размер аудио (до 5 МБ).'})
                        if sum(1 for p in content if isinstance(p,dict) and p.get('type')=='input_audio')>1:
                            return self._json(400, {'error': 'В одном запросе допускается одна аудиодорожка.'})
                    else:
                        return self._json(400, {'error': 'Неподдерживаемое вложение или роль сообщения.'})
            for part_text in text_parts:
                if len(part_text) > MAX_SINGLE_TEXT:
                    return self._json(413, {'error': f'Одно текстовое сообщение превышает лимит {MAX_SINGLE_TEXT:,} символов.'})
                total_text += len(part_text)
                if total_text > MAX_CHAT_TEXT:
                    return self._json(413, {'error': f'Общий объём текста запроса превышает лимит {MAX_CHAT_TEXT:,} символов.'})
        if len(json.dumps(messages, ensure_ascii=False)) > 15 * 1024 * 1024:
            return self._json(413, {'error': 'Общий размер вложений превышает 15 МБ.'})
        temperature = data.get('temperature', 0.35)
        if not isinstance(temperature, (int, float)) or not (0 <= float(temperature) <= 2):
            return self._json(400, {'error': 'Температура должна быть числом от 0 до 2.'})
        payload = {'model': cfg['model'], 'messages': messages, 'stream': True, 'temperature': float(temperature)}
        if isinstance(data.get('max_tokens'), int):
            payload['max_tokens'] = max(1, min(data['max_tokens'], 32768))
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'text/event-stream, application/json',
            'User-Agent': 'ARCHANGEL-AI/4.15',
        }
        if cfg['api_key']:
            headers['Authorization'] = 'Bearer ' + cfg['api_key']
        if cfg['provider'] == 'openrouter':
            headers['HTTP-Referer'] = (('https' if PUBLIC_MODE else 'http') + '://' + (self.headers.get('X-Forwarded-Host') or self.headers.get('Host', 'localhost'))) 
            headers['X-Title'] = 'ARCHANGEL AI by Czernebog'
        req = urllib.request.Request(
            cfg['endpoint'],
            data=json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8'),
            headers=headers,
            method='POST',
        )
        # Do not follow redirects: the authorization header must never be sent to a new host.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, msg, headers, newurl):
                return None
        try:
            upstream = urllib.request.build_opener(NoRedirect).open(req, timeout=180)
        except urllib.error.HTTPError as e:
            detail = e.read(3000).decode('utf-8', 'replace')
            if cfg['api_key']:
                detail = detail.replace(cfg['api_key'], '[скрытый ключ]')
            # Provider error bodies can echo prompts or credentials. Return a safe, actionable status.
            if e.code in (301, 302, 303, 307, 308):
                return self._json(502, {'error': 'Провайдер перенаправил запрос. Проверь адрес API; переход заблокирован ради безопасности ключа.'})
            return self._json(e.code if 400 <= e.code <= 599 else 502,
                              {'error': f'Провайдер вернул HTTP {e.code}. Проверь API-ключ, модель и лимиты провайдера.'})
        except Exception as e:
            return self._json(502, {'error': 'Не удалось подключиться к провайдеру. Проверь его доступность и настройки API.'})

        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache, no-transform')
        self.send_header('X-Accel-Buffering', 'no')
        self.send_header('Connection', 'close')
        self.close_connection = True
        self.end_headers()
        try:
            content_type = upstream.headers.get('Content-Type', '').lower()
            if 'text/event-stream' not in content_type:
                response_body = upstream.read(MAX_UPSTREAM_RESPONSE + 1)
                if len(response_body) > MAX_UPSTREAM_RESPONSE:
                    self._event({'error': 'Ответ провайдера слишком большой.'})
                    return
                obj = json.loads(response_body.decode('utf-8', 'replace'))
                if not isinstance(obj, dict):
                    self._event({'error': 'Провайдер вернул некорректный формат ответа.'})
                    return
                if obj.get('error'):
                    self._event({'error': 'Провайдер сообщил об ошибке. Проверь модель и ключ.'})
                    return
                choices = obj.get('choices') or []
                content = (((choices[0].get('message') or {}).get('content')) if choices else None)
                if isinstance(content, list):
                    content = ''.join(str(x.get('text', '')) for x in content if isinstance(x, dict))
                if isinstance(content, str) and content:
                    self._event({'delta': content})
                if not content:
                    self._event({'error': 'Провайдер вернул пустой ответ. Проверь поддержку модели и её параметры.'})
                else:
                    self._event({'done': True})
                return

            data_lines = []
            done_sent = False
            bytes_received = 0
            has_output = False
            def process_event(lines):
                nonlocal done_sent, has_output
                if not lines:
                    return
                raw_data = '\n'.join(lines).strip()
                if not raw_data:
                    return
                if raw_data == '[DONE]':
                    self._event({'done': True})
                    done_sent = True
                    return
                try:
                    chunk = json.loads(raw_data)
                except Exception:
                    return
                if isinstance(chunk.get('error'), dict):
                    self._event({'error': 'Провайдер сообщил об ошибке при генерации. Проверь модель, ключ и лимиты.'})
                    done_sent = True
                    return
                choices = chunk.get('choices') or []
                if not choices:
                    return
                choice = choices[0]
                delta = (choice.get('delta') or {}).get('content')
                if isinstance(delta, str) and delta:
                    self._event({'delta': delta})
                    has_output = True
                elif isinstance(delta, list):
                    text_value = ''.join(str(x.get('text', '')) for x in delta if isinstance(x, dict))
                    if text_value:
                        self._event({'delta': text_value})
                        has_output = True
                if choice.get('finish_reason') is not None and not done_sent:
                    self._event({'done': True})
                    done_sent = True

            for raw in upstream:
                bytes_received += len(raw)
                if bytes_received > MAX_UPSTREAM_RESPONSE:
                    self._event({'error': 'Ответ модели превысил безопасный размер.'})
                    done_sent = True
                    break
                line = raw.decode('utf-8', 'replace').rstrip('\r\n')
                if not line:
                    process_event(data_lines)
                    data_lines = []
                    if done_sent:
                        break
                    continue
                if line.startswith(':'):
                    continue
                if line.startswith('data:'):
                    data_lines.append(line[5:].lstrip())
            if data_lines and not done_sent:
                process_event(data_lines)
            if not done_sent:
                if has_output:
                    self._event({'done': True})
                else:
                    self._event({'error': 'Модель не вернула текст. Проверь её поддержку потоковых ответов.'})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                self._event({'error': 'Поток ответа прервался. Попробуй повторить запрос.'})
            except Exception:
                pass
        finally:
            upstream.close()

    def _event(self, obj):
        raw = ('data: ' + json.dumps(obj, ensure_ascii=False) + '\n\n').encode('utf-8')
        self.wfile.write(raw); self.wfile.flush()


    def _math(self):
        data = self._read_json(max_bytes=8192)
        expression = data.get('expression', '')
        operation = data.get('operation', 'simplify')
        variable = data.get('variable', 'x')
        if not isinstance(expression, str) or not isinstance(operation, str) or not isinstance(variable, str):
            return self._json(400, {'error': 'Некорректные параметры математической задачи.'})
        from math_engine import calculate
        try:
            output = calculate(expression, operation, variable)
        except ValueError as exc:
            return self._json(400, {'error': str(exc)})
        return self._json(200, output)

    def _extract(self):
        data = self._read_json(max_bytes=15 * 1024 * 1024); name = str(data.get('name', 'file'))[:180]
        encoded = data.get('data', '')
        if not isinstance(encoded, str) or len(encoded) > 14 * 1024 * 1024:
            return self._json(413, {'error': 'Файл слишком большой для извлечения текста (максимум 10 МБ).'} )
        try: raw = base64.b64decode(encoded.split(',', 1)[-1], validate=True)
        except Exception: return self._json(400, {'error': 'Не удалось прочитать данные файла.'})
        ext = Path(name).suffix.lower(); extracted = ''; warning = None
        if ext == '.docx':
            try:
                with zipfile.ZipFile(BytesIO(raw)) as z:
                    info = z.getinfo('word/document.xml')
                    if info.file_size > 24 * 1024 * 1024:
                        raise ValueError('Внутренний XML DOCX слишком велик (максимум 24 МБ).')
                    xml = z.read('word/document.xml')
                root = ET.fromstring(xml)
                ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
                paras = []
                for p in root.findall('.//w:p', ns):
                    line = ''.join(t.text or '' for t in p.findall('.//w:t', ns))
                    if line.strip(): paras.append(line)
                extracted = '\n'.join(paras)
            except Exception as e: warning = 'Не удалось разобрать DOCX: ' + str(e)[:200]
        elif ext == '.pdf':
            try:
                from pypdf import PdfReader
                reader = PdfReader(BytesIO(raw)); pages = reader.pages[:200]; extracted = '\n\n'.join((p.extract_text() or '') for p in pages)
                if len(reader.pages) > 200: warning = 'Извлечено не более 200 страниц.'
            except ImportError:
                warning = 'Для извлечения PDF установи необязательный модуль: python -m pip install pypdf. DOCX и текстовые файлы работают без него.'
            except Exception as e: warning = 'PDF не удалось разобрать: ' + str(e)[:200]
        else:
            try: extracted = raw.decode('utf-8-sig')
            except UnicodeDecodeError: extracted = raw.decode('cp1251', 'replace')
        extracted = extracted[:220000]
        if not extracted.strip() and not warning: warning = 'В файле не найден извлекаемый текст; возможно, это скан или изображение.'
        return self._json(200, {'ok': bool(extracted.strip()), 'name': name, 'text': extracted, 'warning': warning,
                               'chars': len(extracted)})


def open_browser(url: str):
    # Prefer Opera when installed; otherwise use the Windows default browser.
    if os.name == 'nt':
        try:
            controller = webbrowser.get('opera')
            if controller.open_new(url):
                return True
        except Exception:
            pass
        candidates = [Path(found) for found in [shutil.which('opera'), shutil.which('opera.exe')] if found]
        candidates += [
            Path(os.environ.get('LOCALAPPDATA', '')) / 'Programs' / 'Opera' / 'launcher.exe',
            Path(os.environ.get('LOCALAPPDATA', '')) / 'Programs' / 'Opera' / 'opera.exe',
            Path(os.environ.get('LOCALAPPDATA', '')) / 'Programs' / 'Opera GX' / 'opera.exe',
            Path(os.environ.get('PROGRAMFILES', '')) / 'Opera' / 'launcher.exe',
            Path(os.environ.get('PROGRAMFILES(X86)', '')) / 'Opera' / 'launcher.exe',
            Path(os.environ.get('LOCALAPPDATA', '')) / 'Programs' / 'Opera GX' / 'launcher.exe',
            Path(os.environ.get('PROGRAMFILES', '')) / 'Opera GX' / 'launcher.exe',
            Path(os.environ.get('PROGRAMFILES(X86)', '')) / 'Opera GX' / 'launcher.exe',
        ]
        for executable in candidates:
            try:
                if executable.is_file():
                    subprocess.Popen([str(executable), '--new-window', url], close_fds=True)
                    return True
            except Exception:
                continue
    try:
        return bool(webbrowser.open(url, new=2, autoraise=True))
    except Exception:
        return False


def main():
    global PORT
    ThreadingHTTPServer.allow_reuse_address = True
    ThreadingHTTPServer.daemon_threads = True
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    PORT = int(server.server_address[1])
    url = f'http://{HOST}:{PORT}'
    print('\nARCHANGEL AI 4.15 | CZERNEBOG', flush=True)
    if TUNNEL_MODE:
        print(f'Локальный шлюз доступен только на {url}; публичный вход идёт через HTTPS-туннель.', flush=True)
        print('Сессии изолированы; переписки на сервере не сохраняются.', flush=True)
    elif HOSTED_MODE:
        print(f'Веб-сервер слушает {HOST}:{PORT} (ожидается HTTPS reverse proxy).', flush=True)
        print('Сессии изолированы по браузерной cookie; история на сервере не сохраняется.', flush=True)
    else:
        print(f'Локальный адрес: {url}', flush=True)
        print('Сервер готов. Пытаюсь открыть Opera; если она не запустится, используй адрес выше.', flush=True)
        print('API-ключ хранится только в RAM этого процесса и не записывается в файлы.', flush=True)
        opener = threading.Timer(0.8, lambda: open_browser(url))
        opener.daemon = True
        opener.start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print('\nARCHANGEL завершает работу...', flush=True)
    finally:
        with LOCK:
            for entry in SESSIONS.values():
                entry['config'].update(provider=None, model=None, api_key=None, endpoint=None)
            SESSIONS.clear()
        server.shutdown()
        server.server_close()

if __name__ == '__main__': main()