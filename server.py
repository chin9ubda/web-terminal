import asyncio
import fcntl
import hashlib
import hmac
import json
import os
import pty
import secrets
import signal
import struct
import termios
import time
from pathlib import Path

from aiohttp import web

# --- Load .env ---
env_file = Path(__file__).parent / '.env'
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            k, v = k.strip(), v.strip()
            if k not in os.environ:
                os.environ[k] = v

# --- Config ---
PASSWORD = os.environ.get('TERMINAL_PASSWORD', '')
PORT = int(os.environ.get('PORT', '3456'))
SHELL = os.environ.get('SHELL_PATH', '/bin/bash')
MAX_SESSIONS = int(os.environ.get('MAX_SESSIONS', '5'))

if not PASSWORD:
    print('ERROR: TERMINAL_PASSWORD is not set.')
    print('Copy .env.example to .env and set a password.')
    raise SystemExit(1)

# --- Auth ---
active_tokens: dict[str, float] = {}  # token -> expires_at
login_attempts: dict[str, dict] = {}  # ip -> {count, reset_time}


def check_rate_limit(ip: str) -> bool:
    now = time.time()
    entry = login_attempts.get(ip)
    if entry is None or now > entry['reset_time']:
        login_attempts[ip] = {'count': 1, 'reset_time': now + 60}
        return True
    if entry['count'] >= 5:
        return False
    entry['count'] += 1
    return True


def verify_password(input_pw: str) -> bool:
    return hmac.compare_digest(input_pw.encode(), PASSWORD.encode())


def cleanup_tokens():
    now = time.time()
    expired = [t for t, exp in active_tokens.items() if now > exp]
    for t in expired:
        del active_tokens[t]


# --- Routes ---
routes = web.RouteTableDef()


@routes.post('/auth')
async def auth_handler(request: web.Request) -> web.Response:
    ip = request.remote or 'unknown'
    if not check_rate_limit(ip):
        return web.json_response({'error': 'Too many attempts. Try again later.'}, status=429)

    try:
        body = await request.json()
    except Exception:
        return web.json_response({'error': 'Invalid request'}, status=400)

    pw = body.get('password', '')
    if not verify_password(pw):
        return web.json_response({'error': 'Invalid password'}, status=401)

    token = secrets.token_urlsafe(32)
    active_tokens[token] = time.time() + 86400  # 24h
    return web.json_response({'token': token})


# --- PTY Session ---
active_pty_count = 0


class PtySession:
    def __init__(self, ws: web.WebSocketResponse):
        self.ws = ws
        self.master_fd: int | None = None
        self.pid: int | None = None
        self.running = False

    def spawn(self) -> None:
        env = os.environ.copy()
        # Remove claude nesting detection vars
        for key in ['CLAUDECODE', 'CLAUDE_CODE_ENTRYPOINT']:
            env.pop(key, None)
        env.update({
            'TERM': 'xterm-256color',
            'LANG': 'ko_KR.UTF-8',
            'LC_ALL': 'ko_KR.UTF-8',
            'COLORTERM': 'truecolor',
        })

        pid, fd = pty.fork()
        if pid == 0:
            # Child process
            os.chdir(os.environ.get('HOME', '/'))
            os.execvpe(SHELL, [SHELL], env)
        else:
            # Parent
            self.pid = pid
            self.master_fd = fd
            self.running = True

            # Set non-blocking
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def resize(self, cols: int, rows: int) -> None:
        if self.master_fd is not None:
            cols = max(1, min(cols, 500))
            rows = max(1, min(rows, 200))
            winsize = struct.pack('HHHH', rows, cols, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)

    def write(self, data: str) -> None:
        if self.master_fd is not None:
            os.write(self.master_fd, data.encode())

    def kill(self) -> None:
        self.running = False
        if self.pid is not None:
            try:
                os.kill(self.pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

    async def read_loop(self) -> None:
        loop = asyncio.get_event_loop()
        read_event = asyncio.Event()

        def on_readable():
            read_event.set()

        if self.master_fd is None:
            return

        loop.add_reader(self.master_fd, on_readable)

        try:
            while self.running:
                read_event.clear()
                try:
                    data = os.read(self.master_fd, 4096)
                    if not data:
                        break
                    await self.ws.send_json({'type': 'output', 'data': data.decode('utf-8', errors='replace')})
                except BlockingIOError:
                    await read_event.wait()
                except OSError:
                    break
        finally:
            if self.master_fd is not None:
                try:
                    loop.remove_reader(self.master_fd)
                except Exception:
                    pass

        # Wait for child process
        if self.pid is not None:
            try:
                _, status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                status = 0

            exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
            try:
                await self.ws.send_json({'type': 'exit', 'code': exit_code})
            except Exception:
                pass


@routes.get('/ws')
async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
    global active_pty_count

    token = request.query.get('token', '')
    cleanup_tokens()

    if not token or token not in active_tokens:
        raise web.HTTPUnauthorized(text='Invalid token')

    if time.time() > active_tokens.get(token, 0):
        del active_tokens[token]
        raise web.HTTPUnauthorized(text='Token expired')

    if active_pty_count >= MAX_SESSIONS:
        raise web.HTTPServiceUnavailable(text='Max sessions reached')

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    session = PtySession(ws)
    session.spawn()
    active_pty_count += 1
    print(f'PTY opened (pid: {session.pid}, active: {active_pty_count})')

    # Start reading PTY output
    read_task = asyncio.create_task(session.read_loop())

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    if data.get('type') == 'input' and isinstance(data.get('data'), str):
                        session.write(data['data'])
                    elif data.get('type') == 'resize':
                        cols = int(data.get('cols', 80))
                        rows = int(data.get('rows', 24))
                        session.resize(cols, rows)
                except (json.JSONDecodeError, ValueError):
                    pass
            elif msg.type in (web.WSMsgType.ERROR, web.WSMsgType.CLOSE):
                break
    finally:
        session.kill()
        read_task.cancel()
        try:
            await read_task
        except asyncio.CancelledError:
            pass
        active_pty_count -= 1
        print(f'PTY closed (pid: {session.pid}, active: {active_pty_count})')

    return ws


# --- App ---

@routes.get('/')
async def index_handler(request: web.Request) -> web.FileResponse:
    return web.FileResponse(Path(__file__).parent / 'public' / 'index.html')


app = web.Application()
app.router.add_routes(routes)
app.router.add_static('/static', Path(__file__).parent / 'public')

if __name__ == '__main__':
    import socket
    print(f'Web Terminal running at http://0.0.0.0:{PORT}')
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addr = info[4][0]
            if not addr.startswith('127.'):
                print(f'  -> http://{addr}:{PORT}')
    except Exception:
        pass
    web.run_app(app, host='0.0.0.0', port=PORT, print=None)
