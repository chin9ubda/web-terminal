import asyncio
import fcntl
import hashlib
import hmac
import json
import logging
import os
import pty
import secrets
import signal
import struct
import termios
import time
from pathlib import Path

import asyncssh
from aiohttp import web

logging.basicConfig(level=logging.INFO, format='%(message)s')
log = logging.getLogger('wt')

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
HOSTS_FILE = Path(__file__).parent / 'hosts.json'

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


# --- Hosts Management ---
def load_hosts() -> list[dict]:
    if HOSTS_FILE.exists():
        try:
            return json.loads(HOSTS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return []
    return []


def save_hosts(hosts: list[dict]) -> None:
    HOSTS_FILE.write_text(json.dumps(hosts, indent=2, ensure_ascii=False))


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


def _check_token(request: web.Request) -> bool:
    auth = request.headers.get('Authorization', '')
    token = auth.replace('Bearer ', '') if auth.startswith('Bearer ') else ''
    return bool(token and token in active_tokens and time.time() <= active_tokens.get(token, 0))


@routes.get('/api/hosts')
async def get_hosts(request: web.Request) -> web.Response:
    if not _check_token(request):
        return web.json_response({'error': 'Unauthorized'}, status=401)
    return web.json_response(load_hosts())


@routes.post('/api/hosts')
async def add_host(request: web.Request) -> web.Response:
    if not _check_token(request):
        return web.json_response({'error': 'Unauthorized'}, status=401)

    try:
        body = await request.json()
    except Exception:
        return web.json_response({'error': 'Invalid request'}, status=400)

    host_entry = {
        'id': secrets.token_urlsafe(8),
        'name': str(body.get('name', '')).strip(),
        'host': str(body.get('host', '')).strip(),
        'port': int(body.get('port', 22)),
        'username': str(body.get('username', '')).strip(),
        'auth_type': str(body.get('auth_type', 'password')),
        'key_path': str(body.get('key_path', '')).strip(),
    }

    if not host_entry['host'] or not host_entry['username']:
        return web.json_response({'error': 'host and username required'}, status=400)

    if not host_entry['name']:
        host_entry['name'] = f"{host_entry['username']}@{host_entry['host']}"

    hosts = load_hosts()
    hosts.append(host_entry)
    save_hosts(hosts)
    return web.json_response(host_entry, status=201)


@routes.delete('/api/hosts/{host_id}')
async def delete_host(request: web.Request) -> web.Response:
    if not _check_token(request):
        return web.json_response({'error': 'Unauthorized'}, status=401)

    host_id = request.match_info['host_id']
    hosts = load_hosts()
    new_hosts = [h for h in hosts if h.get('id') != host_id]
    if len(new_hosts) == len(hosts):
        return web.json_response({'error': 'Not found'}, status=404)
    save_hosts(new_hosts)
    return web.json_response({'ok': True})


# --- PTY Session (Local) ---
active_session_count = 0


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
            os.execvpe(SHELL, [SHELL, '--login'], env)
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
        if self.master_fd is None:
            return

        try:
            while self.running and self.master_fd is not None:
                try:
                    data = os.read(self.master_fd, 4096)
                    if not data:
                        break
                    await self.ws.send_json({'type': 'output', 'data': data.decode('utf-8', errors='replace')})
                except BlockingIOError:
                    await asyncio.sleep(0.01)
                except OSError:
                    break
        except asyncio.CancelledError:
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


# --- SSH Session (Remote) ---
class SSHSession:
    def __init__(self, ws: web.WebSocketResponse):
        self.ws = ws
        self.conn: asyncssh.SSHClientConnection | None = None
        self.process: asyncssh.SSHClientProcess | None = None
        self.running = False

    async def connect(self, host: str, port: int, username: str,
                      auth_type: str = 'password', password: str = '',
                      key_path: str = '') -> None:
        connect_kwargs = {
            'host': host,
            'port': port,
            'username': username,
            'known_hosts': None,  # Accept all host keys (user already authenticated to web terminal)
        }

        if auth_type == 'key' and key_path:
            expanded = os.path.expanduser(key_path)
            if not os.path.isfile(expanded):
                raise FileNotFoundError(f'SSH key not found: {key_path}')
            connect_kwargs['client_keys'] = [expanded]
        elif auth_type == 'agent':
            pass  # Use SSH agent (default asyncssh behavior)
        else:
            connect_kwargs['password'] = password

        self.conn = await asyncssh.connect(**connect_kwargs)
        self.process = await self.conn.create_process(
            term_type='xterm-256color',
            term_size=(80, 24),
            encoding=None,  # Binary mode for raw bytes
        )
        self.running = True

    def resize(self, cols: int, rows: int) -> None:
        if self.process is not None:
            cols = max(1, min(cols, 500))
            rows = max(1, min(rows, 200))
            self.process.change_terminal_size(cols, rows)

    def write(self, data: str) -> None:
        if self.process is not None and self.process.stdin is not None:
            self.process.stdin.write(data.encode())

    def kill(self) -> None:
        self.running = False
        if self.process is not None:
            try:
                self.process.close()
            except Exception:
                pass
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass

    async def read_loop(self) -> None:
        if self.process is None:
            return

        try:
            while self.running:
                try:
                    data = await asyncio.wait_for(
                        self.process.stdout.read(4096),
                        timeout=0.1
                    )
                    if not data:
                        break
                    await self.ws.send_json({
                        'type': 'output',
                        'data': data.decode('utf-8', errors='replace'),
                    })
                except asyncio.TimeoutError:
                    continue
                except asyncssh.BreakReceived:
                    break
                except (asyncssh.ConnectionLost, asyncssh.DisconnectError):
                    break
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

        try:
            await self.ws.send_json({'type': 'exit', 'code': 0})
        except Exception:
            pass


# --- WebSocket Handler ---
@routes.get('/ws')
async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
    global active_session_count

    ws = web.WebSocketResponse()
    await ws.prepare(request)
    token = request.query.get('token', '')
    cleanup_tokens()

    if not token or token not in active_tokens:
        await ws.close(code=4001, message=b'Invalid token')
        return ws

    if time.time() > active_tokens.get(token, 0):
        del active_tokens[token]
        await ws.close(code=4001, message=b'Token expired')
        return ws

    if active_session_count >= MAX_SESSIONS:
        await ws.close(code=4002, message=b'Max sessions reached')
        return ws

    # Wait for connect message to determine session type
    session = None
    read_task = None

    try:
        # First message should be a connect request
        first_msg = await asyncio.wait_for(ws.receive(), timeout=30)
        if first_msg.type != web.WSMsgType.TEXT:
            await ws.close(code=4003, message=b'Expected connect message')
            return ws

        connect_data = json.loads(first_msg.data)
        mode = connect_data.get('type', '')

        if mode == 'connect_ssh':
            # SSH session
            ssh_session = SSHSession(ws)
            try:
                await ssh_session.connect(
                    host=str(connect_data.get('host', '')),
                    port=int(connect_data.get('port', 22)),
                    username=str(connect_data.get('username', '')),
                    auth_type=str(connect_data.get('auth_type', 'password')),
                    password=str(connect_data.get('password', '')),
                    key_path=str(connect_data.get('key_path', '')),
                )
            except Exception as e:
                error_msg = str(e)
                # Clean up sensitive details
                if 'password' in error_msg.lower() or 'auth' in error_msg.lower():
                    error_msg = 'Authentication failed'
                await ws.send_json({'type': 'error', 'data': f'SSH connection failed: {error_msg}'})
                await ws.close(code=4004, message=b'SSH connection failed')
                return ws

            session = ssh_session
            active_session_count += 1
            label = f"{connect_data.get('username')}@{connect_data.get('host')}"
            log.info(f'SSH opened ({label}, active: {active_session_count})')
            await ws.send_json({'type': 'connected', 'mode': 'ssh', 'host': connect_data.get('host', '')})

        elif mode == 'connect_local':
            # Local PTY session
            pty_session = PtySession(ws)
            pty_session.spawn()
            session = pty_session
            active_session_count += 1
            log.info(f'PTY opened (pid: {pty_session.pid}, active: {active_session_count})')
            await ws.send_json({'type': 'connected', 'mode': 'local'})

        else:
            await ws.close(code=4003, message=b'Invalid connect type')
            return ws

        # Start reading output
        read_task = asyncio.create_task(session.read_loop())

        # Send initial resize if provided
        if connect_data.get('cols') and connect_data.get('rows'):
            session.resize(int(connect_data['cols']), int(connect_data['rows']))

        # Message loop
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

    except asyncio.TimeoutError:
        await ws.close(code=4003, message=b'Connect timeout')
        return ws
    finally:
        if session is not None:
            session.kill()
            if read_task is not None:
                read_task.cancel()
                try:
                    await read_task
                except asyncio.CancelledError:
                    pass
            active_session_count -= 1
            log.info(f'Session closed (active: {active_session_count})')

    return ws


# --- App ---

@routes.get('/')
async def index_handler(request: web.Request) -> web.Response:
    html = (Path(__file__).parent / 'public' / 'index.html').read_text()
    return web.Response(text=html, content_type='text/html', headers={
        'Cache-Control': 'no-cache, no-store, must-revalidate',
    })


app = web.Application()
app.router.add_routes(routes)
app.router.add_static('/static', Path(__file__).parent / 'public')

if __name__ == '__main__':
    import socket
    log.info(f'Web Terminal running at http://0.0.0.0:{PORT}')
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addr = info[4][0]
            if not addr.startswith('127.'):
                log.info(f'  -> http://{addr}:{PORT}')
    except Exception:
        pass
    web.run_app(app, host='0.0.0.0', port=PORT, print=None)
