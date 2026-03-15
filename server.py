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
from collections import deque
from pathlib import Path

import asyncssh
from aiohttp import web

from file_manager import FileManager, LocalFileManager, SFTPFileManager

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
UPLOAD_MAX_SIZE = int(os.environ.get('UPLOAD_MAX_SIZE', str(100 * 1024 * 1024)))  # 100MB
SFTP_LOCAL_ROOT = os.environ.get('SFTP_LOCAL_ROOT', '') or None
SESSION_PERSIST_TIMEOUT = int(os.environ.get('SESSION_PERSIST_TIMEOUT', '300'))  # 5 min
SESSION_BUFFER_SIZE = int(os.environ.get('SESSION_BUFFER_SIZE', '100'))  # max output chunks
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


# --- Session Registry (for SFTP file API) ---
# session_id -> { 'mode': 'local'|'ssh', 'conn': SSHClientConnection|None, 'fm': FileManager|None }
active_sessions: dict[str, dict] = {}


def _get_fm(request: web.Request) -> tuple[FileManager | None, str]:
    """Get FileManager for a session. Returns (fm, error_msg)."""
    sid = request.query.get('session_id', '') or request.match_info.get('session_id', '')
    if not sid or sid not in active_sessions:
        return None, 'Invalid session'
    sess = active_sessions[sid]
    fm = sess.get('fm')
    if fm is None:
        return None, 'File manager not available'
    return fm, ''


@routes.get('/api/files')
async def files_list(request: web.Request) -> web.Response:
    if not _check_token(request):
        return web.json_response({'error': 'Unauthorized'}, status=401)
    fm, err = _get_fm(request)
    if fm is None:
        return web.json_response({'error': err}, status=400)
    path = request.query.get('path', '')
    if not path:
        path = await fm.get_home()
    try:
        entries = await fm.list_dir(path)
        return web.json_response({'path': path, 'entries': entries})
    except PermissionError as e:
        return web.json_response({'error': str(e)}, status=403)
    except FileNotFoundError:
        return web.json_response({'error': 'Path not found'}, status=404)
    except Exception as e:
        return web.json_response({'error': f'List failed: {e}'}, status=500)


@routes.get('/api/files/download')
async def files_download(request: web.Request) -> web.Response:
    if not _check_token(request):
        return web.json_response({'error': 'Unauthorized'}, status=401)
    fm, err = _get_fm(request)
    if fm is None:
        return web.json_response({'error': err}, status=400)
    path = request.query.get('path', '')
    if not path:
        return web.json_response({'error': 'path required'}, status=400)
    try:
        data = await fm.read_file(path)
        filename = path.rstrip('/').rsplit('/', 1)[-1] or 'download'
        return web.Response(
            body=data,
            content_type='application/octet-stream',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'},
        )
    except PermissionError as e:
        return web.json_response({'error': str(e)}, status=403)
    except FileNotFoundError:
        return web.json_response({'error': 'File not found'}, status=404)
    except Exception as e:
        return web.json_response({'error': f'Download failed: {e}'}, status=500)


@routes.post('/api/files/upload')
async def files_upload(request: web.Request) -> web.Response:
    if not _check_token(request):
        return web.json_response({'error': 'Unauthorized'}, status=401)
    fm, err = _get_fm(request)
    if fm is None:
        return web.json_response({'error': err}, status=400)
    dest_dir = request.query.get('path', '')
    if not dest_dir:
        return web.json_response({'error': 'path required'}, status=400)
    try:
        reader = await request.multipart()
        field = await reader.next()
        if field is None or field.name != 'file':
            return web.json_response({'error': 'No file field'}, status=400)
        filename = field.filename or 'upload'
        # Read with size limit
        chunks = []
        total = 0
        while True:
            chunk = await field.read_chunk(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > UPLOAD_MAX_SIZE:
                return web.json_response({'error': f'File too large (max {UPLOAD_MAX_SIZE // (1024*1024)}MB)'}, status=413)
            chunks.append(chunk)
        data = b''.join(chunks)
        dest_path = dest_dir.rstrip('/') + '/' + filename
        await fm.write_file(dest_path, data)
        return web.json_response({'ok': True, 'name': filename, 'size': len(data)})
    except PermissionError as e:
        return web.json_response({'error': str(e)}, status=403)
    except Exception as e:
        return web.json_response({'error': f'Upload failed: {e}'}, status=500)


@routes.delete('/api/files')
async def files_delete(request: web.Request) -> web.Response:
    if not _check_token(request):
        return web.json_response({'error': 'Unauthorized'}, status=401)
    fm, err = _get_fm(request)
    if fm is None:
        return web.json_response({'error': err}, status=400)
    path = request.query.get('path', '')
    if not path:
        return web.json_response({'error': 'path required'}, status=400)
    try:
        await fm.delete(path)
        return web.json_response({'ok': True})
    except PermissionError as e:
        return web.json_response({'error': str(e)}, status=403)
    except FileNotFoundError:
        return web.json_response({'error': 'Not found'}, status=404)
    except OSError as e:
        return web.json_response({'error': f'Delete failed: {e}'}, status=500)


@routes.post('/api/files/mkdir')
async def files_mkdir(request: web.Request) -> web.Response:
    if not _check_token(request):
        return web.json_response({'error': 'Unauthorized'}, status=401)
    fm, err = _get_fm(request)
    if fm is None:
        return web.json_response({'error': err}, status=400)
    try:
        body = await request.json()
    except Exception:
        return web.json_response({'error': 'Invalid request'}, status=400)
    path = body.get('path', '')
    if not path:
        return web.json_response({'error': 'path required'}, status=400)
    try:
        await fm.mkdir(path)
        return web.json_response({'ok': True})
    except PermissionError as e:
        return web.json_response({'error': str(e)}, status=403)
    except FileExistsError:
        return web.json_response({'error': 'Already exists'}, status=409)
    except Exception as e:
        return web.json_response({'error': f'Mkdir failed: {e}'}, status=500)


@routes.post('/api/files/rename')
async def files_rename(request: web.Request) -> web.Response:
    if not _check_token(request):
        return web.json_response({'error': 'Unauthorized'}, status=401)
    fm, err = _get_fm(request)
    if fm is None:
        return web.json_response({'error': err}, status=400)
    try:
        body = await request.json()
    except Exception:
        return web.json_response({'error': 'Invalid request'}, status=400)
    old_path = body.get('old_path', '')
    new_path = body.get('new_path', '')
    if not old_path or not new_path:
        return web.json_response({'error': 'old_path and new_path required'}, status=400)
    try:
        await fm.rename(old_path, new_path)
        return web.json_response({'ok': True})
    except PermissionError as e:
        return web.json_response({'error': str(e)}, status=403)
    except FileNotFoundError:
        return web.json_response({'error': 'Not found'}, status=404)
    except Exception as e:
        return web.json_response({'error': f'Rename failed: {e}'}, status=500)


# --- PTY Session (Local) ---
active_session_count = 0


class PtySession:
    def __init__(self):
        self.master_fd: int | None = None
        self.pid: int | None = None
        self.running = False
        self.on_output = None  # callback: async (str) -> None
        self.on_exit = None    # callback: async (int) -> None

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

    def is_alive(self) -> bool:
        if self.pid is None:
            return False
        try:
            os.kill(self.pid, 0)
            return True
        except ProcessLookupError:
            return False

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
                    if self.on_output:
                        await self.on_output(data.decode('utf-8', errors='replace'))
                except BlockingIOError:
                    await asyncio.sleep(0.01)
                except OSError:
                    break
        except asyncio.CancelledError:
            pass

        # Wait for child process
        exit_code = -1
        if self.pid is not None:
            try:
                _, status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                status = 0
            exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1

        self.running = False
        if self.on_exit:
            await self.on_exit(exit_code)


# --- SSH Session (Remote) ---
class SSHSession:
    def __init__(self):
        self.conn: asyncssh.SSHClientConnection | None = None
        self.process: asyncssh.SSHClientProcess | None = None
        self.running = False
        self.on_output = None  # callback: async (str) -> None
        self.on_exit = None    # callback: async (int) -> None

    async def connect(self, host: str, port: int, username: str,
                      auth_type: str = 'password', password: str = '',
                      key_path: str = '') -> None:
        connect_kwargs = {
            'host': host,
            'port': port,
            'username': username,
            'known_hosts': None,  # Accept all host keys (user already authenticated to web terminal)
            'keepalive_interval': 30,
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

    def is_alive(self) -> bool:
        return self.running and self.process is not None

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
                    if self.on_output:
                        await self.on_output(data.decode('utf-8', errors='replace'))
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

        self.running = False
        if self.on_exit:
            await self.on_exit(0)


# --- Persistent Session Wrapper ---
persistent_sessions: dict[str, 'PersistentSession'] = {}


class PersistentSession:
    def __init__(self, session_id: str, session: PtySession | SSHSession, mode: str):
        self.session_id = session_id
        self.session = session
        self.mode = mode
        self.ws: web.WebSocketResponse | None = None
        self.output_buffer: deque[str] = deque(maxlen=SESSION_BUFFER_SIZE)
        self.created_at = time.time()
        self.last_active = time.time()
        self.exited = False
        self.exit_code = -1
        self.read_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

        # Wire up callbacks
        session.on_output = self._handle_output
        session.on_exit = self._handle_exit

    async def _handle_output(self, data: str) -> None:
        self.last_active = time.time()
        self.output_buffer.append(data)
        async with self._lock:
            if self.ws is not None:
                try:
                    await self.ws.send_json({'type': 'output', 'data': data})
                except (ConnectionResetError, Exception):
                    self.ws = None

    async def _handle_exit(self, exit_code: int) -> None:
        self.exited = True
        self.exit_code = exit_code
        async with self._lock:
            if self.ws is not None:
                try:
                    await self.ws.send_json({'type': 'exit', 'code': exit_code})
                except Exception:
                    pass

    def attach_ws(self, ws: web.WebSocketResponse) -> None:
        self.ws = ws
        self.last_active = time.time()

    def detach_ws(self) -> None:
        self.ws = None
        self.last_active = time.time()

    def is_alive(self) -> bool:
        return not self.exited and self.session.is_alive()

    def start_read_loop(self) -> None:
        if self.read_task is not None:
            self.read_task.cancel()
        self.read_task = asyncio.create_task(self.session.read_loop())

    def kill(self) -> None:
        self.session.kill()
        if self.read_task is not None:
            self.read_task.cancel()
            self.read_task = None


async def cleanup_stale_sessions() -> None:
    """Periodically remove disconnected sessions that exceeded timeout."""
    global active_session_count
    while True:
        await asyncio.sleep(30)
        now = time.time()
        to_remove = []
        for sid, ps in persistent_sessions.items():
            # No WebSocket attached and timed out, or process already dead
            if ps.ws is None and (now - ps.last_active) > SESSION_PERSIST_TIMEOUT:
                to_remove.append(sid)
            elif ps.exited and ps.ws is None:
                to_remove.append(sid)
        for sid in to_remove:
            ps = persistent_sessions.pop(sid, None)
            if ps:
                ps.kill()
                active_sessions.pop(sid, None)
                active_session_count = max(0, active_session_count - 1)
                log.info(f'Stale session cleaned: {sid[:8]}... (active: {active_session_count})')


# --- WebSocket Handler ---
CLOSE_CODE_EXPLICIT_DISCONNECT = 4100


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

    # Wait for connect message to determine session type
    ps: PersistentSession | None = None
    explicit_disconnect = False
    session_id = secrets.token_urlsafe(16)

    try:
        # First message should be a connect request
        first_msg = await asyncio.wait_for(ws.receive(), timeout=30)
        if first_msg.type != web.WSMsgType.TEXT:
            await ws.close(code=4003, message=b'Expected connect message')
            return ws

        connect_data = json.loads(first_msg.data)
        mode = connect_data.get('type', '')

        # --- Reconnect to existing session ---
        if mode == 'reconnect':
            old_sid = connect_data.get('session_id', '')
            old_ps = persistent_sessions.get(old_sid)
            if old_ps and old_ps.is_alive():
                # Detach old WebSocket if still attached
                if old_ps.ws is not None:
                    try:
                        await old_ps.ws.close()
                    except Exception:
                        pass
                old_ps.attach_ws(ws)
                session_id = old_sid
                ps = old_ps

                # Send buffered output
                buffered = list(old_ps.output_buffer)
                await ws.send_json({
                    'type': 'reconnected',
                    'mode': old_ps.mode,
                    'session_id': session_id,
                    'buffered_count': len(buffered),
                })
                for chunk in buffered:
                    try:
                        await ws.send_json({'type': 'output', 'data': chunk})
                    except Exception:
                        break
                old_ps.output_buffer.clear()

                # Resize if provided
                if connect_data.get('cols') and connect_data.get('rows'):
                    old_ps.session.resize(int(connect_data['cols']), int(connect_data['rows']))

                log.info(f'Session reconnected: {session_id[:8]}...')
            else:
                # Session not found or dead
                await ws.send_json({'type': 'reconnect_failed', 'reason': 'session_not_found'})
                # Client should fall back to new session — close this ws
                await ws.close()
                return ws

        elif mode == 'connect_ssh':
            if active_session_count >= MAX_SESSIONS:
                await ws.close(code=4002, message=b'Max sessions reached')
                return ws

            # SSH session
            ssh_session = SSHSession()
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

            # Start SFTP client for file browsing
            sftp_client = None
            try:
                sftp_client = await ssh_session.conn.start_sftp_client()
            except Exception:
                log.warning('SFTP subsystem not available on remote host')

            fm = SFTPFileManager(sftp_client) if sftp_client else None
            active_sessions[session_id] = {'mode': 'ssh', 'conn': ssh_session.conn, 'fm': fm}

            ps = PersistentSession(session_id, ssh_session, 'ssh')
            ps.attach_ws(ws)
            persistent_sessions[session_id] = ps
            ps.start_read_loop()

            active_session_count += 1
            label = f"{connect_data.get('username')}@{connect_data.get('host')}"
            log.info(f'SSH opened ({label}, active: {active_session_count})')
            await ws.send_json({
                'type': 'connected', 'mode': 'ssh',
                'host': connect_data.get('host', ''),
                'session_id': session_id,
            })

        elif mode == 'connect_local':
            if active_session_count >= MAX_SESSIONS:
                await ws.close(code=4002, message=b'Max sessions reached')
                return ws

            # Local PTY session
            pty_session = PtySession()
            pty_session.spawn()

            fm = LocalFileManager(root=SFTP_LOCAL_ROOT)
            active_sessions[session_id] = {'mode': 'local', 'conn': None, 'fm': fm}

            ps = PersistentSession(session_id, pty_session, 'local')
            ps.attach_ws(ws)
            persistent_sessions[session_id] = ps
            ps.start_read_loop()

            active_session_count += 1
            log.info(f'PTY opened (pid: {pty_session.pid}, active: {active_session_count})')
            await ws.send_json({'type': 'connected', 'mode': 'local', 'session_id': session_id})

        else:
            await ws.close(code=4003, message=b'Invalid connect type')
            return ws

        # Send initial resize if provided (for new sessions)
        if mode != 'reconnect' and connect_data.get('cols') and connect_data.get('rows'):
            ps.session.resize(int(connect_data['cols']), int(connect_data['rows']))

        # Message loop
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    if data.get('type') == 'input' and isinstance(data.get('data'), str):
                        ps.session.write(data['data'])
                    elif data.get('type') == 'resize':
                        cols = int(data.get('cols', 80))
                        rows = int(data.get('rows', 24))
                        ps.session.resize(cols, rows)
                    elif data.get('type') == 'disconnect':
                        explicit_disconnect = True
                        break
                except (json.JSONDecodeError, ValueError):
                    pass
            elif msg.type in (web.WSMsgType.ERROR, web.WSMsgType.CLOSE):
                break

    except asyncio.TimeoutError:
        await ws.close(code=4003, message=b'Connect timeout')
        return ws
    finally:
        if ps is not None:
            if explicit_disconnect:
                # User explicitly disconnected — kill the session
                ps.kill()
                persistent_sessions.pop(session_id, None)
                active_sessions.pop(session_id, None)
                active_session_count -= 1
                log.info(f'Session killed (explicit disconnect, active: {active_session_count})')
            else:
                # Network drop / screen lock — keep session alive
                ps.detach_ws()
                log.info(f'Session detached: {session_id[:8]}... (persisted for {SESSION_PERSIST_TIMEOUT}s)')

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


async def on_startup(app: web.Application) -> None:
    app['cleanup_task'] = asyncio.create_task(cleanup_stale_sessions())


async def on_cleanup(app: web.Application) -> None:
    app['cleanup_task'].cancel()
    # Kill all persistent sessions
    for sid, ps in list(persistent_sessions.items()):
        ps.kill()
    persistent_sessions.clear()


app.on_startup.append(on_startup)
app.on_cleanup.append(on_cleanup)

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
