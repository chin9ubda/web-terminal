"""File manager abstraction for local and SFTP file operations."""

import os
import stat
from abc import ABC, abstractmethod
from pathlib import Path

import asyncssh


class FileManager(ABC):
    """Common interface for file system operations."""

    @abstractmethod
    async def list_dir(self, path: str) -> list[dict]:
        ...

    @abstractmethod
    async def read_file(self, path: str) -> bytes:
        ...

    @abstractmethod
    async def write_file(self, path: str, data: bytes) -> None:
        ...

    @abstractmethod
    async def delete(self, path: str) -> None:
        ...

    @abstractmethod
    async def mkdir(self, path: str) -> None:
        ...

    @abstractmethod
    async def rename(self, old_path: str, new_path: str) -> None:
        ...

    @abstractmethod
    async def stat_path(self, path: str) -> dict:
        ...

    @abstractmethod
    async def get_home(self) -> str:
        ...

    @staticmethod
    def _format_size(size: int) -> str:
        for unit in ('B', 'KB', 'MB', 'GB'):
            if size < 1024:
                return f"{size:.1f}{unit}" if unit != 'B' else f"{size}{unit}"
            size /= 1024
        return f"{size:.1f}TB"

    @staticmethod
    def _file_type(mode: int) -> str:
        if stat.S_ISDIR(mode):
            return 'dir'
        if stat.S_ISLNK(mode):
            return 'link'
        return 'file'


class LocalFileManager(FileManager):
    """File operations using os/pathlib for local file system."""

    def __init__(self, root: str | None = None):
        self.root = Path(root).resolve() if root else None

    def _resolve(self, path: str) -> Path:
        resolved = Path(path).expanduser().resolve()
        if self.root and not str(resolved).startswith(str(self.root)):
            raise PermissionError(f'Access denied: {path}')
        return resolved

    async def list_dir(self, path: str) -> list[dict]:
        target = self._resolve(path)
        entries = []
        for item in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            try:
                st = item.lstat()
                entries.append({
                    'name': item.name,
                    'type': self._file_type(st.st_mode),
                    'size': st.st_size,
                    'size_h': self._format_size(st.st_size),
                    'mtime': int(st.st_mtime),
                    'perms': stat.filemode(st.st_mode),
                })
            except OSError:
                continue
        return entries

    async def read_file(self, path: str) -> bytes:
        target = self._resolve(path)
        return target.read_bytes()

    async def write_file(self, path: str, data: bytes) -> None:
        target = self._resolve(path)
        target.write_bytes(data)

    async def delete(self, path: str) -> None:
        target = self._resolve(path)
        if target.is_dir():
            target.rmdir()
        else:
            target.unlink()

    async def mkdir(self, path: str) -> None:
        target = self._resolve(path)
        target.mkdir(parents=False, exist_ok=False)

    async def rename(self, old_path: str, new_path: str) -> None:
        old = self._resolve(old_path)
        new = self._resolve(new_path)
        old.rename(new)

    async def stat_path(self, path: str) -> dict:
        target = self._resolve(path)
        st = target.lstat()
        return {
            'name': target.name,
            'type': self._file_type(st.st_mode),
            'size': st.st_size,
            'size_h': self._format_size(st.st_size),
            'mtime': int(st.st_mtime),
            'perms': stat.filemode(st.st_mode),
        }

    async def get_home(self) -> str:
        return str(Path.home())


class SFTPFileManager(FileManager):
    """File operations using asyncssh SFTP client."""

    def __init__(self, sftp: asyncssh.SFTPClient):
        self.sftp = sftp

    async def list_dir(self, path: str) -> list[dict]:
        entries = []
        for item in await self.sftp.readdir(path):
            name = item.filename
            if name in ('.', '..'):
                continue
            attrs = item.attrs
            mode = attrs.permissions or 0
            entries.append({
                'name': name,
                'type': self._file_type(mode),
                'size': attrs.size or 0,
                'size_h': self._format_size(attrs.size or 0),
                'mtime': int(attrs.mtime or 0),
                'perms': stat.filemode(mode) if mode else '----------',
            })
        entries.sort(key=lambda e: (e['type'] != 'dir', e['name'].lower()))
        return entries

    async def read_file(self, path: str) -> bytes:
        async with self.sftp.open(path, 'rb') as f:
            return await f.read()

    async def write_file(self, path: str, data: bytes) -> None:
        async with self.sftp.open(path, 'wb') as f:
            await f.write(data)

    async def delete(self, path: str) -> None:
        st = await self.sftp.stat(path)
        if stat.S_ISDIR(st.permissions or 0):
            await self.sftp.rmdir(path)
        else:
            await self.sftp.remove(path)

    async def mkdir(self, path: str) -> None:
        await self.sftp.mkdir(path)

    async def rename(self, old_path: str, new_path: str) -> None:
        await self.sftp.rename(old_path, new_path)

    async def stat_path(self, path: str) -> dict:
        attrs = await self.sftp.stat(path)
        mode = attrs.permissions or 0
        name = path.rstrip('/').rsplit('/', 1)[-1] or '/'
        return {
            'name': name,
            'type': self._file_type(mode),
            'size': attrs.size or 0,
            'size_h': self._format_size(attrs.size or 0),
            'mtime': int(attrs.mtime or 0),
            'perms': stat.filemode(mode) if mode else '----------',
        }

    async def get_home(self) -> str:
        return await self.sftp.getcwd() or '/'
