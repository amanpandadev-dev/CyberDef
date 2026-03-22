"""File Watcher - Monitors data/ for new CSV files and auto-triggers analysis."""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any, Callable, Coroutine
from core.config import get_settings
from core.logging import get_logger

logger = get_logger(__name__)

class FileWatcher:
    def __init__(self, on_new_file, watch_dir=None, poll_interval=5.0, stable_wait=2.0):
        settings = get_settings()
        self.watch_dir = watch_dir or settings.data_dir
        self.on_new_file = on_new_file
        self.poll_interval = poll_interval
        self.stable_wait = stable_wait
        self._known_files = {}
        self._running = False
        self._task = None

    async def start(self):
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self._known_files = self._scan_existing()
        logger.info(f"File watcher started | watch_dir={self.watch_dir}, existing_files={len(self._known_files)}")
        self._running = True
        self._task = asyncio.create_task(self._watch_loop())

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try: await self._task
            except asyncio.CancelledError: pass
        logger.info("File watcher stopped")

    def _scan_existing(self):
        files = {}
        for p in self.watch_dir.glob("**/*.csv"):
            try: files[p] = self._quick_hash(p)
            except: pass
        return files

    def _quick_hash(self, path):
        stat = path.stat()
        h = hashlib.md5()
        h.update(f"{stat.st_size}:{stat.st_mtime}".encode())
        with open(path, "rb") as f: h.update(f.read(4096))
        return h.hexdigest()

    async def _watch_loop(self):
        while self._running:
            try: await self._check_for_new_files()
            except asyncio.CancelledError: break
            except Exception as e: logger.error(f"File watcher error | error={e}")
            await asyncio.sleep(self.poll_interval)

    async def _check_for_new_files(self):
        for csv_path in list(self.watch_dir.glob("**/*.csv")):
            rel = csv_path.relative_to(self.watch_dir)
            if rel.parts and rel.parts[0] in ("raw", "processed"):
                continue
            try: file_hash = self._quick_hash(csv_path)
            except: continue
            if csv_path in self._known_files and self._known_files[csv_path] == file_hash:
                continue
            await asyncio.sleep(self.stable_wait)
            try: new_hash = self._quick_hash(csv_path)
            except: continue
            if new_hash != file_hash:
                continue
            logger.info(f"New CSV detected by file watcher | file={csv_path}, size_bytes={csv_path.stat().st_size}")
            self._known_files[csv_path] = new_hash
            try: await self.on_new_file(csv_path)
            except Exception as e: logger.error(f"Auto-analysis failed | file={csv_path}, error={e}")
