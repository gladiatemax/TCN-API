"""
tcn.lockfile — mutua esclusione fra processi.

I lock del registry sono oggetti in memoria: serializzano gli accessi al
token dentro un processo, e non vedono nulla di quello che fa un altro.
Finche' esisteva solo il servizio HTTP bastava `--workers 1`. Con una CLI
che chiama gli stessi servizi direttamente il problema torna, perche' due
processi distinti possono aprire lo stesso lettore.

Il guasto che ne deriverebbe e' silenzioso: pyscard si connette in
modalita' condivisa, quindi nessuno dei due riceve un errore. Si
ottengono APDU interlacciati sullo stesso token — una decifratura
parziale corrotta, o peggio una punzonatura che il ledger non registra.
Lo stesso vale per il ledger stesso, che due processi potrebbero
intrecciare riga per riga.

La difesa deve quindi stare su disco, non in memoria: un flock esclusivo
su un file nella directory di stato. Il secondo processo lo scopre
all'avvio e si ferma dicendo chi tiene il lock, invece di corrompere in
silenzio.

Il lock e' sull'intero nodo centrale, non sul singolo token: e' grosso,
ma e' la granularita' giusta per un prototipo con un solo operatore alla
volta, e la correttezza vale piu' del parallelismo fra interfacce che
nessuno usa contemporaneamente.
"""

from __future__ import annotations

import fcntl
import json
import os
import socket
import time
from contextlib import contextmanager
from pathlib import Path

from .config import settings


class StateLocked(RuntimeError):
    """Un altro processo detiene il nodo centrale."""

    def __init__(self, holder: dict | None, path: Path):
        self.holder = holder or {}
        self.path = path
        who = self.holder.get('owner', 'un altro processo')
        pid = self.holder.get('pid')
        since = self.holder.get('since')
        detail = f'{who}'
        if pid:
            detail += f' (pid {pid})'
        if since:
            detail += f', dalle {time.strftime("%H:%M:%S", time.localtime(since))}'
        super().__init__(
            f'il nodo centrale e\' gia\' in uso da {detail}.\n'
            'Due processi che aprono lo stesso lettore producono APDU '
            'interlacciati senza alcun errore visibile: terminare '
            'l\'altro processo prima di proseguire.')


def lock_path() -> Path:
    return settings.paths.state_dir / '.tcn.lock'


def _read_holder(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError, ValueError):
        return None


@contextmanager
def hold(owner: str, blocking: bool = False, timeout: float = 0.0):
    """Acquisisce il lock esclusivo per la durata del blocco.

    `owner` e' un'etichetta leggibile ('cli: ppke decrypt', 'api') che
    finisce nel file: serve a dire all'utente chi sta occupando il nodo,
    non solo che e' occupato.

    Con blocking=True attende fino a `timeout` secondi prima di
    arrendersi; per difetto fallisce subito, che e' il comportamento
    giusto per una CLI interattiva.
    """
    path = lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    acquired = False
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError:
                if not blocking or time.monotonic() >= deadline:
                    raise StateLocked(_read_holder(path), path) from None
                time.sleep(0.2)

        os.ftruncate(fd, 0)
        os.write(fd, json.dumps({
            'owner': owner,
            'pid': os.getpid(),
            'host': socket.gethostname(),
            'since': time.time(),
        }).encode('utf-8'))
        os.fsync(fd)

        yield path
    finally:
        if acquired:
            try:
                os.ftruncate(fd, 0)
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)
