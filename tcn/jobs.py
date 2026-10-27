"""
tcn.jobs — operazioni asincrone.

Alcune operazioni superano il tempo che ha senso tenere aperta una
connessione HTTP: il keygen GMPpke, il keygen di gruppo per n grande, la
decifratura con molte punzonature, e ogni campagna di punzonatura, che
attraversa N token in sequenza. Per queste l'API risponde 202 con la
posizione del job e il client fa polling.

La soglia e' `settings.runtime.sync_threshold` e va decisa coi tempi
misurati, non a occhio: e' uno dei punti in cui i risultati del
benchmark entrano direttamente nel comportamento del servizio.

Due regole di questo modulo meritano attenzione.

**Il risultato non viene mai persistito.** Il record su disco contiene
stato, tempi, tipo ed errore; il risultato resta in memoria. Un plaintext
GMPpke scritto in un file di job vanificherebbe tutto il lavoro fatto per
tenere i segreti fuori dallo stato persistente del TCN. Dopo un riavvio i
risultati non sono piu' recuperabili, e va bene cosi': gli artefatti
duraturi hanno i propri endpoint.

**Il job non e' la verita' su cosa e' successo.** Un processo che muore a
meta' campagna lascia il job in RUNNING; al riavvio diventa INTERRUPTED,
che significa "non so come sia finita", non "non e' successo nulla". Per
la punzonatura la sorgente autorevole resta il ledger, con le sue sonde:
il job dice solo se l'esecuzione e' arrivata in fondo.
"""

from __future__ import annotations

import json
import os
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from .config import settings


class JobStatus(str, Enum):
    PENDING = 'pending'
    RUNNING = 'running'
    SUCCEEDED = 'succeeded'
    FAILED = 'failed'
    INTERRUPTED = 'interrupted'   # processo terminato durante l'esecuzione


@dataclass
class Job:
    id: str
    kind: str
    status: JobStatus = JobStatus.PENDING
    created_at: float = 0.0
    started_at: float | None = None
    finished_at: float | None = None
    error: str = ''
    meta: dict = field(default_factory=dict)

    @property
    def terminal(self) -> bool:
        return self.status in (JobStatus.SUCCEEDED, JobStatus.FAILED,
                               JobStatus.INTERRUPTED)

    @property
    def duration(self) -> float | None:
        if self.started_at is None:
            return None
        return (self.finished_at or time.time()) - self.started_at

    def to_dict(self) -> dict:
        d = asdict(self)
        d['status'] = self.status.value
        return d


class JobNotFound(KeyError):
    pass


class ResultUnavailable(RuntimeError):
    """Il job e' concluso ma il risultato non e' piu' in memoria.

    Succede dopo un riavvio: i risultati non vengono persistiti per non
    scrivere materiale sensibile sullo stato del TCN.
    """


class JobManager:
    """Coda di esecuzione con persistenza dei soli metadati.

    `workers` limita il parallelismo generale. I job dichiarati
    `exclusive` vengono inoltre serializzati fra loro: e' il caso delle
    campagne di punzonatura, che non devono mai interlacciarsi, perche'
    due campagne concorrenti sugli stessi token renderebbero il ledger
    difficile da interpretare e le punzonature ambigue.
    """

    def __init__(self, workers: int = 4, store_dir: Path | None = None):
        self._dir = Path(store_dir or (settings.paths.state_dir / 'jobs'))
        self._dir.mkdir(parents=True, exist_ok=True)
        self._pool = ThreadPoolExecutor(max_workers=workers,
                                        thread_name_prefix='tcn-job')
        self._meta = threading.Lock()
        self._exclusive = threading.Lock()
        self._jobs: dict[str, Job] = {}
        self._results: dict[str, Any] = {}
        self._recover()

    # -- API ----------------------------------------------------------

    def submit(self, kind: str, fn: Callable[..., Any], *args,
               meta: dict | None = None, exclusive: bool = False,
               **kwargs) -> Job:
        job = Job(id=f'job_{uuid.uuid4().hex[:16]}', kind=kind,
                  created_at=time.time(), meta=dict(meta or {}))
        with self._meta:
            self._jobs[job.id] = job
        self._persist(job)
        self._pool.submit(self._run, job.id, fn, args, kwargs, exclusive)
        return job

    def get(self, job_id: str) -> Job:
        with self._meta:
            job = self._jobs.get(job_id)
        if job is None:
            raise JobNotFound(job_id)
        return job

    def result(self, job_id: str) -> Any:
        job = self.get(job_id)
        if not job.terminal:
            raise ResultUnavailable(f'{job_id} non e\' ancora concluso')
        if job.status is not JobStatus.SUCCEEDED:
            raise ResultUnavailable(f'{job_id} concluso con stato '
                                    f'{job.status.value}')
        with self._meta:
            if job_id not in self._results:
                raise ResultUnavailable(
                    f'risultato di {job_id} non piu\' disponibile: i '
                    'risultati non sopravvivono al riavvio del servizio')
            return self._results[job_id]

    def recent(self, limit: int = 50,
               kind: str | None = None) -> list[Job]:
        with self._meta:
            jobs = list(self._jobs.values())
        if kind is not None:
            jobs = [j for j in jobs if j.kind == kind]
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]

    def prune(self, max_age: float = 86400.0) -> list[str]:
        """Rimuove i job conclusi piu' vecchi di max_age."""
        cutoff = time.time() - max_age
        removed = []
        with self._meta:
            for jid, job in list(self._jobs.items()):
                if job.terminal and (job.finished_at or job.created_at) < cutoff:
                    del self._jobs[jid]
                    self._results.pop(jid, None)
                    removed.append(jid)
        for jid in removed:
            (self._dir / f'{jid}.json').unlink(missing_ok=True)
        return removed

    def shutdown(self, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait)

    # -- esecuzione ---------------------------------------------------

    def _run(self, job_id: str, fn, args, kwargs, exclusive: bool) -> None:
        if exclusive:
            self._exclusive.acquire()
        try:
            job = self._jobs[job_id]
            job.status = JobStatus.RUNNING
            job.started_at = time.time()
            self._persist(job)

            try:
                value = fn(*args, **kwargs)
            except Exception as exc:
                job.status = JobStatus.FAILED
                job.error = f'{type(exc).__name__}: {exc}'
                job.meta['traceback'] = traceback.format_exc(limit=6)
            else:
                with self._meta:
                    self._results[job_id] = value
                job.status = JobStatus.SUCCEEDED

            job.finished_at = time.time()
            self._persist(job)
        finally:
            if exclusive:
                self._exclusive.release()

    # -- persistenza --------------------------------------------------

    def _persist(self, job: Job) -> None:
        """Scrive i soli metadati. Il risultato non tocca mai il disco."""
        path = self._dir / f'{job.id}.json'
        tmp = path.with_suffix('.json.tmp')
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(job.to_dict(), f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(path)

    def _recover(self) -> None:
        """Ricarica i job dal disco.

        Ogni job trovato in RUNNING appartiene a un processo che non c'e'
        piu': diventa INTERRUPTED. Non significa che l'operazione non sia
        avvenuta, ma che il suo esito non e' noto da qui. Per le campagne
        di punzonatura la risposta sta nel ledger, non in questo file.
        """
        for path in self._dir.glob('job_*.json'):
            try:
                with open(path, encoding='utf-8') as f:
                    raw = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue

            try:
                job = Job(id=raw['id'], kind=raw['kind'],
                          status=JobStatus(raw['status']),
                          created_at=raw.get('created_at', 0.0),
                          started_at=raw.get('started_at'),
                          finished_at=raw.get('finished_at'),
                          error=raw.get('error', ''),
                          meta=raw.get('meta', {}))
            except (KeyError, ValueError):
                continue

            if job.status in (JobStatus.RUNNING, JobStatus.PENDING):
                job.status = JobStatus.INTERRUPTED
                job.finished_at = job.finished_at or time.time()
                job.error = ('interrotto dal riavvio del servizio: esito '
                             'non deducibile da qui')
                self._persist(job)

            self._jobs[job.id] = job
