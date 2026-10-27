"""
tcn.api.routers.jobs — operazioni asincrone.

Le operazioni che superano `settings.runtime.sync_threshold` rispondono
202 con la posizione del job; il client interroga GET /jobs/{id} finche'
lo stato non diventa terminale.

Il risultato vive solo in memoria: non viene persistito perche' un
plaintext GMPpke in un file di job vanificherebbe tutto il lavoro fatto
per tenere i segreti fuori dallo stato del TCN. Dopo un riavvio
/jobs/{id}/result risponde 409.

Un job `interrupted` significa che il processo e' terminato durante
l'esecuzione, non che l'operazione non sia avvenuta. Per le campagne di
punzonatura la risposta autorevole e' in /v1/punctures/{id}, che si basa
sul ledger e sulle sonde.
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from ..deps import get_jobs
from ..models import JobListResponse, JobModel

router = APIRouter(prefix='/jobs', tags=['jobs'])


def to_model(job) -> JobModel:
    return JobModel(id=job.id, kind=job.kind, status=job.status.value,
                    created_at=job.created_at, started_at=job.started_at,
                    finished_at=job.finished_at, duration=job.duration,
                    error=job.error, meta=job.meta)


@router.get('', response_model=JobListResponse,
            summary='Job recenti')
def list_jobs(limit: int = Query(50, ge=1, le=200),
              kind: str | None = None) -> JobListResponse:
    return JobListResponse(
        jobs=[to_model(j) for j in get_jobs().recent(limit=limit, kind=kind)])


@router.get('/{job_id}', response_model=JobModel,
            summary='Stato di un job')
def get_job(job_id: str) -> JobModel:
    return to_model(get_jobs().get(job_id))


@router.get('/{job_id}/result',
            summary='Risultato di un job concluso con successo')
def get_result(job_id: str):
    """Il corpo dipende dal tipo di job.

    I risultati binari sono codificati in base64; quelli strutturati
    vengono restituiti come oggetto. Un job non ancora concluso, fallito
    o il cui risultato non e' piu' in memoria producono 409.
    """
    value = get_jobs().result(job_id)

    if isinstance(value, (bytes, bytearray)):
        return JSONResponse({'encoding': 'base64',
                             'value': base64.b64encode(value).decode()})
    if hasattr(value, 'model_dump'):
        return JSONResponse({'encoding': 'json',
                             'value': value.model_dump()})
    if hasattr(value, '__dict__') and not isinstance(value, dict):
        return JSONResponse({'encoding': 'json',
                             'value': _serialise(value)})
    return JSONResponse({'encoding': 'json', 'value': value})


def _serialise(obj):
    """Rende serializzabile una dataclass di dominio."""
    from dataclasses import asdict, is_dataclass
    if is_dataclass(obj):
        out = {}
        for key, val in asdict(obj).items():
            if isinstance(val, (bytes, bytearray)):
                out[key] = base64.b64encode(val).decode()
            elif hasattr(val, 'value'):
                out[key] = val.value
            else:
                out[key] = val
        return out
    return str(obj)


@router.delete('', summary='Rimuove i job conclusi piu\' vecchi')
def prune_jobs(max_age: float = Query(86400.0, ge=0)):
    return {'removed': get_jobs().prune(max_age=max_age)}
