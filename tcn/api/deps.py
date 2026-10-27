"""
tcn.api.deps — istanze condivise.

Registry, ledger, dealer, servizi e gestore dei job sono singleton per
processo, e devono esserlo: i lock del registry e quelli dei job sono
oggetti in memoria, quindi due istanze significherebbero due insiemi di
lock che non si vedono, e la serializzazione degli accessi al token
sarebbe solo apparente.

Da qui discende un vincolo di esercizio che va scritto nell'unit
systemd: il servizio gira con `--workers 1`. Con piu' processi worker
ogni worker avrebbe i propri lock e due di essi aprirebbero lo stesso
lettore. Non e' risolvibile nel codice: servirebbe un lock fuori dal
processo.

Il modulo esiste separato da main.py perche' i router hanno bisogno di
queste istanze e importarle da main creerebbe un ciclo.
"""

from __future__ import annotations

from functools import lru_cache

from ..dealer import Dealer, DealerKeyError
from ..jobs import JobManager
from ..ledger import Ledger
from ..services.ppke import PpkeService
from ..services.sg02 import Sg02Service
from ..tokens.registry import Registry


@lru_cache(maxsize=1)
def get_registry() -> Registry:
    return Registry()


@lru_cache(maxsize=1)
def get_ledger() -> Ledger:
    return Ledger()


@lru_cache(maxsize=1)
def get_jobs() -> JobManager:
    return JobManager(workers=4)


@lru_cache(maxsize=1)
def get_dealer() -> Dealer | None:
    """None se la chiave non e' configurata.

    L'assenza non impedisce al servizio di partire: solo la
    distribuzione delle share SG02 la richiede, e il resto dell'API
    resta utilizzabile. /v1/health lo segnala.
    """
    try:
        return Dealer()
    except DealerKeyError:
        return None


@lru_cache(maxsize=1)
def get_sg02_service() -> Sg02Service:
    return Sg02Service(get_registry(), get_dealer())


@lru_cache(maxsize=1)
def get_ppke_service() -> PpkeService:
    return PpkeService(get_registry(), get_ledger())
