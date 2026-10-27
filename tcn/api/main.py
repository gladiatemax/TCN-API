"""
tcn.api.main — applicazione FastAPI del nodo centrale.

Avvio:

    uvicorn tcn.api.main:app --host 127.0.0.1 --port 8000 --workers 1

Due parametri non sono negoziabili.

`--workers 1`: i lock che serializzano gli accessi PC/SC sono oggetti in
memoria di questo processo. Con piu' worker ognuno avrebbe i propri e due
processi aprirebbero lo stesso lettore.

`--host 127.0.0.1` come difetto: questo servizio espone la capacita' di
decifrare, che e' esattamente cio' che la crittografia a soglia esiste
per proteggere. Pubblicarlo su 0.0.0.0 sposta il confine di fiducia dal
dispositivo fisico al perimetro di rete, e va fatto solo dietro un
reverse proxy che termini TLS e autentichi i client.

La documentazione interattiva e' su /docs: la barra degli indirizzi del
browser sa fare solo GET, quindi POST e PUT si provano da li'.
"""

from __future__ import annotations

from contextlib import ExitStack, asynccontextmanager

from fastapi import FastAPI

from ..config import ensure_dirs, settings
from ..lockfile import StateLocked, hold
from . import API_PREFIX, errors
from .deps import get_jobs, get_registry
from .routers import jobs as jobs_router
from .routers import ppke as ppke_router
from .routers import punctures as punctures_router
from .routers import sg02 as sg02_router
from .routers import tokens as tokens_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_dirs()

    # Lock esclusivo sul nodo centrale, lo stesso che prende la CLI.
    # I lock del registry vivono in memoria e non vedono un secondo
    # processo: senza questo, servizio e CLI potrebbero aprire lo stesso
    # lettore e produrre APDU interlacciati senza alcun errore visibile.
    stack = ExitStack()
    try:
        stack.enter_context(hold('api'))
    except StateLocked as exc:
        stack.close()
        raise RuntimeError(f'avvio impedito: {exc}') from exc

    # Prima scansione: un errore qui non deve impedire l'avvio, altrimenti
    # il servizio non parte proprio quando serve diagnosticare perche' i
    # token non si vedono. /v1/health lo riporta.
    try:
        get_registry().scan()
    except Exception:
        pass

    manager = get_jobs()
    try:
        yield
    finally:
        manager.shutdown(wait=False)
        stack.close()


app = FastAPI(
    title='TCN — Trusted Central Node',
    version='0.1.0',
    lifespan=lifespan,
    description=(
        'Interfaccia HTTP del nodo centrale che orchestra le Nitrokey 3 '
        'collegate.\n\n'
        'Espone due schemi con modelli di fiducia opposti. **SG02** '
        'distribuisce share diverse a n token e ne bastano k per '
        'decifrare. **GMPpke** replica la stessa chiave su tutti i token '
        'e li richiede tutti per punzonare, perche\' un solo token non '
        'punzonato conserva la capacita\' di decifrare il tag che si '
        'voleva cancellare.\n\n'
        'I dati binari viaggiano in base64. Le operazioni lunghe '
        'rispondono 202 con la posizione di un job.'
    ),
)

errors.register(app)

app.include_router(tokens_router.router, prefix=API_PREFIX)
app.include_router(sg02_router.router, prefix=API_PREFIX)
app.include_router(ppke_router.router, prefix=API_PREFIX)
app.include_router(punctures_router.router, prefix=API_PREFIX)
app.include_router(jobs_router.router, prefix=API_PREFIX)


@app.get('/', include_in_schema=False)
def root():
    return {
        'service': 'tcn',
        'version': app.version,
        'docs': '/docs',
        'api': API_PREFIX,
        'schemes': {
            'sg02': f'soglia k={settings.schemes.k} su n={settings.schemes.n}',
            'ppke': f'd={settings.schemes.d} tag per crittogramma, '
                    f'max {settings.schemes.max_punctures} punzonature',
        },
    }
