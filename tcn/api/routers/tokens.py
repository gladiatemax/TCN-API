"""
tcn.api.routers.tokens — stato del servizio e scoperta dei token.

Nota sugli endpoint sincroni: sono definiti con `def` e non `async def`.
FastAPI esegue le funzioni sincrone in un thread pool, quindi le
chiamate bloccanti verso PC/SC e verso i binari host non fermano
l'event loop. Con `async def` servirebbe avvolgere ogni chiamata in
run_in_threadpool, ottenendo lo stesso risultato con piu' rumore.
"""

from __future__ import annotations

import os

from fastapi import APIRouter

from ... import transport
from ...config import settings
from ..deps import get_dealer, get_registry
from ..models import (
    HealthResponse, TokenListResponse, TokenModel,
)

router = APIRouter(tags=['tokens'])


def _to_model(t) -> TokenModel:
    return TokenModel(reader=t.reader, node_id=t.node_id,
                      provisioned=t.provisioned, theta_app=t.theta_app,
                      address=t.address)


@router.get('/health', response_model=HealthResponse,
            summary='Stato del servizio e delle sue dipendenze')
def health() -> HealthResponse:
    """Verifica dipendenze, binari e presenza dei token.

    Non fallisce mai con un errore: riporta cosa non va, cosi' e'
    utilizzabile anche come endpoint di diagnosi quando qualcosa e'
    rotto.
    """
    checks: dict[str, str] = {}

    try:
        import nacl.bindings  # noqa: F401
        sodium = True
    except ImportError:
        sodium = False
        checks['sodium'] = 'PyNaCl non installato: nessuna decifratura DEM'

    if not transport.PCSC_AVAILABLE:
        checks['pcsc'] = 'pyscard non installato'

    thetacli = settings.paths.thetacli.exists() and \
        os.access(settings.paths.thetacli, os.X_OK)
    if not thetacli:
        checks['thetacli'] = f'assente o non eseguibile: {settings.paths.thetacli}'

    pfse = settings.paths.pfse_tool.exists() and \
        os.access(settings.paths.pfse_tool, os.X_OK)
    if not pfse:
        checks['pfse_tool'] = f'assente o non eseguibile: {settings.paths.pfse_tool}'

    dealer = get_dealer() is not None
    if not dealer:
        checks['dealer_key'] = (
            'chiave del dealer non caricata: la distribuzione delle '
            'share SG02 non e\' possibile')

    try:
        tokens = len(get_registry().tokens())
    except Exception as exc:
        tokens = 0
        checks['tokens'] = str(exc)

    if tokens == 0 and 'tokens' not in checks:
        checks['tokens'] = 'nessun token collegato'

    return HealthResponse(
        status='ok' if not checks else 'degraded',
        pcsc=transport.PCSC_AVAILABLE, sodium=sodium,
        thetacli=thetacli, pfse_tool=pfse, dealer_key=dealer,
        tokens=tokens, checks=checks)


@router.get('/tokens', response_model=TokenListResponse,
            summary='Token attualmente noti')
def list_tokens() -> TokenListResponse:
    """Restituisce l'ultima vista nota, senza reinterrogare i lettori.

    Per una vista aggiornata usare POST /tokens/scan: la scansione apre
    un canale verso ogni token e non va fatta a ogni richiesta.
    """
    registry = get_registry()
    return TokenListResponse(
        tokens=[_to_model(t) for t in registry.tokens()],
        nodes=registry.nodes())


@router.post('/tokens/scan', response_model=TokenListResponse,
             summary='Rilegge i lettori e ricostruisce la mappa')
def scan_tokens() -> TokenListResponse:
    """Interroga ogni lettore con INS 0x05 per risolvere il node_id.

    Va richiamata dopo aver inserito o rimosso un token, e dopo una
    distribuzione di share, che e' il momento in cui un token acquisisce
    il proprio node_id.
    """
    registry = get_registry()
    tokens = registry.scan()
    return TokenListResponse(tokens=[_to_model(t) for t in tokens],
                             nodes=registry.nodes())


@router.get('/tokens/{node_id}', response_model=TokenModel,
            summary='Dettaglio di un token provisionato')
def get_token(node_id: int) -> TokenModel:
    return _to_model(get_registry().by_node(node_id))
