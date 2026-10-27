"""
tcn.api.routers.ppke — schema punzonabile GMPpke su BN254.

Modello di fiducia opposto a SG02: la stessa chiave e' replicata su
tutti i token, non divisa fra loro. Non c'e' soglia, e per decifrare
basta un token qualsiasi; per cancellare servono invece tutti, ed e' il
router `punctures` a occuparsene.

Sui tempi: il setup e la decifratura superano la soglia sincrona, quindi
possono diventare job. Il parametro `mode` rende la scelta esplicita
invece di lasciarla dipendere da una stima: 'auto' segue il
pianificatore, 'sync' attende comunque, 'async' restituisce sempre 202.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Query, Response

from ... import planner
from ...tokens.ppke import DecryptVariant
from .. import JOBS_PATH
from ..deps import get_jobs, get_ppke_service, get_registry
from ..models import (
    JobAcceptedResponse, NodeReportModel, PlaintextResponse,
    PpkeCiphertextResponse, PpkeDecryptRequest, PpkeEncryptRequest,
    PpkeSetupRequest, PpkeStateResponse,
)
from .jobs import to_model

router = APIRouter(prefix='/ppke', tags=['ppke'])


def accepted(job, response: Response) -> JobAcceptedResponse:
    """202 con la posizione del job da interrogare."""
    response.status_code = 202
    response.headers['Location'] = f'{JOBS_PATH}/{job.id}'
    return JobAcceptedResponse(job=to_model(job),
                               poll=f'{JOBS_PATH}/{job.id}')


# ---------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------
@router.post('/keys', response_model=JobAcceptedResponse, status_code=202,
             summary='Genera la coppia e la distribuisce a tutti i token')
def setup_keys(response: Response,
               req: PpkeSetupRequest = Body(default_factory=PpkeSetupRequest)):
    """Sempre asincrono: il keygen piu' la distribuzione su N token
    superano ampiamente la soglia sincrona.

    Il job e' esclusivo, cosi' non puo' interlacciarsi con una campagna
    di punzonatura: l'import usa P1=Replace e azzera ogni punzonatura
    precedente, quindi le due cose insieme lascerebbero il ledger a
    descrivere uno stato che il token non ha piu'.

    La chiave privata non tocca lo stato persistente del TCN: vive su
    tmpfs il tempo della conversione, in memoria quello della
    distribuzione, e viene azzerata.
    """
    service = get_ppke_service()
    job = get_jobs().submit(
        'ppke-setup', service.setup_keys, d=req.d, nodes=req.nodes,
        meta={'d': req.d, 'nodes': req.nodes}, exclusive=True)
    return accepted(job, response)


@router.get('/keys/public', summary='Chiave pubblica GMPpke')
def public_key():
    """Formato cereal/RELIC, come prodotto da pfse_tool_bn254."""
    import base64
    pk = get_ppke_service().public_key()
    return {'public_key': base64.b64encode(pk).decode(), 'size': len(pk)}


# ---------------------------------------------------------------------
# Uso
# ---------------------------------------------------------------------
@router.post('/ciphertexts', response_model=PpkeCiphertextResponse,
             summary='Cifra legando il contenuto a d tag')
def encrypt(req: PpkeEncryptRequest):
    """Richiede esattamente d tag.

    Ogni tag e' una maniglia di cancellazione indipendente: punzonarne
    uno qualsiasi rende questo crittogramma indecifrabile. Con d=3 si
    puo' legare lo stesso record a soggetto, categoria di dati e classe
    di retention, e cancellarlo per una qualunque delle tre vie.

    Usa solo la chiave pubblica: nessun segreto e' coinvolto.
    """
    ct_pfse, ct_sym = get_ppke_service().encrypt(req.plaintext, req.tags)
    return PpkeCiphertextResponse(ct_pfse=ct_pfse, ct_sym=ct_sym,
                                  tags=req.tags)


@router.post('/decryptions/{node_id}',
             summary='Decifra su un token')
def decrypt(node_id: int, req: PpkeDecryptRequest, response: Response,
            mode: str = Query('auto', pattern='^(auto|sync|async)$')):
    """Il KEM avviene sul dispositivo, la parte simmetrica sull'host:
    il crittogramma dei dati non transita mai sul bus.

    Senza `variant` la scelta spetta al pianificatore, che usa d e il
    numero di punzonature registrate per quel token. Una stima imprecisa
    cambia il tempo, non il risultato.

    Risponde 410 se la chiave e' punzonata su un tag di questo
    crittogramma: la risorsa esisteva e non e' piu' recuperabile.
    """
    service = get_ppke_service()
    variant = DecryptVariant(req.variant) if req.variant is not None else None

    n = len(service._ledger.node_state(node_id).punctured)
    long_running = planner.is_long_running(n)

    if mode == 'async' or (mode == 'auto' and long_running):
        job = get_jobs().submit(
            'ppke-decrypt', service.decrypt, node_id, req.ct_pfse,
            req.ct_sym, variant,
            meta={'node_id': node_id, 'punctures': n,
                  'variant': int(variant) if variant else None})
        return accepted(job, response)

    plaintext = service.decrypt(node_id, req.ct_pfse, req.ct_sym, variant)
    return PlaintextResponse(plaintext=plaintext, size=len(plaintext))


# ---------------------------------------------------------------------
# Stato
# ---------------------------------------------------------------------
@router.get('/state', response_model=PpkeStateResponse,
            summary='Tag punzonati, capacita\' residua, allineamento')
def state() -> PpkeStateResponse:
    """La vista che conta per la conformita': dice se la cancellazione
    e' effettivamente avvenuta su tutti i token.

    `aligned` confronta gli insiemi di tag, non i byte delle chiavi.
    Puncture e' randomizzata e ogni token usa il proprio RNG, quindi le
    SK divergono nella rappresentazione pur restando equivalenti: non
    esiste modo di verificare l'allineamento per hash.

    I dati vengono dal ledger, non dai token, che non dichiarano il
    proprio stato interno. Le voci in `uncertain` sono trasmissioni
    rimaste senza esito, da accertare con la sonda.
    """
    from ...config import settings

    service = get_ppke_service()
    registry = get_registry()
    roster = service.roster()

    return PpkeStateResponse(
        roster=roster,
        connected=registry.nodes(),
        missing=registry.missing(roster),
        aligned=service.aligned(roster),
        max_punctures=settings.schemes.max_punctures,
        nodes=[NodeReportModel(node_id=r.node_id, punctured=r.punctured,
                               uncertain=r.uncertain, capacity=r.capacity)
               for r in service.report(roster)])
