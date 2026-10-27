"""
tcn.api.routers.punctures — cancellazione crittografica.

La punzonatura e' l'operazione piu' delicata dell'intero sistema:
irreversibile, non idempotente nel firmware, e obbligatoria su *tutti* i
token. Un token non punzonato conserva la capacita' di decifrare il tag
che si voleva cancellare, quindi una campagna a meta' non e' una
cancellazione riuscita in parte: non e' una cancellazione.

Da qui tre scelte di interfaccia.

**Sempre 202.** Attraversare N token in sequenza richiede decine di
secondi, e il job e' esclusivo perche' due campagne concorrenti
renderebbero il ledger ambiguo: due intent pendenti sullo stesso nodo non
sarebbero attribuibili.

**Lo stato e' per token, non aggregato.** `complete` e' l'unico valore in
cui la cancellazione e' avvenuta. `partial` va reso visibile e
allarmante, perche' e' lo stato in cui il sistema crede di aver
cancellato e non l'ha fatto.

**`resume` prima risolve, poi riprende.** Le incertezze si accertano con
il crittogramma sonda, non chiedendo al token. Saltare quel passo
significherebbe rischiare di ripunzonare un token gia' punzonato,
consumando capacita' per nulla.
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Response

from .. import JOBS_PATH
from ...ledger import CampaignNotFound
from ..deps import get_jobs, get_ledger, get_ppke_service
from ..models import (
    CampaignListResponse, CampaignResponse, JobAcceptedResponse,
    PunctureRequest,
)
from .jobs import to_model

router = APIRouter(prefix='/punctures', tags=['punctures'])


def to_campaign(c) -> CampaignResponse:
    return CampaignResponse(
        id=c.id, tag=c.tag, status=c.status.value,
        nodes={str(k): v.value for k, v in sorted(c.nodes.items())},
        detail={str(k): v for k, v in c.detail.items() if v},
        unresolved=c.unresolved, remaining=c.remaining,
        created_at=c.created_at)


def _accepted(job, response: Response) -> JobAcceptedResponse:
    response.status_code = 202
    response.headers['Location'] = f'{JOBS_PATH}/{job.id}'
    return JobAcceptedResponse(job=to_model(job),
                               poll=f'{JOBS_PATH}/{job.id}')


@router.post('', response_model=JobAcceptedResponse, status_code=202,
             summary='Cancella crittograficamente un tag su tutti i token')
def create_puncture(req: PunctureRequest, response: Response):
    """Apre una campagna ed esegue la punzonatura token per token.

    Rifiuta in blocco con 409 se manca un token dell'anagrafica o se la
    capacita' non basta: su un'operazione irreversibile e' meglio non
    iniziare che fermarsi a meta'.

    L'anagrafica non deriva dai token collegati. Se derivasse, staccarne
    uno lo farebbe sparire dai controlli e la campagna si dichiarerebbe
    completa mentre quel token conserva la capacita' di decifrare.

    L'esecuzione e' sequenziale, non parallela: su un'operazione
    irreversibile il determinismo vale piu' del tempo risparmiato.
    """
    service = get_ppke_service()
    job = get_jobs().submit(
        'puncture', service.puncture, req.tag, req.nodes,
        meta={'tag': req.tag, 'nodes': req.nodes}, exclusive=True)
    return _accepted(job, response)


@router.get('', response_model=CampaignListResponse,
            summary='Storico delle campagne')
def list_campaigns(limit: int = Query(50, ge=1, le=500),
                   status: str | None = Query(
                       None, description="Filtra per stato, es. 'partial'.")):
    campaigns = get_ledger().campaigns()
    if status is not None:
        campaigns = [c for c in campaigns if c.status.value == status]
    return CampaignListResponse(
        campaigns=[to_campaign(c) for c in campaigns[:limit]])


@router.get('/{campaign_id}', response_model=CampaignResponse,
            summary='Stato di una campagna, token per token')
def get_campaign(campaign_id: str) -> CampaignResponse:
    """`unresolved` elenca i token la cui trasmissione e' rimasta senza
    esito: il loro stato non e' deducibile e va accertato con POST
    /{id}/resolve. `remaining` elenca quelli su cui la punzonatura va
    ancora eseguita.
    """
    c = get_ledger().campaign(campaign_id)
    if c is None:
        raise CampaignNotFound(f'campagna sconosciuta: {campaign_id}')
    return to_campaign(c)


@router.post('/{campaign_id}/resolve', response_model=CampaignResponse,
             summary='Accerta con la sonda lo stato dei token incerti')
def resolve(campaign_id: str) -> CampaignResponse:
    """Tenta di decifrare un crittogramma sonda legato al tag della
    campagna: SW 6982 significa punzonato, 9000 significa intatto.

    Usa solo comandi gia' esistenti, senza che il token debba dichiarare
    nulla del proprio stato interno. Il costo e' una decrypt per token
    incerto.
    """
    service = get_ppke_service()
    service.resolve_unknown(campaign_id)
    return to_campaign(get_ledger().campaign(campaign_id))


@router.post('/{campaign_id}/resume', response_model=JobAcceptedResponse,
             status_code=202,
             summary='Riprende una campagna incompleta')
def resume(campaign_id: str, response: Response):
    """Risolve le incertezze con la sonda, poi punzona i token rimasti.

    Non esiste un rollback: la punzonatura e' irreversibile per
    costruzione, quindi l'unica strategia dopo un fallimento parziale e'
    andare avanti sui token mancanti.
    """
    service = get_ppke_service()
    job = get_jobs().submit(
        'puncture-resume', service.resume, campaign_id,
        meta={'campaign_id': campaign_id}, exclusive=True)
    return _accepted(job, response)
