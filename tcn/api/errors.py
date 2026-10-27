"""
tcn.api.errors — dal vocabolario del dominio a quello di HTTP.

Il sistema ha gia' un vocabolario di errori preciso: gli status word ISO
7816 del firmware e gli exit code dei binari host. Tradurlo bene conta
piu' di quanto sembri, perche' la distinzione 4xx/5xx dice al client se
ha senso ritentare la stessa richiesta.

Le corrispondenze meno ovvie, con la ragione:

  Punctured            -> 410 Gone
      La risorsa esisteva e non e' piu' recuperabile. E' letteralmente
      la semantica della cancellazione crittografica: non un errore del
      client, non un guasto del server.

  TokenBusy            -> 503 + Retry-After
      Il canale PC/SC e' occupato. Ritentare ha senso, ed e' utile dire
      fra quanto.

  ShareNotImported     -> 409 Conflict
      Lo stato del token non consente l'operazione. Ritentare non serve
      finche' quello stato non cambia.

  ApduError 6D00       -> 501 Not Implemented
      Il firmware non conosce quell'istruzione: e' il server a non
      supportare l'operazione, non il client a sbagliare.

  ToolTimeout          -> 504 Gateway Timeout
      Il TCN si comporta da gateway verso i binari host.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse

from ..convert.sg02_der import MalformedCiphertext
from ..hosttools import PublicKeyNotFound, ToolError, ToolTimeout
from ..jobs import JobNotFound, ResultUnavailable
from ..ledger import CampaignNotFound
from ..services.ppke import (
    CapacityExhausted, KeysNotInitialised, ProbeMissing, TokensMissing,
)
from ..services.sg02 import IncompleteDistribution, ThresholdNotReached
from ..tokens.ppke import (
    KeyNotLoaded, MalformedPayload, Punctured, PunctureCapacityExhausted,
)
from ..tokens.registry import DuplicateNodeId, TokenBusy, TokenNotFound
from ..tokens.sg02 import (
    DealerSignatureRejected, DeviceFault,
    MalformedPayload as Sg02MalformedPayload, ShareNotImported,
)
from ..transport import ApduError, TransportError

# Status word -> (codice HTTP, codice applicativo)
SW_MAP: dict[int, tuple[int, str]] = {
    0x6700: (400, 'wrong_length'),
    0x6A80: (400, 'malformed_payload'),
    0x6581: (502, 'device_fault'),
    0x6982: (403, 'security_status_not_satisfied'),
    0x6985: (409, 'conditions_of_use_not_satisfied'),
    0x6A84: (409, 'puncture_capacity_exhausted'),
    0x6D00: (501, 'instruction_not_supported'),
    0x6400: (502, 'execution_error'),
}


def problem(status: int, code: str, message: str,
            detail: dict | None = None,
            headers: dict | None = None) -> JSONResponse:
    """Formato d'errore unico per tutte le risposte 4xx e 5xx.

    Un codice applicativo stabile permette al client di distinguere i
    casi senza fare parsing del messaggio, che e' pensato per una
    persona e puo' cambiare.
    """
    body = {'error': {'code': code, 'message': message}}
    if detail:
        body['error']['detail'] = detail
    return JSONResponse(status_code=status, content=body, headers=headers)


def _apdu(exc: ApduError) -> JSONResponse:
    status, code = SW_MAP.get(exc.sw, (502, 'unexpected_status_word'))
    return problem(status, code, str(exc), {'sw': f'{exc.sw:04X}'})


def register(app) -> None:
    """Installa i gestori sull'applicazione."""

    @app.exception_handler(TokenBusy)
    def _busy(_: Request, exc: TokenBusy):
        return problem(503, 'token_busy', str(exc),
                       headers={'Retry-After': '5'})

    @app.exception_handler(TokenNotFound)
    def _not_found(_: Request, exc: TokenNotFound):
        return problem(404, 'token_not_found', str(exc))

    @app.exception_handler(DuplicateNodeId)
    def _dup(_: Request, exc: DuplicateNodeId):
        return problem(409, 'duplicate_node_id', str(exc))

    @app.exception_handler(TransportError)
    def _transport(_: Request, exc: TransportError):
        return problem(503, 'token_unavailable', str(exc))

    @app.exception_handler(ApduError)
    def _apdu_error(_: Request, exc: ApduError):
        return _apdu(exc)

    @app.exception_handler(Punctured)
    def _punctured(_: Request, __: Punctured):
        return problem(
            410, 'punctured',
            'La chiave e\' punzonata su un tag di questo crittogramma: '
            'il contenuto non e\' piu\' recuperabile.')

    @app.exception_handler(KeyNotLoaded)
    def _no_key(_: Request, __: KeyNotLoaded):
        return problem(
            409, 'key_not_loaded',
            'Nessun materiale di chiave GMPpke sul dispositivo: '
            'eseguire il setup prima di cifrare o decifrare. '
            'Non e\' una cancellazione: il contenuto non e\' stato '
            'distrutto, il token non e\' in grado di decifrarlo.')

    @app.exception_handler(MalformedPayload)
    def _bad_payload(_: Request, exc: MalformedPayload):
        return problem(400, 'malformed_payload', str(exc))

    @app.exception_handler(PunctureCapacityExhausted)
    def _full(_: Request, __: PunctureCapacityExhausted):
        return problem(409, 'puncture_capacity_exhausted',
                       'Il token ha raggiunto MAX_PUNCTURES.')

    @app.exception_handler(DealerSignatureRejected)
    def _dealer(_: Request, __: DealerSignatureRejected):
        return problem(
            403, 'dealer_signature_rejected',
            'Il token ha rifiutato la firma del dealer: la chiave sul '
            'nodo centrale non corrisponde a quella cablata nel firmware.')

    @app.exception_handler(ShareNotImported)
    def _no_share(_: Request, __: ShareNotImported):
        return problem(409, 'share_not_imported',
                       'Nessuna share SG02 importata su questo token.')

    @app.exception_handler(Sg02MalformedPayload)
    def _sg02_bad_payload(_: Request, exc: Sg02MalformedPayload):
        return problem(400, 'malformed_payload', str(exc))

    @app.exception_handler(DeviceFault)
    def _fault(_: Request, exc: DeviceFault):
        return problem(502, 'device_fault', str(exc))

    @app.exception_handler(ThresholdNotReached)
    def _threshold(_: Request, exc: ThresholdNotReached):
        return problem(409, 'threshold_not_reached', str(exc),
                       {'collected': exc.collected,
                        'threshold': exc.threshold,
                        'errors': {str(k): v for k, v in exc.errors.items()}})

    @app.exception_handler(IncompleteDistribution)
    def _incomplete(_: Request, exc: IncompleteDistribution):
        return problem(409, 'incomplete_distribution', str(exc),
                       {'provisioned': exc.provisioned,
                        'expected': exc.expected})

    @app.exception_handler(TokensMissing)
    def _missing(_: Request, exc: TokensMissing):
        return problem(409, 'tokens_missing', str(exc),
                       {'missing': exc.missing})

    @app.exception_handler(CapacityExhausted)
    def _capacity(_: Request, exc: CapacityExhausted):
        return problem(409, 'capacity_exhausted', str(exc),
                       {'nodes': exc.nodes})

    @app.exception_handler(ProbeMissing)
    def _probe(_: Request, exc: ProbeMissing):
        return problem(409, 'probe_missing', str(exc))

    @app.exception_handler(KeysNotInitialised)
    def _keys(_: Request, exc: KeysNotInitialised):
        return problem(409, 'keys_not_initialised', str(exc))

    @app.exception_handler(MalformedCiphertext)
    def _malformed(_: Request, exc: MalformedCiphertext):
        return problem(400, 'malformed_ciphertext', str(exc))

    @app.exception_handler(PublicKeyNotFound)
    def _pubkey(_: Request, exc: PublicKeyNotFound):
        return problem(409, 'public_key_not_found', str(exc))

    @app.exception_handler(ToolTimeout)
    def _timeout(_: Request, exc: ToolTimeout):
        return problem(504, 'host_tool_timeout', str(exc))

    @app.exception_handler(ToolError)
    def _tool(_: Request, exc: ToolError):
        return problem(502, 'host_tool_failed', str(exc),
                       {'tool': exc.tool, 'returncode': exc.returncode})

    @app.exception_handler(CampaignNotFound)
    def _campaign(_: Request, exc: CampaignNotFound):
        return problem(404, 'campaign_not_found', str(exc).strip("'"))

    @app.exception_handler(JobNotFound)
    def _job(_: Request, exc: JobNotFound):
        return problem(404, 'job_not_found', str(exc))

    @app.exception_handler(ResultUnavailable)
    def _result(_: Request, exc: ResultUnavailable):
        return problem(409, 'result_unavailable', str(exc))
