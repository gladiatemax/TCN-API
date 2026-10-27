"""
tcn.api.models — schemi delle richieste e delle risposte.

Due convenzioni valide ovunque.

**I dati binari viaggiano in base64 standard.** JSON non ha un tipo
binario; base64 e' piu' compatto di hex ed e' gia' il formato con cui
thetacrypt scambia le share, quindi l'API si incastra con gli script
esistenti senza conversioni intermedie. La validazione e' dichiarativa:
un campo malformato produce un 422 prima che venga costruito un APDU.

**La risposta scompone i campi invece di restituire blob opachi.** La
decryption share SG02 arriva dal firmware come 99 byte concatenati; qui
diventa node_id, ui, ei, fi, piu' il blob grezzo per chi lo vuole
passare direttamente altrove. Il layout binario resta un dettaglio del
firmware invece di trapelare nel contratto pubblico.
"""

from __future__ import annotations

import base64
from typing import Annotated

from pydantic import (
    BaseModel, BeforeValidator, Field, PlainSerializer, WithJsonSchema,
)


def _decode_b64(value):
    """Decodifica stretta.

    La decodifica predefinita di pydantic ignora i caratteri fuori
    alfabeto: '!!!' diventerebbe una stringa vuota invece di un errore, e
    il payload malformato arriverebbe fino alla costruzione dell'APDU.
    Qui un input non valido produce 422, che e' il punto di avere una
    validazione dichiarativa.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        raise ValueError('atteso base64 come stringa')
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f'base64 non valido: {exc}') from exc


# Senza WithJsonSchema pydantic descrive `bytes` come format: binary, e
# Swagger genera byte casuali al posto di una stringa: il corpo
# precompilato risulta illeggibile e non supera la validazione.
Base64Bytes = Annotated[
    bytes,
    BeforeValidator(_decode_b64),
    PlainSerializer(lambda b: base64.b64encode(b).decode(),
                    return_type=str),
    WithJsonSchema({'type': 'string', 'format': 'base64',
                    'description': 'Dati binari codificati in base64 '
                                   'standard.'}),
]


# ---------------------------------------------------------------------
# Errori
# ---------------------------------------------------------------------
class ErrorDetail(BaseModel):
    code: str = Field(description='Codice applicativo stabile.')
    message: str
    detail: dict | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail


# ---------------------------------------------------------------------
# Stato del servizio e token
# ---------------------------------------------------------------------
class HealthResponse(BaseModel):
    status: str = Field(description="'ok' oppure 'degraded'.")
    pcsc: bool
    sodium: bool
    thetacli: bool
    pfse_tool: bool
    dealer_key: bool
    tokens: int
    checks: dict[str, str] = Field(
        default_factory=dict,
        description='Dettaglio dei controlli non superati.')


class TokenModel(BaseModel):
    reader: str = Field(description='Nome del lettore PC/SC.')
    node_id: int | None = Field(
        default=None,
        description='Assegnato dal dealer; assente finche\' la share '
                    'SG02 non e\' stata importata.')
    provisioned: bool
    theta_app: bool
    address: str = Field(
        description='Come indirizzare il token: node_id se provisionato, '
                    'altrimenti il nome del lettore.')


class TokenListResponse(BaseModel):
    tokens: list[TokenModel]
    nodes: list[int]


# ---------------------------------------------------------------------
# SG02
# ---------------------------------------------------------------------
class GroupCreateRequest(BaseModel):
    k: int | None = Field(default=None, ge=1, description='Soglia.')
    n: int | None = Field(default=None, ge=1, description='Numero di nodi.')
    reset: bool = Field(
        default=False,
        description='Passa --new a thetacli keygen: cancella il gruppo '
                    'esistente. Distruttivo.')


class GroupResponse(BaseModel):
    key_id: str
    k: int
    n: int
    public_key_path: str


class ShareDistributionRequest(BaseModel):
    reader: str | None = Field(
        default=None,
        description='Indirizzo del token prima dell\'import.')
    node_id: int | None = Field(
        default=None,
        description='Indirizzo del token gia' ' provisionato.')
    keystore_index: int | None = Field(
        default=None, ge=1, examples=[1],
        description='Quale keystore distribuire; obbligatorio quando si '
                    'indirizza per lettore.')


class DistributionModel(BaseModel):
    node_id: int
    reader: str
    ok: bool
    error: str = ''


class DistributionListResponse(BaseModel):
    distributions: list[DistributionModel]


class KeystoreWipeResponse(BaseModel):
    removed: list[int]
    message: str


class Sg02EncryptRequest(BaseModel):
    plaintext: Base64Bytes = Field(
        description='Contenuto da cifrare, in base64.',
        examples=['Y2lhbyBtb25kbw=='])
    label: str = Field(
        description='Etichetta legata al crittogramma; finisce nella '
                    'decryption share e viene verificata in aggregazione.',
        examples=['VERIFY'])
    key_id: str | None = Field(
        default=None, examples=[None],
        description='Lasciare nullo per usare l\'unica chiave pubblica '
                    'presente. Serve solo con piu\' gruppi coesistenti.')


class Sg02CiphertextResponse(BaseModel):
    ciphertext: Base64Bytes
    label: str
    size: int


class DecryptionShareRequest(BaseModel):
    ciphertext: Base64Bytes = Field(
        description='Il crittogramma completo in base64, non il solo '
                    'punto U: la label viene estratta da qui, cosi\' la '
                    'share e\' serializzata con quella giusta. Si ottiene '
                    'da POST /sg02/ciphertexts.',
        examples=['PGluY29sbGFyZSBpbCBjaXBoZXJ0ZXh0IHJlc3RpdHVpdG8gZGEgUE9TVCAvdjEvc2cwMi9jaXBoZXJ0ZXh0cz4='])


class DecryptionShareResponse(BaseModel):
    node_id: int
    ui: Base64Bytes = Field(description='Punto uᵢ, SEC1 compresso, 33 B.')
    ei: Base64Bytes
    fi: Base64Bytes
    raw: Base64Bytes = Field(description='I 99 byte grezzi del firmware.')
    der: str = Field(
        description='Sg02DecryptionShare in DER base64, pronta per '
                    'thetacli assemble.')


class Sg02DecryptRequest(BaseModel):
    ciphertext: Base64Bytes = Field(
        description='Il crittogramma in base64, come restituito da '
                    'POST /sg02/ciphertexts.',
        examples=['PGluY29sbGFyZSBpbCBjaXBoZXJ0ZXh0IHJlc3RpdHVpdG8gZGEgUE9TVCAvdjEvc2cwMi9jaXBoZXJ0ZXh0cz4='])
    nodes: list[int] | None = Field(
        default=None, examples=[None],
        description='Restringe i token interrogati; per difetto tutti '
                    'quelli disponibili.')
    key_id: str | None = Field(default=None, examples=[None])


class PlaintextResponse(BaseModel):
    plaintext: Base64Bytes
    size: int


# ---------------------------------------------------------------------
# GMPpke
# ---------------------------------------------------------------------
class PpkeSetupRequest(BaseModel):
    d: int | None = Field(
        default=None, ge=1,
        description='Numero di tag per crittogramma. Fissato al keygen.')
    nodes: list[int] | None = None


class PpkeSetupResponse(BaseModel):
    d: int
    shares: int
    distributed: list[int]
    failed: dict[str, str]


class PpkeEncryptRequest(BaseModel):
    plaintext: Base64Bytes = Field(
        description='Contenuto da cifrare, in base64.',
        examples=['cmVjb3JkIGRhIGFyY2hpdmlhcmU='])
    tags: list[str] = Field(
        description='Esattamente d tag: ognuno e\' una maniglia di '
                    'cancellazione indipendente per questo crittogramma. '
                    'Punzonarne uno qualsiasi lo rende indecifrabile.',
        examples=[['subject-4417', 'categoria-sanitaria',
                   'retention-2031']])


class PpkeCiphertextResponse(BaseModel):
    ct_pfse: Base64Bytes = Field(description='Parte KEM, formato RELIC.')
    ct_sym: Base64Bytes = Field(
        description='Parte DEM, XChaCha20-Poly1305: nonce(24) || ct || tag.')
    tags: list[str]


class PpkeDecryptRequest(BaseModel):
    ct_pfse: Base64Bytes = Field(
        description='Parte KEM, come restituita da POST /ppke/ciphertexts.',
        examples=['PGN0X3Bmc2UgZGEgUE9TVCAvdjEvcHBrZS9jaXBoZXJ0ZXh0cz4='])
    ct_sym: Base64Bytes = Field(
        description='Parte DEM, come restituita da POST /ppke/ciphertexts.',
        examples=['PGN0X3N5bSBkYSBQT1NUIC92MS9wcGtlL2NpcGhlcnRleHRzPg=='])
    variant: int | None = Field(
        default=None,
        description='INS della variante di decrypt da forzare. Per '
                    'difetto la sceglie il pianificatore in base a d e al '
                    'numero di punzonature registrate.')


class NodeReportModel(BaseModel):
    node_id: int
    punctured: list[str]
    uncertain: list[str]
    capacity: int


class PpkeStateResponse(BaseModel):
    roster: list[int]
    connected: list[int]
    missing: list[int]
    aligned: bool = Field(
        description='Confronta gli insiemi di tag, non i byte delle '
                    'chiavi: Puncture e\' randomizzata e le SK divergono '
                    'nella rappresentazione pur restando equivalenti.')
    max_punctures: int
    nodes: list[NodeReportModel]


# ---------------------------------------------------------------------
# Punzonature
# ---------------------------------------------------------------------
class PunctureRequest(BaseModel):
    tag: str = Field(
        min_length=1,
        description='Il tag da cancellare. Ogni crittogramma legato a '
                    'questo tag diventa indecifrabile su tutti i token.',
        examples=['subject-4417'])
    nodes: list[int] | None = Field(
        default=None,
        description='Per difetto l\'intera anagrafica. Restringerla '
                    'significa dichiarare che i token esclusi non devono '
                    'partecipare alla cancellazione.')


class CampaignResponse(BaseModel):
    id: str
    tag: str
    status: str = Field(
        description="'complete' e' l'unico stato in cui la cancellazione "
                    "e' avvenuta; 'partial' significa che almeno un token "
                    "conserva la capacita' di decifrare.")
    nodes: dict[str, str]
    detail: dict[str, str] = Field(default_factory=dict)
    unresolved: list[int]
    remaining: list[int]
    created_at: float


class CampaignListResponse(BaseModel):
    campaigns: list[CampaignResponse]


# ---------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------
class JobModel(BaseModel):
    id: str
    kind: str
    status: str
    created_at: float
    started_at: float | None = None
    finished_at: float | None = None
    duration: float | None = None
    error: str = ''
    meta: dict = Field(default_factory=dict)


class JobListResponse(BaseModel):
    jobs: list[JobModel]


class JobAcceptedResponse(BaseModel):
    job: JobModel
    poll: str = Field(description='URI da interrogare per lo stato.')
