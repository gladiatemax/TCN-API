"""
tcn.tokens.ppke — operazioni GMPpke su un singolo token.

Livello sottile sopra CardChannel: costruisce i payload, invia l'APDU,
traduce i SW in esiti di dominio. Nessuna logica di orchestrazione, che
appartiene a tcn.services.ppke.

Comandi di forwardsec-app (AID A0 00 00 08 47 00 03):

  INS 0x01  ImportKey   sempre Replace (P1 ignorato dal firmware)
  INS 0x02  Decrypt     baseline, 3*ns ML + 3*ns FE
  INS 0x03  Puncture
  INS 0x04  Decrypt     per-tag algebrico,   (d+1) ML + (d+1) FE
  INS 0x05  Decrypt     per-tag + multipair, (d+1) ML + 1 FE
  INS 0x06  Decrypt     per-share + multipair, (i+2) ML + 1 FE
  INS 0x07  Decrypt     per-share algebrico, (i+2) ML + (i+2) FE
"""

import struct
from enum import IntEnum

from ..transport import CardChannel, ApduError, AID_PPKE, SW_OK
from ..convert.ppke_wire import build_import_payload

INS_IMPORT_KEY = 0x01
INS_PUNCTURE = 0x03

# Status word, allineati a map_backend_error in forwardsec-app.
# Prima della classificazione degli errori ogni fallimento di decrypt
# arrivava come 6982: un dispositivo senza backend o senza chiave era
# indistinguibile da una cancellazione riuscita, e la sonda registrava
# cancellazioni mai avvenute.
SW_PUNCTURED = 0x6982      # SK punzonata sul tag del ciphertext
SW_NO_KEY    = 0x6985      # nessun materiale di chiave sul dispositivo
SW_MALFORMED = 0x6A80      # payload non interpretabile
SW_BAD_PARAM = 0x6700      # tag riservato o troppo lungo
SW_FULL      = 0x6A84      # MAX_PUNCTURES raggiunto sul device
SW_FAULT     = 0x6581      # guasto: flash, aritmetica, RNG

# Il firmware ignora P1: forwardsec-app riceve il parametro come `_p1` e
# il backend rimuove sempre share, skn e s1acc prima di scrivere. Non
# esiste un import incrementale. La costante resta solo per chiarezza
# sul valore trasmesso.
P1_IMPORT = 0x00

# Limite di punzonature del backend. Non dipende da d: e' un vincolo di
# storage su flash. Duplicato qui per poter rifiutare a monte le
# richieste che lo eccederebbero, ma la verita' resta il firmware.
MAX_PUNCTURES = 5

GT_SIZE = 384              # dimensione di M restituito dal device


class DecryptVariant(IntEnum):
    BASELINE = 0x02
    PER_TAG = 0x04
    PER_TAG_MP = 0x05
    PER_SHARE_MP = 0x06
    PER_SHARE = 0x07


class Punctured(Exception):
    """La SK del token e' punzonata su almeno un tag del ciphertext.
    Non e' un errore: e' l'esito atteso dopo una cancellazione."""


class KeyNotLoaded(Exception):
    """Nessun materiale di chiave GMPpke sul dispositivo.

    Va tenuta rigorosamente distinta da Punctured: confonderle
    significa registrare come cancellato un contenuto che e' solo
    irraggiungibile, e la distinzione e' il motivo per cui il firmware
    usa due status word diversi.
    """


class MalformedPayload(Exception):
    """Il dispositivo non ha saputo interpretare il payload."""


class PunctureCapacityExhausted(Exception):
    """Il token ha raggiunto MAX_PUNCTURES."""


def select(ch: CardChannel) -> None:
    ch.select(AID_PPKE)


def import_key(ch: CardChannel, fw_pk: bytes, fw_sk: bytes,
               replace: bool = True) -> None:
    """INS 0x01. Sostituisce integralmente il materiale di chiave.

    Azzera sempre ogni punzonatura precedente: e' l'operazione piu'
    distruttiva del sistema e va autorizzata esplicitamente al livello
    superiore.

    Il parametro `replace` esiste solo per compatibilita' con i
    chiamanti: il firmware ignora P1 e non offre un import incrementale.
    Passarlo a False non ha alcun effetto sul dispositivo, quindi viene
    rifiutato invece di dare l'illusione di funzionare.

    Gli esiti sono distinti: SW 6A80 indica pk o sk non interpretabili,
    SW 6581 una scrittura su flash fallita.
    """
    if not replace:
        raise ValueError(
            'il firmware non supporta un import incrementale: ImportKey '
            'sostituisce sempre l\'intero materiale di chiave')
    payload = build_import_payload(fw_pk, fw_sk)
    _, sw = ch.transmit(INS_IMPORT_KEY, payload, p1=P1_IMPORT)
    if sw == SW_MALFORMED:
        raise MalformedPayload(
            'il dispositivo ha rifiutato pk o sk come non '
            'interpretabili: verificare la conversione RELIC -> arkworks')
    if sw == SW_FAULT:
        raise ApduError(sw, 'ImportKey: scrittura su flash fallita')
    if sw != SW_OK:
        raise ApduError(sw, 'ImportKey')


def decrypt(ch: CardChannel, fw_ct: bytes,
            variant: DecryptVariant = DecryptVariant.PER_SHARE_MP) -> bytes:
    """Restituisce M in rappresentazione arkworks (384 B).

    La conversione in chiave simmetrica e la decifratura del ct_sym
    restano al chiamante: il token non vede mai il ciphertext simmetrico.
    """
    resp, sw = ch.transmit(int(variant), fw_ct)
    if sw == SW_PUNCTURED:
        raise Punctured()
    if sw == SW_NO_KEY:
        raise KeyNotLoaded()
    if sw == SW_MALFORMED:
        raise MalformedPayload('il dispositivo ha rifiutato il '
                               'ciphertext come non interpretabile')
    if sw != SW_OK:
        raise ApduError(sw, f'Decrypt INS 0x{int(variant):02X}')
    if len(resp) != GT_SIZE:
        raise ApduError(sw, f'attesi {GT_SIZE} B, ricevuti {len(resp)}')
    return resp


def puncture(ch: CardChannel, tag: bytes) -> None:
    """INS 0x03. Irreversibile e non idempotente: ripetere lo stesso tag
    consuma una seconda unita' di capacita'."""
    payload = struct.pack('>H', len(tag)) + bytes(tag)
    _, sw = ch.transmit(INS_PUNCTURE, payload)
    if sw == SW_FULL:
        raise PunctureCapacityExhausted()
    if sw == SW_NO_KEY:
        raise KeyNotLoaded()
    if sw == SW_BAD_PARAM:
        raise MalformedPayload(
            'tag rifiutato: riservato (NULLTAG) o oltre MAX_TAG_LEN')
    if sw != SW_OK:
        raise ApduError(sw, 'Puncture')


def probe_tag(ch: CardChannel, fw_ct_probe: bytes,
              variant: DecryptVariant = DecryptVariant.PER_SHARE_MP) -> bool:
    """Test di capacita': True se il token risulta punzonato sul tag del
    ciphertext sonda.

    Serve a risolvere l'ambiguita' lasciata da una trasmissione fallita,
    senza che il token debba dichiarare il proprio stato interno.

    Ogni esito diverso da "decifra" e "punzonato" viene propagato invece
    di essere interpretato: un token senza chiave non e' un token
    punzonato, e scambiarli significherebbe scrivere nel registro una
    cancellazione mai avvenuta. Il chiamante lascia il nodo incerto e
    riproverà, che e' l'unica risposta corretta quando non si sa.
    """
    try:
        decrypt(ch, fw_ct_probe, variant)
        return False
    except Punctured:
        return True
