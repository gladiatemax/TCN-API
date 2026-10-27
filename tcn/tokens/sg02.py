"""
tcn.tokens.sg02 — operazioni SG02-TDH2 su un singolo token.

Comandi di theta-app (AID A0 00 00 08 47 00 01):

  INS 0x01  ImportKeyShare   xi(32) | node_id(2 BE) | sig(64)
  INS 0x02  PartialDecrypt   U(32)  ->  99 byte grezzi
  INS 0x05  GetNodeId        nessun payload -> node_id (2 BE)

I payload stanno entrambi sotto i 255 byte, quindi il trasporto usa
sempre la forma corta dell'APDU.

Import e decifratura parziale sono deliberatamente separati: nel notebook
di benchmark l'import viene ripetuto a ogni iterazione per ripartire da
uno stato noto, ma in esercizio e' un'operazione di setup una-tantum e
ripeterla farebbe transitare xi sul bus a ogni decifratura.
"""

import struct

from ..transport import CardChannel, ApduError, AID_SG02, SW_OK

INS_IMPORT_KEY_SHARE = 0x01
INS_PARTIAL_DECRYPT = 0x02
INS_GET_NODE_ID = 0x05

# Status word, allineati a map_backend_error in theta-app.
# Prima della classificazione degli errori ogni fallimento di import
# arrivava come 6982: una scrittura su flash andata male veniva
# segnalata come firma del dealer rifiutata, cioe' un allarme di
# sicurezza al posto di un guasto.
SW_BAD_SIGNATURE = 0x6982      # firma del dealer non valida
SW_NO_SHARE      = 0x6985      # nessuna share importata
SW_MALFORMED     = 0x6A80      # payload non interpretabile
SW_FAULT         = 0x6581      # guasto: flash, aritmetica, RNG

SHARE_SIZE = 99                # node_id(2) | ui_sec1(33) | ei(32) | fi(32)


class DealerSignatureRejected(Exception):
    """Il token ha rifiutato la firma del dealer su (xi || node_id)."""


class ShareNotImported(Exception):
    """Il token non ha ancora una share SG02 caricata."""


class MalformedPayload(Exception):
    """Il dispositivo non ha saputo interpretare il payload.

    Per partial_decrypt significa che U non e' un punto valido della
    curva; per import_key_share, che xi o la firma non hanno la forma
    attesa. In entrambi i casi e' un input del chiamante, non un guasto.
    """


class DeviceFault(Exception):
    """Guasto sul dispositivo: scrittura su flash, RNG, aritmetica.

    Tenuta distinta da DealerSignatureRejected: confonderle significa
    leggere un problema di storage come un tentativo di importare una
    share non autorizzata.
    """


def select(ch: CardChannel) -> None:
    ch.select(AID_SG02)


def import_key_share(ch: CardChannel, xi: bytes, node_id: int,
                     signature: bytes) -> None:
    """INS 0x01. Setup del nodo, una-tantum.

    xi va passato in big-endian come lo produce thetacrypt: e' il
    firmware a invertirlo per curve25519-dalek.
    """
    if len(xi) != 32:
        raise ValueError(f'xi: attesi 32 byte, ricevuti {len(xi)}')
    if len(signature) != 64:
        raise ValueError(
            f'firma: attesi 64 byte, ricevuti {len(signature)}')

    payload = xi + struct.pack('>H', node_id) + signature
    _, sw = ch.transmit(INS_IMPORT_KEY_SHARE, payload)
    if sw == SW_BAD_SIGNATURE:
        raise DealerSignatureRejected()
    if sw == SW_MALFORMED:
        raise MalformedPayload(
            'il dispositivo ha rifiutato xi o la firma come non '
            'interpretabili')
    if sw == SW_FAULT:
        raise DeviceFault('scrittura su flash fallita durante l\'import')
    if sw != SW_OK:
        raise ApduError(sw, 'ImportKeyShare')


def partial_decrypt(ch: CardChannel, u_raw: bytes) -> bytes:
    """INS 0x02. Restituisce i 99 byte grezzi della share.

    u_raw e' il punto U compresso di curve25519-dalek (32 byte), come lo
    produce extract_u_sg02. La label non viene inviata al token: e' nota
    all'host e serve solo a comporre il DER.
    """
    if len(u_raw) != 32:
        raise ValueError(f'U: attesi 32 byte, ricevuti {len(u_raw)}')

    resp, sw = ch.transmit(INS_PARTIAL_DECRYPT, u_raw)
    if sw == SW_NO_SHARE:
        raise ShareNotImported()
    if sw == SW_MALFORMED:
        raise MalformedPayload(
            'U non e\' un punto valido della curva di Edwards')
    if sw == SW_FAULT:
        raise DeviceFault('guasto durante la decifratura parziale')
    if sw != SW_OK:
        raise ApduError(sw, 'PartialDecrypt')
    if len(resp) != SHARE_SIZE:
        raise ApduError(sw, f'attesi {SHARE_SIZE} B, ricevuti {len(resp)}')
    return resp


# ---------------------------------------------------------------------
# Lettura del node_id
# ---------------------------------------------------------------------
def read_node_id(ch: CardChannel) -> int:
    """INS 0x05. Restituisce il node_id assegnato dal dealer.

    Il file theta/node_id esiste solo dopo un import andato a buon fine:
    su un token vergine il comando risponde SW 6985. Prima dell'import il
    token non ha ancora un'identita' nel gruppo, quindi il registry lo
    indirizza per nome del lettore.
    """
    resp, sw = ch.transmit(INS_GET_NODE_ID)
    if sw == SW_NO_SHARE:
        raise ShareNotImported()
    if sw == SW_FAULT:
        raise DeviceFault('guasto durante la lettura del node_id')
    if sw != SW_OK:
        raise ApduError(sw, 'GetNodeId')
    if len(resp) != 2:
        raise ApduError(sw, f'attesi 2 B, ricevuti {len(resp)}')
    return struct.unpack('>H', resp)[0]
