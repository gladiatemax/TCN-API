"""
tcn.dealer — firma del dealer sulle share SG02.

Isolato in un modulo proprio perche' e' l'unico punto del sistema che
tocca la chiave privata del dealer. Ogni accesso a quel segreto passa da
qui, il che rende il confine ispezionabile invece che disperso.

Cosa fa: firma con Ed25519 il messaggio `xi || node_id` (34 byte), che il
firmware verifica in import_key_share contro la costante
DEALER_ED25519_PK cablata nel binario. Un token rifiuta l'import con
SW 6982 se la firma non torna.

Nota per il threat model: nel prototipo dealer e nodo centrale
coincidono, quindi questa firma non protegge da un TCN compromesso.
Protegge dall'attaccante che abbia accesso fisico ai token ma non alla
chiave del dealer, e vincola l'associazione fra una share e il node_id a
cui e' destinata.
"""

import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_private_key,
)

from .config import settings


class DealerKeyError(RuntimeError):
    """La chiave del dealer non e' caricabile o non e' Ed25519."""


class Dealer:
    """Detiene la chiave privata del dealer per la durata del processo.

    La chiave resta in memoria: non viene mai serializzata, registrata
    nei log, ne' esposta da alcun endpoint.
    """

    def __init__(self, key_path: Path | None = None):
        self._path = Path(key_path or settings.paths.dealer_key)
        try:
            with open(self._path, 'rb') as f:
                key = load_pem_private_key(f.read(), password=None)
        except OSError as exc:
            raise DealerKeyError(
                f'chiave del dealer non leggibile: {exc}') from exc
        except Exception as exc:
            raise DealerKeyError(
                f'chiave del dealer non decodificabile: {exc}') from exc

        if not isinstance(key, Ed25519PrivateKey):
            raise DealerKeyError(
                'la chiave del dealer non e\' Ed25519')
        self._key = key

    def sign_share(self, xi: bytes, node_id: int) -> bytes:
        """Firma `xi || node_id` (34 byte) e restituisce 64 byte grezzi.

        L'ordine e la codifica devono coincidere esattamente con quelli
        ricostruiti dal firmware: xi big-endian seguito da node_id su due
        byte big-endian.
        """
        if len(xi) != 32:
            raise ValueError(f'xi: attesi 32 byte, ricevuti {len(xi)}')
        if not 0 <= node_id <= 0xFFFF:
            raise ValueError(f'node_id fuori range: {node_id}')
        return self._key.sign(xi + struct.pack('>H', node_id))

    def public_key_bytes(self) -> bytes:
        """32 byte grezzi della chiave pubblica.

        Servono a confrontare all'avvio la chiave caricata con la
        costante DEALER_ED25519_PK del firmware: se divergono, ogni
        import fallirebbe con SW 6982 e conviene accorgersene subito
        invece che alla prima distribuzione.
        """
        return self._key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)

    def matches_firmware(self, expected_pk: bytes) -> bool:
        return self.public_key_bytes() == bytes(expected_pk)
