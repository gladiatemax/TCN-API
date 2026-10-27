"""
tcn.transport — trasporto ISO 7816 verso Nitrokey 3 via PC/SC.

Estratto da forwardsec_e2e_nitrokey3.ipynb e theta_app_benchmark.ipynb.
Non conosce gli schemi crittografici né HTTP: costruisce APDU, li invia,
restituisce (payload, SW). La decisione su cosa fare di un SW diverso da
9000 spetta al chiamante (es. 6982 = punzonata, non e' un errore di
trasporto).

Regole di costruzione dell'APDU, identiche al notebook:
  - payload vuoto        -> [CLA INS P1 P2 00]
  - payload <= 255 B     -> APDU corto, Lc 1 byte, Le 1 byte
  - payload  > 255 B     -> APDU esteso, Lc 3 byte (00 hi lo), Le 2 byte
  - response chaining 61XX gestito con GET RESPONSE (00 C0 00 00 XX)
"""

# pyscard e' necessario solo per aprire un canale reale. Importarlo in
# modo tollerante mantiene il modulo utilizzabile dove il lettore non
# serve: il planner, i formati, il mock del token.
try:
    from smartcard.System import readers as _pcsc_readers
    from smartcard.Exceptions import (
        CardConnectionException, NoCardException,
    )
    PCSC_AVAILABLE = True
except ImportError:                       # pragma: no cover
    _pcsc_readers = None
    PCSC_AVAILABLE = False

    class CardConnectionException(Exception):
        pass

    class NoCardException(Exception):
        pass

SW_OK = 0x9000

# AID delle due applicazioni firmware
AID_SG02 = bytes.fromhex('A0000008470001')   # theta-app
AID_PPKE = bytes.fromhex('A0000008470003')   # forwardsec-app


class TransportError(RuntimeError):
    """Il canale verso il token non e' utilizzabile (lettore assente,
    carta rimossa, pcscd non attivo)."""


class ApduError(RuntimeError):
    """L'APDU e' stato trasmesso ma il token ha risposto con un SW di
    errore. Il chiamante puo' ispezionare .sw per distinguere i casi."""

    def __init__(self, sw: int, context: str = ''):
        self.sw = sw
        suffix = f' ({context})' if context else ''
        super().__init__(f'SW={sw:04X}{suffix}')


def list_readers(match: str = 'Nitrokey') -> list:
    """Elenca i lettori PC/SC il cui nome contiene `match`.

    L'ordine restituito da pcscd non e' stabile fra riavvii: la mappatura
    lettore -> node_id va sempre stabilita interrogando il token, mai
    assumendo la posizione nella lista.
    """
    if not PCSC_AVAILABLE:
        raise TransportError(
            'pyscard non installato: nessun accesso PC/SC disponibile')
    try:
        return [r for r in _pcsc_readers() if match in str(r)]
    except Exception as exc:               # pcscd non raggiungibile
        raise TransportError(f'enumerazione lettori fallita: {exc}') from exc


class CardChannel:
    """Canale verso un singolo token. Non e' thread-safe: la
    serializzazione degli accessi e' responsabilita' del registry.
    """

    def __init__(self, reader):
        self._reader = reader
        self._conn = None

    # -- ciclo di vita ------------------------------------------------

    @property
    def reader_name(self) -> str:
        return str(self._reader)

    def connect(self) -> 'CardChannel':
        try:
            self._conn = self._reader.createConnection()
            self._conn.connect()
        except (CardConnectionException, NoCardException) as exc:
            self._conn = None
            raise TransportError(
                f'connessione a {self._reader} fallita: {exc}') from exc
        return self

    def disconnect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc_info):
        self.disconnect()

    # -- APDU ---------------------------------------------------------

    def select(self, aid: bytes) -> None:
        """SELECT by AID. Va rieseguita all'inizio di ogni sessione
        logica: il firmware puo' deselezionare l'applicazione fra
        un'operazione e l'altra."""
        self._require_conn()
        apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid)
        try:
            _, sw1, sw2 = self._conn.transmit(apdu)
        except CardConnectionException as exc:
            raise TransportError(f'SELECT fallita sul canale: {exc}') from exc
        sw = (sw1 << 8) | sw2
        if sw != SW_OK:
            raise ApduError(sw, 'SELECT')

    def transmit(self, ins: int, data: bytes = b'',
                 cla: int = 0x00, p1: int = 0x00, p2: int = 0x00):
        """Invia un APDU e restituisce (payload, sw).

        Non solleva su SW != 9000: solleva solo se il trasporto stesso
        fallisce. Cosi' i chiamanti possono trattare 6982 e 6A84 come
        esiti legittimi del protocollo.
        """
        self._require_conn()
        data = bytes(data)

        if len(data) == 0:
            apdu = [cla, ins, p1, p2, 0x00]
        elif len(data) <= 255:
            apdu = [cla, ins, p1, p2, len(data)] + list(data) + [0x00]
        else:
            apdu = ([cla, ins, p1, p2, 0x00, len(data) >> 8, len(data) & 0xFF]
                    + list(data) + [0x00, 0x00])

        try:
            resp, sw1, sw2 = self._conn.transmit(apdu)
            resp = bytes(resp)
            while sw1 == 0x61:                      # GET RESPONSE
                more, sw1, sw2 = self._conn.transmit(
                    [0x00, 0xC0, 0x00, 0x00, sw2])
                resp += bytes(more)
        except CardConnectionException as exc:
            raise TransportError(
                f'trasmissione INS 0x{ins:02X} fallita: {exc}') from exc

        return resp, (sw1 << 8) | sw2

    # -- interno ------------------------------------------------------

    def _require_conn(self):
        if self._conn is None:
            raise TransportError('canale non connesso')
