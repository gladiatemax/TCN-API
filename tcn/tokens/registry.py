"""
tcn.tokens.registry — scoperta dei token e serializzazione degli accessi.

Risolve tre problemi che nascono dall'avere piu' Nitrokey collegate alla
stessa macchina.

**Identita'.** L'ordine in cui pcscd enumera i lettori non e' stabile fra
riavvii ne' fra reinserimenti: il nome del lettore non e' un
identificatore del nodo. L'identita' va chiesta al token, con INS 0x05.
Il node_id esiste pero' solo dopo l'import della share SG02: prima di
allora il token non ha ancora un ruolo nel gruppo e va indirizzato per
lettore. Gli endpoint di setup usano quindi il lettore, quelli operativi
il node_id.

**Concorrenza.** HTTP e' concorrente per costruzione, il canale PC/SC no.
Serve un lock per lettore, non uno globale: due token indipendenti devono
poter lavorare in parallelo. L'attesa e' limitata da un timeout, cosi'
una richiesta bloccata diventa un 503 invece di restare appesa.

**Ordine di acquisizione.** Un solo lock di token per volta, mai due
insieme. La raccolta delle k share SG02 parallelizza perche' ogni task
prende e rilascia il proprio; la campagna di punzonatura resta invece
sequenziale, che e' quel che si vuole su un'operazione irreversibile.
"""

import threading
from contextlib import contextmanager
from dataclasses import dataclass

from ..config import settings
from ..transport import (
    AID_SG02, ApduError, CardChannel, TransportError, list_readers,
)
from . import sg02 as sg02_token


class TokenBusy(RuntimeError):
    """Il canale verso il token e' occupato oltre il timeout."""


class TokenNotFound(RuntimeError):
    """Nessun token corrisponde all'indirizzo richiesto."""


class DuplicateNodeId(RuntimeError):
    """Due token dichiarano lo stesso node_id: errore di setup."""


@dataclass(frozen=True)
class TokenInfo:
    reader: str
    node_id: int | None       # None finche' la share SG02 non e' importata
    provisioned: bool         # share SG02 presente
    theta_app: bool           # theta-app risponde sul token

    @property
    def address(self) -> str:
        return f'node{self.node_id}' if self.node_id is not None \
            else self.reader


class Registry:
    """Vista corrente dei token collegati.

    Non e' un cache autoaggiornante: `scan()` va richiamata quando la
    topologia puo' essere cambiata (avvio, inserimento di un token, dopo
    un import che assegna un node_id).
    """

    def __init__(self, match: str | None = None,
                 lock_timeout: float | None = None):
        self._match = match or settings.runtime.reader_match
        self._timeout = lock_timeout or settings.runtime.token_lock_timeout
        self._meta = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        self._tokens: dict[str, TokenInfo] = {}

    # -- scoperta -----------------------------------------------------

    def scan(self) -> list[TokenInfo]:
        """Interroga ogni lettore e ricostruisce la mappa.

        Un lettore che non risponde viene omesso invece di far fallire
        l'intera scansione: un token staccato non deve rendere
        inutilizzabili gli altri.
        """
        found: dict[str, TokenInfo] = {}

        for reader in list_readers(self._match):
            name = str(reader)
            try:
                with self._locked(name):
                    ch = CardChannel(reader)
                    try:
                        ch.connect()
                        info = self._interrogate(name, ch)
                    finally:
                        ch.disconnect()
            except (TransportError, TokenBusy):
                continue
            found[name] = info

        seen: dict[int, str] = {}
        for info in found.values():
            if info.node_id is None:
                continue
            if info.node_id in seen:
                raise DuplicateNodeId(
                    f'node_id {info.node_id} dichiarato sia da '
                    f'{seen[info.node_id]} sia da {info.reader}')
            seen[info.node_id] = info.reader

        with self._meta:
            self._tokens = found
        return self.tokens()

    @staticmethod
    def _interrogate(name: str, ch: CardChannel) -> TokenInfo:
        try:
            sg02_token.select(ch)
        except (ApduError, TransportError):
            # theta-app assente o non selezionabile: il token esiste ma
            # non partecipa allo schema a soglia.
            return TokenInfo(reader=name, node_id=None,
                             provisioned=False, theta_app=False)
        try:
            node_id = sg02_token.read_node_id(ch)
            return TokenInfo(reader=name, node_id=node_id,
                             provisioned=True, theta_app=True)
        except sg02_token.ShareNotImported:
            return TokenInfo(reader=name, node_id=None,
                             provisioned=False, theta_app=True)
        except ApduError:
            # INS 0x05 non riconosciuto: firmware precedente
            # all'aggiunta di GetNodeId.
            return TokenInfo(reader=name, node_id=None,
                             provisioned=False, theta_app=True)

    # -- interrogazione della mappa -----------------------------------

    def tokens(self) -> list[TokenInfo]:
        with self._meta:
            values = list(self._tokens.values())
        return sorted(values, key=lambda t: (t.node_id is None,
                                             t.node_id or 0, t.reader))

    def nodes(self) -> list[int]:
        """node_id dei soli token gia' provisionati."""
        return sorted(t.node_id for t in self.tokens()
                      if t.node_id is not None)

    def by_node(self, node_id: int) -> TokenInfo:
        for t in self.tokens():
            if t.node_id == node_id:
                return t
        raise TokenNotFound(f'nessun token con node_id {node_id}')

    def by_reader(self, reader: str) -> TokenInfo:
        with self._meta:
            info = self._tokens.get(reader)
        if info is None:
            raise TokenNotFound(f'lettore non presente: {reader}')
        return info

    def missing(self, expected: list[int]) -> list[int]:
        """node_id attesi ma non collegati.

        La punzonatura richiede tutti gli N token: se ne manca uno la
        campagna va rifiutata in blocco, non iniziata a meta'.
        """
        present = set(self.nodes())
        return sorted(n for n in expected if n not in present)

    # -- accesso serializzato -----------------------------------------

    @contextmanager
    def session(self, *, node_id: int | None = None,
                reader: str | None = None,
                aid: bytes = AID_SG02):
        """Apre un canale verso un token, in mutua esclusione.

        Acquisisce il lock del lettore, connette, seleziona l'AID
        richiesto e restituisce il canale. Tutto viene rilasciato
        all'uscita, anche in caso di eccezione.

        Non annidare due session: violerebbe la regola di un solo lock
        di token per volta.
        """
        if (node_id is None) == (reader is None):
            raise ValueError('indicare esattamente uno fra node_id e reader')

        info = self.by_node(node_id) if node_id is not None \
            else self.by_reader(reader)

        target = next((r for r in list_readers(self._match)
                       if str(r) == info.reader), None)
        if target is None:
            raise TokenNotFound(
                f'lettore scomparso dopo l\'ultima scansione: {info.reader}')

        with self._locked(info.reader):
            ch = CardChannel(target)
            try:
                ch.connect()
                ch.select(aid)
                yield ch
            finally:
                ch.disconnect()

    # -- interno ------------------------------------------------------

    def _lock_for(self, reader: str) -> threading.Lock:
        with self._meta:
            lock = self._locks.get(reader)
            if lock is None:
                lock = threading.Lock()
                self._locks[reader] = lock
            return lock

    @contextmanager
    def _locked(self, reader: str):
        lock = self._lock_for(reader)
        if not lock.acquire(timeout=self._timeout):
            raise TokenBusy(
                f'{reader} occupato oltre {self._timeout}s')
        try:
            yield
        finally:
            lock.release()
