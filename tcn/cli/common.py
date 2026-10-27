"""
tcn.cli.common — infrastruttura condivisa dei comandi.

Contiene quattro cose: il contesto che istanzia i servizi su richiesta,
la lettura e scrittura dei dati binari, la resa dei risultati in forma
leggibile o JSON, e la traduzione delle eccezioni di dominio in codici
d'uscita.

Due differenze di fondo rispetto all'API meritano di essere esplicite.

**La CLI e' sincrona.** Non esistono job: un comando che impiega trenta
secondi li impiega, e mostra l'avanzamento. Il meccanismo asincrono
dell'API serve a non tenere aperta una connessione HTTP, problema che qui
non si pone.

**La CLI lavora con file.** Un crittogramma e' un file o un flusso, non
una stringa base64 dentro un JSON. La codifica resta un dettaglio
dell'API.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Codici d'uscita. Zero e' successo, 2 resta a argparse per gli errori
# d'uso, il resto distingue le famiglie di guasto cosi' che uno script
# possa reagire senza interpretare i messaggi.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 3      # token assente, lettore occupato, nodo bloccato
EXIT_PUNCTURED = 4        # contenuto cancellato: non e' un errore, e' un esito
EXIT_NOT_READY = 6        # dispositivo senza chiave: distinto da cancellato
EXIT_CONFLICT = 5         # stato del sistema incompatibile con la richiesta


class CliError(RuntimeError):
    """Errore gia' formulato per l'utente."""

    def __init__(self, message: str, code: int = EXIT_ERROR):
        self.code = code
        super().__init__(message)


# ---------------------------------------------------------------------
# Contesto
# ---------------------------------------------------------------------
@dataclass
class Context:
    """Istanzia registry, ledger, dealer e servizi su richiesta.

    La scansione dei lettori apre un canale verso ogni token, quindi va
    fatta una volta sola e solo se il comando ne ha bisogno: `tcn
    puncture list` legge il ledger e non deve toccare l'hardware.
    """
    args: Any
    _registry: Any = None
    _ledger: Any = None
    _dealer: Any = field(default=None, repr=False)
    _dealer_loaded: bool = False
    _scanned: bool = False

    @property
    def registry(self):
        if self._registry is None:
            from ..tokens.registry import Registry
            self._registry = Registry()
        return self._registry

    def scanned_registry(self):
        """Il registry con una scansione garantita."""
        reg = self.registry
        if not self._scanned:
            reg.scan()
            self._scanned = True
        return reg

    @property
    def ledger(self):
        if self._ledger is None:
            from ..ledger import Ledger
            self._ledger = Ledger()
        return self._ledger

    @property
    def dealer(self):
        if not self._dealer_loaded:
            from ..dealer import Dealer, DealerKeyError
            try:
                self._dealer = Dealer()
            except DealerKeyError as exc:
                raise CliError(
                    f'chiave del dealer non caricabile: {exc}\n'
                    'Impostare TCN_DEALER_KEY, oppure copiarla nel '
                    'percorso predefinito.') from exc
            self._dealer_loaded = True
        return self._dealer

    def sg02(self):
        from ..services.sg02 import Sg02Service
        # Il dealer serve solo alla distribuzione: non lo si carica qui,
        # altrimenti `tcn sg02 encrypt` fallirebbe su una macchina che
        # non ha la chiave e non ne ha bisogno.
        dealer = self._dealer if self._dealer_loaded else None
        return Sg02Service(self.scanned_registry(), dealer)

    def sg02_with_dealer(self):
        from ..services.sg02 import Sg02Service
        return Sg02Service(self.scanned_registry(), self.dealer)

    def ppke(self):
        from ..services.ppke import PpkeService
        return PpkeService(self.scanned_registry(), self.ledger)


# ---------------------------------------------------------------------
# Ingresso e uscita dei dati
# ---------------------------------------------------------------------
def read_blob(path: str | None, what: str = 'input') -> bytes:
    """Legge da file, oppure da stdin se il percorso e' '-' o assente."""
    if path in (None, '-'):
        data = sys.stdin.buffer.read()
        if not data:
            raise CliError(f'nessun {what} ricevuto da stdin',
                           EXIT_USAGE)
        return data
    p = Path(path)
    if not p.exists():
        raise CliError(f'{what} non trovato: {p}', EXIT_USAGE)
    return p.read_bytes()


def write_blob(path: str | None, data: bytes, label: str = 'output') -> None:
    """Scrive su file, oppure su stdout se il percorso e' '-' o assente."""
    if path in (None, '-'):
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    info(f'{label} scritto in {p} ({len(data)} byte)')


# ---------------------------------------------------------------------
# Resa
# ---------------------------------------------------------------------
_JSON = False
_QUIET = False


def configure_output(as_json: bool, quiet: bool) -> None:
    global _JSON, _QUIET
    _JSON, _QUIET = as_json, quiet


def is_json() -> bool:
    return _JSON


def info(msg: str) -> None:
    """Messaggio diagnostico.

    Va su stderr: stdout puo' contenere un plaintext destinato a una
    pipe, e mescolarci del testo lo corromperebbe.
    """
    if not _QUIET and not _JSON:
        print(msg, file=sys.stderr)


def warn(msg: str) -> None:
    if not _JSON:
        print(f'attenzione: {msg}', file=sys.stderr)


def emit(payload: dict, human: str | None = None) -> None:
    """Risultato strutturato di un comando.

    Con --json stampa l'oggetto su stdout, utilizzabile da uno script;
    altrimenti la forma leggibile, se il comando ne ha fornita una.
    """
    if _JSON:
        print(json.dumps(payload, ensure_ascii=False, indent=2,
                         default=str))
    elif human is not None:
        print(human)


def table(rows: list[tuple], headers: tuple) -> str:
    """Tabella allineata, senza dipendenze."""
    cols = [list(map(str, c)) for c in zip(headers, *rows)] if rows else \
        [[h] for h in headers]
    widths = [max(len(v) for v in col) for col in cols]
    out = ['  '.join(h.ljust(w) for h, w in zip(headers, widths)).rstrip(),
           '  '.join('-' * w for w in widths)]
    for row in rows:
        out.append('  '.join(str(v).ljust(w)
                             for v, w in zip(row, widths)).rstrip())
    return '\n'.join(out)


# ---------------------------------------------------------------------
# Eccezioni di dominio -> codici d'uscita
# ---------------------------------------------------------------------
def translate(exc: Exception) -> CliError:
    """Rende leggibile un'eccezione dei livelli sottostanti.

    Rispecchia la mappatura di api/errors.py: le stesse condizioni
    producono lo stesso significato, in un vocabolario diverso.
    """
    from ..convert.sg02_der import MalformedCiphertext
    from ..hosttools import PublicKeyNotFound, ToolError, ToolTimeout
    from ..ledger import CampaignNotFound
    from ..lockfile import StateLocked
    from ..services.ppke import (
        CapacityExhausted, KeysNotInitialised, ProbeMissing, TokensMissing,
    )
    from ..services.sg02 import (
        IncompleteDistribution, ThresholdNotReached,
    )
    from ..tokens.ppke import (
        KeyNotLoaded, MalformedPayload, Punctured,
        PunctureCapacityExhausted,
    )
    from ..tokens.registry import DuplicateNodeId, TokenBusy, TokenNotFound
    from ..tokens.sg02 import (
        DealerSignatureRejected, DeviceFault,
        MalformedPayload as Sg02MalformedPayload, ShareNotImported,
    )
    from ..transport import ApduError, TransportError

    if isinstance(exc, CliError):
        return exc

    if isinstance(exc, Punctured):
        return CliError(
            'il contenuto non e\' piu\' recuperabile: la chiave e\' '
            'punzonata su un tag di questo crittogramma.', EXIT_PUNCTURED)

    if isinstance(exc, KeyNotLoaded):
        # Deliberatamente distinto da Punctured: il contenuto non e'
        # stato distrutto, il dispositivo non e' in grado di decifrarlo.
        return CliError(
            'nessuna chiave GMPpke sul dispositivo: eseguire '
            '`tcn ppke setup` prima di cifrare o decifrare.',
            EXIT_NOT_READY)

    if isinstance(exc, MalformedPayload):
        return CliError(str(exc), EXIT_USAGE)

    if isinstance(exc, StateLocked):
        return CliError(str(exc), EXIT_UNAVAILABLE)
    if isinstance(exc, (TokenBusy, TransportError)):
        return CliError(f'token non disponibile: {exc}', EXIT_UNAVAILABLE)
    if isinstance(exc, TokenNotFound):
        return CliError(f'{exc}\nProvare `tcn tokens scan`.',
                        EXIT_UNAVAILABLE)

    if isinstance(exc, DeviceFault):
        # Deliberatamente distinto da DealerSignatureRejected: un guasto
        # di storage non e' un tentativo di import non autorizzato.
        return CliError(f'guasto sul dispositivo: {exc}', EXIT_ERROR)

    if isinstance(exc, Sg02MalformedPayload):
        return CliError(str(exc), EXIT_USAGE)

    if isinstance(exc, DealerSignatureRejected):
        return CliError(
            'il token ha rifiutato la firma del dealer: la chiave sul '
            'nodo centrale non corrisponde a quella cablata nel '
            'firmware.', EXIT_CONFLICT)
    if isinstance(exc, ShareNotImported):
        return CliError('nessuna share SG02 importata su questo token.',
                        EXIT_CONFLICT)
    if isinstance(exc, (ThresholdNotReached, TokensMissing,
                        IncompleteDistribution,
                        CapacityExhausted, ProbeMissing, KeysNotInitialised,
                        PublicKeyNotFound, PunctureCapacityExhausted,
                        DuplicateNodeId)):
        return CliError(str(exc), EXIT_CONFLICT)
    if isinstance(exc, CampaignNotFound):
        return CliError(str(exc).strip("'"), EXIT_CONFLICT)

    if isinstance(exc, MalformedCiphertext):
        return CliError(str(exc), EXIT_USAGE)
    if isinstance(exc, ApduError):
        return CliError(f'il token ha risposto {exc}', EXIT_ERROR)
    if isinstance(exc, ToolTimeout):
        return CliError(f'strumento host in timeout: {exc}', EXIT_ERROR)
    if isinstance(exc, ToolError):
        return CliError(f'strumento host fallito: {exc}', EXIT_ERROR)

    return CliError(f'{type(exc).__name__}: {exc}', EXIT_ERROR)
