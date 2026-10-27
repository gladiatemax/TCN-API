"""
tcn.config — configurazione centralizzata.

Ogni percorso, timeout e parametro di schema vive qui. I moduli non
contengono stringhe assolute: rende il servizio riproducibile su una
macchina diversa cambiando solo l'ambiente, e mantiene allineati i
parametri usati in esercizio con quelli dichiarati in tesi.

Tutto e' sovrascrivibile da variabile d'ambiente con prefisso TCN_.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(f'TCN_{name}', default)


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(f'TCN_{name}', default))


def _env_float(name: str, default: float) -> float:
    return float(os.environ.get(f'TCN_{name}', default))


def _user_data_home() -> Path:
    """Radice dei dati dell'utente, secondo XDG.

    Il default NON e' /var/lib/tcn: quella directory richiede root e ha
    senso solo nel deployment con systemd, dove il percorso si imposta
    comunque con TCN_STATE_DIR. Durante lo sviluppo il servizio gira
    come utente normale.
    """
    xdg = os.environ.get('XDG_DATA_HOME')
    return Path(xdg) if xdg else Path.home() / '.local' / 'share'


def _user_config_home() -> Path:
    xdg = os.environ.get('XDG_CONFIG_HOME')
    return Path(xdg) if xdg else Path.home() / '.config'


@dataclass(frozen=True)
class Paths:
    # Binari esterni
    thetacli: Path = field(default_factory=lambda: Path(
        _env('THETACLI',
             '/home/mattei/Scrivania/Tesi/thetacrypt/src/target/release/thetacli')))
    pfse_tool: Path = field(default_factory=lambda: Path(
        _env('PFSE_TOOL',
             '/home/mattei/Scrivania/Tesi/forwardCLI/pfse_tool_bn254')))

    # Stato persistente del TCN.
    # In esercizio con systemd si imposta TCN_STATE_DIR=/var/lib/tcn.
    state_dir: Path = field(default_factory=lambda: Path(
        _env('STATE_DIR', str(_user_data_home() / 'tcn'))))

    # Chiave privata del dealer (Ed25519, PEM)
    dealer_key: Path = field(default_factory=lambda: Path(
        _env('DEALER_KEY', str(_user_config_home() / 'tcn' / 'dealer_sk.pem'))))

    # Directory volatile per il materiale segreto in transito.
    # Deve stare su tmpfs: la SK GMPpke non tocca mai un disco.
    volatile_dir: Path = field(default_factory=lambda: Path(
        _env('VOLATILE_DIR', '/dev/shm/tcn')))

    @property
    def sg02_dir(self) -> Path:
        return self.state_dir / 'sg02'

    @property
    def ppke_dir(self) -> Path:
        return self.state_dir / 'ppke'

    @property
    def ppke_pk(self) -> Path:
        return self.ppke_dir / 'pk.bin'

    @property
    def probes_dir(self) -> Path:
        return self.ppke_dir / 'probes'

    @property
    def ciphertexts_dir(self) -> Path:
        return self.state_dir / 'ciphertexts'

    @property
    def ledger(self) -> Path:
        return self.state_dir / 'ledger.jsonl'


@dataclass(frozen=True)
class Schemes:
    # SG02: soglia k su n
    k: int = field(default_factory=lambda: _env_int('SG02_K', 3))
    n: int = field(default_factory=lambda: _env_int('SG02_N', 5))
    subjects: str = field(default_factory=lambda: _env(
        'SG02_SUBJECTS', 'Sg02-Ed25519'))

    # GMPpke: d tag per ciphertext, deciso al keygen
    d: int = field(default_factory=lambda: _env_int('PPKE_D', 3))
    # Limite di punzonature del backend. Duplicato per rifiutare a monte
    # le richieste eccedenti; la verita' resta il firmware.
    max_punctures: int = field(
        default_factory=lambda: _env_int('PPKE_MAX_PUNCTURES', 5))


@dataclass(frozen=True)
class Timings:
    """Costanti di costo misurate sulla piattaforma, in millisecondi.

    Alimentano la scelta automatica della variante di decrypt. Vanno
    tenute allineate ai valori del capitolo Risultati: se cambiano le
    misure, cambia qui, non nel codice del planner.
    """
    miller_loop: float = field(
        default_factory=lambda: _env_float('T_MILLER_LOOP', 505.0))
    final_exp: float = field(
        default_factory=lambda: _env_float('T_FINAL_EXP', 636.0))
    # Delta = costo(scalarmult G2) - costo(scalarmult G1)
    scalarmult_delta: float = field(
        default_factory=lambda: _env_float('T_SCALARMULT_DELTA', 387.0))


@dataclass(frozen=True)
class Runtime:
    reader_match: str = field(
        default_factory=lambda: _env('READER_MATCH', 'Nitrokey'))
    # Attesa massima sul lock di un token prima di rispondere 503
    token_lock_timeout: float = field(
        default_factory=lambda: _env_float('TOKEN_LOCK_TIMEOUT', 30.0))
    # Timeout di un singolo sottoprocesso host
    subprocess_timeout: float = field(
        default_factory=lambda: _env_float('SUBPROCESS_TIMEOUT', 120.0))
    # Oltre questa soglia un'operazione diventa un job asincrono
    sync_threshold: float = field(
        default_factory=lambda: _env_float('SYNC_THRESHOLD', 2.0))


@dataclass(frozen=True)
class Settings:
    paths: Paths = field(default_factory=Paths)
    schemes: Schemes = field(default_factory=Schemes)
    timings: Timings = field(default_factory=Timings)
    runtime: Runtime = field(default_factory=Runtime)


settings = Settings()


class StateDirUnavailable(RuntimeError):
    """La directory di stato non e' creabile o scrivibile."""


def ensure_dirs() -> None:
    """Crea le directory di stato. La volatile_dir e' esclusa: va creata
    su tmpfs solo quando serve, e rimossa subito dopo.

    Un percorso non scrivibile produce un errore che dice quale variabile
    cambiare, invece di un PermissionError grezzo.
    """
    p = settings.paths
    for d in (p.state_dir, p.sg02_dir, p.ppke_dir, p.probes_dir,
              p.ciphertexts_dir):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except PermissionError as exc:
            raise StateDirUnavailable(
                f'{d} non creabile: {exc.strerror}. '
                f'Impostare TCN_STATE_DIR su un percorso scrivibile '
                f'(attuale: {p.state_dir}).') from exc
    if not os.access(p.state_dir, os.W_OK):
        raise StateDirUnavailable(
            f'{p.state_dir} non e\' scrivibile. Impostare TCN_STATE_DIR.')
