"""
tcn.planner — scelta della variante di decrypt GMPpke.

Il firmware espone cinque implementazioni della stessa funzione. Non
esiste una che domini sempre: il confronto fra la strategia per-tag e
quella per-share dipende da d (fissato al keygen) e da n (punzonature
effettuate su quel token).

  per-tag   (INS 0x05)  (d+1) Miller loop + 1 FinalExp
                        costo costante in n, ma richiede d
                        moltiplicazioni scalari in G2 per il
                        precalcolo
  per-share (INS 0x06)  (n+2) Miller loop + 1 FinalExp
                        costo lineare in n, moltiplicazioni scalari
                        in G1

G2 e G1 non costano uguale: la differenza Delta e' l'ago della bilancia.
Il punto di crossover e'

    n* = d*Delta / (ML - d*Delta)

Se d*Delta >= ML il denominatore non e' positivo, non esiste crossover e
la strategia per-share domina ovunque. E' il caso di d=3 sul Cortex-M33.
Con d=1 il crossover cade intorno a n* ~ 3.3.

Le costanti ML, FE e Delta vivono in config.Timings e vanno tenute
allineate alle misure del capitolo Risultati: qui non sono ricavate ma
lette.

Il client non vede nulla di tutto questo. Puo' comunque forzare una
variante specifica, cosa che serve a rieseguire i benchmark attraverso
l'API invece che dal notebook.
"""

from dataclasses import dataclass

from .config import settings
from .tokens.ppke import DecryptVariant


@dataclass(frozen=True)
class Choice:
    variant: DecryptVariant
    n_star: float | None      # None se il crossover non esiste
    reason: str


def crossover(d: int | None = None) -> float | None:
    """n* = d*Delta / (ML - d*Delta), oppure None se non esiste."""
    d = d if d is not None else settings.schemes.d
    t = settings.timings
    denom = t.miller_loop - d * t.scalarmult_delta
    if denom <= 0:
        return None
    return (d * t.scalarmult_delta) / denom


def choose(n_punctures: int, d: int | None = None) -> Choice:
    """Variante ottimale per un token con n punzonature.

    n si legge dal ledger. Se fosse impreciso il risultato resterebbe
    corretto: cambierebbe solo il tempo di esecuzione. L'ottimizzazione
    non introduce quindi fragilita' sul piano funzionale.
    """
    d = d if d is not None else settings.schemes.d
    n_star = crossover(d)

    if n_star is None:
        return Choice(
            DecryptVariant.PER_SHARE_MP, None,
            f'nessun crossover per d={d}: d*Delta >= ML, '
            'per-share domina ovunque')

    if n_punctures < n_star:
        return Choice(
            DecryptVariant.PER_SHARE_MP, n_star,
            f'n={n_punctures} < n*={n_star:.2f}: per-share piu\' economica')

    return Choice(
        DecryptVariant.PER_TAG_MP, n_star,
        f'n={n_punctures} >= n*={n_star:.2f}: per-tag piu\' economica')


def estimate_ms(variant: DecryptVariant, n_punctures: int,
                d: int | None = None) -> float:
    """Costo atteso in millisecondi.

    Stima grossolana dei soli termini dominanti (Miller loop,
    esponenziazione finale, differenza fra scalarmult G2 e G1). Serve a
    decidere se un'operazione va trattata in modo sincrono o come job, e
    a popolare un campo informativo nella risposta: non e' una misura.
    """
    d = d if d is not None else settings.schemes.d
    t = settings.timings
    ns = n_punctures + 1

    if variant is DecryptVariant.PER_TAG_MP:
        return (d + 1) * t.miller_loop + t.final_exp + d * t.scalarmult_delta
    if variant is DecryptVariant.PER_TAG:
        return (d + 1) * (t.miller_loop + t.final_exp) \
            + d * t.scalarmult_delta
    if variant is DecryptVariant.PER_SHARE_MP:
        return (n_punctures + 2) * t.miller_loop + t.final_exp
    if variant is DecryptVariant.PER_SHARE:
        return (n_punctures + 2) * (t.miller_loop + t.final_exp)
    # BASELINE: 3*ns Miller loop + 3*ns FinalExp
    return 3 * ns * (t.miller_loop + t.final_exp)


def is_long_running(n_punctures: int, d: int | None = None) -> bool:
    """True se la decrypt supera la soglia oltre la quale l'API risponde
    202 invece di attendere."""
    choice = choose(n_punctures, d)
    return estimate_ms(choice.variant, n_punctures, d) / 1000.0 \
        > settings.runtime.sync_threshold
