"""
tcn.services.sg02 — orchestrazione dello schema a soglia SG02.

Compone i livelli inferiori nelle operazioni che hanno senso per un
utente del sistema:

  setup_group        keygen k-su-n sull'host
  distribute         import della share su un token, con firma del dealer
  wipe_keystores     cancellazione del materiale privato dal TCN
  encrypt            cifratura con la sola chiave pubblica
  collect_share      decifratura parziale su un token, gia' in DER base64
  decrypt            raccolta di k share in parallelo e aggregazione

Il momento delicato e' la distribuzione. Il keygen produce n share
private *sul TCN*: fra quel momento e la cancellazione dei keystore il
nodo centrale le possiede tutte insieme, e la soglia non protegge nulla.
La finestra va tenuta corta e la cancellazione va fatta, non rimandata.
E' anche il motivo per cui encrypt e assemble usano --pubkey: senza
quello i keystore andrebbero conservati e la finestra non si chiuderebbe
mai.

Sulla concorrenza: la raccolta delle share parallelizza perche' ogni task
prende e rilascia il lock di un solo token. Nessuna funzione qui annida
due session.
"""

import concurrent.futures as cf
from dataclasses import dataclass
from pathlib import Path

from .. import hosttools
from ..config import settings
from ..convert.sg02_der import (
    extract_u_sg02, extract_xi_sg02, share_to_base64,
)
from ..dealer import Dealer
from ..tokens import sg02 as sg02_token
from ..tokens.registry import Registry, TokenBusy, TokenNotFound
from ..transport import AID_SG02, TransportError


class IncompleteDistribution(RuntimeError):
    """Meno di n token hanno ricevuto la propria share.

    Cancellare i keystore in questa condizione distrugge l'unica copia
    delle share mai consegnate: il gruppo diventa irrecuperabile e va
    rigenerato da capo.
    """

    def __init__(self, provisioned: list[int], expected: int):
        self.provisioned = provisioned
        self.expected = expected
        super().__init__(
            f'solo {len(provisioned)} token su {expected} hanno ricevuto '
            f'la share (nodi {provisioned}). Cancellare ora i keystore '
            'distruggerebbe le share mai consegnate. Collegare i token '
            'mancanti e completare la distribuzione, oppure forzare se '
            'il gruppo e\' intenzionalmente parziale.')


class ThresholdNotReached(RuntimeError):
    """Meno di k share valide raccolte."""

    def __init__(self, collected: int, threshold: int, errors: dict):
        self.collected = collected
        self.threshold = threshold
        self.errors = errors
        super().__init__(
            f'{collected}/{threshold} share raccolte; '
            f'nodi falliti: {sorted(errors)}')


@dataclass(frozen=True)
class GroupInfo:
    key_id: str
    k: int
    n: int
    public_key: Path


@dataclass(frozen=True)
class Distribution:
    node_id: int
    reader: str
    ok: bool
    error: str = ''


class Sg02Service:
    def __init__(self, registry: Registry, dealer: Dealer | None = None):
        self._registry = registry
        self._dealer = dealer

    # -- setup --------------------------------------------------------

    def setup_group(self, k: int | None = None, n: int | None = None,
                    reset: bool = False) -> GroupInfo:
        """`thetacli keygen`. Produce n keystore privati e la chiave
        pubblica del gruppo.

        reset=True passa --new, che cancella pub/ e i keystore esistenti:
        distrugge il gruppo precedente e va richiesto esplicitamente.
        """
        s = settings.schemes
        k = k or s.k
        n = n or s.n
        if k > n:
            raise ValueError(f'soglia k={k} maggiore di n={n}')

        hosttools.sg02_keygen(k=k, n=n, reset=reset)
        key_id = hosttools.sg02_key_id(1)
        # Registrato subito: senza questo riferimento un secondo keygen
        # renderebbe ambiguo quale gruppo sia quello attivo.
        hosttools.set_current_key_id(key_id)
        return GroupInfo(key_id=key_id, k=k, n=n,
                         public_key=hosttools.sg02_public_key_path(key_id))

    def current_group(self) -> GroupInfo:
        """Il gruppo registrato come attivo."""
        key_id = hosttools.current_key_id()
        if key_id is None:
            raise hosttools.PublicKeyNotFound(
                'nessun gruppo registrato: generarlo con POST '
                '/sg02/groups.')
        s = settings.schemes
        return GroupInfo(key_id=key_id, k=s.k, n=s.n,
                         public_key=hosttools.sg02_public_key_path(key_id))

    def distribute(self, *, node_id: int | None = None,
                   reader: str | None = None,
                   keystore_index: int | None = None) -> Distribution:
        """Importa su un token la share del nodo corrispondente.

        Prima dell'import il token non ha ancora un node_id, quindi si
        indirizza per lettore e si indica quale keystore usare. Dopo
        l'import il node_id diventa leggibile con INS 0x05 e il token e'
        indirizzabile per nodo.
        """
        if self._dealer is None:
            raise RuntimeError('nessuna chiave del dealer configurata')

        index = keystore_index if keystore_index is not None else node_id
        if index is None:
            raise ValueError(
                'indicare keystore_index quando si distribuisce per lettore')

        xi, ks_node_id = extract_xi_sg02(str(hosttools.keystore_path(index)))
        signature = self._dealer.sign_share(xi, ks_node_id)

        target = {'node_id': node_id} if node_id is not None \
            else {'reader': reader}
        try:
            with self._registry.session(**target, aid=AID_SG02) as ch:
                sg02_token.import_key_share(ch, xi, ks_node_id, signature)
        except (TransportError, TokenBusy, TokenNotFound,
                sg02_token.DealerSignatureRejected) as exc:
            return Distribution(node_id=ks_node_id,
                                reader=reader or '', ok=False,
                                error=str(exc))
        finally:
            del xi, signature

        return Distribution(node_id=ks_node_id,
                            reader=reader or self._registry
                            .by_node(ks_node_id).reader, ok=True)

    def wipe_keystores(self, force: bool = False) -> list[int]:
        """Rimuove i keystore privati dal TCN dopo la distribuzione.

        Finche' i keystore esistono il nodo centrale detiene tutte le
        share e la proprieta' di soglia vale solo in transito, non a
        riposo. Ma cancellarli prima che la distribuzione sia completa
        e' peggio: le share non consegnate spariscono e il gruppo va
        rigenerato.

        Il controllo confronta i token provisionati con n, non con
        quelli collegati: un token staccato deve risultare mancante, non
        inesistente.

        La chiave pubblica in pub/ resta: serve a encrypt e assemble e
        non e' materiale segreto.
        """
        expected = settings.schemes.n
        provisioned = self._registry.nodes()
        if not force and len(provisioned) < expected:
            raise IncompleteDistribution(provisioned, expected)

        removed = []
        for i in range(1, settings.schemes.n + 1):
            path = hosttools.keystore_path(i)
            if not path.exists():
                continue
            size = path.stat().st_size
            with open(path, 'r+b') as f:
                f.write(b'\x00' * size)
                f.flush()
            path.unlink()
            removed.append(i)
        return removed

    # -- uso ----------------------------------------------------------

    def encrypt(self, plaintext: bytes, label: str,
                key_id: str | None = None) -> bytes:
        return hosttools.sg02_encrypt(plaintext, label, key_id)

    def collect_share_raw(self, node_id: int, u_raw: bytes) -> bytes:
        """I 99 byte grezzi della decifratura parziale su un token."""
        with self._registry.session(node_id=node_id, aid=AID_SG02) as ch:
            return sg02_token.partial_decrypt(ch, u_raw)

    def collect_share(self, node_id: int, u_raw: bytes, label: bytes) -> str:
        """Decifratura parziale su un token, restituita in DER base64
        pronta per `thetacli assemble`."""
        return share_to_base64(self.collect_share_raw(node_id, u_raw), label)

    def decrypt(self, ciphertext: bytes, nodes: list[int] | None = None,
                key_id: str | None = None) -> bytes:
        """Decifratura completa: raccoglie k share e aggrega.

        La label non va passata: e' contenuta nel ciphertext ed e' quella
        con cui la share deve essere serializzata. Prenderla da altrove
        produrrebbe una share che `assemble` rifiuta.

        Le richieste ai token partono in parallelo. Si accettano le prime
        k risposte valide, cosi' un token lento o staccato non blocca la
        decifratura finche' restano abbastanza nodi.
        """
        u_raw, label = extract_u_sg02(ciphertext)
        k = settings.schemes.k
        candidates = nodes if nodes is not None else self._registry.nodes()

        if len(candidates) < k:
            raise ThresholdNotReached(len(candidates), k, {})

        shares: list[str] = []
        errors: dict[int, str] = {}

        with cf.ThreadPoolExecutor(max_workers=len(candidates)) as pool:
            futures = {pool.submit(self.collect_share, n, u_raw, label): n
                       for n in candidates}
            for fut in cf.as_completed(futures):
                node = futures[fut]
                try:
                    shares.append(fut.result())
                except Exception as exc:
                    errors[node] = str(exc)
                if len(shares) >= k:
                    for pending in futures:
                        pending.cancel()
                    break

        if len(shares) < k:
            raise ThresholdNotReached(len(shares), k, errors)

        return hosttools.sg02_assemble(ciphertext, shares[:k], key_id)
