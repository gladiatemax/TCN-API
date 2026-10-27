"""
tcn.ledger — registro delle punzonature.

La punzonatura e' irreversibile, non idempotente nel firmware, e il token
non espone alcun comando per dichiarare il proprio stato. Il TCN e'
quindi l'unico depositario di cosa e' stato punzonato e dove, e questo
registro e' quel deposito.

Formato: append-only, una riga JSON per record, fsync dopo ogni
scrittura. Lo stato in memoria si ricostruisce rileggendo il file
dall'inizio, quindi il processo puo' morire in qualsiasi momento senza
perdere informazione.

Il meccanismo centrale e' il write-ahead log. Prima di trasmettere l'APDU
si registra un `intent`; dopo la risposta si registra un `result`. Un
intent senza result e' uno stato *incerto*: la trasmissione puo' essere
fallita prima o dopo che il token punzonasse, e i due casi non sono
distinguibili dalla sola risposta. Senza WAL un crash produrrebbe un
registro che mente, dichiarando intatto un token che non lo e' piu'.

L'incertezza si risolve empiricamente, non chiedendo al token: si tenta
di decifrare un ciphertext sonda legato a quel tag e si guarda se
risponde SW 6982. Vedi tokens.ppke.probe_tag.
"""

import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .config import settings


class CampaignNotFound(KeyError):
    """Nessuna campagna con quell'identificatore nel registro."""


def tag_id(tag: bytes | str) -> str:
    """Identificatore derivato dal tag, usato per i nomi dei file sonda.

    E' solo igiene sul filesystem: un tag puo' contenere separatori di
    percorso o caratteri non rappresentabili. Il tag in chiaro resta nel
    registro.
    """
    if isinstance(tag, str):
        tag = tag.encode()
    return hashlib.sha256(tag).hexdigest()[:32]


class NodeOutcome(str, Enum):
    PENDING = 'pending'        # non ancora tentato
    IN_FLIGHT = 'in_flight'    # intent registrato, esito ignoto
    DONE = 'done'              # punzonato, confermato
    FAILED = 'failed'          # non punzonato, confermato
    UNKNOWN = 'unknown'        # trasmissione interrotta, da risolvere


class CampaignStatus(str, Enum):
    PENDING = 'pending'
    IN_PROGRESS = 'in_progress'
    COMPLETE = 'complete'      # tutti i token punzonati
    PARTIAL = 'partial'        # alcuni no: la cancellazione NON e' avvenuta
    FAILED = 'failed'          # nessun token punzonato


@dataclass
class Campaign:
    id: str
    tag: str
    nodes: dict[int, NodeOutcome] = field(default_factory=dict)
    detail: dict[int, str] = field(default_factory=dict)
    created_at: float = 0.0

    @property
    def status(self) -> CampaignStatus:
        vals = list(self.nodes.values())
        if not vals:
            return CampaignStatus.PENDING
        if all(v is NodeOutcome.DONE for v in vals):
            return CampaignStatus.COMPLETE
        if all(v is NodeOutcome.PENDING for v in vals):
            return CampaignStatus.PENDING
        # Un token ancora in volo, o non ancora tentato, significa che la
        # campagna non e' conclusa: resta lavoro da fare.
        if any(v in (NodeOutcome.IN_FLIGHT, NodeOutcome.PENDING)
               for v in vals):
            return CampaignStatus.IN_PROGRESS
        if all(v is NodeOutcome.FAILED for v in vals):
            return CampaignStatus.FAILED
        # Conclusa ma non su tutti i token: la cancellazione NON e'
        # avvenuta, ed e' lo stato che va reso visibile e allarmante.
        return CampaignStatus.PARTIAL

    @property
    def unresolved(self) -> list[int]:
        """Token il cui stato va accertato con la sonda."""
        return [n for n, v in self.nodes.items()
                if v in (NodeOutcome.IN_FLIGHT, NodeOutcome.UNKNOWN)]

    @property
    def remaining(self) -> list[int]:
        """Token su cui la punzonatura va ancora eseguita."""
        return [n for n, v in self.nodes.items()
                if v in (NodeOutcome.PENDING, NodeOutcome.FAILED)]


@dataclass
class NodeState:
    node_id: int
    punctured: list[str] = field(default_factory=list)
    uncertain: list[str] = field(default_factory=list)

    def consumed(self, max_punctures: int) -> int:
        """Capacita' consumata, contando le incertezze come consumate.

        Stima conservativa: superare MAX_PUNCTURES nel firmware fa
        fallire l'operazione, quindi conviene fermarsi prima piuttosto
        che scoprirlo con un SW 6A84 a meta' campagna.
        """
        return len(self.punctured) + len(self.uncertain)

    def capacity(self, max_punctures: int) -> int:
        return max(0, max_punctures - self.consumed(max_punctures))


class Ledger:
    """Registro append-only. Sicuro per l'uso da piu' thread; la
    serializzazione degli accessi al token e' invece del registry."""

    def __init__(self, path: Path | None = None):
        self._path = Path(path or settings.paths.ledger)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._campaigns: dict[str, Campaign] = {}
        # Istante dell'ultimo azzeramento della chiave per ciascun nodo.
        self._reset_at: dict[int, float] = {}
        self._replay()

    # -- scrittura ----------------------------------------------------

    def _append(self, rec: dict) -> None:
        rec['ts'] = time.time()
        line = json.dumps(rec, ensure_ascii=False, sort_keys=True) + '\n'
        with open(self._path, 'a', encoding='utf-8') as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        self._apply(rec)

    def open_campaign(self, tag: str, nodes: list[int]) -> str:
        """Apre una campagna di punzonatura su tutti i token indicati."""
        cid = f'punc_{uuid.uuid4().hex[:16]}'
        with self._lock:
            self._append({'t': 'campaign', 'id': cid, 'tag': tag,
                          'nodes': sorted(nodes)})
        return cid

    def record_key_reset(self, nodes: list[int]) -> None:
        """Registra che la chiave e' stata reimportata con P1=Replace.

        Replace azzera ogni punzonatura sul token. Senza questo record il
        registro continuerebbe a contare le punzonature precedenti, e
        capacita', allineamento e scelta della variante si baserebbero su
        uno stato che il dispositivo non ha piu'. Il sintomo e' subdolo:
        il registro sovrastima, quindi il sistema si ferma prima del
        necessario, finche' un giorno sottostima e incontra SW 6A84.

        Le campagne restano nel file: e' un registro append-only e la
        storia non si riscrive. Vengono semplicemente ignorate, per quel
        nodo, se precedenti al reset.
        """
        with self._lock:
            self._append({'t': 'reset', 'nodes': sorted(nodes)})

    def record_intent(self, cid: str, node: int) -> None:
        """Da chiamare PRIMA di trasmettere l'APDU."""
        with self._lock:
            self._append({'t': 'intent', 'id': cid, 'node': node})

    def record_result(self, cid: str, node: int, ok: bool,
                      detail: str = '') -> None:
        """Da chiamare DOPO aver ricevuto una risposta interpretabile."""
        with self._lock:
            self._append({'t': 'result', 'id': cid, 'node': node,
                          'ok': bool(ok), 'detail': detail})

    def record_unknown(self, cid: str, node: int, detail: str = '') -> None:
        """Trasmissione interrotta: l'esito non e' deducibile."""
        with self._lock:
            self._append({'t': 'unknown', 'id': cid, 'node': node,
                          'detail': detail})

    def resolve(self, cid: str, node: int, punctured: bool,
                detail: str = 'probe') -> None:
        """Esito del test di capacita' su un token incerto."""
        with self._lock:
            self._append({'t': 'resolved', 'id': cid, 'node': node,
                          'punctured': bool(punctured), 'detail': detail})

    # -- lettura ------------------------------------------------------

    def campaign(self, cid: str) -> Campaign | None:
        return self._campaigns.get(cid)

    def campaigns(self) -> list[Campaign]:
        return sorted(self._campaigns.values(),
                      key=lambda c: c.created_at, reverse=True)

    def node_state(self, node: int) -> NodeState:
        st = NodeState(node_id=node)
        since = self._reset_at.get(node, 0.0)
        for c in self._campaigns.values():
            if c.created_at < since:
                continue          # precedente all'azzeramento della chiave
            outcome = c.nodes.get(node)
            if outcome is NodeOutcome.DONE:
                st.punctured.append(c.tag)
            elif outcome in (NodeOutcome.IN_FLIGHT, NodeOutcome.UNKNOWN):
                st.uncertain.append(c.tag)
        return st

    def aligned(self, nodes: list[int]) -> bool:
        """True se tutti i token hanno lo stesso insieme di tag punzonati
        e nessuna incertezza pendente.

        Le SK non sono confrontabili byte a byte: la punzonatura e'
        randomizzata e ogni token usa il proprio RNG, quindi
        rappresentazioni diverse convergono sulla stessa capacita'. Il
        criterio di allineamento e' l'insieme dei tag, non i byte.
        """
        states = [self.node_state(n) for n in nodes]
        if any(s.uncertain for s in states):
            return False
        reference = set(states[0].punctured) if states else set()
        return all(set(s.punctured) == reference for s in states)

    # -- ricostruzione ------------------------------------------------

    def _apply(self, rec: dict) -> None:
        t = rec.get('t')
        if t == 'reset':
            for n in rec.get('nodes', []):
                self._reset_at[int(n)] = rec['ts']
            return

        cid = rec.get('id')
        if t == 'campaign':
            self._campaigns[cid] = Campaign(
                id=cid, tag=rec['tag'], created_at=rec['ts'],
                nodes={int(n): NodeOutcome.PENDING for n in rec['nodes']})
            return

        c = self._campaigns.get(cid)
        if c is None:
            return                       # record orfano: ignorato
        node = int(rec['node'])

        if t == 'intent':
            c.nodes[node] = NodeOutcome.IN_FLIGHT
        elif t == 'result':
            c.nodes[node] = (NodeOutcome.DONE if rec['ok']
                             else NodeOutcome.FAILED)
            c.detail[node] = rec.get('detail', '')
        elif t == 'unknown':
            c.nodes[node] = NodeOutcome.UNKNOWN
            c.detail[node] = rec.get('detail', '')
        elif t == 'resolved':
            c.nodes[node] = (NodeOutcome.DONE if rec['punctured']
                             else NodeOutcome.FAILED)
            c.detail[node] = rec.get('detail', '')

    def _replay(self) -> None:
        """Ricostruisce lo stato dal file e promuove a UNKNOWN ogni
        intent rimasto senza esito: e' un processo morto a meta'
        trasmissione, non un token intatto."""
        if not self._path.exists():
            return
        with open(self._path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    self._apply(json.loads(line))
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue          # riga troncata da un crash: si salta

        for c in self._campaigns.values():
            for node, outcome in c.nodes.items():
                if outcome is NodeOutcome.IN_FLIGHT:
                    c.nodes[node] = NodeOutcome.UNKNOWN
                    c.detail[node] = 'intent senza esito al riavvio'
