"""
tcn.services.ppke — orchestrazione dello schema punzonabile GMPpke.

Modello di fiducia opposto a SG02, ed e' bene tenerlo presente leggendo
questo file. SG02 distribuisce share *diverse* a n token e ne bastano k;
GMPpke replica la *stessa* chiave su tutti gli N token e li richiede
tutti per punzonare. Un token non punzonato conserva la capacita' di
decifrare il tag che si voleva distruggere, quindi una campagna parziale
non e' una cancellazione riuscita a meta': non e' una cancellazione.

Tre proprieta' del firmware governano il disegno:

  - Puncture e' irreversibile.
  - Puncture non e' idempotente: ripetere lo stesso tag consuma una
    seconda unita' della capacita' MAX_PUNCTURES.
  - Il token non dichiara il proprio stato interno.

Insieme rendono pericoloso il ritentativo cieco. Una trasmissione fallita
lascia due possibilita' indistinguibili — il token ha punzonato e la
risposta si e' persa, oppure non ha ricevuto nulla — e nessun comando
permette di chiederglielo. L'ambiguita' si risolve empiricamente, con un
ciphertext sonda legato a quel tag: se la decifratura risponde SW 6982 la
punzonatura c'e' stata.

Da qui la sequenza rigida di ogni passo: si registra l'intento nel
ledger, si trasmette, si registra l'esito. E l'esecuzione e' sequenziale,
non parallela: su un'operazione irreversibile il determinismo vale piu'
del tempo risparmiato.
"""

import secrets
from dataclasses import dataclass

from .. import hosttools, planner
from ..config import settings
from ..convert.ppke_wire import (
    build_fw_ct, build_fw_pk, build_fw_sk, gt_ark_bytes_to_key,
    parse_ct, parse_pk, parse_sk,
)
from ..ledger import Campaign, CampaignNotFound, Ledger, tag_id
from ..tokens import ppke as ppke_token
from ..tokens.registry import Registry, TokenBusy, TokenNotFound
from ..transport import AID_PPKE, ApduError, TransportError

# PyNaCl serve solo alla parte simmetrica. Import tollerante: i moduli
# restano utilizzabili dove la DEM non serve.
try:
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_decrypt as _xchacha_decrypt,
    )
    SODIUM_AVAILABLE = True
except ImportError:                       # pragma: no cover
    _xchacha_decrypt = None
    SODIUM_AVAILABLE = False

NONCE_LEN = 24
PROBE_FILLER_PREFIX = '__tcn_probe_filler_'


class TokensMissing(RuntimeError):
    """Non tutti i token sono collegati: la campagna non puo' iniziare."""

    def __init__(self, missing: list[int]):
        self.missing = missing
        super().__init__(
            f'token assenti: {missing}. La punzonatura richiede tutti i '
            'token; una campagna parziale non cancella nulla.')


class CapacityExhausted(RuntimeError):
    """Almeno un token ha raggiunto MAX_PUNCTURES."""

    def __init__(self, nodes: list[int]):
        self.nodes = nodes
        super().__init__(f'capacita' f' esaurita sui nodi {nodes}')


class ProbeMissing(RuntimeError):
    """Manca il ciphertext sonda per il tag: l'incertezza non e'
    risolvibile."""


class KeysNotInitialised(RuntimeError):
    """Nessuna chiave pubblica GMPpke sul TCN."""


@dataclass(frozen=True)
class PpkeSetup:
    d: int
    shares: int
    distributed: list[int]
    failed: dict[int, str]


@dataclass(frozen=True)
class NodeReport:
    node_id: int
    punctured: list[str]
    uncertain: list[str]
    capacity: int


class PpkeService:
    def __init__(self, registry: Registry, ledger: Ledger | None = None):
        self._registry = registry
        self._ledger = ledger or Ledger()

    # -- chiave pubblica ----------------------------------------------

    def public_key(self) -> bytes:
        path = settings.paths.ppke_pk
        if not path.exists():
            raise KeysNotInitialised(f'chiave pubblica assente: {path}')
        return path.read_bytes()

    def _fw_pk(self) -> bytes:
        return build_fw_pk(parse_pk(self.public_key()))

    # -- anagrafica dei nodi ------------------------------------------

    def roster(self) -> list[int]:
        """Insieme dei token che *devono* partecipare a una campagna.

        Non deriva da chi risponde adesso, e la differenza e' critica: se
        l'insieme atteso fosse quello dei token collegati, staccarne uno
        lo farebbe sparire dai controlli e la campagna si dichiarerebbe
        completa mentre quel token conserva la capacita' di decifrare il
        tag. Un token assente deve risultare mancante, non inesistente.

        La sorgente e' l'anagrafica: i nodi gia' coinvolti in campagne
        precedenti, oppure 1..n dalla configurazione del gruppo al primo
        avvio.
        """
        known: set[int] = set()
        for c in self._ledger.campaigns():
            known.update(c.nodes)
        if known:
            return sorted(known)
        return list(range(1, settings.schemes.n + 1))

    # -- setup --------------------------------------------------------

    def setup_keys(self, d: int | None = None,
                   nodes: list[int] | None = None) -> PpkeSetup:
        """Genera la coppia e la distribuisce a tutti i token.

        La SK non viene mai scritta sullo stato persistente del TCN: vive
        su tmpfs il tempo della conversione e in memoria il tempo della
        distribuzione, poi viene azzerata. E' l'unica finestra in cui il
        nodo centrale conosce il segreto, ed e' il punto piu' esposto
        dell'intero sistema.

        L'import usa P1=Replace: azzera ogni punzonatura precedente sui
        token. Va quindi trattata come operazione di setup, non come un
        aggiornamento.
        """
        d = d or settings.schemes.d
        targets = nodes if nodes is not None else self.roster()
        if not targets:
            raise TokensMissing([])

        pk_blob, sk_blob = hosttools.ppke_keygen(d)
        fw_sk = bytearray()
        try:
            parsed_pk = parse_pk(pk_blob)
            shares = parse_sk(bytes(sk_blob))
            fw_pk = build_fw_pk(parsed_pk)
            fw_sk.extend(build_fw_sk(shares))

            done, failed = [], {}
            for node in sorted(targets):
                try:
                    with self._registry.session(node_id=node,
                                                aid=AID_PPKE) as ch:
                        ppke_token.import_key(ch, fw_pk, bytes(fw_sk),
                                              replace=True)
                    done.append(node)
                except (ApduError, TransportError, TokenBusy,
                        TokenNotFound) as exc:
                    failed[node] = str(exc)

            # La chiave pubblica si persiste solo se almeno un token ha
            # la corrispondente privata. Scriverla comunque lascerebbe il
            # nodo centrale capace di cifrare contenuti che nessuno
            # potra' mai decifrare.
            if done:
                settings.paths.ppke_pk.parent.mkdir(parents=True,
                                                    exist_ok=True)
                settings.paths.ppke_pk.write_bytes(pk_blob)
                # Replace ha azzerato le punzonature sui token raggiunti:
                # il registro deve saperlo, o continuera' a contare uno
                # stato che il dispositivo non ha piu'.
                self._ledger.record_key_reset(done)

            return PpkeSetup(d=parsed_pk['d'], shares=len(shares),
                             distributed=done, failed=failed)
        finally:
            hosttools.zeroize(fw_sk)
            hosttools.zeroize(sk_blob)

    # -- cifratura ----------------------------------------------------

    def encrypt(self, plaintext: bytes,
                tags: list[str]) -> tuple[bytes, bytes]:
        """Cifra con la sola chiave pubblica.

        Richiede esattamente d tag: ogni crittogramma resta legato a d
        maniglie di cancellazione indipendenti, e punzonarne una
        qualsiasi lo rende indecifrabile.
        """
        for t in tags:
            if t.startswith(PROBE_FILLER_PREFIX):
                raise ValueError(
                    f'prefisso {PROBE_FILLER_PREFIX} riservato alle sonde')
        return hosttools.ppke_encrypt(self.public_key(), tags, plaintext)

    def to_fw_ct(self, ct_pfse: bytes) -> bytes:
        """Converte un crittogramma cereal/RELIC nel payload arkworks."""
        return build_fw_ct(parse_ct(ct_pfse))

    # -- decifratura --------------------------------------------------

    def decrypt(self, node_id: int, ct_pfse: bytes, ct_sym: bytes,
                variant: ppke_token.DecryptVariant | None = None) -> bytes:
        """Decifratura completa su un token.

        Il KEM avviene sul dispositivo, che restituisce M in GT; la parte
        simmetrica resta sull'host, cosi' il crittogramma dei dati non
        transita mai sul bus.

        Se `variant` non e' indicata, il planner sceglie la piu'
        economica in base a d e al numero di punzonature registrate per
        quel token. Il numero puo' essere impreciso senza conseguenze
        funzionali: cambierebbe solo il tempo.
        """
        if not SODIUM_AVAILABLE:
            raise RuntimeError(
                'PyNaCl non installato: decifratura simmetrica non '
                'disponibile')
        if len(ct_sym) < NONCE_LEN:
            raise ValueError('ct_sym troppo corto')

        if variant is None:
            n = len(self._ledger.node_state(node_id).punctured)
            variant = planner.choose(n).variant

        fw_ct = self.to_fw_ct(ct_pfse)
        with self._registry.session(node_id=node_id, aid=AID_PPKE) as ch:
            m_ark = ppke_token.decrypt(ch, fw_ct, variant)

        key = gt_ark_bytes_to_key(m_ark)
        return _xchacha_decrypt(ct_sym[NONCE_LEN:], None,
                                ct_sym[:NONCE_LEN], key)

    # -- sonde --------------------------------------------------------

    def _probe_path(self, tag: str):
        return settings.paths.probes_dir / f'{tag_id(tag)}.bin'

    def ensure_probe(self, tag: str) -> bytes:
        """Crea, se manca, il crittogramma sonda legato a un tag.

        E' un crittogramma su contenuto casuale, che serve solo a
        chiedere a un token se e' punzonato su quel tag. I d-1 tag di
        riempimento usano un prefisso riservato e non vengono mai
        punzonati, quindi un SW 6982 sulla sonda e' attribuibile
        univocamente a `tag`.

        Costa una encrypt, che usa solo la chiave pubblica: nessun
        segreto e' coinvolto nel crearla.
        """
        path = self._probe_path(tag)
        if path.exists():
            return path.read_bytes()

        d = settings.schemes.d
        tags = [tag] + [f'{PROBE_FILLER_PREFIX}{i}' for i in range(1, d)]
        ct_pfse, _ = hosttools.ppke_encrypt(
            self.public_key(), tags, secrets.token_bytes(32))

        fw_ct = self.to_fw_ct(ct_pfse)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fw_ct)
        return fw_ct

    def probe(self, node_id: int, tag: str) -> bool:
        """True se il token risulta punzonato su `tag`."""
        path = self._probe_path(tag)
        if not path.exists():
            raise ProbeMissing(f'nessuna sonda per il tag {tag!r}')
        with self._registry.session(node_id=node_id, aid=AID_PPKE) as ch:
            return ppke_token.probe_tag(ch, path.read_bytes())

    # -- campagne di punzonatura --------------------------------------

    def puncture(self, tag: str, nodes: list[int] | None = None) -> Campaign:
        """Apre ed esegue una campagna su tutti i token.

        Rifiuta in blocco se manca un token o se la capacita' non basta:
        meglio non iniziare che fermarsi a meta' su un'operazione
        irreversibile.
        """
        targets = sorted(nodes if nodes is not None else self.roster())
        if not targets:
            raise TokensMissing([])

        missing = self._registry.missing(targets)
        if missing:
            raise TokensMissing(missing)

        limit = settings.schemes.max_punctures
        full = [n for n in targets
                if self._ledger.node_state(n).capacity(limit) < 1]
        if full:
            raise CapacityExhausted(full)

        self.ensure_probe(tag)
        cid = self._ledger.open_campaign(tag, targets)
        self._execute(cid)
        return self._ledger.campaign(cid)

    def resume(self, campaign_id: str) -> Campaign:
        """Riprende una campagna incompleta.

        Prima risolve le incertezze con la sonda, poi punzona i token
        rimasti. Senza il primo passo si rischierebbe di ripunzonare un
        token gia' punzonato, consumando capacita' per nulla.
        """
        self.resolve_unknown(campaign_id)
        self._execute(campaign_id)
        return self._ledger.campaign(campaign_id)

    def resolve_unknown(self, campaign_id: str) -> dict[int, bool]:
        """Accerta con la sonda lo stato dei token incerti."""
        c = self._ledger.campaign(campaign_id)
        if c is None:
            raise CampaignNotFound(
                f'campagna sconosciuta: {campaign_id}')

        resolved: dict[int, bool] = {}
        for node in c.unresolved:
            try:
                punctured = self.probe(node, c.tag)
            except (TransportError, TokenBusy, TokenNotFound, ProbeMissing,
                    ppke_token.KeyNotLoaded, ppke_token.MalformedPayload):
                # Un token senza chiave, o che rifiuta la sonda, non e'
                # un token punzonato: resta incerto e si riprovera'.
                # Dedurre "punzonato" da un errore qualsiasi scriverebbe
                # nel registro una cancellazione mai avvenuta.
                continue
            self._ledger.resolve(campaign_id, node, punctured)
            resolved[node] = punctured
        return resolved

    def _execute(self, campaign_id: str) -> None:
        """Esegue la punzonatura sui token rimanenti, uno alla volta.

        La sequenza per ogni token e' intent, trasmissione, esito. Un
        ApduError significa che una risposta e' arrivata, quindi lo stato
        del token e' noto; un errore di trasporto no, e va registrato
        come incerto invece che come fallimento.
        """
        c = self._ledger.campaign(campaign_id)
        if c is None:
            raise CampaignNotFound(
                f'campagna sconosciuta: {campaign_id}')
        tag = c.tag.encode()

        for node in list(c.remaining):
            self._ledger.record_intent(campaign_id, node)
            try:
                with self._registry.session(node_id=node,
                                            aid=AID_PPKE) as ch:
                    ppke_token.puncture(ch, tag)
            except ppke_token.PunctureCapacityExhausted:
                self._ledger.record_result(campaign_id, node, False,
                                           'SW 6A84: MAX_PUNCTURES')
            except ApduError as exc:
                self._ledger.record_result(campaign_id, node, False, str(exc))
            except (TransportError, TokenBusy, TokenNotFound) as exc:
                # Nessuna risposta interpretabile: lo stato del token non
                # e' deducibile e va accertato con la sonda.
                self._ledger.record_unknown(campaign_id, node, str(exc))
            else:
                self._ledger.record_result(campaign_id, node, True)

    # -- stato --------------------------------------------------------

    def report(self, nodes: list[int] | None = None) -> list[NodeReport]:
        limit = settings.schemes.max_punctures
        targets = sorted(nodes if nodes is not None else self.roster())
        out = []
        for n in targets:
            st = self._ledger.node_state(n)
            out.append(NodeReport(node_id=n, punctured=sorted(st.punctured),
                                  uncertain=sorted(st.uncertain),
                                  capacity=st.capacity(limit)))
        return out

    def aligned(self, nodes: list[int] | None = None) -> bool:
        """True se tutti i token hanno lo stesso insieme di tag punzonati.

        Il confronto e' sull'insieme dei tag, non sui byte delle chiavi:
        Puncture e' randomizzata e ogni token usa il proprio RNG, quindi
        le SK divergono nella rappresentazione pur restando equivalenti.
        """
        targets = sorted(nodes if nodes is not None else self.roster())
        return self._ledger.aligned(targets)
