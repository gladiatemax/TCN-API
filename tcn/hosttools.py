"""
tcn.hosttools — invocazione dei binari host.

Due strumenti esterni:
  thetacli          keygen di gruppo, encrypt, decifratura parziale
                    software, assemble  (schema SG02)
  pfse_tool_bn254   keygen ed encrypt   (schema GMPpke)

Tre regole seguite ovunque:

1. Nessun parsing di stdout. Sia `dec` che `assemble` scrivono messaggi
   diagnostici e risultato sullo stesso flusso; si usa --output su file
   temporaneo e si leggono i byte. Prendere l'ultima riga di stdout
   funziona finche' nessuno aggiunge una println, poi corrompe il
   plaintext in silenzio.

2. Timeout esplicito su ogni invocazione. Un binario bloccato non deve
   trattenere una richiesta HTTP a tempo indefinito.

3. Il materiale segreto in transito vive su tmpfs e viene azzerato. La
   SK GMPpke esiste sul TCN solo il tempo della distribuzione ai token.

Nota su `pfse_tool_bn254 decrypt`: richiede il file della SK, che il TCN
non possiede. Non e' esposto: la decifratura GMPpke e' esclusivamente
on-device.
"""

import json
import os
import secrets
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .config import settings


class ToolError(RuntimeError):
    """Un binario esterno ha terminato con esito negativo."""

    def __init__(self, tool: str, args, returncode: int, stderr: str):
        self.tool = tool
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(
            f'{tool} {args[0] if args else ""} -> exit {returncode}: '
            f'{stderr.strip()[:400]}')


class ToolTimeout(RuntimeError):
    """Un binario esterno non ha terminato entro il timeout."""


class PublicKeyNotFound(RuntimeError):
    """Nessuna chiave pubblica SG02 corrisponde alla richiesta.

    Non e' un fallimento di un binario: e' uno stato del sistema, e come
    tale merita un codice diverso da 502.
    """


# ---------------------------------------------------------------------
# Materiale volatile
# ---------------------------------------------------------------------
def zeroize(buf: bytearray) -> None:
    """Sovrascrive un buffer mutabile. Sui bytes immutabili di Python non
    e' possibile: il materiale segreto va tenuto in bytearray."""
    for i in range(len(buf)):
        buf[i] = 0


@contextmanager
def volatile_workdir():
    """Directory temporanea su tmpfs, distrutta all'uscita.

    Il contenuto non raggiunge mai un dispositivo a blocchi. I file
    vengono comunque sovrascritti prima di essere rimossi, cosi' il
    comportamento resta corretto anche se la directory fosse
    erroneamente configurata su disco.
    """
    base = settings.paths.volatile_dir
    base.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=base))
    try:
        yield path
    finally:
        for f in path.rglob('*'):
            if f.is_file():
                try:
                    size = f.stat().st_size
                    with open(f, 'r+b') as fh:
                        fh.write(secrets.token_bytes(size))
                        fh.flush()
                        os.fsync(fh.fileno())
                except OSError:
                    pass
        shutil.rmtree(path, ignore_errors=True)


def _run(tool: Path, args, timeout: float | None = None):
    timeout = timeout or settings.runtime.subprocess_timeout
    try:
        proc = subprocess.run([str(tool), *[str(a) for a in args]],
                              capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise ToolError(tool.name, args, -1, str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolTimeout(
            f'{tool.name} {args[0] if args else ""} oltre {timeout}s') from exc
    if proc.returncode != 0:
        raise ToolError(tool.name, args, proc.returncode,
                        proc.stderr.decode(errors='replace'))
    return proc


# =====================================================================
# thetacli — schema SG02
# =====================================================================
def _thetacli():
    return settings.paths.thetacli


def keystore_path(node_id: int) -> Path:
    return settings.paths.sg02_dir / f'node{node_id}.keystore'


def sg02_keygen(k: int | None = None, n: int | None = None,
                subjects: str | None = None, reset: bool = False) -> None:
    """`thetacli keygen`. Produce n keystore e la chiave pubblica.

    reset=True aggiunge --new, che cancella la directory pub/ e ignora i
    keystore preesistenti. E' distruttivo: resta opt-in esplicito, mai
    implicito in una chiamata di setup.
    """
    s = settings.schemes
    args = ['keygen',
            '-k', k or s.k,
            '-n', n or s.n,
            '--subjects', subjects or s.subjects,
            '--output', settings.paths.sg02_dir]
    if reset:
        args.append('--new')
    _run(_thetacli(), args)


def sg02_key_id(node_id: int = 1) -> str:
    """Legge l'id della chiave Sg02-Ed25519 da un keystore."""
    with open(keystore_path(node_id)) as f:
        entries = json.load(f)
    return next(e['id'] for e in entries
                if e.get('scheme') == 'Sg02' and e.get('group') == 'Ed25519')


def _current_key_id_path() -> Path:
    return settings.paths.sg02_dir / 'current-key-id'


def set_current_key_id(key_id: str) -> None:
    """Registra quale gruppo e' quello attivo.

    `thetacli keygen` senza --new accumula i file .pub, quindi dopo il
    secondo keygen la directory ne contiene piu' d'uno e dedurre il
    gruppo corrente dal filesystem diventa impossibile. Il riferimento
    va scritto, non indovinato.
    """
    path = _current_key_id_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key_id.strip() + '\n', encoding='utf-8')


def current_key_id() -> str | None:
    path = _current_key_id_path()
    if not path.exists():
        return None
    return path.read_text(encoding='utf-8').strip() or None


def sg02_available_key_ids() -> list[str]:
    """key_id dei gruppi presenti, ricavati dai nomi dei file .pub."""
    pub_dir = settings.paths.sg02_dir / 'pub'
    if not pub_dir.is_dir():
        return []
    out = []
    for f in sorted(pub_dir.glob('*.pub')):
        stem = f.stem
        out.append(stem.split('_', 1)[1] if '_' in stem else stem)
    return out


def sg02_public_key_path(key_id: str | None = None) -> Path:
    """Percorso del file .pub prodotto da keygen.

    Usare la chiave pubblica al posto del keystore permette di cancellare
    ogni traccia di materiale privato dal TCN dopo la distribuzione ai
    token: `thetacli` accetta --pubkey e load_key lo preferisce al
    keystore.
    """
    pub_dir = settings.paths.sg02_dir / 'pub'
    # Ordine: quello richiesto, poi quello registrato come corrente.
    key_id = (key_id or '').strip() or current_key_id()
    pattern = f'*_{key_id}.pub' if key_id else '*.pub'
    candidates = sorted(pub_dir.glob(pattern))
    if not candidates:
        if key_id:
            raise PublicKeyNotFound(
                f'nessuna chiave pubblica con key_id {key_id!r} in '
                f'{pub_dir}. Lasciare key_id vuoto per usare l\'unica '
                'presente, oppure generare il gruppo con POST '
                '/sg02/groups.')
        raise PublicKeyNotFound(
            f'nessuna chiave pubblica in {pub_dir}: generare il gruppo '
            'con POST /sg02/groups.')
    if len(candidates) > 1 and key_id is None:
        raise PublicKeyNotFound(
            f'{len(candidates)} gruppi presenti e nessuno registrato '
            'come corrente: indicare key_id, oppure rigenerare con '
            'reset=true. Disponibili: '
            + ', '.join(sg02_available_key_ids()))
    return candidates[0]


def sg02_encrypt(plaintext: bytes, label: str,
                 key_id: str | None = None) -> bytes:
    """`thetacli enc`. Usa solo la chiave pubblica."""
    pubkey = sg02_public_key_path(key_id)
    with volatile_workdir() as wd:
        pt = wd / 'pt.bin'
        ct = wd / 'ct.enc'
        pt.write_bytes(plaintext)
        _run(_thetacli(), [
            'enc',
            f'--infile={pt}',
            f'--pubkey={pubkey}',
            f'--label={label}',
            f'--output={ct}',
        ])
        return ct.read_bytes()


def sg02_partial_decrypt(node_id: int, ciphertext: bytes, key_id: str,
                         label: str) -> str:
    """`thetacli dec`. Share software, per i nodi senza token.

    Ripiego: richiede che il keystore privato del nodo sia ancora
    presente sul TCN, cosa che dopo la distribuzione non e' piu' vera.
    Nell'architettura a token non viene usato.

    Restituisce la share gia' in base64, letta da file: `dec` scrive su
    stdout anche l'intestazione "Share Calcolata", quindi --output e'
    l'unica lettura affidabile.
    """
    with volatile_workdir() as wd:
        ct = wd / 'ct.enc'
        out = wd / 'share.b64'
        ct.write_bytes(ciphertext)
        _run(_thetacli(), [
            'dec',
            f'--pvtshare={keystore_path(node_id)}',
            f'--key-id={key_id}',
            f'--ciph={ct}',
            f'--label={label}',
            f'--output={out}',
        ])
        return out.read_text().strip()


def sg02_assemble(ciphertext: bytes, partials: list[str],
                  key_id: str | None = None) -> bytes:
    """`thetacli assemble`. Aggrega k share verificate e restituisce il
    plaintext.

    Il risultato si legge da file: assemble stampa su stdout una riga per
    ogni share verificata prima del plaintext.
    """
    pubkey = sg02_public_key_path(key_id)
    with volatile_workdir() as wd:
        ct = wd / 'ct.enc'
        out = wd / 'plain.bin'
        ct.write_bytes(ciphertext)
        _run(_thetacli(), [
            'assemble',
            f'--pubkey={pubkey}',
            f'--ciph={ct}',
            f'--output={out}',
            f'--partials={",".join(partials)}',
        ])
        if not out.exists():
            raise ToolError(
                'thetacli', ['assemble'], -2,
                'assemble non ha prodotto alcun plaintext. Due cause '
                'possibili: meno di k share fornite, oppure share '
                'scartate da verify_share perche\' calcolate con una '
                'chiave privata che non corrisponde a questa chiave '
                'pubblica (tipico dopo un keygen senza reimportare le '
                'share sui token).')
        return out.read_bytes()


# =====================================================================
# pfse_tool_bn254 — schema GMPpke
# =====================================================================
def _pfse():
    return settings.paths.pfse_tool


def ppke_keygen(d: int | None = None) -> tuple[bytes, bytearray]:
    """`pfse_tool_bn254 keygen <pk> <sk> [d]`.

    Restituisce (pk, sk). La PK e' pubblica e puo' essere persistita; la
    SK torna in un bytearray perche' il chiamante deve poterla azzerare
    con zeroize() subito dopo la distribuzione ai token.

    Il binario scrive la SK su file: la generiamo su tmpfs e la
    rimuoviamo all'uscita del context manager. Questa e' l'unica finestra
    in cui il TCN conosce il segreto.
    """
    d = d or settings.schemes.d
    with volatile_workdir() as wd:
        pk_file = wd / 'pk.bin'
        sk_file = wd / 'sk.bin'
        _run(_pfse(), ['keygen', pk_file, sk_file, d])
        return pk_file.read_bytes(), bytearray(sk_file.read_bytes())


def ppke_encrypt(pk: bytes, tags: list[str],
                 plaintext: bytes) -> tuple[bytes, bytes]:
    """`pfse_tool_bn254 encrypt <pk> <tags_csv> <pt> <ct_pfse> <ct_sym>`.

    Richiede esattamente d tag: ogni ciphertext e' legato a d maniglie di
    cancellazione indipendenti, e punzonarne una qualsiasi lo rende
    indecifrabile.

    Usa solo la chiave pubblica, quindi e' eseguibile sul TCN senza che
    alcun segreto sia presente.
    """
    d = settings.schemes.d
    if len(tags) != d:
        raise ValueError(f'attesi {d} tag, ricevuti {len(tags)}')
    if any(',' in t for t in tags):
        raise ValueError('un tag non puo\' contenere virgole')

    with volatile_workdir() as wd:
        pk_file = wd / 'pk.bin'
        pt_file = wd / 'pt.bin'
        ct_pfse = wd / 'ct_pfse.bin'
        ct_sym = wd / 'ct_sym.bin'
        pk_file.write_bytes(pk)
        pt_file.write_bytes(plaintext)
        _run(_pfse(), ['encrypt', pk_file, ','.join(tags),
                       pt_file, ct_pfse, ct_sym])
        return ct_pfse.read_bytes(), ct_sym.read_bytes()
