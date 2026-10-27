#!/usr/bin/env python3
"""
verify_tcn.py — verifica end-to-end dello stack TCN su hardware reale.

Esercita ogni livello (trasporto, conversioni, wrapper dei binari,
registry, ledger, servizi) senza passare per HTTP, cosi' che un problema
si manifesti a un livello solo ed emerga dove nasce.

    python3 verify_tcn.py --phases preflight,discover
    python3 verify_tcn.py --all --yes

ATTENZIONE — le fasi oltre `discover` sono distruttive:

  sg02-setup     `thetacli keygen --new` cancella il gruppo esistente,
                 sovrascrive la share SG02 su ogni token e infine
                 cancella i keystore privati dal TCN
  ppke-setup     ImportKey con P1=Replace azzera TUTTE le punzonature
                 gia' effettuate sui token
  puncture       consuma capacita' in modo IRREVERSIBILE: ogni token
                 tollera MAX_PUNCTURES punzonature e non si torna
                 indietro

Non eseguirle su token in esercizio. Servono `--yes` per procedere.

Il collegamento fra lettori e nodi, al primo setup, e' posizionale: i
lettori vengono ordinati per nome e associati ai keystore 1..n. Prima
dell'import il token non ha un node_id, quindi non c'e' altro criterio;
dopo l'import l'identita' si legge con INS 0x05.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import time
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))

# Il package va cercato accanto allo script, ma anche un livello sopra:
# se questo file viene copiato dentro tcn/, la sua directory contiene i
# moduli, non il package, e `import tcn` fallirebbe.
for _candidate in (_HERE, os.path.dirname(_HERE)):
    if os.path.isfile(os.path.join(_candidate, 'tcn', '__init__.py')):
        sys.path.insert(0, _candidate)
        break
else:
    sys.exit(
        'package `tcn` non trovato.\n'
        f'Cercato in {_HERE} e nella directory superiore.\n'
        'Posizionare verify_tcn.py accanto alla cartella tcn/, e '
        'verificare che tcn/__init__.py esista.')

PHASES = ['preflight', 'discover', 'sg02-setup', 'sg02-e2e',
          'ppke-setup', 'ppke-e2e', 'puncture', 'errors']

DESTRUCTIVE = {'sg02-setup', 'ppke-setup', 'puncture'}

# Costante cablata in trussed-sg02-backend: se la chiave del dealer sul
# TCN non corrisponde, ogni ImportKeyShare fallira' con SW 6982.
FIRMWARE_DEALER_PK = bytes([
    0xb5, 0x2a, 0x0a, 0xa6, 0x3a, 0xe1, 0x97, 0xae,
    0x5b, 0x46, 0x81, 0x2c, 0x94, 0x25, 0x3d, 0xec,
    0x76, 0x30, 0x61, 0x9f, 0x28, 0xd2, 0xc5, 0xca,
    0xa2, 0x72, 0xf9, 0x7a, 0x28, 0x63, 0x6b, 0xa8,
])

_state: dict = {}
_failures: list[str] = []


# ---------------------------------------------------------------------
# Presentazione
# ---------------------------------------------------------------------
def phase(name: str) -> None:
    print(f'\n\033[1m── {name} {"─" * max(0, 62 - len(name))}\033[0m')


def ok(msg: str, extra: str = '') -> None:
    tail = f'  \033[2m{extra}\033[0m' if extra else ''
    print(f'  \033[32m✓\033[0m {msg}{tail}')


def fail(msg: str, detail: str = '') -> None:
    _failures.append(msg)
    print(f'  \033[31m✗\033[0m {msg}')
    if detail:
        for line in detail.strip().splitlines():
            print(f'      \033[2m{line}\033[0m')


def note(msg: str) -> None:
    print(f'  \033[2m·\033[0m \033[2m{msg}\033[0m')


def get_dealer():
    """Carica la chiave del dealer alla prima richiesta.

    Le fasi non devono dipendere dall'ordine in cui vengono lanciate:
    memorizzarla solo durante il preflight rendeva sg02-setup
    inutilizzabile da solo.
    """
    if 'dealer' in _state:
        return _state['dealer']
    from tcn.dealer import Dealer, DealerKeyError
    try:
        _state['dealer'] = Dealer()
    except DealerKeyError:
        _state['dealer'] = None
    return _state['dealer']


def timed(label: str, fn, *args, **kwargs):
    t0 = time.perf_counter()
    value = fn(*args, **kwargs)
    dt = (time.perf_counter() - t0) * 1000
    ok(label, f'{dt:.0f} ms')
    return value


# ---------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------
def do_preflight(args) -> None:
    phase('preflight — dipendenze e configurazione')

    import tcn.transport as transport
    from tcn.config import settings, ensure_dirs

    if transport.PCSC_AVAILABLE:
        ok('pyscard disponibile')
    else:
        fail('pyscard non installato', 'pip install pyscard')

    try:
        import nacl.bindings  # noqa: F401
        ok('PyNaCl disponibile')
    except ImportError:
        fail('PyNaCl non installato', 'pip install pynacl')

    for label, path in (('thetacli', settings.paths.thetacli),
                        ('pfse_tool_bn254', settings.paths.pfse_tool)):
        if path.exists() and os.access(path, os.X_OK):
            ok(f'{label} eseguibile', str(path))
        else:
            fail(f'{label} assente o non eseguibile', str(path))

    try:
        ensure_dirs()
        ok('directory di stato pronte', str(settings.paths.state_dir))
    except Exception as exc:
        fail('directory di stato non utilizzabile', str(exc))

    vol = settings.paths.volatile_dir
    if str(vol).startswith('/dev/shm'):
        ok('directory volatile su tmpfs', str(vol))
    else:
        fail('directory volatile NON su tmpfs',
             f'{vol}: la SK GMPpke finirebbe su disco')

    dealer = get_dealer()
    if dealer is None:
        fail('chiave del dealer non caricabile',
             f'attesa in {settings.paths.dealer_key}')
    else:
        if dealer.matches_firmware(FIRMWARE_DEALER_PK):
            ok('chiave del dealer allineata al firmware')
        else:
            fail('chiave del dealer DIVERSA da quella cablata nel firmware',
                 f'TCN      : {dealer.public_key_bytes().hex()}\n'
                 f'firmware : {FIRMWARE_DEALER_PK.hex()}\n'
                 'Ogni ImportKeyShare fallira\' con SW 6982.')

    s = settings.schemes
    note(f'parametri: k={s.k} n={s.n} d={s.d} '
         f'max_punctures={s.max_punctures}')


# ---------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------
def do_discover(args) -> None:
    phase('discover — scoperta dei token')

    from tcn.tokens.registry import Registry
    from tcn.transport import TransportError

    registry = Registry()
    _state['registry'] = registry

    try:
        tokens = timed('scansione dei lettori', registry.scan)
    except TransportError as exc:
        fail('scansione impossibile', str(exc))
        note('verificare che pcscd sia attivo: systemctl status pcscd')
        return
    if not tokens:
        fail('nessun token trovato',
             'pcscd attivo? Nitrokey inserite? Provare `pcsc_scan`.')
        return

    for t in tokens:
        if t.node_id is not None:
            ok(f'{t.reader}', f'node_id={t.node_id}')
        elif t.theta_app:
            note(f'{t.reader} — theta-app presente, nessuna share importata')
        else:
            fail(f'{t.reader} — theta-app non risponde',
                 'firmware senza theta-app, oppure INS 0x05 non riconosciuto '
                 '(SW 6D00): verificare che 0x05 finisca in '
                 'Instruction::Unknown')

    provisioned = registry.nodes()
    if provisioned:
        ok(f'{len(provisioned)} token con node_id leggibile',
           f'nodi {provisioned}')
        ok('INS 0x05 GetNodeId funzionante')

    from tcn.config import settings
    if len(tokens) < settings.schemes.k:
        fail(f'{len(tokens)} token per una soglia k={settings.schemes.k}',
             'la decifratura a soglia non sara\' possibile')


# ---------------------------------------------------------------------
# sg02-setup
# ---------------------------------------------------------------------
def do_sg02_setup(args) -> None:
    phase('sg02-setup — gruppo, distribuzione, cancellazione keystore')

    from tcn.config import settings
    from tcn.services.sg02 import Sg02Service
    from tcn.tokens.registry import Registry

    registry = _state.get('registry')
    if registry is None:
        fail('scansione dei token non riuscita: fase discover fallita')
        return
    assert registry is not None
    service = Sg02Service(registry, get_dealer())
    _state['sg02'] = service

    tokens = registry.tokens()
    n = min(len(tokens), settings.schemes.n)
    if n < settings.schemes.k:
        fail('token insufficienti per la soglia configurata')
        return

    group = timed(f'keygen k={settings.schemes.k} n={n}',
                  service.setup_group, n=n, reset=True)
    _state['group'] = group
    note(f'key_id={group.key_id}')
    ok('chiave pubblica prodotta', str(group.public_key))

    note('associazione posizionale lettore → keystore (token ancora vergini)')
    distributed = []
    for index, token in enumerate(tokens[:n], start=1):
        try:
            t0 = time.perf_counter()
            res = service.distribute(reader=token.reader,
                                     keystore_index=index)
            dt = (time.perf_counter() - t0) * 1000
        except Exception as exc:
            fail(f'import su {token.reader}', str(exc))
            continue
        if res.ok:
            ok(f'share {index} → {token.reader}',
               f'node_id={res.node_id}, {dt:.0f} ms')
            distributed.append(res.node_id)
        else:
            fail(f'import su {token.reader}', res.error)

    registry.scan()
    resolved = registry.nodes()
    if sorted(resolved) == sorted(distributed) and distributed:
        ok('node_id riletti dai token dopo l\'import', f'nodi {resolved}')
    else:
        fail('node_id riletti non coincidono con quelli distribuiti',
             f'attesi {sorted(distributed)}, letti {sorted(resolved)}')

    if len(distributed) != n:
        fail('distribuzione incompleta: i keystore NON vengono cancellati',
             f'{len(distributed)}/{n} share importate. Cancellarli ora '
             'distruggerebbe l\'unica copia di una share mai consegnata '
             'al token.')
        note('correggere la causa e rilanciare sg02-setup')
        return

    removed = service.wipe_keystores()
    ok('keystore privati cancellati dal TCN', f'nodi {removed}')
    note('da qui in avanti il TCN non detiene alcuna share SG02')


# ---------------------------------------------------------------------
# sg02-e2e
# ---------------------------------------------------------------------
def do_sg02_e2e(args) -> None:
    phase('sg02-e2e — cifratura e decifratura a soglia')

    from tcn.config import settings
    from tcn.convert.sg02_der import extract_u_sg02
    from tcn.services.sg02 import Sg02Service, ThresholdNotReached

    registry = _state.get('registry')
    if registry is None:
        fail('registry non disponibile: la fase discover non e\' riuscita')
        return
    service: Sg02Service = _state.get('sg02') or Sg02Service(
        registry, get_dealer())

    plaintext = b'verify-tcn-sg02-' + secrets.token_hex(16).encode()
    label = 'VERIFY'

    try:
        ct = timed('encrypt con --pubkey', service.encrypt, plaintext, label)
    except Exception as exc:
        fail('encrypt fallita', str(exc))
        note('se l\'errore riguarda argomenti mancanti, `thetacli enc` '
             'potrebbe pretendere --key-id anche con --pubkey')
        return
    ok('ciphertext prodotto', f'{len(ct)} B')

    u_raw, embedded = extract_u_sg02(ct)
    if embedded == label.encode():
        ok('label estratta dal ciphertext', embedded.decode())
    else:
        fail('label estratta diversa da quella usata',
             f'attesa {label!r}, letta {embedded!r}')

    nodes = registry.nodes()
    for node in nodes[:settings.schemes.k]:
        try:
            share = timed(f'decryption share dal nodo {node} (INS 0x02)',
                          service.collect_share, node, u_raw, embedded)
            note(f'share DER base64, {len(share)} caratteri')
        except Exception as exc:
            fail(f'share dal nodo {node}', str(exc))
            note('SW 6700 o risposta troncata indicano che il byte Le '
                 'dell\'APDU corto non e\' gradito: rimuoverlo in '
                 'transport.transmit per il ramo SG02')

    try:
        recovered = timed(f'decrypt a soglia k={settings.schemes.k}',
                          service.decrypt, ct)
    except ThresholdNotReached as exc:
        fail('soglia non raggiunta', str(exc))
        return
    except Exception as exc:
        fail('decrypt fallita', str(exc))
        return

    if recovered == plaintext:
        ok('plaintext recuperato identico all\'originale')
    else:
        fail('plaintext DIVERSO dall\'originale',
             f'atteso  {plaintext!r}\nottenuto {recovered!r}')


# ---------------------------------------------------------------------
# ppke-setup
# ---------------------------------------------------------------------
def do_ppke_setup(args) -> None:
    phase('ppke-setup — keygen GMPpke e distribuzione a tutti i token')

    from tcn.config import settings
    from tcn.services.ppke import PpkeService

    registry = _state.get('registry')
    if registry is None:
        fail('registry non disponibile: la fase discover non e\' riuscita')
        return
    service = PpkeService(registry)
    _state['ppke'] = service

    note('ImportKey con P1=Replace: azzera ogni punzonatura sui token')
    try:
        setup = timed(f'keygen d={settings.schemes.d} + distribuzione',
                      service.setup_keys)
    except Exception as exc:
        fail('setup GMPpke fallito', str(exc))
        return

    ok(f'chiave generata', f'd={setup.d}, {setup.shares} share nella SK')
    if setup.distributed:
        ok('SK importata sui token', f'nodi {setup.distributed}')
    for node, err in setup.failed.items():
        fail(f'import GMPpke sul nodo {node}', err)

    if not settings.paths.ppke_pk.exists():
        fail('chiave pubblica non persistita')
    else:
        ok('chiave pubblica salvata', str(settings.paths.ppke_pk))
    note('la SK non e\' stata scritta sullo stato persistente del TCN')


# ---------------------------------------------------------------------
# ppke-e2e
# ---------------------------------------------------------------------
def _ppke_tags(prefix: str) -> list[str]:
    from tcn.config import settings
    d = settings.schemes.d
    return [f'{prefix}-{i}' for i in range(1, d + 1)]


def do_ppke_e2e(args) -> None:
    phase('ppke-e2e — cifratura e decifratura sul token')

    from tcn import planner
    from tcn.services.ppke import PpkeService
    from tcn.tokens.ppke import DecryptVariant

    registry = _state.get('registry')
    if registry is None:
        fail('registry non disponibile: la fase discover non e\' riuscita')
        return
    service: PpkeService = _state.get('ppke') or PpkeService(registry)

    nodes = registry.nodes()
    if not nodes:
        fail('nessun token disponibile')
        return
    node = nodes[0]

    plaintext = b'verify-tcn-ppke-' + secrets.token_hex(16).encode()
    tags = _ppke_tags('verify-alpha')

    try:
        ct_pfse, ct_sym = timed(f'encrypt su {len(tags)} tag',
                                service.encrypt, plaintext, tags)
    except Exception as exc:
        fail('encrypt GMPpke fallita', str(exc))
        return
    ok('crittogrammi prodotti',
       f'ct_pfse={len(ct_pfse)} B, ct_sym={len(ct_sym)} B')
    _state['ct_alpha'] = (ct_pfse, ct_sym, plaintext, tags)

    try:
        fw_ct = service.to_fw_ct(ct_pfse)
        ok('conversione cereal/RELIC → arkworks', f'{len(fw_ct)} B')
    except Exception as exc:
        fail('conversione del ciphertext fallita', str(exc))
        return

    choice = planner.choose(0)
    note(f'variante scelta: INS 0x{int(choice.variant):02X} — {choice.reason}')

    try:
        recovered = timed(f'decrypt sul nodo {node}',
                          service.decrypt, node, ct_pfse, ct_sym)
    except Exception as exc:
        fail('decrypt GMPpke fallita', str(exc))
        note('APDU esteso rifiutato dal lettore? Il payload supera i 255 B')
        return

    if recovered == plaintext:
        ok('plaintext recuperato identico all\'originale')
    else:
        fail('plaintext DIVERSO dall\'originale')

    if args.variants:
        note('confronto fra le varianti di decrypt (stesso ciphertext)')
        for variant in DecryptVariant:
            try:
                t0 = time.perf_counter()
                out = service.decrypt(node, ct_pfse, ct_sym, variant)
                dt = (time.perf_counter() - t0) * 1000
            except Exception as exc:
                fail(f'INS 0x{int(variant):02X} {variant.name}', str(exc))
                continue
            correct = out == plaintext
            (ok if correct else fail)(
                f'INS 0x{int(variant):02X} {variant.name}',
                f'{dt:.0f} ms' if correct else 'plaintext diverso')


# ---------------------------------------------------------------------
# puncture
# ---------------------------------------------------------------------
def do_puncture(args) -> None:
    phase('puncture — campagna su tutti i token e verifica dell\'effetto')

    from tcn.services.ppke import PpkeService, TokensMissing
    from tcn.tokens.ppke import Punctured

    registry = _state.get('registry')
    if registry is None:
        fail('registry non disponibile: la fase discover non e\' riuscita')
        return
    service: PpkeService = _state.get('ppke') or PpkeService(registry)

    if 'ct_alpha' not in _state:
        fail('nessun ciphertext dalla fase ppke-e2e',
             'eseguire ppke-e2e prima di puncture')
        return
    ct_pfse, ct_sym, plaintext, tags = _state['ct_alpha']

    # Secondo crittogramma su tag distinti: deve restare decifrabile
    beta_tags = _ppke_tags('verify-beta')
    beta_plain = b'verify-tcn-beta-' + secrets.token_hex(8).encode()
    ct_beta, ct_beta_sym = service.encrypt(beta_plain, beta_tags)
    ok('secondo crittogramma su tag distinti', f'tag {beta_tags[0]}...')

    note(f'roster atteso: {service.roster()}')
    target = tags[0]

    try:
        campaign = timed(f'campagna di punzonatura su {target!r}',
                         service.puncture, target)
    except TokensMissing as exc:
        fail('campagna rifiutata', str(exc))
        return
    except Exception as exc:
        fail('campagna fallita', str(exc))
        return

    ok(f'campagna {campaign.id}', f'stato: {campaign.status.value}')
    for node, outcome in sorted(campaign.nodes.items()):
        detail = campaign.detail.get(node, '')
        (ok if outcome.value == 'done' else fail)(
            f'  nodo {node}: {outcome.value}', detail)

    if campaign.status.value != 'complete':
        fail('la cancellazione NON e\' avvenuta su tutti i token',
             f'incerti: {campaign.unresolved}, da rifare: {campaign.remaining}')
        note(f'riprendere con service.resume({campaign.id!r})')

    # Effetto atteso: il primo ciphertext non e' piu' decifrabile su
    # nessun token, il secondo lo e' ancora.
    for node in registry.nodes():
        try:
            service.decrypt(node, ct_pfse, ct_sym)
            fail(f'nodo {node}: il ciphertext punzonato e\' ANCORA decifrabile')
        except Punctured:
            ok(f'nodo {node}: ciphertext punzonato rifiutato (SW 6982)')
        except Exception as exc:
            fail(f'nodo {node}: errore inatteso', str(exc))

    node = registry.nodes()[0]
    try:
        out = service.decrypt(node, ct_beta, ct_beta_sym)
        (ok if out == beta_plain else fail)(
            f'nodo {node}: il secondo crittogramma decifra ancora')
    except Exception as exc:
        fail('il secondo crittogramma non decifra piu\'', str(exc))

    ok('allineamento dei token', str(service.aligned()))
    for r in service.report():
        note(f'nodo {r.node_id}: punzonati={r.punctured} '
             f'incerti={r.uncertain} capacita={r.capacity}')


# ---------------------------------------------------------------------
# errors — classificazione degli status word
# ---------------------------------------------------------------------
def _invalid_edwards_point() -> bytes:
    """Un punto compresso che NON sta sulla curva di Edwards.

    Cerca una y per cui x^2 = (y^2-1)/(d*y^2+1) non e' un residuo
    quadratico: il firmware deve rifiutarlo in decompressione.
    """
    P = 2 ** 255 - 19
    D = -121665 * pow(121666, P - 2, P) % P
    for y in range(2, 2000):
        y2 = y * y % P
        den = (D * y2 + 1) % P
        if den == 0:
            continue
        x2 = (y2 - 1) * pow(den, P - 2, P) % P
        if x2 == 0:
            continue
        if pow(x2, (P - 1) // 2, P) != 1:      # non residuo
            return y.to_bytes(32, 'little')
    raise RuntimeError('nessun punto non valido trovato')


def do_errors(args) -> None:
    phase('errors — ogni condizione produce il proprio status word')

    from tcn.tokens import ppke as ppke_token
    from tcn.tokens import sg02 as sg02_token
    from tcn.transport import AID_PPKE, AID_SG02, ApduError

    registry = _state.get('registry')
    if registry is None:
        fail('registry non disponibile: la fase discover non e\' riuscita')
        return
    nodes = registry.nodes()
    if not nodes:
        fail('nessun token provisionato')
        return
    node = nodes[0]

    note('nessuna di queste prove modifica lo stato del dispositivo: '
         'ogni operazione viene rifiutata prima di scrivere')

    def expect(label, aid, fn, wanted):
        try:
            with registry.session(node_id=node, aid=aid) as ch:
                fn(ch)
        except wanted as exc:
            ok(f'{label}', f'{type(exc).__name__}')
            return
        except ApduError as exc:
            fail(f'{label}', f'atteso {wanted.__name__}, ricevuto '
                             f'ApduError SW={exc.sw:04X}')
            return
        except Exception as exc:
            fail(f'{label}', f'atteso {wanted.__name__}, ricevuto '
                             f'{type(exc).__name__}: {exc}')
            return
        fail(f'{label}', 'nessun errore: il dispositivo ha accettato '
                         'un input che doveva rifiutare')

    # ---- SG02 -------------------------------------------------------
    note('SG02')
    expect('firma del dealer non valida -> SW 6982', AID_SG02,
           lambda ch: sg02_token.import_key_share(
               ch, bytes(32), 9999, bytes(64)),
           sg02_token.DealerSignatureRejected)

    expect('U non sulla curva -> SW 6A80', AID_SG02,
           lambda ch: sg02_token.partial_decrypt(
               ch, _invalid_edwards_point()),
           sg02_token.MalformedPayload)

    # ---- GMPpke -----------------------------------------------------
    note('GMPpke')
    expect('ciphertext non interpretabile -> SW 6A80', AID_PPKE,
           lambda ch: ppke_token.decrypt(ch, bytes(200)),
           ppke_token.MalformedPayload)

    # NULLTAG e' il tag riservato alla share base: il backend lo rifiuta
    nulltag = (b'whoever wishes to keep a secret, must hide from us that '
               b'he possesses one.-- Johann Wolfgang von Goethe')
    expect('tag riservato (NULLTAG) -> SW 6700', AID_PPKE,
           lambda ch: ppke_token.puncture(ch, nulltag),
           ppke_token.MalformedPayload)

    note('lo stato del token non e\' cambiato: nessuna punzonatura '
         'consumata, nessuna share sovrascritta')


# ---------------------------------------------------------------------
# main
# ---------------------------------------------------------------------
RUNNERS = {
    'preflight': do_preflight,
    'discover': do_discover,
    'sg02-setup': do_sg02_setup,
    'sg02-e2e': do_sg02_e2e,
    'ppke-setup': do_ppke_setup,
    'ppke-e2e': do_ppke_e2e,
    'puncture': do_puncture,
    'errors': do_errors,
}


def main() -> int:
    ap = argparse.ArgumentParser(
        description='Verifica end-to-end dello stack TCN.')
    ap.add_argument('--phases', default='preflight,discover',
                    help=f'elenco separato da virgole fra: {", ".join(PHASES)}')
    ap.add_argument('--all', action='store_true',
                    help='esegue tutte le fasi (distruttivo)')
    ap.add_argument('--yes', action='store_true',
                    help='conferma le fasi distruttive senza chiedere')
    ap.add_argument('--variants', action='store_true',
                    help='in ppke-e2e prova tutte le varianti di decrypt')
    args = ap.parse_args()

    selected = PHASES if args.all else [p.strip() for p in
                                        args.phases.split(',') if p.strip()]
    unknown = [p for p in selected if p not in RUNNERS]
    if unknown:
        print(f'fasi sconosciute: {unknown}', file=sys.stderr)
        return 2

    danger = [p for p in selected if p in DESTRUCTIVE]
    if danger and not args.yes:
        print(f'\n\033[33mLe fasi {danger} sono distruttive.\033[0m')
        print('Sovrascrivono le chiavi sui token e consumano capacita\' di')
        print('punzonatura in modo irreversibile. Rilanciare con --yes.\n')
        return 3

    # discover e' presupposto da tutto il resto
    if any(p not in ('preflight', 'discover') for p in selected) \
            and 'discover' not in selected:
        selected.insert(0, 'discover')

    t0 = time.perf_counter()
    for name in selected:
        try:
            RUNNERS[name](args)
        except Exception:
            fail(f'fase {name} interrotta da un\'eccezione',
                 traceback.format_exc(limit=8))

    elapsed = time.perf_counter() - t0
    phase('esito')
    if _failures:
        print(f'  \033[31m{len(_failures)} verifiche fallite\033[0m '
              f'in {elapsed:.1f}s')
        for f in _failures:
            print(f'    · {f}')
        return 1

    print(f'  \033[32mtutte le verifiche superate\033[0m in {elapsed:.1f}s')
    return 0


if __name__ == '__main__':
    sys.exit(main())
