"""
tcn.cli.sg02 — schema a soglia SG02 su Ed25519.

L'ordine dei comandi di setup conta: keygen, distribute, wipe-keystores.
Fra il primo e il terzo il nodo centrale detiene tutte le share insieme e
la proprieta' di soglia non protegge nulla. Il terzo passo non e'
facoltativo.
"""

from __future__ import annotations

import base64

from .common import CliError, emit, info, read_blob, table, write_blob


def register(sub) -> None:
    grp = sub.add_parser('sg02', help='crittografia a soglia')
    s = grp.add_subparsers(dest='subcommand', required=True)

    p = s.add_parser('keygen', help='genera un gruppo k-su-n')
    p.add_argument('-k', type=int, help='soglia')
    p.add_argument('-n', type=int, help='numero di nodi')
    p.add_argument('--reset', action='store_true',
                   help='cancella il gruppo esistente (distruttivo)')
    p.set_defaults(func=cmd_keygen)

    p = s.add_parser('group', help='gruppo registrato come attivo')
    p.set_defaults(func=cmd_group, needs_lock=False)

    p = s.add_parser('distribute', help='importa le share sui token')
    p.add_argument('--reader', help='un singolo token, per lettore')
    p.add_argument('--node', type=int, help='un singolo token, per node_id')
    p.add_argument('--keystore-index', type=int,
                   help='quale keystore usare (obbligatorio con --reader)')
    p.set_defaults(func=cmd_distribute)

    p = s.add_parser('wipe-keystores',
                     help='cancella dal nodo centrale le share private')
    p.add_argument('--yes', action='store_true', help='senza conferma')
    p.add_argument('--force', action='store_true',
                   help='cancella anche con la distribuzione incompleta')
    p.set_defaults(func=cmd_wipe)

    p = s.add_parser('encrypt', help='cifra con la chiave pubblica')
    p.add_argument('-i', '--input', help="file da cifrare, '-' per stdin")
    p.add_argument('--label', required=True)
    p.add_argument('-o', '--output', help="crittogramma, '-' per stdout")
    p.add_argument('--key-id')
    p.set_defaults(func=cmd_encrypt, needs_lock=False)

    p = s.add_parser('share', help='decifratura parziale su un token')
    p.add_argument('--node', type=int, required=True)
    p.add_argument('-i', '--input', help='crittogramma')
    p.add_argument('-o', '--output', help='share in DER base64')
    p.set_defaults(func=cmd_share)

    p = s.add_parser('decrypt', help='raccoglie k share e aggrega')
    p.add_argument('-i', '--input', help='crittogramma')
    p.add_argument('-o', '--output', help="plaintext, '-' per stdout")
    p.add_argument('--nodes', help='restringe i token, es. 1,2,3')
    p.add_argument('--key-id')
    p.set_defaults(func=cmd_decrypt)


def _nodes(arg: str | None) -> list[int] | None:
    if not arg:
        return None
    try:
        return [int(x) for x in arg.split(',') if x.strip()]
    except ValueError:
        raise CliError(f'elenco di nodi non valido: {arg!r}', 2) from None


# ---------------------------------------------------------------------
def cmd_keygen(ctx) -> int:
    a = ctx.args
    if a.reset:
        info('--reset: il gruppo esistente viene cancellato; le share '
             'gia\' sui token diventano inservibili')
    group = ctx.sg02().setup_group(k=a.k, n=a.n, reset=a.reset)
    emit({'key_id': group.key_id, 'k': group.k, 'n': group.n,
          'public_key': str(group.public_key)},
         f'gruppo k={group.k} su n={group.n}\n'
         f'  key_id        {group.key_id}\n'
         f'  chiave pubbl. {group.public_key}')
    info('passo successivo: tcn sg02 distribute')
    return 0


def cmd_group(ctx) -> int:
    group = ctx.sg02().current_group()
    emit({'key_id': group.key_id, 'k': group.k, 'n': group.n,
          'public_key': str(group.public_key)},
         f'key_id {group.key_id}\nchiave pubblica {group.public_key}')
    return 0


def cmd_distribute(ctx) -> int:
    a = ctx.args
    service = ctx.sg02_with_dealer()
    results = []

    if a.reader or a.node is not None:
        if a.reader and a.keystore_index is None:
            raise CliError(
                '--keystore-index e\' obbligatorio con --reader: prima '
                'dell\'import il token non ha un node_id, quindi non c\'e\' '
                'modo di dedurre quale share gli spetti.', 2)
        results.append(service.distribute(
            node_id=a.node, reader=a.reader,
            keystore_index=a.keystore_index))
    else:
        from ..config import settings
        tokens = ctx.scanned_registry().tokens()
        expected = settings.schemes.n
        info(f'{len(tokens)} token collegati su n={expected}, '
             'associazione posizionale ai keystore 1..n')
        for index, token in enumerate(tokens[:expected], start=1):
            results.append(service.distribute(reader=token.reader,
                                              keystore_index=index))

    payload = {'distributions': [
        {'node_id': r.node_id, 'reader': r.reader, 'ok': r.ok,
         'error': r.error} for r in results]}
    emit(payload, table([(r.node_id, 'ok' if r.ok else 'FALLITO',
                          r.error or r.reader) for r in results],
                        ('node_id', 'esito', 'dettaglio')))

    from ..config import settings
    expected = settings.schemes.n
    ok_count = sum(1 for r in results if r.ok)
    failed = [r for r in results if not r.ok]

    if failed:
        for r in failed:
            info(f'  ! nodo {r.node_id}: {r.error}')
    if ok_count < expected:
        info('')
        info(f'DISTRIBUZIONE INCOMPLETA: {ok_count} share su {expected}.')
        info('NON eseguire wipe-keystores: cancellerebbe le share mai '
             'consegnate, e il gruppo andrebbe rigenerato da capo.')
        info('Collegare i token mancanti e ripetere, oppure rigenerare '
             'il gruppo con un n coerente (TCN_SG02_N).')
        return 1

    info('passo successivo: tcn sg02 wipe-keystores')
    return 0


def cmd_wipe(ctx) -> int:
    from ..config import settings
    provisioned = ctx.scanned_registry().nodes()
    expected = settings.schemes.n
    if ctx.args.force and len(provisioned) < expected:
        info(f'--force: solo {len(provisioned)} token su {expected} sono '
             'provisionati; le share mancanti vengono distrutte')
    if not ctx.args.yes:
        reply = input('Cancellare le share private dal nodo centrale? '
                      'Procedere solo se tutti i token sono stati '
                      'provisionati [s/N] ')
        if reply.strip().lower() not in ('s', 'si', 'sì', 'y', 'yes'):
            info('annullato')
            return 1
    removed = ctx.sg02().wipe_keystores(force=ctx.args.force)
    emit({'removed': removed},
         f'keystore cancellati: {removed}' if removed
         else 'nessun keystore da cancellare')
    if removed:
        info('le share SG02 esistono ora solo nei token')
    return 0


def cmd_encrypt(ctx) -> int:
    a = ctx.args
    data = read_blob(a.input, 'plaintext')
    ct = ctx.sg02().encrypt(data, a.label, a.key_id)
    if ctx_json(ct, a):
        return 0
    write_blob(a.output, ct, 'crittogramma')
    return 0


def ctx_json(ct: bytes, a) -> bool:
    """Con --json il binario non puo' andare su stdout: lo si codifica."""
    from .common import is_json
    if not is_json():
        return False
    emit({'ciphertext': base64.b64encode(ct).decode(), 'size': len(ct)})
    return True


def cmd_share(ctx) -> int:
    from ..convert.sg02_der import (
        extract_u_sg02, parse_raw_share, share_to_base64,
    )
    a = ctx.args
    ct = read_blob(a.input, 'crittogramma')
    u_raw, label = extract_u_sg02(ct)

    raw = ctx.sg02().collect_share_raw(a.node, u_raw)
    parsed = parse_raw_share(raw)
    der = share_to_base64(raw, label)

    emit({'node_id': parsed['node_id'],
          'ui': base64.b64encode(parsed['ui_sec1']).decode(),
          'ei': base64.b64encode(parsed['ei']).decode(),
          'fi': base64.b64encode(parsed['fi']).decode(),
          'raw': base64.b64encode(raw).decode(), 'der': der},
         f'share dal nodo {parsed["node_id"]} (label {label.decode()})')
    if a.output:
        write_blob(a.output, der.encode(), 'share')
    return 0


def cmd_decrypt(ctx) -> int:
    a = ctx.args
    ct = read_blob(a.input, 'crittogramma')
    nodes = _nodes(a.nodes)
    info('raccolta delle share in parallelo...')
    plaintext = ctx.sg02().decrypt(ct, nodes=nodes, key_id=a.key_id)
    from .common import is_json
    if is_json():
        emit({'plaintext': base64.b64encode(plaintext).decode(),
              'size': len(plaintext)})
        return 0
    write_blob(a.output, plaintext, 'plaintext')
    return 0
