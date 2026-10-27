"""
tcn.cli.ppke — schema punzonabile GMPpke su BN254.

Un crittogramma GMPpke e' composto da due parti che vanno sempre
insieme: ct_pfse incapsula la chiave simmetrica, ct_sym contiene i dati.
La CLI le tratta come una coppia di file con lo stesso prefisso, cosi'
non si separano per sbaglio.
"""

from __future__ import annotations

import base64
from pathlib import Path

from .common import CliError, emit, info, is_json, read_blob, table, write_blob


def register(sub) -> None:
    grp = sub.add_parser('ppke', help='crittografia punzonabile')
    s = grp.add_subparsers(dest='subcommand', required=True)

    p = s.add_parser('setup', help='genera la chiave e la distribuisce')
    p.add_argument('-d', type=int, help='tag per crittogramma')
    p.add_argument('--nodes', help='restringe i token, es. 1,2,3')
    p.add_argument('--yes', action='store_true', help='senza conferma')
    p.set_defaults(func=cmd_setup)

    p = s.add_parser('pubkey', help='esporta la chiave pubblica')
    p.add_argument('-o', '--output', help="file, '-' per stdout")
    p.set_defaults(func=cmd_pubkey, needs_lock=False)

    p = s.add_parser('encrypt', help='cifra legando il contenuto a d tag')
    p.add_argument('-i', '--input', help="file da cifrare, '-' per stdin")
    p.add_argument('--tags', required=True,
                   help='esattamente d tag separati da virgola')
    p.add_argument('-o', '--output', required=True,
                   help='prefisso: produce <prefisso>.kem e <prefisso>.dem')
    p.set_defaults(func=cmd_encrypt, needs_lock=False)

    p = s.add_parser('decrypt', help='decifra su un token')
    p.add_argument('--node', type=int, required=True)
    p.add_argument('-i', '--input', required=True,
                   help='prefisso dei file prodotti da encrypt')
    p.add_argument('-o', '--output', help="plaintext, '-' per stdout")
    p.add_argument('--variant', type=lambda v: int(v, 0),
                   help='INS della variante da forzare, es. 0x06; '
                        'per difetto la sceglie il pianificatore')
    p.set_defaults(func=cmd_decrypt)

    p = s.add_parser('state', help='tag punzonati e capacita\' residua')
    p.set_defaults(func=cmd_state, needs_lock=False)


def _pair(prefix: str) -> tuple[Path, Path]:
    return Path(f'{prefix}.kem'), Path(f'{prefix}.dem')


# ---------------------------------------------------------------------
def cmd_setup(ctx) -> int:
    a = ctx.args
    if not a.yes:
        info('ImportKey usa P1=Replace: ogni punzonatura gia\' effettuata '
             'sui token viene azzerata.')
        reply = input('Procedere? [s/N] ')
        if reply.strip().lower() not in ('s', 'si', 'sì', 'y', 'yes'):
            info('annullato')
            return 1

    nodes = [int(x) for x in a.nodes.split(',')] if a.nodes else None
    info('generazione della chiave e distribuzione...')
    setup = ctx.ppke().setup_keys(d=a.d, nodes=nodes)

    emit({'d': setup.d, 'shares': setup.shares,
          'distributed': setup.distributed, 'failed': setup.failed},
         f'chiave generata: d={setup.d}, {setup.shares} share nella SK\n'
         f'distribuita ai nodi {setup.distributed}')
    for node, err in setup.failed.items():
        info(f'  ! nodo {node}: {err}')
    info('la chiave privata non e\' stata scritta su disco')
    return 1 if setup.failed else 0


def cmd_pubkey(ctx) -> int:
    pk = ctx.ppke().public_key()
    if is_json():
        emit({'public_key': base64.b64encode(pk).decode(), 'size': len(pk)})
        return 0
    write_blob(ctx.args.output, pk, 'chiave pubblica')
    return 0


def cmd_encrypt(ctx) -> int:
    from ..config import settings
    a = ctx.args
    tags = [t.strip() for t in a.tags.split(',') if t.strip()]
    if len(tags) != settings.schemes.d:
        raise CliError(
            f'attesi esattamente {settings.schemes.d} tag, ricevuti '
            f'{len(tags)}. Ogni tag e\' una maniglia di cancellazione '
            'indipendente per questo crittogramma.', 2)

    data = read_blob(a.input, 'plaintext')
    ct_pfse, ct_sym = ctx.ppke().encrypt(data, tags)

    kem, dem = _pair(a.output)
    kem.parent.mkdir(parents=True, exist_ok=True)
    kem.write_bytes(ct_pfse)
    dem.write_bytes(ct_sym)

    emit({'ct_pfse': str(kem), 'ct_sym': str(dem), 'tags': tags,
          'sizes': {'kem': len(ct_pfse), 'dem': len(ct_sym)}},
         f'crittogramma legato a {len(tags)} tag: {", ".join(tags)}\n'
         f'  {kem}  ({len(ct_pfse)} byte)\n'
         f'  {dem}  ({len(ct_sym)} byte)')
    return 0


def cmd_decrypt(ctx) -> int:
    from ..tokens.ppke import DecryptVariant
    a = ctx.args
    kem, dem = _pair(a.input)
    for f in (kem, dem):
        if not f.exists():
            raise CliError(f'file mancante: {f}', 2)

    variant = DecryptVariant(a.variant) if a.variant is not None else None
    if variant is None:
        from .. import planner
        n = len(ctx.ledger.node_state(a.node).punctured)
        choice = planner.choose(n)
        info(f'variante INS 0x{int(choice.variant):02X} — {choice.reason}')

    plaintext = ctx.ppke().decrypt(a.node, kem.read_bytes(),
                                   dem.read_bytes(), variant)
    if is_json():
        emit({'plaintext': base64.b64encode(plaintext).decode(),
              'size': len(plaintext)})
        return 0
    write_blob(a.output, plaintext, 'plaintext')
    return 0


def cmd_state(ctx) -> int:
    from ..config import settings
    service = ctx.ppke()
    registry = ctx.scanned_registry()
    roster = service.roster()
    reports = service.report(roster)
    missing = registry.missing(roster)

    payload = {
        'roster': roster, 'connected': registry.nodes(), 'missing': missing,
        'aligned': service.aligned(roster),
        'max_punctures': settings.schemes.max_punctures,
        'nodes': [{'node_id': r.node_id, 'punctured': r.punctured,
                   'uncertain': r.uncertain, 'capacity': r.capacity}
                  for r in reports]}

    rows = [(r.node_id,
             f'{r.capacity}/{settings.schemes.max_punctures}',
             ', '.join(r.punctured) or '-',
             ', '.join(r.uncertain) or '-') for r in reports]
    human = [table(rows, ('nodo', 'capacita', 'punzonati', 'incerti'))]
    human.append('')
    human.append(f'allineati: {"si" if payload["aligned"] else "NO"}')
    if missing:
        human.append(f'token assenti: {missing} — nessuna cancellazione '
                     'e\' possibile finche\' mancano')
    emit(payload, '\n'.join(human))
    return 0
