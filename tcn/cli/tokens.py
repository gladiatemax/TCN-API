"""tcn.cli.tokens — stato del nodo centrale e scoperta dei token."""

from __future__ import annotations

import os

from .common import emit, info, table


def register(sub) -> None:
    p = sub.add_parser('health', help='stato del servizio e delle dipendenze')
    p.set_defaults(func=cmd_health, needs_lock=False)

    grp = sub.add_parser('tokens', help='token collegati')
    s = grp.add_subparsers(dest='subcommand', required=True)

    q = s.add_parser('list', help='elenca i token noti, senza reinterrogare')
    q.set_defaults(func=cmd_list, needs_lock=False)

    q = s.add_parser('scan', help='rilegge i lettori e risolve i node_id')
    q.set_defaults(func=cmd_scan)

    q = s.add_parser('show', help='dettaglio di un token provisionato')
    q.add_argument('node_id', type=int)
    q.set_defaults(func=cmd_show)


# ---------------------------------------------------------------------
def cmd_health(ctx) -> int:
    from .. import transport
    from ..config import settings

    checks: dict[str, str] = {}

    try:
        import nacl.bindings  # noqa: F401
        sodium = True
    except ImportError:
        sodium = False
        checks['sodium'] = 'PyNaCl non installato'

    if not transport.PCSC_AVAILABLE:
        checks['pcsc'] = 'pyscard non installato'

    tools = {}
    for name, path in (('thetacli', settings.paths.thetacli),
                       ('pfse_tool', settings.paths.pfse_tool)):
        tools[name] = path.exists() and os.access(path, os.X_OK)
        if not tools[name]:
            checks[name] = f'assente o non eseguibile: {path}'

    try:
        ctx.dealer
        dealer = True
    except Exception as exc:
        dealer = False
        checks['dealer_key'] = str(exc).splitlines()[0]

    try:
        tokens = ctx.scanned_registry().tokens()
    except Exception as exc:
        tokens = []
        checks['tokens'] = str(exc)
    if not tokens and 'tokens' not in checks:
        checks['tokens'] = 'nessun token collegato'

    s = settings.schemes
    payload = {
        'status': 'ok' if not checks else 'degraded',
        'pcsc': transport.PCSC_AVAILABLE, 'sodium': sodium,
        'dealer_key': dealer, 'tokens': len(tokens),
        'schemes': {'k': s.k, 'n': s.n, 'd': s.d,
                    'max_punctures': s.max_punctures},
        'state_dir': str(settings.paths.state_dir),
        'checks': checks, **tools,
    }

    lines = [f"stato: {payload['status']}",
             f"token collegati: {len(tokens)}",
             f"schema SG02: k={s.k} n={s.n}   GMPpke: d={s.d} "
             f"max {s.max_punctures} punzonature",
             f"stato persistente: {settings.paths.state_dir}"]
    for key, msg in checks.items():
        lines.append(f'  ! {key}: {msg}')
    emit(payload, '\n'.join(lines))
    return 0


def _rows(tokens):
    return [(t.node_id if t.node_id is not None else '-',
             'si' if t.provisioned else 'no',
             'si' if t.theta_app else 'no',
             t.reader) for t in tokens]


def _emit_tokens(registry) -> int:
    tokens = registry.tokens()
    payload = {'tokens': [{'reader': t.reader, 'node_id': t.node_id,
                           'provisioned': t.provisioned,
                           'theta_app': t.theta_app} for t in tokens],
               'nodes': registry.nodes()}
    if not tokens:
        emit(payload, 'nessun token collegato')
        return 0
    emit(payload, table(_rows(tokens),
                        ('node_id', 'share', 'app', 'lettore')))
    return 0


def cmd_list(ctx) -> int:
    return _emit_tokens(ctx.registry)


def cmd_scan(ctx) -> int:
    info('interrogazione dei lettori...')
    return _emit_tokens(ctx.scanned_registry())


def cmd_show(ctx) -> int:
    t = ctx.scanned_registry().by_node(ctx.args.node_id)
    payload = {'reader': t.reader, 'node_id': t.node_id,
               'provisioned': t.provisioned, 'theta_app': t.theta_app,
               'address': t.address}
    emit(payload,
         f'nodo {t.node_id}\n  lettore   {t.reader}\n'
         f'  share     {"presente" if t.provisioned else "assente"}\n'
         f'  theta-app {"risponde" if t.theta_app else "non risponde"}')
    return 0
