"""
tcn.cli.punctures — cancellazione crittografica.

E' l'unico gruppo di comandi che compie un'operazione irreversibile.
`create` chiede conferma e stampa cosa sta per fare, perche' una
punzonatura non si annulla e la capacita' di ogni token e' limitata.

Lo stato che conta e' per token: `complete` e' l'unico valore in cui la
cancellazione e' avvenuta davvero. `partial` significa che almeno un
token conserva la capacita' di decifrare il tag.
"""

from __future__ import annotations

import time

from .common import CliError, emit, info, table, warn


def register(sub) -> None:
    grp = sub.add_parser('puncture', help='cancellazione crittografica')
    s = grp.add_subparsers(dest='subcommand', required=True)

    p = s.add_parser('create', help='cancella un tag su tutti i token')
    p.add_argument('--tag', required=True)
    p.add_argument('--nodes', help='restringe i token, es. 1,2,3')
    p.add_argument('--yes', action='store_true', help='senza conferma')
    p.set_defaults(func=cmd_create)

    p = s.add_parser('list', help='storico delle campagne')
    p.add_argument('--status', help="filtra, es. partial")
    p.add_argument('--limit', type=int, default=50)
    p.set_defaults(func=cmd_list, needs_lock=False)

    p = s.add_parser('show', help='stato di una campagna, token per token')
    p.add_argument('campaign_id')
    p.set_defaults(func=cmd_show, needs_lock=False)

    p = s.add_parser('resolve',
                     help='accerta con la sonda i token incerti')
    p.add_argument('campaign_id')
    p.set_defaults(func=cmd_resolve)

    p = s.add_parser('resume', help='riprende una campagna incompleta')
    p.add_argument('campaign_id')
    p.set_defaults(func=cmd_resume)


def _payload(c) -> dict:
    return {'id': c.id, 'tag': c.tag, 'status': c.status.value,
            'nodes': {str(k): v.value for k, v in sorted(c.nodes.items())},
            'detail': {str(k): v for k, v in c.detail.items() if v},
            'unresolved': c.unresolved, 'remaining': c.remaining,
            'created_at': c.created_at}


def _human(c) -> str:
    rows = [(n, o.value, c.detail.get(n, ''))
            for n, o in sorted(c.nodes.items())]
    out = [f'campagna {c.id}',
           f'  tag    {c.tag}',
           f'  stato  {c.status.value}',
           '',
           table(rows, ('nodo', 'esito', 'dettaglio'))]
    if c.status.value == 'complete':
        out.append('\nla cancellazione e\' avvenuta su tutti i token')
    else:
        out.append('\nATTENZIONE: la cancellazione NON e\' completa.')
        if c.unresolved:
            out.append(f'  da accertare: {c.unresolved} '
                       f'(tcn puncture resolve {c.id})')
        if c.remaining:
            out.append(f'  da eseguire:  {c.remaining} '
                       f'(tcn puncture resume {c.id})')
    return '\n'.join(out)


# ---------------------------------------------------------------------
def cmd_create(ctx) -> int:
    from ..config import settings
    a = ctx.args
    service = ctx.ppke()
    nodes = [int(x) for x in a.nodes.split(',')] if a.nodes else None
    roster = nodes or service.roster()

    if not a.yes:
        info(f'Cancellazione del tag {a.tag!r} sui token {roster}.')
        info('L\'operazione e\' IRREVERSIBILE e consuma una delle '
             f'{settings.schemes.max_punctures} punzonature disponibili '
             'su ogni token.')
        reply = input('Procedere? [s/N] ')
        if reply.strip().lower() not in ('s', 'si', 'sì', 'y', 'yes'):
            info('annullato')
            return 1

    info('esecuzione sequenziale sui token...')
    t0 = time.perf_counter()
    campaign = service.puncture(a.tag, nodes)
    info(f'conclusa in {time.perf_counter() - t0:.1f}s')

    emit(_payload(campaign), _human(campaign))
    return 0 if campaign.status.value == 'complete' else 1


def cmd_list(ctx) -> int:
    campaigns = ctx.ledger.campaigns()
    if ctx.args.status:
        campaigns = [c for c in campaigns
                     if c.status.value == ctx.args.status]
    campaigns = campaigns[:ctx.args.limit]

    emit({'campaigns': [_payload(c) for c in campaigns]},
         table([(c.id, c.tag, c.status.value,
                 time.strftime('%d/%m %H:%M', time.localtime(c.created_at)))
                for c in campaigns],
               ('id', 'tag', 'stato', 'quando'))
         if campaigns else 'nessuna campagna registrata')
    return 0


def _campaign(ctx, cid):
    c = ctx.ledger.campaign(cid)
    if c is None:
        raise CliError(f'campagna sconosciuta: {cid}', 5)
    return c


def cmd_show(ctx) -> int:
    c = _campaign(ctx, ctx.args.campaign_id)
    emit(_payload(c), _human(c))
    return 0 if c.status.value == 'complete' else 1


def cmd_resolve(ctx) -> int:
    cid = ctx.args.campaign_id
    c = _campaign(ctx, cid)
    if not c.unresolved:
        info('nessun token da accertare')
    else:
        info(f'interrogazione dei token {c.unresolved} con il '
             'crittogramma sonda...')
        resolved = ctx.ppke().resolve_unknown(cid)
        for node, punctured in resolved.items():
            info(f'  nodo {node}: '
                 f'{"punzonato" if punctured else "intatto"}')
    c = _campaign(ctx, cid)
    emit(_payload(c), _human(c))
    return 0 if c.status.value == 'complete' else 1


def cmd_resume(ctx) -> int:
    cid = ctx.args.campaign_id
    before = _campaign(ctx, cid)
    if before.status.value == 'complete':
        info('la campagna e\' gia\' completa')
        emit(_payload(before), _human(before))
        return 0

    info('risoluzione delle incertezze, poi punzonatura dei token '
         'rimanenti...')
    campaign = ctx.ppke().resume(cid)
    if campaign.status.value != 'complete':
        warn('la campagna resta incompleta')
    emit(_payload(campaign), _human(campaign))
    return 0 if campaign.status.value == 'complete' else 1
