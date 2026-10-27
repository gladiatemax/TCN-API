"""
tcn.cli.main — punto d'ingresso della riga di comando.

La CLI e l'API sono due interfacce parallele sopra lo stesso livello di
servizi: nessuna delle due passa per l'altra. E' il motivo per cui
`tcn.services` non sa che esiste HTTP.

Da questa simmetria discende pero' un vincolo. I lock che serializzano
gli accessi al token vivono in memoria, quindi non vedono un secondo
processo. Ogni comando che tocca l'hardware o scrive sullo stato
acquisisce percio' un lock esclusivo su file, lo stesso che prende il
servizio HTTP: se uvicorn e' in esecuzione, la CLI si ferma dicendolo
invece di interlacciare APDU sullo stesso lettore.

I comandi di sola lettura (`health`, `tokens list`, `puncture list`,
`ppke state`) ne fanno a meno: dichiarano `needs_lock=False`.
"""

from __future__ import annotations

import argparse
import sys

from . import ppke, punctures, sg02, tokens
from .common import (
    EXIT_OK, EXIT_USAGE, CliError, Context, configure_output, translate,
)

PROG = 'tcn'

EPILOG = """\
esempi:
  tcn health
  tcn tokens scan
  tcn sg02 keygen -k 2 -n 3 --reset
  tcn sg02 distribute
  tcn sg02 wipe-keystores
  tcn sg02 encrypt -i cartella.pdf --label DEMO -o cartella.enc
  tcn sg02 decrypt -i cartella.enc -o cartella.pdf
  tcn ppke setup
  tcn ppke encrypt -i record.json --tags subject-4417,sanitaria,ret-2031 -o ct/rec
  tcn ppke decrypt --node 1 -i ct/rec -o record.json
  tcn puncture create --tag subject-4417
  tcn ppke state

codici d'uscita:
  0 successo        4 contenuto cancellato (punzonato)
  1 errore          5 stato incompatibile con la richiesta
  2 uso errato      6 dispositivo senza chiave (NON cancellato)
  3 token o nodo non disponibile
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description='Nodo centrale: orchestra le Nitrokey 3 collegate, '
                    'per la crittografia a soglia SG02 e per la '
                    'cancellazione crittografica GMPpke.',
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--json', action='store_true',
                        help='risultato in JSON su stdout')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='sopprime i messaggi diagnostici')
    parser.add_argument('--state-dir',
                        help='directory di stato (equivale a TCN_STATE_DIR)')
    parser.add_argument('--wait-lock', type=float, default=0.0,
                        metavar='SEC',
                        help='attende il lock del nodo invece di fallire')

    sub = parser.add_subparsers(dest='command', required=True,
                                metavar='<comando>')
    tokens.register(sub)
    sg02.register(sub)
    ppke.register(sub)
    punctures.register(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # --state-dir va applicata prima che config venga importata, perche'
    # le impostazioni sono congelate alla prima lettura.
    if args.state_dir:
        import os
        os.environ['TCN_STATE_DIR'] = args.state_dir

    configure_output(args.json, args.quiet)

    from ..config import StateDirUnavailable, ensure_dirs
    try:
        ensure_dirs()
    except StateDirUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE

    ctx = Context(args=args)
    needs_lock = getattr(args, 'needs_lock', True)

    try:
        if not needs_lock:
            return args.func(ctx) or EXIT_OK

        from ..lockfile import hold
        label = f'cli: {args.command}'
        if getattr(args, 'subcommand', None):
            label += f' {args.subcommand}'
        with hold(label, blocking=args.wait_lock > 0,
                  timeout=args.wait_lock):
            return args.func(ctx) or EXIT_OK

    except KeyboardInterrupt:
        print('\ninterrotto', file=sys.stderr)
        return 130
    except Exception as exc:                      # noqa: BLE001
        err = translate(exc)
        print(f'{PROG}: {err}', file=sys.stderr)
        if isinstance(exc, CliError) is False and args.json:
            import json
            print(json.dumps({'error': str(err)}, ensure_ascii=False))
        return err.code


if __name__ == '__main__':
    sys.exit(main())
