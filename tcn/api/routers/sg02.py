"""
tcn.api.routers.sg02 — schema a soglia SG02 su Ed25519.

Il flusso e' in tre tempi e l'ordine conta.

1. `POST /sg02/groups` genera sul TCN n share private e la chiave
   pubblica del gruppo.
2. `POST /sg02/key-distributions` le trasferisce sui token, firmate dal
   dealer.
3. `DELETE /sg02/keystores` cancella dal TCN il materiale privato.

Fra il primo e il terzo passo il nodo centrale detiene tutte le share
insieme, e in quella finestra la proprieta' di soglia non protegge nulla.
Va tenuta corta, e il terzo passo va eseguito: non e' facoltativo.

`encrypt` e `assemble` usano --pubkey e non il keystore, proprio perche'
il terzo passo sia possibile.
"""

from __future__ import annotations

from fastapi import APIRouter, Body

from ...convert.sg02_der import (
    extract_u_sg02, parse_raw_share, share_to_base64,
)
from ..deps import get_sg02_service
from ..models import (
    DecryptionShareRequest, DecryptionShareResponse, DistributionListResponse,
    DistributionModel, GroupCreateRequest, GroupResponse, KeystoreWipeResponse,
    PlaintextResponse, Sg02CiphertextResponse, Sg02DecryptRequest,
    Sg02EncryptRequest, ShareDistributionRequest,
)

router = APIRouter(tags=['sg02'])


# ---------------------------------------------------------------------
# Setup del gruppo
# ---------------------------------------------------------------------
@router.post('/sg02/groups', response_model=GroupResponse,
             summary='Genera un gruppo k-su-n')
def create_group(req: GroupCreateRequest = Body(default_factory=GroupCreateRequest)):
    """`thetacli keygen`.

    Con `reset: true` passa --new, che cancella il gruppo esistente:
    tutte le share gia' distribuite ai token diventano inservibili
    perche' appartengono a una chiave pubblica che non esiste piu'.
    """
    group = get_sg02_service().setup_group(k=req.k, n=req.n, reset=req.reset)
    return GroupResponse(key_id=group.key_id, k=group.k, n=group.n,
                         public_key_path=str(group.public_key))


@router.get('/sg02/groups/current', response_model=GroupResponse,
            summary='Gruppo registrato come attivo')
def current_group():
    """Quale gruppo usano encrypt e assemble quando `key_id` e' nullo.

    Il riferimento viene scritto al momento del keygen. Dedurlo dai file
    presenti non funziona: `thetacli keygen` senza --new li accumula, e
    dopo il secondo gruppo la directory ne contiene piu' d'uno.
    """
    group = get_sg02_service().current_group()
    return GroupResponse(key_id=group.key_id, k=group.k, n=group.n,
                         public_key_path=str(group.public_key))


@router.post('/sg02/key-distributions',
             response_model=DistributionListResponse,
             summary='Importa le share sui token')
def distribute(req: ShareDistributionRequest = Body(
        default_factory=ShareDistributionRequest)):
    """Con un corpo vuoto distribuisce a tutti i token collegati,
    associandoli ai keystore 1..n in ordine di lettore.

    L'associazione e' posizionale perche' prima dell'import il token non
    ha un node_id: non esiste altro criterio. Dopo l'import l'identita'
    si legge con INS 0x05, quindi conviene richiamare POST /tokens/scan.
    """
    service = get_sg02_service()

    if req.reader is not None or req.node_id is not None:
        res = service.distribute(node_id=req.node_id, reader=req.reader,
                                 keystore_index=req.keystore_index)
        return DistributionListResponse(distributions=[
            DistributionModel(node_id=res.node_id, reader=res.reader,
                              ok=res.ok, error=res.error)])

    out = []
    for index, token in enumerate(service._registry.tokens(), start=1):
        res = service.distribute(reader=token.reader, keystore_index=index)
        out.append(DistributionModel(node_id=res.node_id,
                                     reader=res.reader or token.reader,
                                     ok=res.ok, error=res.error))
    return DistributionListResponse(distributions=out)


@router.delete('/sg02/keystores', response_model=KeystoreWipeResponse,
               summary='Cancella dal TCN le share private')
def wipe_keystores(force: bool = False):
    """Da invocare solo quando tutti i token sono stati provisionati.

    Cancellare prima distruggerebbe l'unica copia di una share mai
    consegnata a un token. La chiave pubblica resta: serve a encrypt e
    assemble e non e' materiale segreto.
    """
    removed = get_sg02_service().wipe_keystores(force=force)
    return KeystoreWipeResponse(
        removed=removed,
        message='Il nodo centrale non detiene piu\' alcuna share SG02.'
        if removed else 'Nessun keystore da cancellare.')


# ---------------------------------------------------------------------
# Uso
# ---------------------------------------------------------------------
@router.post('/sg02/ciphertexts', response_model=Sg02CiphertextResponse,
             summary='Cifra con la chiave pubblica del gruppo')
def encrypt(req: Sg02EncryptRequest):
    ct = get_sg02_service().encrypt(req.plaintext, req.label, req.key_id)
    return Sg02CiphertextResponse(ciphertext=ct, label=req.label,
                                  size=len(ct))


@router.post('/tokens/{node_id}/decryption-shares',
             response_model=DecryptionShareResponse,
             summary='Decifratura parziale su un token')
def create_decryption_share(node_id: int, req: DecryptionShareRequest):
    """INS 0x02.

    Il corpo contiene il crittogramma intero, non il solo punto U: la
    label va estratta da li', perche' e' quella con cui la share deve
    essere serializzata. Prenderla da altrove produrrebbe una share che
    `assemble` rifiuta in silenzio.

    La share non viene conservata: il nodo centrale restituisce la
    rappresentazione e non tiene stato.
    """
    u_raw, label = extract_u_sg02(req.ciphertext)
    raw = get_sg02_service().collect_share_raw(node_id, u_raw)
    parsed = parse_raw_share(raw)
    return DecryptionShareResponse(
        node_id=parsed['node_id'], ui=parsed['ui_sec1'], ei=parsed['ei'],
        fi=parsed['fi'], raw=raw, der=share_to_base64(raw, label))


@router.post('/sg02/decryptions', response_model=PlaintextResponse,
             summary='Decifratura completa: raccoglie k share e aggrega')
def decrypt(req: Sg02DecryptRequest):
    """Interroga i token in parallelo e si ferma alle prime k risposte
    valide, cosi' un token lento o staccato non blocca la decifratura
    finche' restano abbastanza nodi.

    Con meno di k share valide risponde 409 elencando i nodi falliti.
    """
    plaintext = get_sg02_service().decrypt(req.ciphertext, nodes=req.nodes,
                                           key_id=req.key_id)
    return PlaintextResponse(plaintext=plaintext, size=len(plaintext))
