"""
tcn.convert.ppke_wire — ponte fra i blob cereal di libforwardsec (RELIC) e i
payload attesi da forwardsec-app (arkworks).

Estratto dalla cella 2.3 di forwardsec_e2e_nitrokey3.ipynb.

Due direzioni:
  host -> device : parse_pk / parse_sk / parse_ct  seguiti da
                   build_fw_pk / build_fw_sk / build_fw_ct
  device -> host : gt_ark_bytes_to_key, che riporta M in rappresentazione
                   RELIC e ne deriva la chiave simmetrica
"""

import struct
from hashlib import sha256

from .bn254 import (
    relic_g1_decode, relic_g2_decode, relic_gt_decode, relic_gt_encode,
    ark_g1_encode, ark_g2_encode, ark_gt_encode, ark_gt_decode,
    g2_relic_to_ark, gt_relic_to_ark, gt_ark_to_relic,
)


# ---------------------------------------------------------------------
# Parser cereal (BinaryArchive)
# ---------------------------------------------------------------------
class CerealReader:
    def __init__(self, blob):
        self.b = blob
        self.off = 0

    def u32(self):
        v = struct.unpack_from('<I', self.b, self.off)[0]
        self.off += 4
        return v

    def u64(self):
        v = struct.unpack_from('<Q', self.b, self.off)[0]
        self.off += 8
        return v

    def raw(self, n):
        v = self.b[self.off:self.off + n]
        self.off += n
        return v

    def vec_bytes(self):                # vector<uint8_t>
        return self.raw(self.u64())

    def string(self):
        return self.raw(self.u64())

    def g1(self):
        return relic_g1_decode(self.vec_bytes())

    def g2(self):
        return relic_g2_decode(self.vec_bytes())

    def gt(self):
        return relic_gt_decode(self.vec_bytes())

    def done(self):
        assert self.off == len(self.b), \
            f'bytes residui: {len(self.b) - self.off}'


def parse_pk(blob):
    """GmppkePublicKey: baseKey(gG1,gG2,g2G1,g2G2) | ppkeg1 | d
    | gqofxG1 | gqofxG2

    I campi in G1 non finiscono nel payload firmware ma vanno comunque
    letti per far avanzare l'offset del reader.
    """
    r = CerealReader(blob)
    pk = {}
    pk['gG1'] = r.g1()
    pk['gG2'] = r.g2()
    pk['g2G1'] = r.g1()
    pk['g2G2'] = r.g2()
    pk['ppkeg1'] = r.g2()
    pk['d'] = r.u32()
    pk['gqofxG1'] = [r.g1() for _ in range(r.u64())]
    pk['gqofxG2'] = [r.g2() for _ in range(r.u64())]
    r.done()
    return pk


def parse_sk(blob):
    """GmppkePrivateKey: vector<share>; share = sk1, sk2, sk3 (G2),
    sk4 (string, il tag)."""
    r = CerealReader(blob)
    shares = []
    for _ in range(r.u64()):
        shares.append({'sk1': r.g2(), 'sk2': r.g2(), 'sk3': r.g2(),
                       'sk4': r.string()})
    r.done()
    return shares


def parse_ct(blob):
    """GmmppkeCT: PartialGmmppkeCT(ct2, ct3[], tags[]) | ct1(GT)."""
    r = CerealReader(blob)
    ct = {}
    ct['ct2'] = r.g1()
    ct['ct3'] = [r.g1() for _ in range(r.u64())]
    ct['tags'] = [r.string() for _ in range(r.u64())]
    ct['ct1'] = r.gt()
    r.done()
    return ct


# ---------------------------------------------------------------------
# Payload per forwardsec-app (formati arkworks)
#
# PK : gG2(128) | g2G2(128) | d(4 BE) | nq(4 BE) | nq x gqofxG2(128)
# SK : ns(4 BE) | ns x [ sk1 | sk2 | sk3 (128 cad.) | tlen(2 BE) | tag ]
# CT : ct1(384) | ct2(64) | nct3(4 BE) | nct3 x ct3(64)
#      | ntags(4 BE) | ntags x [ tlen(2 BE) | tag ]
# ---------------------------------------------------------------------
def build_fw_pk(pk):
    out = ark_g2_encode(g2_relic_to_ark(pk['gG2']))
    out += ark_g2_encode(g2_relic_to_ark(pk['g2G2']))
    out += struct.pack('>I', pk['d'])
    out += struct.pack('>I', len(pk['gqofxG2']))
    for q in pk['gqofxG2']:
        out += ark_g2_encode(g2_relic_to_ark(q))
    return out


def build_fw_sk(shares):
    out = struct.pack('>I', len(shares))
    for s in shares:
        out += ark_g2_encode(g2_relic_to_ark(s['sk1']))
        out += ark_g2_encode(g2_relic_to_ark(s['sk2']))
        out += ark_g2_encode(g2_relic_to_ark(s['sk3']))
        out += struct.pack('>H', len(s['sk4'])) + s['sk4']
    return out


def build_fw_ct(ct):
    out = ark_gt_encode(gt_relic_to_ark(ct['ct1']))
    out += ark_g1_encode(ct['ct2'])       # G1: curva identica, solo encoding
    out += struct.pack('>I', len(ct['ct3']))
    for c in ct['ct3']:
        out += ark_g1_encode(c)
    out += struct.pack('>I', len(ct['tags']))
    for t in ct['tags']:
        out += struct.pack('>H', len(t)) + t
    return out


def build_import_payload(fw_pk: bytes, fw_sk: bytes) -> bytes:
    """Payload di INS 0x01: pk_len(4 BE) | pk | sk_len(4 BE) | sk."""
    return (struct.pack('>I', len(fw_pk)) + fw_pk
            + struct.pack('>I', len(fw_sk)) + fw_sk)


# ---------------------------------------------------------------------
# Chiave simmetrica lato host: key = SHA256(cereal(GT_relic))
#
# Identico a gt_to_key di pfse_tool con POINT_COMPRESS=0: il cereal di
# un vector<uint8_t> e' len u64 LE (=384) seguito da gt_write_bin non
# compresso.
# ---------------------------------------------------------------------
def gt_ark_bytes_to_key(m_ark_bytes: bytes) -> bytes:
    gt_relic = gt_ark_to_relic(ark_gt_decode(m_ark_bytes))
    raw = relic_gt_encode(gt_relic)
    cereal = struct.pack('<Q', len(raw)) + raw
    return sha256(cereal).digest()
