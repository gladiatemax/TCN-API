"""
tcn.convert.bn254 — aritmetica di campo, isomorfismo fra le torri RELIC e
arkworks, codec dei formati binari su BN254 (alt_bn128).

Estratto verbatim dalle celle 2.1 e 2.2 di forwardsec_e2e_nitrokey3.ipynb,
depurato del codice mai invocato nel percorso operativo.

RELIC e arkworks costruiscono la torre Fp12 con non-residui diversi
(32+u contro 9+u). L'isomorfismo esplicito e' definito dalla costante Z
con Z^6 = (32+u)/(9+u): G2 si mappa come (x,y) -> (Z^2 x, Z^3 y), GT
moltiplicando il coefficiente (i,j) per Z^(2j+i).
"""

# ---------------------------------------------------------------------
# Parametri della curva
# ---------------------------------------------------------------------
P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# z : z^6 = (32+u)/(9+u)
Z = (0x048DB4F55FE93AE78A85920E2965D2A9411D4705AFC8B2283243B7B26D0AAD67,
     0x195536E0C4CCE098BFA13785C2533723DC4282C5F2F9E7EBAF661EAF41B01ADB)

B_G1 = 3
XI_RELIC = (32, 1)
XI_ARK = (9, 1)


# ---------------------------------------------------------------------
# Aritmetica Fp2
# ---------------------------------------------------------------------
def f2_add(a, b):
    return ((a[0] + b[0]) % P, (a[1] + b[1]) % P)


def f2_sub(a, b):
    return ((a[0] - b[0]) % P, (a[1] - b[1]) % P)


def f2_mul(a, b):
    return ((a[0] * b[0] - a[1] * b[1]) % P,
            (a[0] * b[1] + a[1] * b[0]) % P)


def f2_sqr(a):
    return f2_mul(a, a)


def f2_neg(a):
    return ((-a[0]) % P, (-a[1]) % P)


def f2_inv(a):
    n = pow((a[0] * a[0] + a[1] * a[1]) % P, -1, P)
    return ((a[0] * n) % P, ((-a[1]) % P) * n % P)


def fp_sqrt(a):
    """sqrt in Fp (p = 3 mod 4). None se non e' QR."""
    if a == 0:
        return 0
    r = pow(a, (P + 1) // 4, P)
    return r if (r * r) % P == a else None


def f2_sqrt(a):
    """sqrt in Fp2 con il metodo della norma. None se non e' QR."""
    if a == (0, 0):
        return (0, 0)
    if a[1] == 0:
        r = fp_sqrt(a[0])
        if r is not None:
            return (r, 0)
        r = fp_sqrt((-a[0]) % P)
        return (0, r) if r is not None else None
    alpha = fp_sqrt((a[0] * a[0] + a[1] * a[1]) % P)
    if alpha is None:
        return None
    inv2 = pow(2, -1, P)
    x0sq = (a[0] + alpha) * inv2 % P
    x0 = fp_sqrt(x0sq)
    if x0 is None:
        x0sq = (a[0] - alpha) * inv2 % P
        x0 = fp_sqrt(x0sq)
    if x0 is None:
        return None
    x1 = a[1] * pow(2 * x0 % P, -1, P) % P
    res = (x0, x1)
    assert f2_sqr(res) == a
    return res


# Potenze di z (e inverse) per la mappa GT
ZPOW = [(1, 0)]
for _ in range(5):
    ZPOW.append(f2_mul(ZPOW[-1], Z))
ZINV = f2_inv(Z)
ZIPOW = [(1, 0)]
for _ in range(5):
    ZIPOW.append(f2_mul(ZIPOW[-1], ZINV))

Z2, Z3 = ZPOW[2], ZPOW[3]          # G2 RELIC -> ark
ZI2, ZI3 = ZIPOW[2], ZIPOW[3]      # G2 ark   -> RELIC

B_TWIST_RELIC = f2_mul((3, 0), f2_inv(XI_RELIC))


# ---------------------------------------------------------------------
# Decodifica formati RELIC (write_bin)
#
# Con POINT_COMPRESS=0 il tool emette sempre il prefisso 0x04
# (non compresso). I rami 0x02/0x03 restano come difesa: richiedono
# una radice quadrata di campo, mai eseguita nel percorso normale.
# ---------------------------------------------------------------------
def relic_g1_decode(b):
    """bytes RELIC -> (x, y) oppure None (punto all'infinito)."""
    if all(v == 0 for v in b):
        return None
    if b[0] == 0x04 and len(b) == 65:
        return (int.from_bytes(b[1:33], 'big'),
                int.from_bytes(b[33:65], 'big'))
    if b[0] in (0x02, 0x03) and len(b) == 33:
        x = int.from_bytes(b[1:33], 'big')
        y = fp_sqrt((pow(x, 3, P) + B_G1) % P)
        assert y is not None, 'punto G1 non sulla curva'
        if (y & 1) != (b[0] & 1):
            y = P - y
        return (x, y)
    raise ValueError(
        f'formato G1 RELIC sconosciuto (len={len(b)}, b0={b[0]:02x})')


def relic_g2_decode(b):
    if all(v == 0 for v in b):
        return None
    if b[0] == 0x04 and len(b) == 129:
        x = (int.from_bytes(b[1:33], 'big'), int.from_bytes(b[33:65], 'big'))
        y = (int.from_bytes(b[65:97], 'big'), int.from_bytes(b[97:129], 'big'))
        return (x, y)
    if b[0] in (0x02, 0x03) and len(b) == 65:
        x = (int.from_bytes(b[1:33], 'big'), int.from_bytes(b[33:65], 'big'))
        y = f2_sqrt(f2_add(f2_mul(f2_sqr(x), x), B_TWIST_RELIC))
        assert y is not None, 'punto G2 non sulla curva RELIC'
        if (y[0] & 1) != (b[0] & 1):
            y = f2_neg(y)
        return (x, y)
    raise ValueError(
        f'formato G2 RELIC sconosciuto (len={len(b)}, b0={b[0]:02x})')


def relic_gt_decode(b):
    """384 B RELIC -> dict {(i,j): (c0, c1)}."""
    if len(b) != 384:
        raise ValueError(
            f'GT RELIC: attesi 384B non compressi, trovati {len(b)}B '
            '(compilare con POINT_COMPRESS=0)')
    out, off = {}, 0
    for i in range(2):
        for j in range(3):
            c0 = int.from_bytes(b[off:off + 32], 'big')
            c1 = int.from_bytes(b[off + 32:off + 64], 'big')
            out[(i, j)] = (c0, c1)
            off += 64
    return out


def relic_gt_encode(gt):
    """Necessaria per ricostruire la chiave simmetrica lato host."""
    out = b''
    for i in range(2):
        for j in range(3):
            c0, c1 = gt[(i, j)]
            out += c0.to_bytes(32, 'big') + c1.to_bytes(32, 'big')
    return out


# ---------------------------------------------------------------------
# Codifica formati arkworks — wire format NON COMPRESSO
#
# La decompressione richiederebbe sqrt in Fq/Fq2 nel firmware: eliminata
# per ridurre la flash e velocizzare il parsing on-device.
#
#   G1 = x LE(32) | y LE(32)                     64 B
#   G2 = x0|x1|y0|y1 LE(32 cad.)                128 B
#   flag nei 2 bit alti dell'ULTIMO byte di y:
#     0x80 = y "negativo", 0x40 = infinito
#   GT = 12 x 32 B LE, ordine (i,j,k) con i esterno   384 B
# ---------------------------------------------------------------------
def _fq2_is_neg(y):
    """Predicato di segno arkworks per Fq2: lessicografico c1-prima."""
    ny = f2_neg(y)
    return (y[1], y[0]) > (ny[1], ny[0])


def ark_g1_encode(pt):
    if pt is None:
        b = bytearray(64)
        b[63] = 0x40
        return bytes(b)
    x, y = pt
    b = bytearray(x.to_bytes(32, 'little') + y.to_bytes(32, 'little'))
    if y > P - y:
        b[63] |= 0x80
    return bytes(b)


def ark_g2_encode(pt):
    if pt is None:
        b = bytearray(128)
        b[127] = 0x40
        return bytes(b)
    x, y = pt
    b = bytearray(x[0].to_bytes(32, 'little') + x[1].to_bytes(32, 'little')
                  + y[0].to_bytes(32, 'little') + y[1].to_bytes(32, 'little'))
    if _fq2_is_neg(y):
        b[127] |= 0x80
    return bytes(b)


def ark_gt_encode(gt):
    out = b''
    for i in range(2):
        for j in range(3):
            c0, c1 = gt[(i, j)]
            out += c0.to_bytes(32, 'little') + c1.to_bytes(32, 'little')
    return out


def ark_gt_decode(b):
    if len(b) != 384:
        raise ValueError(f'GT ark: attesi 384 B, ricevuti {len(b)}')
    out, off = {}, 0
    for i in range(2):
        for j in range(3):
            c0 = int.from_bytes(b[off:off + 32], 'little')
            c1 = int.from_bytes(b[off + 32:off + 64], 'little')
            out[(i, j)] = (c0, c1)
            off += 64
    return out


# ---------------------------------------------------------------------
# Isomorfismo phi / psi (RELIC <-> arkworks)
# ---------------------------------------------------------------------
def g2_relic_to_ark(pt):
    if pt is None:
        return None
    x, y = pt
    return (f2_mul(x, Z2), f2_mul(y, Z3))


def gt_relic_to_ark(gt):
    return {(i, j): f2_mul(gt[(i, j)], ZPOW[2 * j + i])
            for i in range(2) for j in range(3)}


def gt_ark_to_relic(gt):
    return {(i, j): f2_mul(gt[(i, j)], ZIPOW[2 * j + i])
            for i in range(2) for j in range(3)}
