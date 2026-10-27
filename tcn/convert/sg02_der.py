"""
tcn.convert.sg02_der — ASN.1 DER per lo schema SG02 su Ed25519.

Estratto da theta_app_benchmark.ipynb (e da sg02_asn1.py). Copre le due
direzioni:

  device -> thetacrypt : i 99 byte grezzi di INS 0x02 diventano una
      Sg02DecryptionShare in DER, base64, accettata da `thetacli
      assemble`.
  thetacrypt -> device : estrazione di xi e node_id da un keystore, e di
      U e label da un ciphertext, nei formati attesi dal firmware.

Il nodo di conversione e' che curve25519-dalek e mcore comprimono i punti
di Edwards in modo diverso: il firmware emette `02/03 || y_be` (RFC
8032), mentre ECP::frombytes di mcore interpreta il campo compresso come
x_be. Il ponte e' `firmware_ui_to_mcore`, che ricava x da y con la
formula della curva e restituisce il punto non compresso.
"""

import base64
import json
import struct

class MalformedCiphertext(ValueError):
    """Il crittogramma non e' interpretabile come struttura SG02.

    E' un input sbagliato del chiamante, non un guasto: merita 400, non
    500. Capita tipicamente quando si inviano byte che non sono affatto
    un crittogramma, o quello di un altro schema.
    """


GROUP_ED25519 = 2       # discriminante di Group in thetacrypt

# Primo campo della struttura esterna. NON e' il node_id: thetacrypt vi
# scrive sempre lo stesso valore, qualunque sia il nodo, e lo legge come
# discriminante prima di interpretare il resto. Il valore e' stato
# determinato confrontando l'output di `thetacli dec` per nodi diversi.
#
# Scriverci il node_id funziona per il nodo 1, dove i due valori
# coincidono per caso, e fa fallire ogni altro nodo con
# Threshold(DeserializationFailed) — prima della verifica, perche' il
# deserializzatore si ferma sul discriminante. Il difetto e' rimasto
# invisibile finche' le share dei nodi diversi dal primo venivano
# calcolate in software da thetacli invece che dai token.
SCHEME_SG02 = 1

# Parametri di Ed25519
_P = 2 ** 255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P


# ---------------------------------------------------------------------
# Lettura DER
# ---------------------------------------------------------------------
def read_tlv(data, i):
    """Legge un TLV a partire da `i`. Ritorna (tag, value, next_index)."""
    tag = data[i]
    i += 1
    length = data[i]
    i += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[i:i + n], 'big')
        i += n
    return tag, data[i:i + length], i + length


def skip_sequence_header(data, i=0):
    """Salta tag e lunghezza di una SEQUENCE, posizionandosi sul primo
    elemento contenuto."""
    i += 1
    l = data[i]
    i += 1
    if l & 0x80:
        i += (l & 0x7F)
    return i


# ---------------------------------------------------------------------
# Scrittura DER
# ---------------------------------------------------------------------
def _asn1_length(n):
    if n < 128:
        return bytes([n])
    if n < 256:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _asn1_integer_u64(v):
    if v == 0:
        return b'\x02\x01\x00'
    raw = v.to_bytes((v.bit_length() + 7) // 8, 'big')
    if raw[0] & 0x80:
        raw = b'\x00' + raw
    return b'\x02' + _asn1_length(len(raw)) + raw


def _asn1_integer_i32(v):
    raw = v.to_bytes(4, 'big', signed=True)
    start = 0
    while start < 3:
        if raw[start] == 0x00 and (raw[start + 1] & 0x80) == 0:
            start += 1
        else:
            break
    raw = raw[start:]
    return b'\x02' + _asn1_length(len(raw)) + raw


def _asn1_octet_string(data):
    return b'\x04' + _asn1_length(len(data)) + data


def _asn1_sequence(content):
    return b'\x30' + _asn1_length(len(content)) + content


# ---------------------------------------------------------------------
# device -> thetacrypt
# ---------------------------------------------------------------------
def parse_raw_share(raw: bytes) -> dict:
    """Scompone la risposta di INS 0x02:
    node_id (2 B BE) | ui_sec1 (33 B) | ei (32 B) | fi (32 B)."""
    if len(raw) != 99:
        raise ValueError(f'attesi 99 byte, ricevuti {len(raw)}')
    return {
        'node_id': struct.unpack_from('>H', raw, 0)[0],
        'ui_sec1': raw[2:35],      # 02/03 || y_be, formato firmware
        'ei': raw[35:67],
        'fi': raw[67:99],
    }


def firmware_ui_to_mcore(ui_fw: bytes) -> bytes:
    """Converte ui dal formato firmware (02/03 || y_be, 33 B) al formato
    non compresso mcore (04 || x_be || y_be, 65 B).

    ECP::frombytes con prefisso 02/03 interpreta il campo come x_be,
    quindi y_be non puo' essere passato direttamente: x va ricavato dalla
    curva di Edwards, x^2 = (y^2 - 1) / (d*y^2 + 1) mod p.
    """
    if len(ui_fw) != 33:
        raise ValueError(f'attesi 33 byte, ricevuti {len(ui_fw)}')
    prefix = ui_fw[0]
    y_be = ui_fw[1:]
    sign_x = prefix & 1

    y = int.from_bytes(y_be, 'big')
    y2 = y * y % _P
    num = (y2 - 1) % _P
    den = (_D * y2 + 1) % _P
    x2 = num * pow(den, _P - 2, _P) % _P

    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if x % 2 != sign_x:
        x = _P - x

    return bytes([0x04]) + x.to_bytes(32, 'big') + y_be


def build_sg02_decryption_share(raw: bytes, label) -> bytes:
    """Costruisce la Sg02DecryptionShare in DER dai 99 byte del firmware."""
    if isinstance(label, str):
        label = label.encode()
    s = parse_raw_share(raw)
    ui_mcore = firmware_ui_to_mcore(s['ui_sec1'])

    inner = (
        _asn1_integer_u64(s['node_id'])
        + _asn1_integer_i32(GROUP_ED25519)
        + _asn1_octet_string(label)
        + _asn1_octet_string(ui_mcore)
        + _asn1_octet_string(s['ei'])
        + _asn1_octet_string(s['fi'])
    )
    outer = (
        _asn1_integer_u64(SCHEME_SG02)
        + _asn1_octet_string(_asn1_sequence(inner))
    )
    return _asn1_sequence(outer)


def share_to_base64(raw: bytes, label) -> str:
    """Forma pronta per `thetacli assemble --partials`."""
    return base64.b64encode(build_sg02_decryption_share(raw, label)).decode()


# ---------------------------------------------------------------------
# thetacrypt -> device
# ---------------------------------------------------------------------
def extract_xi_sg02(keystore_path: str):
    """Estrae (xi, node_id) dalla voce Sg02-Ed25519 di un keystore.

    xi e' in big-endian, come lo attende INS 0x01: e' il firmware a
    invertirlo per curve25519-dalek.
    """
    with open(keystore_path) as f:
        ks = json.load(f)
    entry = next(e for e in ks
                 if e.get('scheme') == 'Sg02' and e.get('group') == 'Ed25519')
    raw = base64.urlsafe_b64decode(entry['key'] + '==')

    i = skip_sequence_header(raw)
    _, _, i = read_tlv(raw, i)
    _, wrapper, _ = read_tlv(raw, i)

    j = skip_sequence_header(wrapper)
    _, id_val, j = read_tlv(wrapper, j)
    _, xi, _ = read_tlv(wrapper, j)
    return bytes(xi), int.from_bytes(id_val, 'big')


def extract_u_sg02(source):
    """Estrae (U, label) da un ciphertext SG02.

    `source` puo' essere i byte del ciphertext o il percorso di un file.
    La variante su byte evita di scrivere il crittogramma su disco solo
    per rileggerlo.

    U e' memorizzato in SEC1 non compresso (65 B); il firmware attende il
    punto di Edwards compresso di curve25519-dalek (32 B, y little-endian
    con il segno di x nel bit piu' significativo).
    """
    if isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
    else:
        with open(source, 'rb') as f:
            raw = f.read()

    try:
        i = skip_sequence_header(raw)
        _, _, i = read_tlv(raw, i)
        _, wrapper, _ = read_tlv(raw, i)

        j = skip_sequence_header(wrapper)
        _, _, j = read_tlv(wrapper, j)          # group
        _, label, j = read_tlv(wrapper, j)      # label
        _, _, j = read_tlv(wrapper, j)          # ctxt
        _, u_bytes, _ = read_tlv(wrapper, j)    # U
    except (IndexError, ValueError, struct.error) as exc:
        raise MalformedCiphertext(
            f'struttura DER non riconosciuta ({len(raw)} byte): '
            'inviare il crittogramma prodotto da POST '
            f'/v1/sg02/ciphertexts. Dettaglio: {exc}') from exc

    if len(u_bytes) != 65 or u_bytes[0] != 0x04:
        raise MalformedCiphertext(
            'il punto U non e\' in formato SEC1 non compresso: il '
            'contenuto non sembra un crittogramma SG02.')

    x_be = u_bytes[1:33]
    y_be = u_bytes[33:65]
    y_le = bytearray(reversed(y_be))
    sign_x = x_be[-1] & 1
    y_le[31] = (y_le[31] & 0x7F) | (sign_x << 7)
    return bytes(y_le), bytes(label)
