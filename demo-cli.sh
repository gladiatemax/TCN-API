#!/usr/bin/env bash
# demo-cli.sh — dimostrazione del nodo centrale dalla riga di comando.
#
#   ./demo-cli.sh            passo per passo, invio per proseguire
#   ./demo-cli.sh --fast     di seguito, per una prova a vuoto
#   ./demo-cli.sh --sg02     solo la crittografia a soglia
#   ./demo-cli.sh --ppke     solo la cancellazione crittografica
#
# Presuppone: tcn.env caricato, Nitrokey collegate, servizio HTTP SPENTO
# (CLI e servizio non possono detenere il nodo contemporaneamente).
#
# Le fasi di setup sono distruttive: rigenerano le chiavi sui token e
# consumano una punzonatura delle cinque disponibili.

set -u

# I messaggi diagnostici della CLI vanno su stderr, i risultati su
# stdout. Unendoli in una pipe, stdout viene bufferizzato a blocchi e
# stderr no: le righe arrivano fuori ordine, e il suggerimento del passo
# successivo compare prima del risultato del passo corrente.
export PYTHONUNBUFFERED=1

CLI=${CLI:-./tcn-cli}
WORK=${WORK:-/tmp/tcn-demo}
FAST=0; ONLY=all

for arg in "$@"; do
  case "$arg" in
    --fast) FAST=1 ;;
    --sg02) ONLY=sg02 ;;
    --ppke) ONLY=ppke ;;
    *) echo "opzione sconosciuta: $arg"; exit 2 ;;
  esac
done

B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; D=$'\e[2m'; Y=$'\e[33m'; N=$'\e[0m'

step()  { echo; echo "${B}━━ $* ${N}"; echo; }
say()   { echo "   ${D}$*${N}"; }
good()  { echo "   ${G}✓${N} $*"; }
bad()   { echo "   ${R}✗${N} $*"; }
pause() { [ "$FAST" = 1 ] || { echo; read -rsp "   ${D}[invio]${N}"; echo; }; }

# Mostra il comando e poi lo esegue: in una presentazione il comando e'
# parte di cio' che si vuole far vedere.
run() {
  echo "   ${B}\$ $*${N}"
  echo
  "$@" 2>&1 | sed 's/^/   /'
  return "${PIPESTATUS[0]}"
}

[ -x "$CLI" ] || { echo "CLI non trovata o non eseguibile: $CLI"; exit 1; }
mkdir -p "$WORK"

if pgrep -f "uvicorn.*tcn.api" >/dev/null 2>&1; then
  echo "${Y}Il servizio HTTP e' in esecuzione.${N}"
  echo "CLI e servizio non possono detenere il nodo contemporaneamente:"
  echo "terminare uvicorn e rilanciare."
  exit 1
fi

# =====================================================================
step "Il sistema"
say "Un nodo centrale orchestra le Nitrokey 3 collegate via USB."
say "Due schemi crittografici con modelli di fiducia opposti:"
say ""
say "  SG02    distribuisce share DIVERSE a n token; ne bastano k."
say "          Protegge dalla compromissione di meno di k dispositivi."
say ""
say "  GMPpke  replica la STESSA chiave su tutti i token; per cancellare"
say "          servono tutti. Un solo token non punzonato conserva la"
say "          capacita' di decifrare cio' che si voleva distruggere."
pause

step "Stato del nodo"
run "$CLI" health || bad "il nodo non e' pronto"
pause

run "$CLI" tokens scan
say "Il node_id non viene dal nome del lettore, che cambia fra i riavvii:"
say "lo dichiara il token stesso (INS 0x05)."
pause

# =====================================================================
if [ "$ONLY" = all ] || [ "$ONLY" = sg02 ]; then

step "SG02 — crittografia a soglia"
say "Il nodo centrale genera n share. Per un istante le detiene tutte,"
say "ed e' il momento piu' esposto dell'intero sistema."
pause

run "$CLI" sg02 keygen --reset || { bad "keygen fallito"; exit 1; }
pause

run "$CLI" sg02 distribute || { bad "distribuzione incompleta"; exit 1; }
say "Ogni share viaggia firmata dal dealer: un token rifiuta con SW 6982"
say "qualunque share non firmata dalla chiave cablata nel firmware."
pause

step "Chiusura della finestra di esposizione"
say "Finche' i keystore esistono sul nodo centrale, la soglia protegge"
say "solo in transito. Cancellarli la rende valida anche a riposo."
run "$CLI" sg02 wipe-keystores --yes
pause

step "Cifratura"
echo "dati clinici del paziente 4417" > "$WORK/record.txt"
say "contenuto: $(cat "$WORK/record.txt")"
echo
run "$CLI" sg02 encrypt -i "$WORK/record.txt" --label DEMO \
    -o "$WORK/record.enc"
say "Usa solo la chiave pubblica: nessun segreto coinvolto nella"
say "cifratura, che puo' quindi avvenire ovunque."
pause

step "Decifratura parziale su un singolo token"
run "$CLI" sg02 share --node 1 -i "$WORK/record.enc"
say "La share da sola non rivela nulla del contenuto. Servono k share"
say "da token distinti, e ciascuna porta una prova a conoscenza zero"
say "che viene verificata in aggregazione."
pause

step "Aggregazione"
run "$CLI" sg02 decrypt -i "$WORK/record.enc" -o -
echo
say "Share raccolte in parallelo, ZKP verificate, plaintext ricostruito."
pause
fi

# =====================================================================
if [ "$ONLY" = all ] || [ "$ONLY" = ppke ]; then

step "GMPpke — cancellazione crittografica"
say "Articolo 17 GDPR: il diritto alla cancellazione. Su un backup"
say "immutabile o replicato non si puo' cancellare un record."
say "Si distrugge invece la capacita' di decifrarlo."
pause

run "$CLI" ppke setup --yes || { bad "setup fallito"; exit 1; }
say "La chiave privata non tocca mai il disco del nodo centrale: vive"
say "in memoria il tempo della distribuzione e viene azzerata."
pause

step "Due record, etichette diverse"
echo "cartella clinica — Mario Rossi"  > "$WORK/rossi.txt"
echo "cartella clinica — Anna Bianchi" > "$WORK/bianchi.txt"

run "$CLI" ppke encrypt -i "$WORK/rossi.txt" \
    --tags subject-4417,categoria-sanitaria,retention-2031 \
    -o "$WORK/rossi"
echo
run "$CLI" ppke encrypt -i "$WORK/bianchi.txt" \
    --tags subject-9002,categoria-sanitaria,retention-2033 \
    -o "$WORK/bianchi"
say ""
say "Tre etichette per record: soggetto, categoria di dati, classe di"
say "retention. Tre maniglie di cancellazione INDIPENDENTI: punzonarne"
say "una qualsiasi rende il record indecifrabile."
pause

step "Entrambi i record si decifrano"
run "$CLI" ppke decrypt --node 1 -i "$WORK/rossi"   -o -
echo
run "$CLI" ppke decrypt --node 1 -i "$WORK/bianchi" -o -
pause

step "Il soggetto 4417 chiede la cancellazione"
say "L'operazione e' IRREVERSIBILE e deve raggiungere TUTTI i token."
say "Uno solo non punzonato basta a vanificarla, quindi il nodo"
say "centrale rifiuta di iniziare se un token manca."
echo
run "$CLI" puncture create --tag subject-4417 --yes
pause

step "L'effetto"
run "$CLI" ppke decrypt --node 1 -i "$WORK/rossi" -o -
rc=$?
echo
if [ "$rc" = 4 ]; then
  good "codice d'uscita 4: contenuto cancellato"
  say ""
  say "Non e' un permesso negato che qualcuno potrebbe riabilitare."
  say "La capacita' di decifrare e' stata DISTRUTTA nel dispositivo."
  say "Nell'API corrisponde a 410 Gone, non a 403 Forbidden."
else
  bad "atteso codice 4, ricevuto $rc"
fi
pause

step "La cancellazione e' circoscritta"
run "$CLI" ppke decrypt --node 1 -i "$WORK/bianchi" -o -
echo
say "L'altro record e' intatto: a essere distrutta e' la capacita'"
say "legata a quell'etichetta, non la chiave."
pause

step "Stato verificabile"
run "$CLI" ppke state
say ""
say "Il registro e' tenuto dal nodo centrale: i token non dichiarano"
say "il proprio stato interno, per non offrire un canale di lettura."
say "L'allineamento confronta gli INSIEMI di etichette, non i byte:"
say "la punzonatura e' randomizzata e ogni token usa il proprio RNG,"
say "quindi le chiavi divergono nella forma restando equivalenti."
pause

run "$CLI" puncture list
say "Traccia di conformita': l'articolo 5(2) richiede di poter"
say "DIMOSTRARE che la cancellazione e' avvenuta."
fi

echo
echo "${B}━━ fine ${N}"
echo
say "I file prodotti restano in $WORK"
