#!/usr/bin/env bash
# demo.sh — dimostrazione end-to-end del TCN via HTTP.
#
#   ./demo.sh              passo per passo, invio per proseguire
#   ./demo.sh --fast       tutto di seguito senza pause
#   ./demo.sh --sg02       solo la parte a soglia
#   ./demo.sh --ppke       solo la cancellazione crittografica
#
# Presuppone il servizio avviato su localhost:8000 e una Nitrokey
# collegata. Le fasi di setup sono distruttive: rigenerano le chiavi sul
# token e consumano una punzonatura.

set -u
API=${API:-http://localhost:8000}
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

step()  { echo; echo "${B}── $* ${N}"; }
note()  { echo "   ${D}$*${N}"; }
good()  { echo "   ${G}✓${N} $*"; }
bad()   { echo "   ${R}✗${N} $*"; }
pause() { [ "$FAST" = 1 ] || { echo; read -rsp "   ${D}invio per proseguire${N}"; echo; }; }

# Mostra il comando prima di eseguirlo: in una dimostrazione la
# richiesta HTTP e' parte di cio' che si vuole far vedere.
show() { echo "   ${D}\$ $*${N}"; }

jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)" 2>/dev/null; }
b64()  { printf '%s' "$1" | base64 -w0; }
unb64(){ python3 -c "import sys,base64; print(base64.b64decode(sys.argv[1]).decode())" "$1"; }

post() { curl -s -X POST "$API$1" -H 'Content-Type: application/json' -d "$2"; }
get()  { curl -s "$API$1"; }

# ---------------------------------------------------------------------
step "Stato del servizio"
show "curl $API/v1/health"
HEALTH=$(get /v1/health)
STATUS=$(echo "$HEALTH" | jget "d['status']")
TOKENS=$(echo "$HEALTH" | jget "d['tokens']")
if [ "$STATUS" = ok ]; then good "servizio ok, $TOKENS token collegati"
else
  bad "stato: ${STATUS:-nessuna risposta}"
  echo "$HEALTH" | python3 -m json.tool 2>/dev/null
  [ -z "$STATUS" ] && { echo "   il servizio risponde su $API?"; exit 1; }
fi

show "curl -X POST $API/v1/tokens/scan"
NODES=$(post /v1/tokens/scan '{}' | jget "d['nodes']")
good "nodi con identita' leggibile: $NODES"
note "il node_id non viene dal nome del lettore: lo dichiara il token (INS 0x05)"
pause

# ---------------------------------------------------------------------
if [ "$ONLY" = all ] || [ "$ONLY" = sg02 ]; then

step "SG02 — crittografia a soglia"
note "le share stanno nei token, il nodo centrale non le conserva"

show "curl -X POST $API/v1/sg02/groups -d '{\"reset\":true}'"
GROUP=$(post /v1/sg02/groups '{"reset":true}')
KEYID=$(echo "$GROUP" | jget "d['key_id']")
K=$(echo "$GROUP" | jget "d['k']"); NN=$(echo "$GROUP" | jget "d['n']")
if [ -z "$KEYID" ]; then bad "keygen fallito"; echo "$GROUP" | python3 -m json.tool; exit 1; fi
good "gruppo k=$K su n=$NN generato"
note "key_id ${KEYID:0:24}..."
pause

show "curl -X POST $API/v1/sg02/key-distributions -d '{}'"
DIST=$(post /v1/sg02/key-distributions '{}')
echo "$DIST" | python3 -c "
import sys,json
for d in json.load(sys.stdin)['distributions']:
    mark = '\033[32m✓\033[0m' if d['ok'] else '\033[31m✗\033[0m'
    print(f\"   {mark} nodo {d['node_id']} ← {d['reader'][:46]}\")
    if d['error']: print('      ' + d['error'])
"
note "ogni share viaggia firmata dal dealer; il token rifiuta quelle non firmate"
post /v1/tokens/scan '{}' >/dev/null
pause

step "Cancellazione del materiale privato dal nodo centrale"
show "curl -X DELETE $API/v1/sg02/keystores"
WIPE=$(curl -s -X DELETE "$API/v1/sg02/keystores")
good "$(echo "$WIPE" | jget "d['message']")"
note "da qui la soglia protegge anche a riposo: le share esistono solo nei token"
pause

step "Cifratura"
PT="dati clinici del paziente 4417"
show "curl -X POST $API/v1/sg02/ciphertexts -d '{\"plaintext\":\"...\",\"label\":\"DEMO\"}'"
CT=$(post /v1/sg02/ciphertexts "{\"plaintext\":\"$(b64 "$PT")\",\"label\":\"DEMO\"}" | jget "d['ciphertext']")
if [ -z "$CT" ]; then bad "cifratura fallita"; exit 1; fi
good "crittogramma prodotto (${#CT} caratteri base64)"
note "usa solo la chiave pubblica: nessun segreto coinvolto"
pause

step "Decifratura parziale su un singolo token"
FIRST=$(echo "$NODES" | tr -d '[] ' | cut -d, -f1)
show "curl -X POST $API/v1/tokens/$FIRST/decryption-shares -d '{\"ciphertext\":\"...\"}'"
SHARE=$(post "/v1/tokens/$FIRST/decryption-shares" "{\"ciphertext\":\"$CT\"}")
echo "$SHARE" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if 'error' in d: print('   \033[31m✗\033[0m', d['error']['message'][:90]); raise SystemExit
print(f\"   \033[32m✓\033[0m share dal nodo {d['node_id']}\")
for f in ('ui','ei','fi'): print(f\"      {f:3s} {d[f][:40]}...\")
"
note "la share da sola non rivela nulla del contenuto"
pause

step "Aggregazione: il plaintext torna"
show "curl -X POST $API/v1/sg02/decryptions -d '{\"ciphertext\":\"...\"}'"
OUT=$(post /v1/sg02/decryptions "{\"ciphertext\":\"$CT\"}")
REC=$(echo "$OUT" | jget "d['plaintext']")
if [ -n "$REC" ]; then good "$(unb64 "$REC")"
  note "raccolte k share in parallelo, verificate le ZKP, aggregate"
else bad "$(echo "$OUT" | jget "d['error']['message']")"; fi
pause
fi

# ---------------------------------------------------------------------
if [ "$ONLY" = all ] || [ "$ONLY" = ppke ]; then

step "GMPpke — cancellazione crittografica"
note "modello opposto: la stessa chiave su tutti i token, e per cancellare servono tutti"

show "curl -X POST $API/v1/ppke/keys -d '{}'"
JOB=$(post /v1/ppke/keys '{}' | jget "d['job']['id']")
note "operazione lunga: risponde 202 e prosegue come job $JOB"
for _ in $(seq 1 40); do
  ST=$(get "/v1/jobs/$JOB" | jget "d['status']")
  [ "$ST" = running ] || [ "$ST" = pending ] || break
  sleep 0.5
done
if [ "$ST" = succeeded ]; then
  RES=$(get "/v1/jobs/$JOB/result")
  good "chiave generata e distribuita: $(echo "$RES" | jget "'d=%s, nodi %s' % (d['value']['d'], d['value']['distributed'])")"
  note "la chiave privata non tocca mai il disco del nodo centrale"
else bad "setup fallito: $(get "/v1/jobs/$JOB" | jget "d['error']" )"; fi
pause

step "Cifratura legata a tre etichette"
PT2="cartella clinica — Mario Rossi"
TAGS='["subject-4417","categoria-sanitaria","retention-2031"]'
show "curl -X POST $API/v1/ppke/ciphertexts -d '{\"plaintext\":\"...\",\"tags\":$TAGS}'"
CTS=$(post /v1/ppke/ciphertexts "{\"plaintext\":\"$(b64 "$PT2")\",\"tags\":$TAGS}")
CTP=$(echo "$CTS" | jget "d['ct_pfse']"); CSY=$(echo "$CTS" | jget "d['ct_sym']")
good "crittogramma legato a 3 etichette"
note "soggetto, categoria di dati, classe di retention: tre vie di cancellazione indipendenti"
pause

step "Secondo record, etichette diverse"
PT3="cartella clinica — Anna Bianchi"
TAGS2='["subject-9002","categoria-sanitaria","retention-2033"]'
CTS2=$(post /v1/ppke/ciphertexts "{\"plaintext\":\"$(b64 "$PT3")\",\"tags\":$TAGS2}")
CTP2=$(echo "$CTS2" | jget "d['ct_pfse']"); CSY2=$(echo "$CTS2" | jget "d['ct_sym']")
good "secondo crittogramma prodotto"
pause

step "Entrambi decifrano"
for pair in "$CTP|$CSY|primo" "$CTP2|$CSY2|secondo"; do
  IFS='|' read -r a b lbl <<<"$pair"
  R=$(post "/v1/ppke/decryptions/$FIRST?mode=sync" "{\"ct_pfse\":\"$a\",\"ct_sym\":\"$b\"}")
  P=$(echo "$R" | jget "d['plaintext']")
  if [ -n "$P" ]; then good "$lbl record → $(unb64 "$P")"
  else bad "$lbl record → $(echo "$R" | jget "d['error']['code']")"; fi
done
pause

step "Richiesta di cancellazione: articolo 17 GDPR"
note "il soggetto 4417 esercita il diritto all'oblio"
show "curl -X POST $API/v1/punctures -d '{\"tag\":\"subject-4417\"}'"
PJ=$(post /v1/punctures '{"tag":"subject-4417"}' | jget "d['job']['id']")
note "campagna su TUTTI i token: uno solo non punzonato basta a vanificarla"
for _ in $(seq 1 120); do
  ST=$(get "/v1/jobs/$PJ" | jget "d['status']")
  [ "$ST" = running ] || [ "$ST" = pending ] || break
  sleep 0.5
done
if [ "$ST" = succeeded ]; then good "campagna conclusa"
else bad "campagna: $ST — $(get "/v1/jobs/$PJ" | jget "d['error']")"; fi
pause

step "L'effetto della cancellazione"
R=$(post "/v1/ppke/decryptions/$FIRST?mode=sync" "{\"ct_pfse\":\"$CTP\",\"ct_sym\":\"$CSY\"}")
CODE=$(echo "$R" | jget "d['error']['code']" )
if [ "$CODE" = punctured ]; then
  echo "   ${Y}410 Gone${N} — $(echo "$R" | jget "d['error']['message']")"
  note "410, non 403: non e' un permesso negato, il contenuto non esiste piu' per nessuno"
else
  bad "il record cancellato e' ancora decifrabile"
fi
echo
R2=$(post "/v1/ppke/decryptions/$FIRST?mode=sync" "{\"ct_pfse\":\"$CTP2\",\"ct_sym\":\"$CSY2\"}")
P2=$(echo "$R2" | jget "d['plaintext']")
if [ -n "$P2" ]; then good "secondo record intatto → $(unb64 "$P2")"
else bad "anche il secondo record e' stato colpito"; fi
note "la cancellazione e' circoscritta all'etichetta, non alla chiave"
pause

step "Stato verificabile"
show "curl $API/v1/ppke/state"
get /v1/ppke/state | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f\"   anagrafica {d['roster']}  collegati {d['connected']}  assenti {d['missing']}\")
print(f\"   allineati: {d['aligned']}\")
for n in d['nodes']:
    print(f\"   nodo {n['node_id']}: punzonati {n['punctured']}  capacita' residua {n['capacity']}/{d['max_punctures']}\")
"
note "registro tenuto dal nodo centrale: i token non dichiarano il proprio stato"
fi

echo
echo "${B}── fine ${N}"
