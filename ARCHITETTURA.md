# TCN — struttura del codice e funzione dei moduli

Il sistema espone due schemi crittografici realizzati come estensioni del
firmware Trussed per Nitrokey 3:

| | SG02 (TDH2) | GMPpke |
|---|---|---|
| Curva | Ed25519 | BN254 |
| Proprietà | decifratura a soglia *k*-su-*n* | cifratura punzonabile |
| Chiave sui token | share **diverse** | la **stessa**, replicata |
| Per decifrare | servono *k* token | basta **un** token |
| Per cancellare | — | servono **tutti** i token |

---

## 1. La regola delle dipendenze

Il package è stratificato e le dipendenze vanno **solo verso il basso**.
Nessuna eccezione nel codice attuale.

```
                  ┌──────────────┐   ┌──────────────┐
   interfacce     │   tcn.cli    │   │   tcn.api    │   ← fratelli,
                  └──────┬───────┘   └──────┬───────┘     non si parlano
                         └────────┬─────────┘
                  ┌───────────────▼────────────────┐
   orchestrazione │         tcn.services           │   ← non sa che
                  └───────────────┬────────────────┘     esiste HTTP
            ┌────────────┬────────┴─────┬──────────────┐
   dominio  │ tcn.tokens │ tcn.convert  │ tcn.hosttools│
            └──────┬─────┴──────────────┴──────────────┘
                   │
            ┌──────▼────────┐
   trasporto│ tcn.transport │  ← non conosce gli schemi
            └───────────────┘

   trasversali:  config · dealer · ledger · planner · lockfile · jobs
```

**La CLI non passa dall'API.** Sono due interfacce parallele sopra lo
stesso livello di servizi. Chi integra può aggiungere una terza
interfaccia (un worker, un adattatore gRPC, un cron) allo stesso modo:
istanziando i servizi, non chiamando HTTP.

I lock che serializzano gli accessi PC/SC sono
oggetti in memoria, quindi non vedono altri processi. Da qui il lock su
file di `tcn.lockfile`, che vale fra processi, e il vincolo
`uvicorn --workers 1`.

---

## 2. L'albero

```
API/
├── tcn-cli                   eseguibile: `python -m tcn.cli.main`
├── tcn.env                   configurazione d'ambiente (da sorgere)
├── verify_tcn.py             verifica end-to-end in 8 fasi
├── demo.sh                   dimostrazione dell'API via curl
├── demo-cli.sh               dimostrazione della CLI in 14 passi
│
└── tcn/
    ├── config.py             ogni percorso, timeout e parametro
    ├── transport.py          APDU ISO 7816 su PC/SC
    ├── dealer.py             firma Ed25519 sulle share  (unico accesso
    │                         alla chiave privata del dealer)
    ├── ledger.py             registro append-only delle punzonature
    ├── planner.py            scelta della variante di decrypt GMPpke
    ├── lockfile.py           mutua esclusione fra processi
    ├── jobs.py               operazioni asincrone (solo API)
    │
    ├── convert/              formati binari
    │   ├── bn254.py          aritmetica Fp2, isomorfismo RELIC↔arkworks
    │   ├── ppke_wire.py      blob cereal → payload firmware
    │   └── sg02_der.py       ASN.1 DER delle share SG02
    │
    ├── tokens/               un token alla volta
    │   ├── registry.py       scoperta, identità, lock per lettore
    │   ├── sg02.py           INS 0x01, 0x02, 0x05 di theta-app
    │   └── ppke.py           INS 0x01–0x07 di forwardsec-app
    │
    ├── services/             orchestrazione
    │   ├── sg02.py           setup, distribuzione, soglia
    │   └── ppke.py           setup, decifratura, campagne di punzonatura
    │
    ├── cli/                  interfaccia a riga di comando (argparse)
    │   ├── main.py           parser, dispatch, acquisizione del lock
    │   ├── common.py         contesto, I/O, resa, codici d'uscita
    │   ├── tokens.py  sg02.py  ppke.py  punctures.py
    │
    └── api/                  interfaccia HTTP (FastAPI)
        ├── main.py           applicazione, CORS, handler
        ├── deps.py           singleton per processo
        ├── errors.py         dominio → status HTTP
        ├── models.py         schemi Pydantic di richiesta e risposta
        └── routers/
            tokens.py  sg02.py  ppke.py  punctures.py  jobs.py
```

Circa 7 300 righe di Python, di cui 714 di sola verifica.

---

## 3. Trasporto

### `transport.py`

Costruisce gli APDU, li trasmette, restituisce `(payload, SW)`. Non
conosce gli schemi crittografici né HTTP.

| payload | forma |
|---|---|
| vuoto | `[CLA INS P1 P2 00]` |
| ≤ 255 B | APDU corto, Lc e Le di 1 byte |
| > 255 B | APDU esteso, Lc di 3 byte (`00 hi lo`), Le di 2 byte |
| risposta lunga | chaining `61XX` risolto con GET RESPONSE `00 C0 00 00 XX` |

- **La decisione su un SW diverso da `9000` spetta al chiamante.** Il
  trasporto solleva `ApduError(sw)` e si ferma lì: `6982` significa
  "punzonata", che non è un errore di trasporto ma un esito legittimo
  del dominio.
- `pyscard` è importato in modo tollerante. Senza lettore il modulo
  resta utilizzabile per tutto ciò che non tocca l'hardware: planner,
  conversioni di formato, test dei formati binari. `PCSC_AVAILABLE` dice
  quale dei due casi vale.
- `CardChannel` è un context manager; `select(aid)` va chiamata prima di
  ogni gruppo di comandi.

---

## 4. Formati binari — `convert/`

Tre moduli di pura conversione: nessuna I/O, nessuno stato, nessuna
dipendenza dall'hardware.

### `convert/bn254.py`

Aritmetica di campo su BN254 (alt_bn128) e **isomorfismo fra le torri di
RELIC e di arkworks**. Le due librerie costruiscono Fp12 con non-residui
diversi — `32+u` contro `9+u` — e la traduzione non è un semplice
riordino di byte: è definita dalla costante `Z` con
`Z⁶ = (32+u)/(9+u)`, da cui

- G2: `(x, y) → (Z²x, Z³y)`
- GT: il coefficiente `(i,j)` si moltiplica per `Z^(2j+i)`

Chi dovesse cambiare libreria di pairing lato host deve rivedere **questo
file e nient'altro**.

### `convert/ppke_wire.py`

Ponte fra i blob `cereal` di libforwardsec e i payload attesi da
`forwardsec-app`. `CerealReader` legge il formato BinaryArchive;
`parse_pk` / `parse_sk` / `parse_ct` smontano, `build_fw_*` rimontano
nella codifica arkworks. `gt_ark_bytes_to_key` chiude il giro: riporta M
in rappresentazione RELIC e ne deriva la chiave simmetrica con SHA-256.

### `convert/sg02_der.py`

ASN.1 DER per SG02, nelle due direzioni.

- **device → thetacrypt**: i 99 byte grezzi di INS 0x02
  (`node_id` 2 B · `ui` 33 B · `ei` 32 B · `fi` 32 B) diventano una
  `Sg02DecryptionShare` in DER, accettata da `thetacli assemble`.
- **thetacrypt → device**: estrazione di `xi` e `node_id` da un keystore,
  di `U` e `label` da un crittogramma.

Due dettagli importanti:

**La compressione dei punti differisce.** Il firmware emette
`02/03 ‖ y_be` (RFC 8032); `ECP::frombytes` di mcore interpreta il campo
compresso come `x_be`. `firmware_ui_to_mcore` fa il ponte ricavando x
dalla curva, `x² = (y²−1)/(d·y²+1) mod p`, e restituisce il punto non
compresso a 65 byte.

**Il primo campo della struttura esterna non è il `node_id`.** È il
discriminante di schema, costante (`SCHEME_SG02 = 1`), che thetacrypt
legge *prima* di interpretare il resto. Scriverci il `node_id` funziona
per il nodo 1 — dove i due valori coincidono per caso — e fa fallire ogni
altro nodo con `Threshold(DeserializationFailed)`, prima della verifica
crittografica. 

---

## 5. Un token alla volta — `tokens/`

Livello sottile sopra `CardChannel`: costruisce i payload, invia l'APDU,
traduce i SW in **eccezioni di dominio**. Nessuna orchestrazione, che
appartiene a `services/`.

### `tokens/registry.py`

Risolve tre problemi che nascono dall'avere più Nitrokey sulla stessa
macchina.

**Identità.** L'ordine in cui `pcscd` enumera i lettori non è stabile fra
riavvii né fra reinserimenti: *il nome del lettore non identifica il
nodo*. L'identità va chiesta al token con INS 0x05. Ma il `node_id`
esiste solo dopo l'import della share SG02, quindi:

> gli endpoint di **setup** indirizzano per **lettore**,
> quelli **operativi** per **node_id**.

**Concorrenza.** Un lock **per lettore**, non globale: due token
indipendenti devono poter lavorare in parallelo. L'attesa ha un timeout
(`TCN_TOKEN_LOCK_TIMEOUT`, 30 s), così una richiesta bloccata diventa un
503 invece di restare appesa.

**Ordine di acquisizione.** Un solo lock di token per volta, mai due
annidati. È la regola che rende sicura la raccolta parallela delle share
e che va rispettata da qualunque codice nuovo.

API principale: `scan()`, `tokens()`, `nodes()`, `by_node()`,
`by_reader()`, `missing(expected)`, e il context manager `session(...)`
che acquisisce il lock e seleziona l'AID.

### `tokens/sg02.py` — theta-app, AID `A0 00 00 08 47 00 01`

| INS | Comando | Payload |
|---|---|---|
| `0x01` | ImportKeyShare | `xi(32) ‖ node_id(2 BE) ‖ sig(64)` |
| `0x02` | PartialDecrypt | `U(32)` → 99 byte grezzi |
| `0x05` | GetNodeId | — → `node_id(2 BE)` |

Eccezioni: `DealerSignatureRejected`, `ShareNotImported`,
`MalformedPayload`, `DeviceFault`.

### `tokens/ppke.py` — forwardsec-app, AID `A0 00 00 08 47 00 03`

| INS | Comando | Costo |
|---|---|---|
| `0x01` | ImportKey (sempre Replace) | — |
| `0x02` | Decrypt baseline | 3·ns ML + 3·ns FE |
| `0x03` | Puncture | — |
| `0x04` | Decrypt per-tag algebrico | (d+1) ML + (d+1) FE |
| `0x05` | Decrypt per-tag + multipair | (d+1) ML + 1 FE |
| `0x06` | Decrypt per-share + multipair | (i+2) ML + 1 FE |
| `0x07` | Decrypt per-share algebrico | (i+2) ML + (i+2) FE |

`probe_tag` è il meccanismo con cui il TCN risolve l'incertezza dopo una
trasmissione fallita: non chiede al token il suo stato — non esiste un
comando per farlo — ma tenta di decifrare un crittogramma sonda legato a
quel tag e guarda se risponde `6982`.

Eccezioni: `Punctured`, `KeyNotLoaded`, `MalformedPayload`,
`PunctureCapacityExhausted`.

---

## 6. Orchestrazione — `services/`

Qui vivono le operazioni che hanno senso per un utente del sistema. È il
livello su cui si appoggia qualunque interfaccia nuova.

### `services/sg02.py`

| Metodo | Che cosa fa |
|---|---|
| `setup_group(k, n)` | keygen *k*-su-*n* sull'host, via `thetacli` |
| `distribute(...)` | import della share su un token, firmata dal dealer |
| `wipe_keystores(force)` | cancella il materiale privato dal TCN |
| `encrypt(pt, label)` | cifratura con la sola chiave pubblica |
| `collect_share(node, U, label)` | decifratura parziale, già in DER base64 |
| `decrypt(ct, nodes)` | raccoglie *k* share e aggrega |

**Il momento delicato è la distribuzione.** Il keygen produce *n* share
private sul TCN: fra quel momento e `wipe_keystores` il nodo centrale le
possiede tutte insieme, e la proprietà di soglia non protegge nulla. La
finestra va tenuta corta e la cancellazione va fatta, non rimandata. È
anche la ragione per cui `encrypt` e `assemble` usano `--pubkey` e non il
keystore: altrimenti i keystore andrebbero conservati e la finestra non
si chiuderebbe mai.

`wipe_keystores` rifiuta di procedere se la distribuzione non è completa
(`IncompleteDistribution`), perché cancellare le share prima di averle
consegnate rende il gruppo inservibile. `--force` scavalca il controllo.

La raccolta delle share è parallela per difetto (un thread per token,
ciascuno con il proprio lock). `TCN_PARALLEL_SHARES=0` passa alla
sequenza: più lento, ma non espone `pyscard` alla concorrenza.

### `services/ppke.py`

Tre proprietà del firmware governano il disegno di questo modulo:

1. la punzonatura è **irreversibile**;
2. **non è idempotente** — ripetere lo stesso tag consuma una seconda
   unità di `MAX_PUNCTURES`;
3. il token **non dichiara il proprio stato interno**.

Insieme rendono pericoloso il ritentativo cieco: una trasmissione fallita
lascia due possibilità indistinguibili — il token ha punzonato e la
risposta si è persa, oppure non ha ricevuto nulla — e nessun comando
permette di chiederglielo.

Da qui la sequenza rigida di ogni passo di una campagna:

```
   ledger.record_intent(cid, node)      ← write-ahead
   token: INS 0x03 Puncture
   ledger.record_result(cid, node, ok)  ← oppure record_unknown
```

e l'esecuzione **sequenziale** sui token, non parallela: su
un'operazione irreversibile la prevedibilità vale più della velocità.

| Metodo | Nota |
|---|---|
| `setup_keys(d)` | keygen + distribuzione; la SK vive su tmpfs ed è azzerata |
| `roster()` | i nodi **attesi**, dedotti da ledger e configurazione |
| `encrypt(pt, tags)` | produce la coppia `ct_pfse` + `ct_sym` |
| `decrypt(node, ...)` | on-device; la variante la scegli o la sceglie il planner |
| `puncture(tag, nodes)` | apre una campagna e la esegue |
| `resume(cid)` | riprende una campagna interrotta |
| `resolve_unknown(cid)` | risolve gli intent pendenti con le sonde |
| `report()`, `aligned()` | stato per token, allineamento del gruppo |

**`roster()` non deriva dai token collegati.** Deriva dal ledger e dalla
configurazione. È una distinzione che conta: un token staccato deve
apparire **mancante**, non *inesistente*. Un roster dedotto dalla
presenza farebbe sembrare completa una campagna che ha saltato un token.

---

## 7. Moduli trasversali

### `config.py`

Ogni percorso, timeout e parametro di schema vive qui; nessun altro
modulo contiene stringhe assolute. Tutto è sovrascrivibile da variabile
d'ambiente con prefisso `TCN_`.

| Variabile | Difetto | Significato |
|---|---|---|
| `TCN_THETACLI` | — | binario `thetacli` |
| `TCN_PFSE_TOOL` | — | binario `pfse_tool_bn254` |
| `TCN_STATE_DIR` | `~/.local/share/tcn` | stato persistente |
| `TCN_DEALER_KEY` | `~/.config/tcn/dealer_sk.pem` | chiave privata del dealer |
| `TCN_VOLATILE_DIR` | `/dev/shm/tcn` | **deve stare su tmpfs** |
| `TCN_SG02_K` / `_N` | 3 / 5 | soglia e numero di nodi |
| `TCN_PPKE_D` | 3 | tag per crittogramma, fissato al keygen |
| `TCN_PPKE_MAX_PUNCTURES` | 5 | limite di capacità del backend |
| `TCN_READER_MATCH` | `Nitrokey` | filtro sui nomi dei lettori |
| `TCN_TOKEN_LOCK_TIMEOUT` | 30 s | attesa massima prima di un 503 |
| `TCN_SUBPROCESS_TIMEOUT` | 120 s | timeout di un binario host |
| `TCN_SYNC_THRESHOLD` | 2 s | oltre questa soglia un'operazione diventa job |
| `TCN_PARALLEL_SHARES` | 1 | raccolta delle share in parallelo |
| `TCN_T_MILLER_LOOP` | 505 ms | costanti di costo per il planner |
| `TCN_T_FINAL_EXP` | 636 ms | |
| `TCN_T_SCALARMULT_DELTA` | 387 ms | |

`ensure_dirs()` crea le directory di stato e, su percorso non
scrivibile, solleva `StateDirUnavailable` dicendo **quale variabile
cambiare** invece di un `PermissionError` grezzo. `volatile_dir` è
esclusa: va creata su tmpfs solo quando serve e rimossa subito dopo.

> `d` e `MAX_PUNCTURES` rappresentano informazioni diverse e vengono confuse spesso: `d`
> è il numero di tag per crittogramma, deciso al keygen;
> `MAX_PUNCTURES` è il limite di punzonature memorizzabili nel backend.

### `dealer.py`

Isolato in un modulo proprio perché è **l'unico punto del sistema che
tocca la chiave privata del dealer**. Il confine è così ispezionabile
invece che disperso.

Firma con Ed25519 il messaggio `xi ‖ node_id` (34 byte), che il firmware
verifica in `import_key_share` contro la costante `DEALER_ED25519_PK`
cablata nel binario. Un token rifiuta l'import con `6982` se la firma
non torna.

Nota per il threat model: nel prototipo dealer e nodo centrale
coincidono, quindi questa firma **non protegge da un TCN compromesso**.
Protegge dall'attaccante con accesso fisico ai token ma non alla chiave
del dealer, e vincola l'associazione fra una share e il `node_id` a cui è
destinata.

### `ledger.py`

Il token non espone alcun comando per dichiarare il proprio stato, e la
punzonatura è irreversibile: **il TCN è l'unico depositario** di cosa è
stato punzonato e dove. Questo registro è quel deposito.

Formato append-only, una riga JSON per record, `fsync` dopo ogni
scrittura. Lo stato in memoria si ricostruisce rileggendo il file
dall'inizio, quindi il processo può morire in qualsiasi momento senza
perdere informazione.

Il meccanismo centrale è il **write-ahead log**. Un `intent` senza
`result` è uno stato *incerto*, non uno stato negativo. Senza WAL un
crash produrrebbe un registro che mente, dichiarando intatto un token
che non lo è più.

Stati di campagna: `complete` · `partial` · `uncertain` · `pending`.
Solo `complete` significa che la cancellazione è avvenuta.

`record_key_reset(nodes)` esiste perché un `ImportKey` con P1=Replace
azzera lo stato interno del token: le campagne precedenti al reset non
descrivono più la realtà e `node_state` le ignora.

### `planner.py`

Il firmware espone cinque implementazioni della stessa funzione e
**nessuna domina sempre**. Il confronto fra strategia per-tag e per-share
dipende da `d` (fissato al keygen) e da `n` (punzonature su quel token):

```
   per-tag   (INS 0x05)   (d+1) Miller loop + 1 FinalExp
                          costante in n, ma d moltiplicazioni in G2
   per-share (INS 0x06)   (n+2) Miller loop + 1 FinalExp
                          lineare in n, moltiplicazioni in G1
```

G1 e G2 non costano uguale: la differenza Δ è l'ago della bilancia, e il
crossover cade in

```
   n* = d·Δ / (ML − d·Δ)
```

Se `d·Δ ≥ ML` il denominatore non è positivo, non esiste crossover e la
strategia per-share domina ovunque — è il caso di `d=3` sul Cortex-M33.
Con `d=1` il crossover cade intorno a `n* ≈ 3.3`.

Le costanti vivono in `config.Timings` e vanno **tenute allineate alle
misure del benchmark**: qui non sono ricavate, sono lette. Il client può
comunque forzare una variante; il planner decide solo in `auto`.

### `lockfile.py`

I lock del registry sono oggetti in memoria: serializzano gli accessi
dentro un processo e non vedono nulla di quel che fa un altro. Finché
esisteva solo il servizio HTTP bastava `--workers 1`; con una CLI che
chiama gli stessi servizi direttamente il problema torna.

Il guasto che ne deriverebbe è **silenzioso**: `pyscard` si connette in
modalità condivisa, quindi nessuno dei due processi riceve un errore. Si
ottengono APDU interlacciati sullo stesso token — una decifratura
corrotta, o peggio una punzonatura che il ledger non registra.

La difesa sta quindi su disco: un `flock` esclusivo su un file nella
directory di stato. Il secondo processo lo scopre all'avvio e si ferma
**dicendo chi tiene il lock**. Granularità: l'intero nodo centrale, non
il singolo token — grossa, ma giusta per un prototipo con un operatore
alla volta.

### `jobs.py`

Alcune operazioni superano il tempo che ha senso tenere aperta una
connessione HTTP: keygen GMPpke, keygen di gruppo per *n* grande,
decifratura con molte punzonature, e **ogni** campagna di punzonatura.
Per queste l'API risponde 202 e il client fa polling.

Due regole meritano attenzione:

**Il risultato non viene mai persistito.** Il record su disco contiene
stato, tempi, tipo ed errore; il risultato resta in memoria. Un
plaintext GMPpke scritto in un file di job vanificherebbe tutto il lavoro
fatto per tenere i segreti fuori dallo stato persistente del TCN. Dopo un
riavvio `/jobs/{id}/result` risponde 409, e va bene così.

**Il job non è la verità su cosa è successo.** Un processo che muore a
metà campagna lascia il job in `running`; al riavvio diventa
`interrupted`, che significa *"non so come sia finita"*, non *"non è
successo nulla"*. Per la punzonatura la sorgente autorevole resta il
ledger con le sue sonde.

Usato **solo dall'API**: la CLI è sincrona e non ne ha bisogno.

---

## 8. L'interfaccia a riga di comando — `cli/`

`tcn-cli` è un eseguibile di tre righe che invoca `tcn.cli.main`.

### `cli/main.py`

Parser, dispatch e acquisizione del lock. Ogni comando che tocca
l'hardware o scrive sullo stato prende il lock esclusivo su file — lo
stesso del servizio HTTP. I comandi di sola lettura dichiarano
`needs_lock=False`: `health`, `tokens list`, `puncture list`,
`ppke state`.

### `cli/common.py`

Quattro cose: il `Context` che istanzia i servizi su richiesta, la
lettura/scrittura dei dati binari, la resa in forma leggibile o JSON
(`--json`), e `translate()` che porta le eccezioni di dominio nei codici
d'uscita.

Due differenze di fondo rispetto all'API, deliberate:

- **La CLI è sincrona.** Non esistono job: un comando che impiega trenta
  secondi li impiega, mostrando l'avanzamento.
- **La CLI lavora con file.** Un crittogramma è un file o un flusso, non
  una stringa base64 dentro un JSON. La codifica resta un dettaglio
  dell'API.

### I comandi

| Gruppo | Comandi |
|---|---|
| — | `health` |
| `tokens` | `list` · `scan` · `show` |
| `sg02` | `keygen` · `group` · `distribute` · `wipe-keystores` · `encrypt` · `share` · `decrypt` |
| `ppke` | `setup` · `pubkey` · `encrypt` · `decrypt` · `state` |
| `puncture` | `create` · `list` · `show` · `resolve` · `resume` |

L'ordine dei comandi di setup SG02 conta: `keygen` → `distribute` →
`wipe-keystores`. Il terzo passo non è facoltativo.

`puncture create` è l'unico comando irreversibile: chiede conferma e
stampa cosa sta per fare.

### I codici d'uscita

Pensati perché uno script possa reagire **senza interpretare i
messaggi**:

| Codice | Significato |
|---|---|
| `0` | successo |
| `1` | errore generico |
| `2` | errore d'uso (argparse) |
| `3` | non disponibile: token assente, lettore occupato, nodo bloccato |
| `4` | **contenuto cancellato** — non è un errore, è un esito |
| `5` | conflitto: stato del sistema incompatibile con la richiesta |
| `6` | **non pronto**: dispositivo senza chiave |

La distinzione fra `4` e `6` è la più importante dell'intera interfaccia:
*cancellato* e *non ancora pronto* producono entrambi un fallimento della
decifratura, ma significano cose opposte e richiedono reazioni opposte.

---

## 9. L'interfaccia HTTP — `api/`

```bash
uvicorn tcn.api.main:app --host 127.0.0.1 --port 8000 --workers 1
```

Due parametri non sono negoziabili.

**`--workers 1`**: i lock PC/SC sono oggetti in memoria di questo
processo. Con più worker ognuno avrebbe i propri e due processi
aprirebbero lo stesso lettore. Non è risolvibile nel codice del
servizio — da qui `lockfile.py`.

**`--host 127.0.0.1`**: questo servizio espone la capacità di decifrare,
che è esattamente ciò da cui la crittografia a soglia esiste per
proteggere. Pubblicarlo su `0.0.0.0` sposta il confine di fiducia dal
dispositivo fisico al perimetro di rete, e va fatto solo dietro un
reverse proxy che termini TLS e autentichi i client.

### `api/deps.py`

Registry, ledger, dealer, servizi e `JobManager` sono singleton per
processo e **devono** esserlo: due istanze significherebbero due insiemi
di lock che non si vedono, e la serializzazione sarebbe solo apparente.
Il modulo è separato da `main.py` perché i router hanno bisogno di queste
istanze e importarle da `main` creerebbe un ciclo.

### `api/models.py`

Due convenzioni valide ovunque:

- **I dati binari viaggiano in base64 standard**, con validazione
  dichiarativa: un campo malformato produce 422 *prima* che venga
  costruito un APDU.
- **Le risposte scompongono i campi** invece di restituire blob opachi.
  La decryption share arriva dal firmware come 99 byte concatenati; nel
  contratto pubblico diventa `node_id`, `ui`, `ei`, `fi`, più il blob
  grezzo per chi lo passa altrove. Il layout binario resta un dettaglio
  del firmware.

### `api/errors.py`

Il sistema ha già un vocabolario di errori preciso — gli status word ISO
7816 e gli exit code dei binari host. Tradurlo bene conta, perché la
distinzione 4xx/5xx dice al client **se ha senso ritentare**.

| SW | HTTP | Codice |
|---|---|---|
| `6700` | 400 | `wrong_length` |
| `6A80` | 400 | `malformed_payload` |
| `6982` | 403 | `security_status_not_satisfied` |
| `6985` | 409 | `conditions_of_use_not_satisfied` |
| `6A84` | 409 | `puncture_capacity_exhausted` |
| `6D00` | 501 | `instruction_not_supported` |
| `6400` | 502 | `execution_error` |
| `6581` | 502 | `device_fault` |

Le corrispondenze meno ovvie, con la ragione:

- `Punctured` → **410 Gone**. La risorsa esisteva e non è più
  recuperabile: è letteralmente la semantica della cancellazione
  crittografica. Non un errore del client, non un guasto del server.
- `TokenBusy` → **503 + Retry-After**. Il canale PC/SC è occupato;
  ritentare ha senso, ed è utile dire fra quanto.

### Gli endpoint

| Metodo e percorso | Nota |
|---|---|
| `GET /v1/health` | stato del servizio e delle dipendenze |
| `GET /v1/tokens` · `POST /v1/tokens/scan` · `GET /v1/tokens/{node_id}` | |
| `POST /v1/sg02/groups` · `GET /v1/sg02/groups/current` | |
| `POST /v1/sg02/key-distributions` | |
| `DELETE /v1/sg02/keystores` | il passo da non dimenticare |
| `POST /v1/sg02/ciphertexts` | |
| `POST /v1/tokens/{node_id}/decryption-shares` | share da un singolo nodo |
| `POST /v1/sg02/decryptions` | raccolta e aggregazione |
| `POST /v1/ppke/keys` | 202, sempre job |
| `GET /v1/ppke/keys/public` · `POST /v1/ppke/ciphertexts` | |
| `POST /v1/ppke/decryptions/{node_id}` | `mode`: `auto` · `sync` · `async` |
| `GET /v1/ppke/state` | |
| `POST /v1/punctures` | **sempre 202**, job esclusivo |
| `GET /v1/punctures` · `GET /v1/punctures/{id}` | |
| `POST /v1/punctures/{id}/resolve` · `/resume` | |
| `GET /v1/jobs` · `/{id}` · `/{id}/result` · `DELETE /v1/jobs` | |

Gli endpoint sono definiti con `def` e non `async def`: FastAPI esegue le
funzioni sincrone in un thread pool, quindi le chiamate bloccanti verso
PC/SC e verso i binari host non fermano l'event loop. Con `async def`
servirebbe avvolgere ogni chiamata in `run_in_threadpool`, ottenendo lo
stesso risultato con più rumore.

Il router `punctures` risponde **sempre 202**, e il job è **esclusivo**:
due campagne concorrenti renderebbero il ledger ambiguo, perché due
intent pendenti sullo stesso nodo non sarebbero attribuibili.

---

## 10. Lo stato su disco

```
$TCN_STATE_DIR/                      (~/.local/share/tcn)
├── ledger.jsonl                 registro delle punzonature, append-only
├── tcn.lock                     flock fra processi
├── sg02/
│   ├── node<N>.keystore         share private — DA CANCELLARE
│   ├── <key_id>.pub             chiave pubblica del gruppo
│   └── current-key-id           quale gruppo è quello in esercizio
├── ppke/
│   ├── pk.bin                   chiave pubblica GMPpke
│   └── probes/<tag>.probe       crittogrammi sonda
├── ciphertexts/
└── jobs/                        stato dei job, mai i risultati

$TCN_VOLATILE_DIR/                   (/dev/shm/tcn, tmpfs)
└── ...                          SK GMPpke in transito, azzerata
```

**Che cosa non deve mai stare qui:**

- la **SK GMPpke**, che vive su tmpfs il solo tempo della distribuzione
  ai token ed è azzerata subito dopo;
- le **share delle punzonature**, che risiedono *dentro* le Nitrokey e
  non sul TCN — altrimenti il sistema non ha più senso;
- i **risultati dei job** (plaintext inclusi), che restano in memoria;
- i **keystore SG02**, dopo la distribuzione.

`current-key-id` esiste perché il gruppo in esercizio va **registrato
esplicitamente**, non dedotto dai file `.pub` presenti: un `keygen`
ripetuto ne accumula più di uno e la deduzione sceglierebbe a caso.

---

## 11. Dove si innesta il codice nuovo

**Aggiungere un comando CLI.** Una funzione `cmd_*` nel modulo del
gruppo giusto in `cli/`, registrata in `register(sub)`. Se non tocca
hardware né stato, `needs_lock=False`. Gli errori si sollevano come
eccezioni di dominio: `translate()` li porta nel codice d'uscita
corretto.

**Aggiungere un endpoint.** Un modello in `api/models.py`, una funzione
nel router giusto. Non catturare le eccezioni di dominio: gli handler di
`api/errors.py` le mappano. Se l'operazione supera `sync_threshold`,
passarla a `jobs.submit()`.

**Aggiungere una funzionalità vera** (presente in entrambe le
interfacce): un metodo in `services/`, poi un comando CLI e un endpoint
che lo invocano. Il servizio non deve sapere quale dei due lo sta
chiamando.

**Aggiungere un comando del firmware.** Tre livelli, in quest'ordine:
estensione (tipi di richiesta e risposta), backend (la crittografia),
app (parsing APDU e traduzione degli errori). Poi una funzione in
`tokens/`, e solo dopo l'orchestrazione.

Compilazione e flash:

```bash
cd nitrokey-3-firmware-backends
sudo make -C utils/lpc55-builder flash \
  FEATURES=develop,theta-app,forwardsec-app,sg02-backend,gmppke-backend
```

**Portare il TCN su un'altra macchina.** Soltanto variabili d'ambiente:
`TCN_THETACLI`, `TCN_PFSE_TOOL`, `TCN_STATE_DIR`, `TCN_DEALER_KEY`.
Nessun percorso assoluto vive fuori da `config.py`. In esercizio con
systemd: `TCN_STATE_DIR=/var/lib/tcn` e `--workers 1` nell'unit.

---

## 12. Invarianti da non rompere

1. **Le dipendenze vanno solo verso il basso.** `services` non importa
   da `cli` né da `api`; `transport` non conosce gli schemi.
2. **Un solo lock di token per volta.** Mai due `session()` annidate.
3. **La punzonatura passa dal WAL.** `record_intent` prima dell'APDU,
   `record_result` dopo. Sempre, anche nel codice nuovo.
4. **Le campagne di punzonatura sono sequenziali** e il loro job è
   esclusivo.
5. **Il roster viene dal ledger**, non dai token presenti.
6. **La SK GMPpke non tocca il disco persistente.** Solo tmpfs, e
   azzerata.
7. **`--workers 1`**, o il lock in memoria non serve a niente.
8. **Cancellato (`6982`) e non pronto (`6985`) restano distinti** a
   ogni livello: firmware, servizi, exit code, status HTTP.
9. **Il token non dichiara il proprio stato interno.** Se serve
   saperlo, lo si deduce con una sonda o lo si legge dal ledger. Non si
   aggiunge un INS che lo enumeri.

Il punto 9 non è una scelta di comodo. Un comando che elenchi i tag
punzonati o conti le share direbbe a chiunque abbia accesso fisico al
token ciò che il sistema esiste per non rivelare.

---

## 13. Limiti dichiarati

- **Il TCN è un punto di convergenza.** Durante la distribuzione
  possiede tutte le share; durante una decifratura vede *k* share
  parziali. È inevitabile con un solo host, e va detto invece che
  aggirato.
- **`MAX_PUNCTURES = 5`** è un vincolo di memoria del backend, non dello
  schema.
- **L'import GMPpke non verifica firme.** La firma del dealer è
  implementata per SG02 e funzionerebbe identica qui; non è stata
  reimplementata perché il sistema è un proof-of-concept.
- **Le costanti del planner** (ML, FE, Δ) non sono separabili a `n = 0`:
  il crossover è calcolato, non misurato punto per punto.
