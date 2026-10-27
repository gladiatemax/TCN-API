# TCN — CLI e architettura

Oct 26, 2026 · @Massimiliano

Il nodo centrale (TCN) orchestra le Nitrokey 3 collegate via USB e combina due schemi crittografici con modelli di fiducia opposti: SG02 a soglia per la custodia distribuita delle chiavi, GMPpke punzonabile per la cancellazione crittografica richiesta dall'art. 17 GDPR.

## I due schemi

I due schemi non sono varianti della stessa idea: distribuiscono la fiducia in direzioni opposte, e il sistema li fa convivere sullo stesso hardware.

|  | SG02 (TDH2, Ed25519) | GMPpke (BN254) |
| --- | --- | --- |
| Distribuzione della chiave | share **diverse** a n token | **stessa** chiave su tutti i token |
| Per decifrare | bastano k token su n | basta un token qualsiasi |
| Per cancellare | — | servono **tutti** i token |
| Protegge da | compromissione di meno di k dispositivi | — |
| Scopo | custodia distribuita delle chiavi | cancellazione crittografica (art. 17 GDPR) |

L'asimmetria è obbligata, non una scelta di comodo. Un token su cui la punzonatura non è arrivata conserva la capacità di decifrare proprio il dato che si voleva distruggere: una cancellazione parziale non è una cancellazione riuscita a metà, non è una cancellazione. Il nodo centrale quindi rifiuta di avviare una campagna se anche un solo token dell'anagrafica non è collegato, mentre per la decifratura tollera le assenze fino alla soglia k.

## Architettura

&#91;embedded content: architettura · 4 livelli, 2 interfacce\]

Le frecce vanno sempre verso il basso: nessun livello conosce quello sopra di sé. È la proprietà che ha permesso di aggiungere la CLI **dopo** l'API senza modificare una riga dei servizi, e che renderebbe sostituibile l'intera interfaccia HTTP — sei file su ventisei — senza toccare la crittografia.

### I tre livelli del firmware

La separazione dentro il dispositivo segue l'architettura Trussed e ha una conseguenza che vale la pena dire: l'applicazione fa **solo** parsing APDU, routing e traduzione degli errori. La matematica e il materiale di chiave vivono nel backend, e `xi` non transita mai nel codice dell'app. L'extension in mezzo è un crate di soli tipi, che definisce il contratto fra le due.

### Da dove viene il codice del nodo centrale

Nulla è stato riscritto da zero: `transport`, `convert`, i wrapper dei binari host e la serializzazione DER sono l'estrazione diretta dei notebook di benchmark, ripulita dalle parti di misura. La conseguenza è metodologica, non di comodo: i tempi del capitolo Risultati sono misurati **sullo stesso percorso** che CLI e API eseguono.

## La CLI

La CLI espone l'intero sistema in quattro gruppi di comandi, uno per area funzionale.

| Gruppo | Comandi | Che cosa copre |
| --- | --- | --- |
| `tcn health`, `tcn tokens` | `health`, `scan`, `list`, `show` | stato del nodo, scoperta dei token, identità dichiarata da ciascuno |
| `tcn sg02` | `keygen`, `distribute`, `wipe-keystores`, `encrypt`, `share`, `decrypt` | ciclo completo dello schema a soglia |
| `tcn ppke` | `setup`, `pubkey`, `encrypt`, `decrypt`, `state` | ciclo completo dello schema punzonabile |
| `tcn puncture` | `create`, `list`, `show`, `resolve`, `resume` | campagne di cancellazione e loro verifica |

### Una sessione tipica

1. `tcn tokens scan` — interroga i lettori e risolve l'identità di ogni token.
2. `tcn sg02 keygen --reset` — genera il gruppo k-su-n. Da qui il nodo centrale detiene tutte le share: è il momento più esposto dell'intero sistema.
3. `tcn sg02 distribute` — importa su ogni token la sua share, firmata dal dealer.
4. `tcn sg02 wipe-keystores` — cancella il materiale privato dal nodo centrale. Chiude la finestra: da qui la proprietà di soglia vale anche a riposo, non solo in transito.
5. `tcn ppke setup` — genera la chiave punzonabile e la replica su tutti i token. La chiave privata non tocca mai il disco: vive in memoria il tempo della distribuzione e viene azzerata.
6. `tcn ppke encrypt` / `decrypt` — cifratura legata a d etichette, decifratura su un token.
7. `tcn puncture create --tag …` — cancellazione crittografica di un'etichetta.

Il passo 4 non è facoltativo e la CLI lo rifiuta se la distribuzione non è completa: cancellare prima distruggerebbe l'unica copia di una share mai consegnata a un token.

### Due scelte di interfaccia

La CLI lavora con **file e pipe**, non con stringhe codificate: `tcn sg02 encrypt -i cartella.pdf -o cartella.enc`. La codifica resta un dettaglio dell'API. I messaggi diagnostici vanno su stderr, così un plaintext su stdout può finire in una pipe senza essere corrotto.

La CLI è **sincrona**: un comando che impiega trenta secondi li impiega, mostrando l'avanzamento. Il meccanismo asincrono dell'API serve a non tenere aperta una connessione HTTP, problema che a riga di comando non esiste.

## La cancellazione crittografica

Il problema non è distruggere la capacità di decifrare: è saperlo con certezza e poterlo dimostrare, come chiede l'art. 5(2).

Tre proprietà del firmware rendono il compito non banale. La punzonatura è **irreversibile**. Non è **idempotente**: ripetere lo stesso tag consuma una seconda unità di una capacità finita. E il token **non dichiara il proprio stato interno**, per scelta: nessun comando permette di enumerare i tag punzonati, perché sarebbe un canale di lettura in più da difendere.

Messe insieme, rendono pericoloso il ritentativo cieco: una trasmissione fallita lascia due possibilità indistinguibili — il token ha punzonato e la risposta si è persa, oppure non ha ricevuto nulla.

### Come il nodo centrale lo risolve

**Registro con write-ahead log.** Prima di trasmettere si registra l'intento, poi si trasmette, poi l'esito. Un intento rimasto senza esito è uno stato *incerto*, non un token intatto: senza questa sequenza un processo morto a metà campagna produrrebbe un registro che mente.

**La sonda.** L'incertezza si risolve empiricamente, non chiedendo al token: si tenta di decifrare un crittogramma di prova legato a quel tag e si guarda la risposta. Usa solo comandi già esistenti, al costo di una decifratura.

**Esecuzione sequenziale.** I token vengono percorsi uno alla volta, non in parallelo: su un'operazione irreversibile il determinismo vale più del tempo risparmiato. La raccolta delle share SG02, che è reversibile, parallelizza invece.

**Anagrafica, non presenza.** L'insieme dei token attesi viene dal registro, non da chi risponde in quel momento. È una distinzione sottile con conseguenze pesanti: se derivasse dai token collegati, staccarne uno lo farebbe sparire dai controlli e la campagna si dichiarerebbe completa mentre quel token conserva la capacità di decifrare.

### Distinguere «cancellato» da «non pronto»

È il punto in cui una scelta di implementazione decide se il sistema può mentire su una conformità. Il firmware classifica ogni causa di fallimento con uno status word proprio, che risale fino al codice d'uscita:

| Condizione | Status word | Esito CLI |
| --- | --- | --- |
| chiave punzonata sul tag | `6982` | `4` — contenuto cancellato |
| nessuna chiave sul dispositivo | `6985` | `6` — dispositivo non pronto |
| payload non interpretabile | `6A80` | `2` — errore d'uso |
| limite di punzonature raggiunto | `6A84` | `5` — stato incompatibile |
| guasto su flash, RNG, aritmetica | `6581` | `1` — errore |

Prima di questa classificazione il firmware collassava ogni fallimento di decifratura su `6982`: un dispositivo senza chiave rispondeva «contenuto cancellato». In un sistema che deve **attestare** la cancellazione è la bugia peggiore possibile, perché certificherebbe come distrutto un dato che è soltanto irraggiungibile. La sonda, che si basa proprio su quel codice, avrebbe registrato cancellazioni mai avvenute.

Nell'API la stessa distinzione diventa **410 Gone**, non 403 Forbidden: non un permesso negato che qualcuno potrebbe riabilitare, ma una capacità distrutta nel dispositivo.

## Limiti dichiarati

Sono vincoli del prototipo, non difetti scoperti: vanno detti perché un lettore attento li troverebbe comunque.

**Il nodo centrale è un punto unico di convergenza.** La crittografia a soglia proteggerebbe dalla compromissione di meno di k nodi, ma se tutti i token sono raggiungibili dallo stesso processo, chi compromette il nodo centrale ottiene tutto. È la conseguenza inevitabile di un prototipo su hardware singolo e va distinta dal modello di deployment che l'architettura prevede — un servizio per token, su macchine separate. Il protocollo non cambierebbe: cambierebbe solo l'indirizzo che il coordinatore contatta.

**Con un solo token la soglia è degenere.** A `k = n = 1` si dimostra che la catena funziona, non che la soglia protegge: le due cose diventano indistinguibili. Serve una configurazione a tre token per staccarne uno e mostrare che la decifratura procede comunque.

**Il limite di cinque punzonature è una costante di storage del backend**, non dello schema, e non dipende da d. Va letto insieme al fatto che `d` conta tutt'altro: il numero di etichette legate a un singolo crittogramma, cioè quante maniglie di cancellazione indipendenti ha ogni record. Due vincoli indipendenti che si sommano.

**L'import della chiave GMPpke non verifica firme**, mentre quello della share SG02 lo fa. È una scelta di perimetro: il meccanismo è dimostrato su SG02 e si trasferisce identico, senza riprogettarlo. Nel modello di minaccia va comunque dichiarato, perché un attaccante con accesso fisico a un token potrebbe sostituirne la chiave e con essa azzerare le punzonature già effettuate.
