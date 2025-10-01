#!/usr/bin/env bash
# recon_nobrute_hardened.sh — passivo -> dedup -> resolução -> ativo/TLS
# tolerante a erros (522/5xx/429/403/timeout) com skip automático e logs.

set -euo pipefail

banner(){ printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
usage(){
  cat <<'EOF'
Uso: ./recon_nobrute_hardened.sh <domínio> [opções]

Opções:
  -o DIR        diretório de saída (default: recon-<domínio>-<data>)
  -R RESOLVERS  arquivo de resolvers para puredns (opcional, recomendado)
  -t THREADS    threads (default: 50)
  --no-active   pular httpx/tlsx
  --no-pdcp     pular ferramentas que usam ProjectDiscovery Cloud (ex.: chaos)
  --strict      abortar no primeiro erro não-ignorado
  --timeout S   timeout por ferramenta em segundos (default: 180)

Exemplos:
  ./recon_nobrute_hardened.sh exemplo.com
  ./recon_nobrute_hardened.sh exemplo.com -R resolvers.txt -t 100
EOF
}

[[ $# -lt 1 ]] && usage && exit 1
DOMAIN_RAW="$1"; shift || true

OUTDIR="recon-$(echo "$DOMAIN_RAW" | tr '[:upper:]' '[:lower:]' | tr -d ' ')-$(date +%F_%H%M%S)"
RESOLVERS=""
THREADS=50
DO_ACTIVE=1
NO_PDCP=0
STRICT=0
STEP_TIMEOUT=180

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) OUTDIR="$2"; shift 2;;
    -R) RESOLVERS="$2"; shift 2;;
    -t) THREADS="$2"; shift 2;;
    --no-active) DO_ACTIVE=0; shift;;
    --no-pdcp) NO_PDCP=1; shift;;
    --strict) STRICT=1; shift;;
    --timeout) STEP_TIMEOUT="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Opção desconhecida: $1"; usage; exit 1;;
  esac
done

# normaliza domínio (IDN opcional via idn2, se existir)
DOMAIN="$(echo "$DOMAIN_RAW" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
if command -v idn2 >/dev/null 2>&1; then DOMAIN="$(idn2 "$DOMAIN" 2>/dev/null || echo "$DOMAIN")"; fi
[[ -z "$DOMAIN" ]] && { echo "[erro] domínio vazio"; exit 1; }

mkdir -p "$OUTDIR"/{sources,stage,logs}
LOGDIR="$OUTDIR/logs"

# sobe limite de arquivos se possível
( ulimit -n 4096 ) >/dev/null 2>&1 || true

# checa escrita / espaço
touch "$OUTDIR/.write_test" 2>/dev/null || { echo "[erro] sem permissão de escrita em $OUTDIR"; exit 1; }
rm -f "$OUTDIR/.write_test"
df -P "$OUTDIR" >/dev/null 2>&1 || echo "[warn] não consegui checar espaço em disco (df)"

have(){ command -v "$1" &>/dev/null; }

# regex do domínio
domre="$(printf '%s' "$DOMAIN" | sed 's/\./\\./g')"

hostify(){
  sed -E 's#^[^/]*//##' | sed -E 's#/.*$##' | sed -E 's/:[0-9]+$//' |
  sed -E 's/^\.+//; s/\.+$//' | tr '[:upper:]' '[:lower:]' |
  grep -E "[A-Za-z0-9.-]+\.$domre$" || true
}

# detecta se o erro pode ser ignorado (rede/serviço)
should_skip_err(){
  local f="$1"
  grep -Eiq \
    '(^|[^0-9])52(0|1|2|3|4|5|6)([^0-9]|$)|HTTP[^0-9]*5(0|2)[0-9]|status code[^0-9]*5(0|2)[0-9]|(^|[^0-9])429([^0-9]|$)|(^|[^0-9])403([^0-9]|$)|rate.?limit|too many requests|context deadline exceeded|i/o timeout|TLS handshake timeout|timeout .*exceeded|connection (reset|refused)|temporarily unavailable|EOF|network is unreachable|no such host' \
    "$f"
}

# executor com timeout + retry + tolerância
run_src(){
  local name="$1"; shift
  local cmd="$1"; shift
  local outfile="$1"; shift

  local errfile="$LOGDIR/${name}.err"
  : > "$outfile"; : > "$errfile"

  local attempt status
  for attempt in 1 2; do
    set +e
    # timeout mata o comando com exit 124; preservamos stderr
    timeout -k 2s "$STEP_TIMEOUT" bash -c "$cmd" >"$outfile" 2>>"$errfile"
    status=$?
    set -e

    # timeout explícito
    if [[ $status -eq 124 ]]; then
      echo "[warn] ${name}: timeout (${STEP_TIMEOUT}s) — $( ((attempt==1)) && echo 'retry' || echo 'skip')"
      [[ $attempt -eq 2 ]] && { : > "$outfile"; return 0; }
      continue
    fi

    # erros rede/serviço -> skip
    if should_skip_err "$errfile"; then
      echo "[warn] ${name}: erro de rede/serviço (ex.: 522/5xx/429/timeout) — skip (log: $errfile)"
      : > "$outfile"
      return 0
    fi

    # se houve erro diferente e STRICT=1 -> aborta
    if [[ $status -ne 0 ]]; then
      echo "[warn] ${name}: falhou com código ${status} — veja $errfile"
      if [[ $STRICT -eq 1 ]]; then
        echo "[erro] modo --strict ativo. abortando."
        exit 1
      fi
      # sem strict: segue adiante
      : > "$outfile"
      return 0
    fi

    # sucesso
    break
  done
}

# --------------------------- pré-checagem de APIs -----------------------------
PDCP_KEY="${PDCP_API_KEY:-${CHAOS_KEY:-}}"
USE_CHAOS=0
if have chaos && [[ $NO_PDCP -eq 0 ]]; then [[ -n "$PDCP_KEY" ]] && USE_CHAOS=1; fi

banner "Pré-checagem"
echo "  - chaos: $( [[ $USE_CHAOS -eq 1 ]] && echo 'ativado' || echo 'ignorado (sem PDCP_API_KEY ou --no-pdcp)' )"
echo "  - fontes: subfinder, assetfinder, crobat, waybackurls, gau, katana/hakrawler/gospider"
[[ $DO_ACTIVE -eq 1 ]] && echo "  - ativo: httpx/tlsx" || echo "  - ativo: ignorado (--no-active)"
[[ -n "${RESOLVERS}" ]] && echo "  - resolvers: $RESOLVERS" || echo "  - resolvers: padrão"

# ----------------------------- Enumeração passiva -----------------------------
banner "Coletando passivamente subdomínios de ${DOMAIN}"

have subfinder && run_src subfinder \
  "subfinder -silent -d \"$DOMAIN\" -all -recursive -t \"$THREADS\"" \
  "$OUTDIR/sources/subfinder.txt"

have assetfinder && run_src assetfinder \
  "assetfinder --subs-only \"$DOMAIN\" | sort -u" \
  "$OUTDIR/sources/assetfinder.txt"

if [[ $USE_CHAOS -eq 1 ]]; then
  run_src chaos "chaos -d \"$DOMAIN\" -silent | sort -u" "$OUTDIR/sources/chaos.txt"
else
  echo "[info] chaos ignorado"
fi

have crobat && run_src crobat \
  "crobat -s \"$DOMAIN\" | sort -u" \
  "$OUTDIR/sources/crobat.txt"

have waybackurls && run_src waybackurls \
  "waybackurls \"$DOMAIN\" | hostify | sort -u" \
  "$OUTDIR/sources/waybackurls.txt"

have gau && run_src gau \
  "gau --subs \"$DOMAIN\" | hostify | sort -u" \
  "$OUTDIR/sources/gau.txt"

if have katana; then
  run_src katana \
    "katana -silent -u \"https://$DOMAIN\" -d 2 -jc -fx -ps -kf robotstxt | hostify | sort -u" \
    "$OUTDIR/sources/katana.txt"
elif have hakrawler; then
  run_src hakrawler \
    "echo \"https://$DOMAIN\" | hakrawler -plain -depth 2 -subs | hostify | sort -u" \
    "$OUTDIR/sources/hakrawler.txt"
elif have gospider; then
  run_src gospider \
    "gospider -s \"https://$DOMAIN\" -d 2 --include-subs -q | hostify | sort -u" \
    "$OUTDIR/sources/gospider.txt"
fi

# juntar & dedup
cat "$OUTDIR"/sources/*.txt 2>/dev/null | sort -u > "$OUTDIR/stage/passive_all.txt" || true
PASSIVE_COUNT=$(wc -l < "$OUTDIR/stage/passive_all.txt" || echo 0)
banner "Passivo: ${PASSIVE_COUNT} candidatos"

# ----------------------------- Resolução DNS ----------------------------------
banner "Resolvendo subdomínios"
resolve_candidates(){
  local in="$1"; local out="$2"
  if have puredns && [[ -n "${RESOLVERS}" && -s "${RESOLVERS}" ]]; then
    puredns resolve "$in" -r "$RESOLVERS" -w "$out" -q -t "$THREADS" || true
  elif have dnsx; then
    dnsx -silent -l "$in" -a -resp -t "$THREADS" | awk '{print $1}' | sort -u > "$out" || true
  else
    echo "[warn] nem puredns nem dnsx estão disponíveis; mantendo candidatos sem validar."
    cp "$in" "$out"
  fi
}
resolve_candidates "$OUTDIR/stage/passive_all.txt" "$OUTDIR/stage/resolved.txt"
RES_COUNT=$(wc -l < "$OUTDIR/stage/resolved.txt" || echo 0)
banner "Resolvidos: ${RES_COUNT}"

# ------------------------------ Ativo -----------------------------------------
if [[ $DO_ACTIVE -eq 1 ]]; then
  if have httpx && [[ -s "$OUTDIR/stage/resolved.txt" ]]; then
    banner "Probing HTTP (httpx)"
    httpx -silent -l "$OUTDIR/stage/resolved.txt" -threads "$THREADS" \
      -follow-redirects -status-code -title -tech-detect -web-server \
      -ports 80,443,8080,8443 -o "$OUTDIR/live_httpx.txt" || true
  fi

  if have tlsx && [[ -s "$OUTDIR/stage/resolved.txt" ]]; then
    banner "Coletando nomes adicionais via TLS (tlsx)"
    tlsx -silent -l "$OUTDIR/stage/resolved.txt" -san -cn -resp-only \
      | hostify | sort -u > "$OUTDIR/stage/tlsx_hosts.txt" || true
    if [[ -s "$OUTDIR/stage/tlsx_hosts.txt" ]]; then
      cat "$OUTDIR/stage/passive_all.txt" "$OUTDIR/stage/tlsx_hosts.txt" | sort -u > "$OUTDIR/stage/all2.txt"
      resolve_candidates "$OUTDIR/stage/all2.txt" "$OUTDIR/stage/resolved.txt"
    fi
  fi
fi

# ------------------------------ Saídas ----------------------------------------
sort -u "$OUTDIR/stage/passive_all.txt" > "$OUTDIR/all_candidates.txt" || true
sort -u "$OUTDIR/stage/resolved.txt" > "$OUTDIR/resolved_hosts.txt" || true

banner "Resumo:"
printf "  Candidatos (passivo): %s\n" "$(wc -l < "$OUTDIR/all_candidates.txt" || echo 0)"
printf "  Resolvidos:           %s\n" "$(wc -l < "$OUTDIR/resolved_hosts.txt" || echo 0)"
[[ -f "$OUTDIR/live_httpx.txt" ]] && printf "  HTTP vivos:           %s\n" "$(wc -l < "$OUTDIR/live_httpx.txt")"

echo -e "\nArquivos:"
echo "  - $OUTDIR/all_candidates.txt"
echo "  - $OUTDIR/resolved_hosts.txt"
[[ -f "$OUTDIR/live_httpx.txt" ]] && echo "  - $OUTDIR/live_httpx.txt"
echo "  - $LOGDIR/*.err (logs por ferramenta)"

banner "feito."
