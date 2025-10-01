#!/usr/bin/env bash
set -Eeuo pipefail

red()   { printf "\e[31m%s\e[0m\n" "$*"; }
green() { printf "\e[32m%s\e[0m\n" "$*"; }
yellow(){ printf "\e[33m%s\e[0m\n" "$*"; }

need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || { red "❌ rode como root: sudo $0"; exit 1; }; }
apt_install() { DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"; }

detect_go_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) yellow "arquitetura não mapeada ($(uname -m)), usando amd64"; echo amd64 ;;
  esac
}

install_go_official() {
  local os=linux arch json ver filename sha url
  arch="$(detect_go_arch)"; mkdir -p /tmp/go-install && cd /tmp/go-install
  if [[ -n "${GO_TARBALL_URL:-}" ]]; then
    url="$GO_TARBALL_URL"; filename="$(basename "$url")"
    curl -fsSLO "$url" || { red "falhou download do Go"; exit 1; }
    if curl -fsSLO "$url.sha256"; then sha="$(cut -d' ' -f1 <"$filename.sha256")"; fi
  else
    json="$(curl -fsSL 'https://go.dev/dl/?mode=json')"
    ver="${GO_VERSION:-$(jq -r '.[0].version' <<<"$json")}"
    read -r filename sha < <(jq -r --arg v "$ver" --arg os "$os" --arg arch "$arch" '
      .[]|select(.version==$v)|.files[]|
      select(.os==$os and .arch==$arch and .kind=="archive" and (.filename|endswith(".tar.gz")))|
      "\(.filename) \(.sha256)"' <<<"$json" | head -n1)
    [[ -n "$filename" ]] || { red "não achei tarball para $ver ($os-$arch)"; exit 1; }
    url="https://go.dev/dl/$filename"; curl -fsSLO "$url"
  fi
  [[ -n "${sha:-}" ]] && echo "$sha  $filename" | sha256sum -c - || yellow "⚠️ sem SHA256 conhecido"
  green "→ Instalando Go ($filename)…"
  rm -rf /usr/local/go && tar -C /usr/local -xzf "$filename"
}

go_install() { env GOBIN=/usr/local/bin GOFLAGS="-buildvcs=false" go install "$1"; }

ensure_global_path() {
  install -m0644 /dev/stdin /etc/profile.d/99-recon-path.sh <<'EOF'
# Recon paths (global)
export PATH="/usr/local/bin:/usr/local/go/bin:${PATH}"
EOF
  export PATH="/usr/local/bin:/usr/local/go/bin:${PATH}"
}

# --- pipx (instala CLIs Python isoladas e joga os binários em /usr/local/bin) ---
py_cli_install() {
  local pkg="$1"
  # pipx --global (se suportado) senão cai pro normal; PIPX_BIN_DIR já aponta pra /usr/local/bin
  if pipx install --global "$pkg"; then
    : # ok
  else
    pipx install "$pkg"
  fi
}

link_into_usr_local_bin() {
  install -d /usr/local/bin
  for cmd in "$@"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      local src dest
      src="$(readlink -f "$(command -v "$cmd")")"
      dest="/usr/local/bin/$cmd"
      [[ "$src" == /usr/local/bin/* ]] && continue
      [[ -e "$dest" ]] && continue
      ln -s "$src" "$dest" && printf "↪ link: %s -> %s\n" "$dest" "$src"
    fi
  done
}

### run
need_root
apt-get update -y

green "→ Dependências base (APT)…"
apt_install ca-certificates curl wget git jq unzip xz-utils tar \
  build-essential pkg-config libssl-dev libpcap-dev \
  python3 python3-venv python3-pip pipx parallel dnsutils net-tools \
  nmap masscan zmap chromium || true

green "→ Ferramentas APT úteis…"
apt_install amass massdns findomain theharvester dnsrecon fierce dnsenum \
  ffuf feroxbuster gobuster gowitness eyewitness whatweb arjun || true

green "→ Instalando Go oficial (último estável)…"
install_go_official
ensure_global_path

green "→ ProjectDiscovery (Go)…"
go_install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go_install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go_install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go_install github.com/projectdiscovery/httpx/cmd/httpx@latest
go_install github.com/projectdiscovery/katana/cmd/katana@latest
go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest   # fingerprint geral
go_install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go_install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go_install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go_install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go_install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

green "→ Outros binários Go de recon…"
go_install github.com/d3mondev/puredns/v2@latest
go_install github.com/tomnomnom/assetfinder@latest
go_install github.com/tomnomnom/httprobe@latest
go_install github.com/lc/gau/v2/cmd/gau@latest
go_install github.com/tomnomnom/waybackurls@latest
go_install github.com/hakluke/hakrawler@latest
go_install github.com/jaeles-project/gospider@latest
go_install github.com/lc/subjs@latest
go_install github.com/cgboal/sonarsearch/cmd/crobat@latest
go_install github.com/rverton/webanalyze@latest
go_install github.com/tomnomnom/anew@latest
go_install github.com/tomnomnom/unfurl@latest
go_install github.com/tomnomnom/qsreplace@latest
go_install github.com/zmap/zgrab2@latest
# (opcional)
go_install github.com/michenriksen/aquatone@latest || true

green "→ Configurando pipx para usar /usr/local…"
export PIPX_HOME=/usr/local/pipx
export PIPX_BIN_DIR=/usr/local/bin
# garante diretórios e permissões
install -d -m 0755 "$PIPX_HOME" "$PIPX_BIN_DIR"

green "→ Instalando CLIs Python via pipx…"
py_cli_install dnsgen
py_cli_install dnsvalidator
py_cli_install sublist3r
py_cli_install uro
py_cli_install dirsearch
py_cli_install 'git+https://github.com/GerbenJavado/LinkFinder.git'
py_cli_install 'git+https://github.com/m4ll0k/SecretFinder.git'
py_cli_install 'git+https://github.com/xnl-h4ck3r/waymore.git'

green "→ Wordlists e datasets…"
mkdir -p /opt/wordlists
if [[ -d /opt/wordlists/SecLists/.git ]]; then git -C /opt/wordlists/SecLists pull --ff-only
else git clone --depth=1 https://github.com/danielmiessler/SecLists /opt/wordlists/SecLists; fi
if [[ -d /opt/wordlists/OneListForAll/.git ]]; then git -C /opt/wordlists/OneListForAll pull --ff-only
else git clone --depth=1 https://github.com/six2dez/OneListForAll /opt/wordlists/OneListForAll; fi
if [[ -d /opt/wordlists/commonspeak2/.git ]]; then git -C /opt/wordlists/commonspeak2 pull --ff-only
else git clone --depth=1 https://github.com/assetnote/commonspeak2-wordlists /opt/wordlists/commonspeak2; fi
if [[ -d /opt/wordlists/assetnote/.git ]]; then git -C /opt/wordlists/assetnote pull --ff-only
else git clone --depth=1 https://github.com/assetnote/wordlists /opt/wordlists/assetnote; fi
chmod -R a+rX /opt/wordlists

green "→ (Opcional) Gerando resolvers com dnsvalidator…"
if command -v dnsvalidator >/dev/null 2>&1; then
  dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o /opt/resolvers.txt || true
  chmod a+r /opt/resolvers.txt || true
fi

green "→ Criando symlinks em /usr/local/bin (garantia)…"
link_into_usr_local_bin \
  subfinder dnsx naabu httpx katana nuclei mapcidr shuffledns chaos asnmap tlsx \
  amass massdns findomain theharvester dnsrecon fierce dnsenum \
  ffuf feroxbuster gobuster gowitness eyewitness whatweb arjun \
  puredns assetfinder httprobe gau waybackurls hakrawler gospider subjs \
  crobat webanalyze anew unfurl qsreplace zgrab2 zmap masscan nmap \
  sublist3r dirsearch waymore uro dnsgen dnsvalidator

green "→ Resumo de versões:"
for b in go subfinder dnsx naabu httpx katana nuclei mapcidr shuffledns chaos asnmap tlsx \
         amass massdns findomain theharvester dnsrecon fierce dnsenum \
         ffuf feroxbuster gobuster gowitness eyewitness whatweb arjun \
         puredns assetfinder httprobe gau waybackurls hakrawler gospider subjs \
         crobat webanalyze anew unfurl qsreplace zgrab2 zmap masscan nmap \
         sublist3r dirsearch waymore uro dnsgen dnsvalidator; do
  if command -v "$b" >/dev/null 2>&1; then
    printf "  - %-12s %s\n" "$b" "$($b -version 2>/dev/null || $b --version 2>/dev/null || echo ok)"
  fi
done

green "✅ Recon core instalado.
• Binaries em /usr/local/bin (incluindo as CLIs Python via pipx)
• PATH global: /etc/profile.d/99-recon-path.sh
• Go em /usr/local/go; wordlists em /opt/wordlists; resolvers em /opt/resolvers.txt"
