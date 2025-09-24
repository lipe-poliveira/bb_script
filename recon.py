#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Recon de subdomínios com múltiplas ferramentas + validação de hosts vivos.

Ferramentas suportadas (detectadas automaticamente):
- subfinder (ProjectDiscovery)
- amass (OWASP)
- assetfinder (tomnomnom)
- findomain
- crobat
- github-subdomains
Opcional: chaos (ProjectDiscovery) — se tiver instalado e CHAOS_KEY no ambiente

Saída:
- ./recon-out/<timestamp>/all_subdomains.txt
- ./recon-out/<timestamp>/alive_subdomains.txt
"""

# ====== imports padrão da stdlib (sem dependências externas) ======
import argparse          # parse de argumentos de linha de comando
import concurrent.futures as futures  # paralelismo leve para acelerar
import datetime          # timestamp em pastas/arquivos
import os                # interações com sistema, env vars
import shutil            # detectar binários (shutil.which)
import socket            # resolução DNS e conexões
import ssl               # TLS para HTTPS
import subprocess        # para chamar as ferramentas CLI
import sys               # utilidades (sair, stdout)
from typing import Iterable, List, Set, Tuple  # tipos para clareza

# ====== utilidade: impressão com corzinha leve (opcional) ======
def info(msg: str) -> None:
    print(f"[i] {msg}")

def warn(msg: str) -> None:
    print(f"[!] {msg}")

def ok(msg: str) -> None:
    print(f"[✓] {msg}")

# ====== normalização de domínios/wildcards ======
def normalize_domain(s: str) -> str:
    """
    Recebe algo como '*.example.com' e devolve 'example.com'.
    Também remove espaços e ponto à direita.
    """
    s = s.strip()
    if s.startswith("*."):
        s = s[2:]
    return s.rstrip(".")

# ====== executor genérico para chamar ferramentas ======
def run_cmd_collect_lines(cmd: List[str], timeout: int = 120) -> Set[str]:
    """
    Executa um comando (lista) e coleta cada linha do stdout como item do set.
    Usa timeout para evitar travas. Ignora stderr.
    """
    try:
        # subprocess.run executa e captura saída; text=True retorna str
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        # Se o binário não existir, tratamos acima (with which), mas por via das dúvidas
        return set()
    except subprocess.TimeoutExpired:
        warn(f"Timeout: {' '.join(cmd)}")
        return set()

    # Quebra por linhas, strip e descarta vazios
    lines = {line.strip() for line in out.stdout.splitlines() if line.strip()}
    return lines

# ====== wrappers por ferramenta (cada uma retorna um set de subdomínios) ======
def tool_subfinder(domain: str) -> Set[str]:
    if not shutil.which("subfinder"):
        return set()
    return run_cmd_collect_lines(["subfinder", "-silent", "-d", domain])

def tool_amass(domain: str) -> Set[str]:
    if not shutil.which("amass"):
        return set()
    # -passive evita varredura ativa; -norecursive reduz ruído; -silent só stdout
    return run_cmd_collect_lines(["amass", "enum", "-passive", "-norecursive", "-d", domain, "-silent"])

def tool_assetfinder(domain: str) -> Set[str]:
    if not shutil.which("assetfinder"):
        return set()
    return run_cmd_collect_lines(["assetfinder", "--subs-only", domain])

def tool_findomain(domain: str) -> Set[str]:
    if not shutil.which("findomain"):
        return set()
    # --quiet para somente os domínios
    return run_cmd_collect_lines(["findomain", "--quiet", "-t", domain])

def tool_crobat(domain: str) -> Set[str]:
    if not shutil.which("crobat"):
        return set()
    # -s busca subdomínios
    return run_cmd_collect_lines(["crobat", "-s", domain])

def tool_github_subdomains(domain: str) -> Set[str]:
    if not shutil.which("github-subdomains"):
        return set()
    # Requer GITHUB_TOKEN exportado (a ferramenta costuma usar)
    return run_cmd_collect_lines(["github-subdomains", "-d", domain])

def tool_chaos(domain: str) -> Set[str]:
    """
    Opcional: Chaos (ProjectDiscovery). Só roda se tiver binário e CHAOS_KEY.
    """
    if not shutil.which("chaos"):
        return set()
    if not os.environ.get("CHAOS_KEY"):
        return set()
    return run_cmd_collect_lines(["chaos", "-d", domain, "-silent"])

# ====== coleta via "seis ferramentas top" (e extras opcionais) ======
TOOL_FUNCS = [
    ("subfinder", tool_subfinder),
    ("amass", tool_amass),
    ("assetfinder", tool_assetfinder),
    ("findomain", tool_findomain),
    ("crobat", tool_crobat),
    ("github-subdomains", tool_github_subdomains),
    # extra opcional:
    ("chaos (opcional)", tool_chaos),
]

# ====== validação de host vivo ======
def resolves(host: str) -> bool:
    """
    Tenta resolver DNS (A/AAAA) do host. Se resolver, consideramos um bom sinal.
    """
    try:
        socket.getaddrinfo(host, None)  # qualquer família/protocolo
        return True
    except socket.gaierror:
        return False

def tcp_connect(host: str, port: int, timeout: float = 3.0) -> bool:
    """
    Teste rápido de conexão TCP (sem TLS/HTTP ainda).
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def http_head(host: str, use_https: bool, timeout: float = 4.0) -> bool:
    """
    Faz um HEAD / com HTTP/1.1. Considera qualquer status 2xx-5xx como 'vivo'.
    """
    # Escolhe porta e prepara socket
    port = 443 if use_https else 80
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return False

    try:
        if use_https:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)

        # Monta uma requisição HEAD minimalista
        req = (
            "HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: recon-check/1.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", "ignore")
        sock.sendall(req)

        # Lê um pequeno pedaço da resposta (cabeçalho)
        data = sock.recv(4096).decode("latin1", "ignore")
        # Esperamos algo como "HTTP/1.1 200 OK"
        if data.startswith("HTTP/1."):
            # Pega o código de status
            parts = data.split()
            if len(parts) >= 2 and parts[1].isdigit():
                code = int(parts[1])
                # 2xx-5xx indicam algum serviço respondendo
                return 200 <= code <= 599
        return False
    except ssl.SSLError:
        # Falha de TLS (ex.: somente HTTP) -> não considera vivo aqui
        return False
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass

def is_host_alive(host: str) -> bool:
    """
    Estratégia:
    1) DNS resolve?
    2) Tenta HTTPS (443). Se falhar por TLS/conexão, tenta HTTP (80).
    3) Se qualquer um responder, consideramos 'vivo'.
    """
    if not resolves(host):
        return False
    # Tentativa HTTPS
    if http_head(host, use_https=True):
        return True
    # Fallback: HTTP
    if tcp_connect(host, 80) and http_head(host, use_https=False):
        return True
    return False

# ====== pipeline de enumeração para um domínio ======
def enumerate_domain(domain: str) -> Tuple[str, Set[str], List[str]]:
    """
    Roda as ferramentas suportadas para um domínio.
    Retorna: (domain, set_subs, lista_de_ferramentas_utilizadas)
    """
    subs: Set[str] = set()
    used: List[str] = []

    for name, fn in TOOL_FUNCS:
        res = fn(domain)
        if res:
            used.append(name)
            subs |= res  # une resultados
            info(f"{domain}: {name} -> {len(res)}")
        else:
            # Só loga como 'skip' se a ferramenta principal (6) não está presente
            if name != "chaos (opcional)":
                warn(f"{domain}: {name} não disponível/sem resultados")

    return domain, subs, used

# ====== valida todos os subdomínios com paralelismo ======
def validate_hosts(hosts: Iterable[str], max_workers: int = 64) -> Set[str]:
    alive: Set[str] = set()
    with futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        # Submete cada host para checagem
        fut_map = {ex.submit(is_host_alive, h): h for h in hosts}
        for fut in futures.as_completed(fut_map):
            h = fut_map[fut]
            try:
                if fut.result():
                    alive.add(h)
            except Exception as e:
                warn(f"erro validando {h}: {e}")
    return alive

# ====== leitura de entrada (arquivo ou lista no CLI) ======
def load_domains(args) -> List[str]:
    items: List[str] = []
    if args.input_file:
        # Lê cada linha do arquivo, ignora comentários e vazios
        with open(args.input_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                items.append(line)
    # Adiciona domínios passados diretamente após flags
    if args.domains:
        items.extend(args.domains)

    # Normaliza todos e deduplica mantendo ordem básica
    seen = set()
    normed: List[str] = []
    for x in items:
        d = normalize_domain(x)
        if d and d not in seen:
            seen.add(d)
            normed.append(d)
    return normed

# ====== função principal ======
def main():
    # Parser de argumentos com ajuda amigável
    p = argparse.ArgumentParser(
        description="Enumeração de subdomínios com 6 ferramentas + validação."
    )
    p.add_argument(
        "-f", "--input-file",
        help="Arquivo com wildcards/domínios (um por linha). Ex.: *.exemplo.com",
    )
    p.add_argument(
        "domains", nargs="*",
        help="Wildcards/domínios direto no CLI. Ex.: *.alvo.com alvo2.com"
    )
    p.add_argument(
        "-w", "--workers", type=int, default=64,
        help="Máximo de threads para validação (default: 64)"
    )
    p.add_argument(
        "-t", "--timeout", type=int, default=120,
        help="Timeout (seg) por ferramenta (default: 120)."
    )
    args = p.parse_args()

    # Se nada foi passado, mostra uso e sai
    if not args.input_file and not args.domains:
        p.print_help()
        sys.exit(1)

    # Carrega e normaliza domínios
    domains = load_domains(args)
    if not domains:
        warn("Nenhum domínio válido encontrado.")
        sys.exit(1)

    ok(f"Alvos: {', '.join(domains)}")

    # Ajusta timeout global das ferramentas (opcional, se quiser influenciar run_cmd_collect_lines)
    # Aqui, para simplificar, mantemos o valor no default da função; se quiser,
    # dá para transformar 'timeout' em parâmetro global/função.

    # Enumera em paralelo por domínio (cada domínio roda todas as ferramentas)
    all_found: Set[str] = set()
    used_tools_agg: Set[str] = set()
    with futures.ThreadPoolExecutor(max_workers=min(8, len(domains) or 1)) as ex:
        futs = [ex.submit(enumerate_domain, d) for d in domains]
        for fut in futures.as_completed(futs):
            domain, subs, used = fut.result()
            ok(f"{domain}: total coletado = {len(subs)}")
            all_found |= subs
            used_tools_agg |= set(used)

    # Pós-processamento: filtra apenas subdomínios dos domínios alvo (safety)
    # Evita caso alguma ferramenta traga domínios fora do escopo.
    roots = tuple(domains)
    in_scope = {s for s in all_found if any(s.endswith("." + r) or s == r for r in roots)}

    info(f"Subdomínios únicos (in-scope): {len(in_scope)}")

    # Validação de "vivo" (DNS + HTTP/HTTPS) com paralelismo
    ok("Validando hosts (DNS/HTTP/HTTPS)...")
    alive = validate_hosts(in_scope, max_workers=args.workers)
    ok(f"Hosts vivos: {len(alive)}")

    # Escrita de resultados em pasta com timestamp
    stamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    outdir = os.path.join("recon-out", stamp)
    os.makedirs(outdir, exist_ok=True)

    all_path = os.path.join(outdir, "all_subdomains.txt")
    alive_path = os.path.join(outdir, "alive_subdomains.txt")

    # Ordena alfabeticamente para consistência
    with open(all_path, "w", encoding="utf-8") as f:
        for s in sorted(in_scope):
            f.write(s + "\n")
    with open(alive_path, "w", encoding="utf-8") as f:
        for s in sorted(alive):
            f.write(s + "\n")

    # Resumo final
    print()
    ok("Resumo")
    print(f"  Ferramentas utilizadas: {', '.join(sorted(used_tools_agg)) or 'nenhuma (verifique instalações)'}")
    print(f"  Subdomínios (in-scope): {len(in_scope)}  -> {all_path}")
    print(f"  Vivos: {len(alive)}                     -> {alive_path}")

# ====== ponto de entrada ======
if __name__ == "__main__":
    main()
