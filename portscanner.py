#!/usr/bin/env python3
# simple port scanner
# usage: python portscanner.py <host> -p <ports>

import socket, sys, argparse, threading, time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
    from rich import box
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "-q"])
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
    from rich import box

console = Console()

SERVICES = {
    21:"FTP", 22:"SSH", 23:"TELNET", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 135:"MS-RPC", 139:"NETBIOS", 143:"IMAP",
    443:"HTTPS", 445:"SMB", 3306:"MySQL", 3389:"RDP", 5432:"Postgres",
    5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 27017:"MongoDB",
}

RISKY = {
    23: "Telnet is unencrypted!!",
    135: "MS-RPC - often exploited",
    445: "SMB - ransomware uses this",
    3306: "MySQL shouldnt be public",
    3389: "RDP - brute force target",
    6379: "Redis - usually no auth",
    27017: "MongoDB - often misconfigured",
}

TOP20  = [21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5432,5900,6379,8080,8443,27017]
ALL    = list(range(1, 65536))


def check_port(host, port, timeout):
    # try to connect - if it works, port is open
    try:
        s = socket.socket()
        s.settimeout(timeout)
        if s.connect_ex((host, port)) == 0:   # 0 means success
            s.close()
            return {"port": port, "service": SERVICES.get(port, "unknown"), "risk": RISKY.get(port)}
        s.close()
    except:
        pass
    return None  # closed or unreachable


def scan(host, ports, timeout, threads):
    console.print(f"\n[bold cyan]  PORT SCANNER[/bold cyan]  [dim]by me[/dim]\n")

    # turn hostname into an IP address
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        console.print(f"  [red]could not resolve {host}[/red]")
        sys.exit(1)

    console.print(f"  target: [cyan]{host}[/cyan] ({ip})")
    console.print(f"  ports:  {len(ports)}\n")

    open_ports = []
    lock = threading.Lock()   # stops threads writing to open_ports at the same time

    # --- how the progress bar works ---
    # Progress() is a rich "live display" - it re-draws the same line every tick
    # SpinnerColumn = the spinning animation on the left
    # BarColumn     = the [====   ] fill bar
    # TextColumn    = the percentage text on the right
    # transient=True means it disappears when done, leaving a clean screen
    #
    # inside the loop we call progress.advance(task, 1) after each port finishes
    # rich sees that and redraws the bar slightly more filled each time
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(bar_width=35),
        TextColumn("{task.percentage:.0f}%"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("scanning...", total=len(ports))

        # ThreadPoolExecutor runs up to `threads` check_port() calls at once
        # instead of checking ports one-by-one (slow), we check hundreds in parallel
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(check_port, ip, p, timeout): p for p in ports}
            for f in as_completed(futures):   # as_completed fires when each thread finishes
                result = f.result()
                with lock:
                    if result:
                        open_ports.append(result)
                    progress.advance(task, 1)  # nudge the bar forward by 1

    # show results table
    if not open_ports:
        console.print("  [yellow]no open ports found[/yellow]\n")
        return

    from rich.markup import escape as esc
    table = Table(box=box.SIMPLE_HEAVY, border_style="cyan", header_style="bold", show_lines=False)
    table.add_column("PORT",    justify="right", style="cyan", width=8)
    table.add_column("SERVICE", style="yellow",  width=12)
    table.add_column("STATUS",  justify="center", width=8)
    table.add_column("NOTE",    style="dim")

    for r in sorted(open_ports, key=lambda x: x["port"]):
        note = f"[red]{esc(r['risk'])}[/red]" if r["risk"] else "[dim]ok[/dim]"
        table.add_row(str(r["port"]), esc(r["service"]), "[green]open[/green]", note)

    console.print(table)
    console.print(f"  [green]{len(open_ports)}[/green] open port(s)  |  scanned at {datetime.now().strftime('%H:%M:%S')}\n")


def main():
    parser = argparse.ArgumentParser(description="simple port scanner")
    parser.add_argument("host")
    parser.add_argument("-p", "--ports", default="top20",
                        help="top20 | all | 22,80,443 | 1-1024  (default: top20)")
    parser.add_argument("-t", "--threads", type=int, default=100)
    parser.add_argument("--timeout",      type=float, default=1.0)
    args = parser.parse_args()

    # figure out which ports to scan
    p = args.ports.strip().lower()
    if   p == "top20": ports = TOP20
    elif p == "all":   ports = ALL
    else:
        ports = set()
        for part in p.split(","):
            if "-" in part:
                a, b = part.split("-")
                ports.update(range(int(a), int(b)+1))
            else:
                ports.add(int(part))
        ports = sorted(ports)

    try:
        scan(args.host, ports, args.timeout, args.threads)
    except KeyboardInterrupt:
        console.print("\n  [yellow]stopped[/yellow]\n")

if __name__ == "__main__":
    main()