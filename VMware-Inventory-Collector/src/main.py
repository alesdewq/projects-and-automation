"""Инвентаризация инфраструктуры: vCenter + сканирование подсетей → отчёты JSON/CSV/Markdown.

    python main.py                       окно программы
    python main.py --demo                окно с тестовым vCenter (mock) и подсетью 127.0.0.0/29
    python main.py --cli --vcenter vc.local --user ro@vsphere.local --subnet 10.0.0.0/24 --out reports
                                         без окна (пароль — из INVENTORY_VC_PASSWORD или запросом)
"""
from __future__ import annotations

import argparse
import getpass
import logging
import os
import platform
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

if sys.version_info < (3, 10):
    sys.exit("Нужен Python 3.10 или новее")

APP_DIR_NAME = "InfraInventory"


def user_dirs() -> tuple[Path, Path, Path]:
    """(папка настроек, папка журнала, папка отчётов по умолчанию) — в профиле пользователя, без прав администратора."""
    home = Path.home()
    system = platform.system()
    if system == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local") / APP_DIR_NAME
        config, logs = base, base / "logs"
    elif system == "Darwin":
        config = home / "Library" / "Application Support" / APP_DIR_NAME
        logs = home / "Library" / "Logs" / APP_DIR_NAME
    else:
        config = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config") / "infra-inventory"
        logs = Path(os.environ.get("XDG_STATE_HOME") or home / ".local" / "state") / "infra-inventory"
    docs = home / "Documents"
    reports = (docs if docs.is_dir() else home) / APP_DIR_NAME
    return config, logs, reports


def setup_logging(log_file: Path, verbose: bool = False, console: bool = False) -> Path:
    """Все действия — в файл (ротация 5 × 2 МБ). Пароли в журнал не попадают: их нигде не логируем."""
    root = logging.getLogger("inventory")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s [%(name)s] %(message)s")
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(log_file, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8")
    except OSError as e:
        fallback = Path.cwd() / "inventory.log"
        print(f"Не удалось открыть журнал {log_file}: {e}; пишу в {fallback}", file=sys.stderr)
        log_file = fallback
        fh = RotatingFileHandler(log_file, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    if console:
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
        root.addHandler(ch)
    # библиотеки (pyvmomi, urllib3) — только предупреждения, и тоже в файл
    for name in ("pyVmomi", "urllib3"):
        lib = logging.getLogger(name)
        lib.setLevel(logging.WARNING)
        lib.addHandler(fh)
    return log_file


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Инвентаризация инфраструктуры: vCenter + подсети → JSON/CSV/Markdown")
    p.add_argument("--demo", action="store_true", help="подставить тестовый vCenter (mock) и подсеть 127.0.0.0/29")
    p.add_argument("--browser", action="store_true", help="открыть интерфейс в браузере по умолчанию, а не в окне")
    p.add_argument("--log-file", type=Path, help="файл журнала (по умолчанию — в профиле пользователя)")
    p.add_argument("-v", "--verbose", action="store_true", help="подробный журнал (DEBUG)")
    cli = p.add_argument_group("консольный режим (без окна)")
    cli.add_argument("--cli", action="store_true", help="выполнить задание без окна и сохранить отчёты")
    cli.add_argument("--vcenter", default="", help="адрес vCenter (mock — тестовый)")
    cli.add_argument("--user", default="", help="логин vCenter")
    cli.add_argument("--verify-ssl", action="store_true", help="проверять сертификат vCenter")
    cli.add_argument("--subnet", action="append", default=[], help="подсеть/диапазон/адрес (можно несколько раз)")
    cli.add_argument("--no-vsphere", action="store_true", help="не опрашивать vSphere")
    cli.add_argument("--no-scan", action="store_true", help="не сканировать подсети")
    cli.add_argument("--no-types", action="store_true", help="не определять типы устройств")
    cli.add_argument("--no-ping", action="store_true", help="не использовать ping")
    cli.add_argument("--ports", help="TCP-порты через запятую")
    cli.add_argument("--timeout", type=float, default=600, help="лимит времени сканирования, с (0 — без лимита)")
    cli.add_argument("--workers", type=int, default=64, help="потоков сканирования")
    cli.add_argument("--out", type=Path, help="папка для отчётов")
    cli.add_argument("--formats", default="json,csv,md", help="форматы через запятую: json,csv,md")
    return p.parse_args(argv)


def run_cli(args, reports_dir: Path) -> int:
    import exporter
    from inventory import JobConfig, run_job
    from network_scanner import DEFAULT_PORTS

    password = ""
    if not args.no_vsphere:
        password = os.environ.get("INVENTORY_VC_PASSWORD")
        if password is None:
            if not sys.stdin.isatty():
                print("Пароль vCenter: задайте INVENTORY_VC_PASSWORD (stdin не терминал)", file=sys.stderr)
                return 2
            password = getpass.getpass(f"Пароль vCenter для {args.user}: ")
    try:
        ports = tuple(int(x) for x in args.ports.split(",") if x.strip()) if args.ports else DEFAULT_PORTS
        formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
        if any(f not in exporter.FORMATS for f in formats):
            raise ValueError(f"форматы: {', '.join(exporter.FORMATS)}")
    except ValueError as e:
        print(f"Ошибка параметров: {e}", file=sys.stderr)
        return 2
    cfg = JobConfig(vcenter=args.vcenter, user=args.user, password=password, verify_ssl=args.verify_ssl,
                    subnets="\n".join(args.subnet), scan_vsphere=not args.no_vsphere, scan_subnets=not args.no_scan,
                    detect_types=not args.no_types, use_ping=not args.no_ping, ports=ports,
                    scan_timeout=args.timeout, workers=args.workers)
    problems = cfg.validate()
    if problems:
        for pr in problems:
            print(f"Ошибка: {pr}", file=sys.stderr)
        return 2
    last = [-1]

    def progress(frac, msg):
        pct = int(frac * 100)
        if pct // 10 != last[0] // 10:
            last[0] = pct
            print(f"  {pct:3d}%  {msg}", flush=True)

    try:
        result = run_job(cfg, progress=progress)
    except KeyboardInterrupt:
        print("Прервано", file=sys.stderr)
        return 130
    paths = exporter.export(result, args.out or reports_dir, formats)
    print(f"Устройств: {len(result['devices'])}, ошибок: {len(result['errors'])}")
    for path in paths:
        print(f"Отчёт: {path}")
    return 1 if result["errors"] else 0


def main(argv=None) -> int:
    args = parse_args(argv)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    config_dir, log_dir, reports_dir = user_dirs()
    log_file = setup_logging(args.log_file or log_dir / "inventory.log", args.verbose, console=args.cli)
    log = logging.getLogger("inventory")
    log.info("Запуск: Python %s, %s %s, режим %s", platform.python_version(), platform.system(), platform.release(),
             "cli" if args.cli else "gui")
    if args.cli:
        return run_cli(args, reports_dir)
    try:
        from gui import InventoryApp
    except ImportError as e:
        print(f"Не удалось загрузить интерфейс: {e}\nУстановите зависимости: pip install -r requirements.txt",
              file=sys.stderr)
        return 2
    gui = InventoryApp(config_dir / "settings.json", log_file, reports_dir, demo=args.demo)
    gui.run("browser" if args.browser else "auto")
    return 0


if __name__ == "__main__":
    sys.exit(main())
