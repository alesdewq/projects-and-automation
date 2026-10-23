"""Сбор структуры Active Directory в JSON. Запуск: python main.py (окно) или python main.py --cli ... (консоль)."""
from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

APP = "ADCollector"


def user_dirs() -> tuple[Path, Path]:
    """(папка журнала, файл настроек) — в профиле пользователя, права администратора не нужны."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / APP
        return base / "logs", base / "settings.json"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / APP, Path.home() / "Library" / "Application Support" / APP / "settings.json"
    state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return state / "ad-collector", config / "ad-collector" / "settings.json"


def setup_logging(log_file: Path | None, verbose: bool) -> Path | None:
    logger = logging.getLogger("ad_collector")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S"))
    console.setLevel(logging.INFO)
    logger.addHandler(console)
    if log_file is None:
        log_file = user_dirs()[0] / "ad_collector.log"
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(log_file, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        return log_file
    except OSError as e:
        logger.warning("Не удалось открыть файл журнала %s: %s — пишу только в консоль", log_file, e)
        return None


def run_cli(args) -> int:
    import collector as col
    from ad_client import ADError
    from mock_ad import make_client

    log = logging.getLogger("ad_collector.cli")
    if not args.dc or not args.user:
        print("Нужны --dc и --user", file=sys.stderr)
        return 2
    password = os.environ.get("AD_PASSWORD")
    if password is None:
        if not sys.stdin.isatty():
            print("Пароль: задайте переменную AD_PASSWORD (нет терминала для ввода)", file=sys.stderr)
            return 2
        password = getpass.getpass(f"Пароль для {args.user}: ")
    client = make_client(args.dc, args.user, password, security=args.security, verify_cert=args.verify_cert,
                         connect_timeout=args.timeout, receive_timeout=max(30, args.timeout * 3), base_dn=args.base_dn)
    try:
        client.connect()
    except ADError as e:
        log.error("Подключение не выполнено: %s", e)
        return 1
    try:
        last = [-1]

        def progress(frac, msg):
            pct = int(frac * 100)
            if pct // 10 != last[0] // 10:
                last[0] = pct
                log.info("%3d%%  %s", pct, msg)
        result = col.Collector(client, progress, offices_ou=args.offices_ou).collect()
    finally:
        client.close()
    out = Path(args.out)
    if out.is_dir() or str(args.out).endswith(("/", "\\")):
        out = out / col.default_filename(result)
    path = col.save_json(result, out)
    si = result["scan_info"]
    log.info("Сохранено: %s — пользователей %d, групп %d, OU %d, компьютеров %d, площадок %d, должностей %d",
             path, si["total_users"], si["total_groups"], si["total_ous"], si["total_computers"],
             len(result["offices"]), len(result["positions"]))
    for w in si["warnings"]:
        log.warning("Предупреждение: %s", w)
    return 0 if si["complete"] else 1


def main(argv=None) -> int:
    from ad_client import SECURITY_MODES

    p = argparse.ArgumentParser(description="Сбор структуры Active Directory (OU, пользователи, группы, "
                                            "компьютеры, площадки, должности) в JSON")
    p.add_argument("--demo", action="store_true", help="тестовый домен в памяти, без настоящего AD")
    p.add_argument("--log-file", type=Path, help="файл журнала (по умолчанию — в профиле пользователя)")
    p.add_argument("-v", "--verbose", action="store_true", help="подробный журнал")
    g = p.add_argument_group("консольный режим (без окна)")
    g.add_argument("--cli", action="store_true", help="работать без окна")
    g.add_argument("--dc", help="адрес контроллера домена (имя, IP, имя домена; можно с :порт)")
    g.add_argument("--user", help="логин: ДОМЕН\\пользователь или пользователь@домен")
    g.add_argument("--security", choices=list(SECURITY_MODES), default="auto", help="защита соединения (auto)")
    g.add_argument("--verify-cert", action="store_true", help="проверять сертификат контроллера домена")
    g.add_argument("--timeout", type=int, default=10, help="таймаут подключения, с (10)")
    g.add_argument("--base-dn", help="DN домена, если не определяется автоматически")
    g.add_argument("--offices-ou", help="OU с площадками (имя или DN), если не находится сама")
    g.add_argument("--out", default=".", help="файл или папка для JSON (по умолчанию текущая папка)")
    args = p.parse_args(argv)

    log_path = setup_logging(args.log_file, args.verbose)
    log = logging.getLogger("ad_collector")
    log.info("Запуск: %s", " ".join(a for a in (sys.argv[1:] if argv is None else argv)))
    if args.cli:
        if args.demo:
            args.dc, args.user = args.dc or "mock", args.user or "DEMO\\reader"
            os.environ.setdefault("AD_PASSWORD", "demo")
        return run_cli(args)
    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("Нет модуля tkinter. Linux: sudo apt install python3-tk (Debian/Ubuntu) или dnf install python3-tkinter; "
              "либо запустите с --cli", file=sys.stderr)
        return 2
    import gui
    try:
        return gui.run(user_dirs()[1], log_path, demo=args.demo)
    except Exception as e:   # например, нет дисплея
        log.exception("Окно не запустилось: %s", e)
        print(f"Окно не запустилось: {e}. Используйте --cli", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
