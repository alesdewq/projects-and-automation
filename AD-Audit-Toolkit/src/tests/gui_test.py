"""Проверка окна (tkinter) — нужен дисплей (на сервере: xvfb-run). Нажимает кнопки так же, как пользователь.

python tests/gui_test.py <DC> <логин> <пароль> <папка для JSON и скриншотов>
"""
import json
import subprocess
import sys
import tempfile
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import gui  # noqa: E402
import main  # noqa: E402

dc, user, password, out = sys.argv[1:5]
out = Path(out)
out.mkdir(parents=True, exist_ok=True)
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok or not detail else ' — ' + str(detail)}", flush=True)


root = tk.Tk()
root.geometry("980x760+0+0")
tmp = Path(tempfile.mkdtemp())
log_file = main.setup_logging(tmp / "app.log", False)
app = gui.CollectorApp(root, tmp / "settings.json", log_file)

# пульс: насколько главный поток успевает обрабатывать события, пока идёт работа
beats = []


def beat():
    beats.append(time.monotonic())
    root.after(20, beat)


root.after(20, beat)


def pump(cond, timeout=30.0):
    t = time.monotonic()
    while time.monotonic() - t < timeout:
        root.update()
        if cond():
            return True
        time.sleep(0.01)
    return False


def max_gap(since):
    b = [x for x in beats if x >= since]
    return max((y - x for x, y in zip(b, b[1:])), default=0)


def shot(name):
    root.update()
    subprocess.run(["import", "-window", "root", "-crop", "990x770+0+0", str(out / f"{name}.png")], check=False)


def fill(dc_, user_, pw):
    app.v_dc.set(dc_)
    app.v_user.set(user_)
    app.v_pass.set(pw)


# 1. неверный пароль
fill(dc, user, password + "-wrong")
app.b_connect.invoke()
check("неверный пароль → красный статус", pump(lambda: "Неверный логин" in app.v_status.get(), 30),
      app.v_status.get())
check("индикатор красный", app.dot.itemcget(app.dot_id, "fill") == gui.STATUS_COLORS["error"])
check("«Собрать данные» недоступна без подключения", str(app.b_collect["state"]) == "disabled")
shot("1_wrong_password")

# 2. недоступный DC
fill("127.0.0.1:1", user, password)
app.b_connect.invoke()
check("недоступный DC → понятная ошибка", pump(lambda: "отклонено" in app.v_status.get(), 30), app.v_status.get())

# 3. верный пароль
fill(dc, user, password)
app.b_connect.invoke()
check("подключение → «Подключено»", pump(lambda: app.v_status.get().startswith("Подключено"), 30), app.v_status.get())
check("индикатор зелёный", app.dot.itemcget(app.dot_id, "fill") == gui.STATUS_COLORS["ok"])
shot("2_connected")

# 4. сбор
t0 = time.monotonic()
app.b_collect.invoke()
check("во время сбора кнопки заблокированы", str(app.b_connect["state"]) == "disabled" and str(app.b_stop["state"]) == "normal")
done = pump(lambda: app.busy is None and app.result is not None, 120)
check("сбор завершён", done and app.result["scan_info"]["status"] == "complete",
      app.result and app.result["scan_info"]["errors"])
gap = max_gap(t0)
check("окно не зависает во время сбора (пауза < 0,5 с)", gap < 0.5, f"{gap:.2f} с")
si = app.result["scan_info"]
check("итоги в окне", app.stats["users"].get().startswith(str(si["total_users"])) and app.stats["ous"].get() == str(si["total_ous"]),
      {k: v.get() for k, v in app.stats.items()})
check("прогресс 100%", app.v_progress.get() == 100)
check("журнал заполнен", "Итого: пользователей" in app.t_log.get("1.0", "end"))
check("дерево OU заполнено", len(app.tree.get_children()) > 0)
shot("3_collected")
app.nb.select(1)
shot("4_tree")
app.nb.select(2)
shot("5_lists")
app.nb.select(0)

# 5. сохранение
check("«Сохранить JSON» доступна", str(app.b_save["state"]) == "normal")
target = out / "gui_result.json"
app.save_to(str(target))
check("файл сохранён", pump(lambda: app.busy is None and "Сохранено" in app.v_phase.get(), 30), app.v_phase.get())
data = json.loads(target.read_text(encoding="utf-8"))
check("JSON корректен", data["scan_info"]["total_users"] == si["total_users"] and data["offices"] == app.result["offices"])
settings = json.loads((tmp / "settings.json").read_text(encoding="utf-8"))
check("пароль не сохранён в настройках", password not in json.dumps(settings) and "password" not in settings)
log_text = log_file.read_text(encoding="utf-8")
check("журнал пишется в файл, пароля в нём нет", "Итого: пользователей" in log_text and password not in log_text)

# 6. медленный DC + «Остановить»
fill("mock", "DEMO\\reader", "mock-slow")
app.b_connect.invoke()
pump(lambda: app.v_status.get().startswith("Подключено"), 30)
t0 = time.monotonic()
app.b_collect.invoke()
pump(lambda: False, 1.5)
app.b_stop.invoke()
stopped = pump(lambda: app.busy is None, 15)
check("«Остановить» прерывает сбор", stopped and app.result["scan_info"]["status"] == "cancelled",
      app.result and app.result["scan_info"]["status"])
check("после остановки можно сохранить неполные данные", str(app.b_save["state"]) == "normal")
check("окно отвечает во время медленного сбора", max_gap(t0) < 0.5, f"{max_gap(t0):.2f} с")
shot("6_stopped")

app.closing = True
root.destroy()
failed = results.count(False)
print(f"\n{len(results) - failed}/{len(results)} PASS")
sys.exit(1 if failed else 0)
