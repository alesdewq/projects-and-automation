"""Генерирует LDIF с тестовой структурой домена COMPANY.LOCAL для Samba AD (ldbadd).

python3 seed.py > seed.ldif   — детерминированно (одни и те же данные при каждом запуске).
Больше 1000 пользователей (проверка постраничного поиска) и группа больше 1500 участников
(проверка «range retrieval» атрибута member).
"""
import base64
import random
import sys

BASE = "DC=company,DC=local"
N_USERS = 1600
rnd = random.Random(2026)

SURNAMES = ["Иванов", "Петров", "Сидоров", "Кузнецов", "Смирнов", "Попов", "Васильев", "Соколов", "Михайлов",
            "Новиков", "Фёдоров", "Морозов", "Волков", "Алексеев", "Лебедев", "Семёнов", "Егоров", "Павлов"]
NAMES = ["Иван", "Пётр", "Алексей", "Сергей", "Дмитрий", "Андрей", "Михаил", "Николай", "Юрий", "Олег"]
PATRONYMICS = ["Иванович", "Петрович", "Сергеевич", "Андреевич", "Николаевич", "Олегович"]
TR = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
              "a b v g d e e zh z i y k l m n o p r s t u f kh ts ch sh sch - y - e yu ya".split()))

# площадка → отделы (OU) → должности
SITES = {
    "Площадка-А": {"Производство": ["Оператор", "Наладчик", "Мастер смены"], "Офис": ["Менеджер", "Инженер"]},
    "Площадка-В": {"Продажи": ["Менеджер", "Руководитель группы"], "Бухгалтерия": ["Бухгалтер", "Главный бухгалтер"],
               "Отдел продаж, маркетинг": ["Маркетолог"]},
    "Санкт-Петербург": {"Склад": ["Кладовщик", "Водитель погрузчика"]},
}


def translit(s):
    return "".join(TR.get(ch, ch) for ch in s.lower()).replace("-", "")


def esc_rdn(v):
    return v.replace("\\", "\\\\").replace(",", "\\,").replace("+", "\\+").replace('"', '\\"')


def attr(name, value):
    value = str(value)
    if value.isascii() and not value.startswith((" ", ":", "<")):
        return f"{name}: {value}"
    return f"{name}:: {base64.b64encode(value.encode()).decode()}"


def entry(dn, **attrs):
    lines = [attr("dn", dn)]
    for k, v in attrs.items():
        for item in (v if isinstance(v, list) else [v]):
            lines.append(attr(k, item))
    print("\n".join(lines) + "\n")


def ou(dn, name, description=""):
    kw = {"description": description} if description else {}
    entry(dn, objectClass="organizationalUnit", ou=name, **kw)


ou(f"OU=Площадки,{BASE}", "Площадки", "Площадки компании (города)")
ou(f"OU=Группы,{BASE}", "Группы", "Группы доступа и рассылки")
ou(f"OU=Компьютеры,{BASE}", "Компьютеры")
ou(f"OU=Сервисные учётные записи,{BASE}", "Сервисные учётные записи")
for site, depts in SITES.items():
    ou(f"OU={site},OU=Площадки,{BASE}", site, f"Площадка {site}")
    ou(f"OU={site},OU=Компьютеры,{BASE}", site)
    for dept in depts:
        ou(f"OU={esc_rdn(dept)},OU={site},OU=Площадки,{BASE}", dept)

users = []          # (dn, site, dept)
heads = {}          # (site, dept) -> dn руководителя
slots = [(s, d) for s, ds in SITES.items() for d in ds]
for i in range(N_USERS):
    site, dept = slots[i % len(slots)] if i < len(slots) else rnd.choice(slots)
    sn, gn, pat = rnd.choice(SURNAMES), rnd.choice(NAMES), rnd.choice(PATRONYMICS)
    sam = f"{translit(sn)}.{translit(gn)[0]}{i:04d}"
    cn = f"{sn} {gn} {i:04d}"
    container = f"OU={esc_rdn(dept)},OU={site},OU=Площадки,{BASE}" if i % 50 else f"CN=Users,{BASE}"
    dn = f"CN={esc_rdn(cn)},{container}"
    head = (site, dept) not in heads
    title = "Начальник отдела" if head else rnd.choice(SITES[site][dept])
    a = dict(objectClass="user", sAMAccountName=sam, userPrincipalName=f"{sam}@company.local",
             givenName=gn, sn=sn, displayName=f"{sn} {gn} {pat}", mail=f"{sam}@company.local",
             telephoneNumber=f"+7 (4922) {i // 100:02d}-{i % 100:02d}-{rnd.randint(10, 99)}",
             department=dept, company="ООО Компания",
             userAccountControl=str(514 if i % 37 == 5 else 66080))   # отключён / включён + пароль не истекает + не требуется
    if i % 23 != 7:                                                    # у части сотрудников должность не заполнена
        a["title"] = title
    if i % 41 != 3:                                                    # и площадка тоже
        a["physicalDeliveryOfficeName"] = site
    if not head:
        a["manager"] = heads[(site, dept)]
    else:
        heads[(site, dept)] = dn
    entry(dn, **a)
    users.append((dn, site, dept))

entry(f"CN=svc-backup,OU=Сервисные учётные записи,{BASE}", objectClass="user", sAMAccountName="svc-backup",
      description="Резервное копирование", userAccountControl="66080")

groups_ou = f"OU=Группы,{BASE}"
for site, depts in SITES.items():
    for dept in depts:
        name = f"GG_{dept.split(',')[0].replace(' ', '_')}_{site}"
        entry(f"CN={name},{groups_ou}", objectClass="group", sAMAccountName=name, groupType="-2147483646",
              description=f"{dept} — площадка {site}",
              member=[dn for dn, s, d in users if s == site and d == dept])
entry(f"CN=Производство (все),{groups_ou}", objectClass="group", sAMAccountName="Производство_все",
      groupType="-2147483640", description="Вложенная группа",
      member=[f"CN=GG_Производство_Площадка-А,{groups_ou}"])
entry(f"CN=Рассылка Площадка-В,{groups_ou}", objectClass="group", sAMAccountName="Рассылка_Площадка-В", groupType="2",
      mail="moscow@company.local", member=[dn for dn, s, _ in users if s == "Площадка-В"][:40])
entry(f"CN=Все сотрудники,{groups_ou}", objectClass="group", sAMAccountName="Все_сотрудники",
      groupType="-2147483640", description="Больше 1500 участников", member=[dn for dn, _, _ in users])

OS = [("Windows 10 Pro", "10.0 (19045)"), ("Windows 11 Pro", "10.0 (22631)"),
      ("Windows Server 2019 Standard", "10.0 (17763)")]
for i in range(60):
    site = ["Площадка-А", "Площадка-В"][i % 2]
    name = f"PC-{'VLD' if site == 'Площадка-А' else 'MSK'}-{i:03d}"
    osname, osver = OS[i % 3]
    entry(f"CN={name},OU={site},OU=Компьютеры,{BASE}", objectClass="computer", sAMAccountName=name + "$",
          dNSHostName=f"{name.lower()}.company.local", operatingSystem=osname, operatingSystemVersion=osver,
          userAccountControl="4096")

entry(f"CN=Поставщик ООО Ромашка,OU=Площадка-В,OU=Площадки,{BASE}", objectClass="contact",
      displayName="ООО Ромашка", mail="info@romashka.example")
print(f"# пользователей: {len(users) + 1}", file=sys.stderr)
