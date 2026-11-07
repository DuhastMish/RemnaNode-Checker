"""Геолокация IP чекеров: страна, регион, город, оператор (ASN) по локальным базам DB-IP Lite.

Базы (CC BY 4.0, https://db-ip.com) скачиваются раз в месяц в DATA_DIR/geoip: город ~130 МБ, ASN ~10 МБ.
IP никуда не отправляется — поиск локальный. Пока базы не скачаны, lookup() возвращает None, и проверка
страны чекера не работает (чекер не блокируется).

Точность: страна и оператор — надёжно; регион/город для домашнего интернета обычно верны, для мобильного
часто показывают город шлюза оператора (Москва и т.п.).
В DB-IP Lite по-русски есть только названия стран; регионы РФ и крупные города переводим словарём ниже,
остальные города остаются латиницей.
"""

import gzip
import ipaddress
import os
import shutil
import threading
import time

import httpx
import maxminddb

from . import config, db, egress

DIR = os.path.join(config.DATA_DIR, "geoip")
KINDS = {"city": "dbip-city-lite-{month}.mmdb.gz", "asn": "dbip-asn-lite-{month}.mmdb.gz"}
URL = "https://download.db-ip.com/free/"

_lock = threading.Lock()
_readers: dict = {}
_cache: dict = {}
last_error = ""


def _path(kind):
    return os.path.join(DIR, f"dbip-{kind}.mmdb")


def _open():
    """Открыть (или переоткрыть) базы с диска. Вызывается под _lock."""
    for kind in KINDS:
        old = _readers.pop(kind, None)
        if old:
            old.close()
        if os.path.exists(_path(kind)):
            _readers[kind] = maxminddb.open_database(_path(kind), maxminddb.MODE_MMAP)
    _cache.clear()


def _ensure_open():
    if not _readers and any(os.path.exists(_path(k)) for k in KINDS):
        with _lock:
            if not _readers:
                _open()


def loaded():
    _ensure_open()
    return "city" in _readers


def version():
    """Идентификатор загруженных баз: меняется после обновления — по нему пересчитываем геоданные чекеров."""
    _ensure_open()
    return "-".join(str(_readers[k].metadata().build_epoch) for k in KINDS if k in _readers)


def _month(offset=0):
    t = time.gmtime()
    y, m = t.tm_year, t.tm_mon - offset
    while m < 1:
        y, m = y - 1, m + 12
    return f"{y:04d}-{m:02d}"


def _download(kind, month):
    """Скачать и распаковать базу во временный файл, проверить, что открывается. None — если месяца ещё нет."""
    url = URL + KINDS[kind].format(month=month)
    tmp_gz, tmp = _path(kind) + ".gz.part", _path(kind) + ".part"
    try:
        with httpx.stream("GET", url, proxy=egress.proxy_url(), timeout=120, follow_redirects=True) as r:
            if r.status_code == 404:
                return None
            r.raise_for_status()
            with open(tmp_gz, "wb") as f:
                for chunk in r.iter_bytes(1 << 20):
                    f.write(chunk)
        with gzip.open(tmp_gz, "rb") as src, open(tmp, "wb") as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
        maxminddb.open_database(tmp, maxminddb.MODE_FILE).close()
        return tmp
    finally:
        if os.path.exists(tmp_gz):
            os.remove(tmp_gz)


def update():
    """Плановая задача: скачать базы за текущий месяц, если их ещё нет (DB-IP выкладывает их в начале месяца).
    Пока текущего месяца нет — остаёмся на старых; если баз нет совсем — берём прошлый месяц."""
    global last_error
    os.makedirs(DIR, exist_ok=True)
    have = db.kv_get("geoip_month", "")
    present = all(os.path.exists(_path(k)) for k in KINDS)
    months = [_month(0)] + ([] if present else [_month(1)])
    if present and have == months[0]:
        return
    try:
        for month in months:
            files = {}
            for kind in KINDS:
                tmp = _download(kind, month)
                if not tmp:
                    break
                files[kind] = tmp
            if len(files) < len(KINDS):
                for tmp in files.values():
                    os.remove(tmp)
                continue
            with _lock:
                for kind, tmp in files.items():
                    os.replace(tmp, _path(kind))
                _open()
            db.kv_set("geoip_month", month)
            last_error = ""
            return
        last_error = "базы DB-IP за текущий и прошлый месяц не найдены" if not present else ""
    except Exception as e:
        last_error = f"{type(e).__name__}: {e}"[:200]
        raise


def _ru(names):
    return (names or {}).get("ru") or (names or {}).get("en") or ""


def _clean(name):
    """'Moscow (Tsentralnyy administrativnyy okrug)' → 'Moscow'."""
    return name.split(" (")[0].strip() if name else ""


def lookup(ip):
    """{country, country_name, region, city, asn, org} или None (частный адрес / базы не загружены)."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    if not addr.is_global:
        return None
    _ensure_open()
    key = (str(addr), version())
    if key in _cache:
        return _cache[key]
    with _lock:
        city = _readers["city"].get(str(addr)) if "city" in _readers else None
        asn = _readers["asn"].get(str(addr)) if "asn" in _readers else None
    if not city and not asn:
        return None
    city, asn = city or {}, asn or {}
    country = (city.get("country") or {}).get("iso_code") or ""
    region = ""
    if city.get("subdivisions"):
        region = (city["subdivisions"][0].get("names") or {}).get("en") or ""
    town = _clean((city.get("city") or {}).get("names", {}).get("en") or "")
    if country == "RU":
        region = RU_REGIONS.get(region, region)
        town = RU_CITIES.get(town, town)
    out = {
        "country": country,
        "country_name": _ru((city.get("country") or {}).get("names")),
        "region": region,
        "city": town,
        "asn": asn.get("autonomous_system_number"),
        "org": asn.get("autonomous_system_organization") or "",
    }
    if len(_cache) > 2000:
        _cache.clear()
    _cache[key] = out
    return out


def place(geo):
    """'Россия, Пермский край, Пермь' (без повторов: 'Россия, Москва')."""
    parts = []
    for p in (geo or {}).get("country_name"), (geo or {}).get("region"), (geo or {}).get("city"):
        if p and p not in parts:
            parts.append(p)
    return ", ".join(parts)


def operator(geo):
    """'AS12768 JSC "ER-Telecom Holding"'."""
    geo = geo or {}
    asn = f"AS{geo['asn']}" if geo.get("asn") else ""
    return " ".join(p for p in (asn, geo.get("org") or "") if p)


# Регионы РФ: все написания, которые встречаются в DB-IP Lite
RU_REGIONS = {
    "Adygeya Republic": "Адыгея",
    "Altai": "Республика Алтай",
    "Altay Kray": "Алтайский край",
    "Amur Oblast": "Амурская область",
    "Arkhangelsk Oblast": "Архангельская область",
    "Arkhangelskaya": "Архангельская область",
    "Astrakhan": "Астраханская область",
    "Astrakhan Oblast": "Астраханская область",
    "Bashkortostan Republic": "Башкортостан",
    "Belgorod Oblast": "Белгородская область",
    "Bryansk Oblast": "Брянская область",
    "Buryatiya Republic": "Бурятия",
    "Chechnya": "Чечня",
    "Chelyabinsk": "Челябинская область",
    "Chukotka": "Чукотский АО",
    "Chuvash Republic": "Чувашия",
    "Chuvashia": "Чувашия",
    "Crimea": "Крым",
    "Dagestan": "Дагестан",
    "Ingushetiya Republic": "Ингушетия",
    "Irkutsk Oblast": "Иркутская область",
    "Ivanovo": "Ивановская область",
    "Ivanovo Oblast": "Ивановская область",
    "Jaroslavl": "Ярославская область",
    "Jewish Autonomous Oblast": "Еврейская АО",
    "Kabardino-Balkariya Republic": "Кабардино-Балкария",
    "Kaliningrad": "Калининградская область",
    "Kaliningrad Oblast": "Калининградская область",
    "Kalmykiya Republic": "Калмыкия",
    "Kaluga": "Калужская область",
    "Kaluga Oblast": "Калужская область",
    "Kamchatka": "Камчатский край",
    "Karachayevo-Cherkesiya Republic": "Карачаево-Черкесия",
    "Karelia": "Карелия",
    "Kemerovo Oblast": "Кемеровская область",
    "Khabarovsk": "Хабаровский край",
    "Khakasiya Republic": "Хакасия",
    "Khanty-Mansia": "ХМАО — Югра",
    "Kirov": "Кировская область",
    "Kirov Oblast": "Кировская область",
    "Komi": "Республика Коми",
    "Kostroma Oblast": "Костромская область",
    "Krasnodar Krai": "Краснодарский край",
    "Krasnodarskiy": "Краснодарский край",
    "Krasnoyarsk Krai": "Красноярский край",
    "Krasnoyarskiy": "Красноярский край",
    "Kurgan Oblast": "Курганская область",
    "Kursk": "Курская область",
    "Kursk Oblast": "Курская область",
    "Kuzbass": "Кемеровская область",
    "Leningradskaya Oblast'": "Ленинградская область",
    "Lipetsk Oblast": "Липецкая область",
    "Magadan Oblast": "Магаданская область",
    "Mariy-El Republic": "Марий Эл",
    "Mordoviya Republic": "Мордовия",
    "Moscow": "Москва",
    "Moscow Oblast": "Московская область",
    "Murmansk": "Мурманская область",
    "Nenets": "Ненецкий АО",
    "Nizhny Novgorod Oblast": "Нижегородская область",
    "North Ossetia": "Северная Осетия",
    "North Ossetia–Alania": "Северная Осетия",
    "Novgorod Oblast": "Новгородская область",
    "Novosibirsk Oblast": "Новосибирская область",
    "Omsk": "Омская область",
    "Omsk Oblast": "Омская область",
    "Orel Oblast": "Орловская область",
    "Orenburg Oblast": "Оренбургская область",
    "Oryol oblast": "Орловская область",
    "Penza": "Пензенская область",
    "Penza Oblast": "Пензенская область",
    "Perm": "Пермский край",
    "Perm Krai": "Пермский край",
    "Primorskiy (Maritime) Kray": "Приморский край",
    "Primorye": "Приморский край",
    "Pskov Oblast": "Псковская область",
    "Rostov": "Ростовская область",
    "Ryazan Oblast": "Рязанская область",
    "Sakha": "Якутия",
    "Sakhalin Oblast": "Сахалинская область",
    "Samara Oblast": "Самарская область",
    "Saratov Oblast": "Саратовская область",
    "Saratovskaya Oblast": "Саратовская область",
    "Sebastopol City": "Севастополь",
    "Smolensk": "Смоленская область",
    "Smolensk Oblast": "Смоленская область",
    "Smolenskaya Oblast’": "Смоленская область",
    "St. Petersburg": "Санкт-Петербург",
    "St.-Petersburg": "Санкт-Петербург",
    "Stavropol Kray": "Ставропольский край",
    "Stavropol’ Kray": "Ставропольский край",
    "Sverdlovsk": "Свердловская область",
    "Sverdlovsk Oblast": "Свердловская область",
    "Tambov": "Тамбовская область",
    "Tambov Oblast": "Тамбовская область",
    "Tatarstan Republic": "Татарстан",
    "Tomsk Oblast": "Томская область",
    "Transbaikal Territory": "Забайкальский край",
    "Tula": "Тульская область",
    "Tula Oblast": "Тульская область",
    "Tver Oblast": "Тверская область",
    "Tver’ Oblast": "Тверская область",
    "Tyumen Oblast": "Тюменская область",
    "Tyumen’ Oblast": "Тюменская область",
    "Tyva Republic": "Тыва",
    "Udmurtiya Republic": "Удмуртия",
    "Ulyanovsk": "Ульяновская область",
    "Vladimir": "Владимирская область",
    "Vladimir Oblast": "Владимирская область",
    "Volgograd Oblast": "Волгоградская область",
    "Vologda": "Вологодская область",
    "Vologda Oblast": "Вологодская область",
    "Voronezh Oblast": "Воронежская область",
    "Voronezj": "Воронежская область",
    "Yamalo-Nenets": "ЯНАО",
    "Yaroslavl Oblast": "Ярославская область",
    "Zabaykalskiy (Transbaikal) Kray": "Забайкальский край",
}

# Города РФ: региональные центры и самые частые в DB-IP Lite
RU_CITIES = {
    "Abakan": "Абакан",
    "Anadyr": "Анадырь",
    "Arkhangelsk": "Архангельск",
    "Armavir": "Армавир",
    "Astrakhan": "Астрахань",
    "Balashikha": "Балашиха",
    "Barnaul": "Барнаул",
    "Belgorod": "Белгород",
    "Berdsk": "Бердск",
    "Birobidzhan": "Биробиджан",
    "Blagoveshchensk": "Благовещенск",
    "Bryansk": "Брянск",
    "Cheboksary": "Чебоксары",
    "Chelyabinsk": "Челябинск",
    "Cherepovets": "Череповец",
    "Cherkessk": "Черкесск",
    "Chita": "Чита",
    "Dolgoprudny": "Долгопрудный",
    "Domodedovo": "Домодедово",
    "Dubna": "Дубна",
    "Ekaterinburg": "Екатеринбург",
    "Elektrostal": "Электросталь",
    "Elista": "Элиста",
    "Gorno-Altaysk": "Горно-Алтайск",
    "Grozny": "Грозный",
    "Irkutsk": "Иркутск",
    "Ivanovo": "Иваново",
    "Izhevsk": "Ижевск",
    "Kaliningrad": "Калининград",
    "Kaluga": "Калуга",
    "Kamensk-Uralsky": "Каменск-Уральский",
    "Kazan": "Казань",
    "Kazan’": "Казань",
    "Kemerovo": "Кемерово",
    "Khabarovsk": "Хабаровск",
    "Khanty-Mansiysk": "Ханты-Мансийск",
    "Khimki": "Химки",
    "Kirov": "Киров",
    "Kolomna": "Коломна",
    "Korolyov": "Королёв",
    "Kostroma": "Кострома",
    "Krasnodar": "Краснодар",
    "Krasnogorsk": "Красногорск",
    "Krasnoyarsk": "Красноярск",
    "Kurgan": "Курган",
    "Kursk": "Курск",
    "Kyzyl": "Кызыл",
    "Lipetsk": "Липецк",
    "Lyubertsy": "Люберцы",
    "Magadan": "Магадан",
    "Magas": "Магас",
    "Magnitogorsk": "Магнитогорск",
    "Makhachkala": "Махачкала",
    "Maykop": "Майкоп",
    "Moscow": "Москва",
    "Murmansk": "Мурманск",
    "Murom": "Муром",
    "Mytishchi": "Мытищи",
    "Naberezhnye Chelny": "Набережные Челны",
    "Nakhodka": "Находка",
    "Nal'chik": "Нальчик",
    "Naryan-Mar": "Нарьян-Мар",
    "Nizhnevartovsk": "Нижневартовск",
    "Nizhny Novgorod": "Нижний Новгород",
    "Nizhny Tagil": "Нижний Тагил",
    "Noginsk": "Ногинск",
    "Noril'sk": "Норильск",
    "Novgorod": "Великий Новгород",
    "Novokuznetsk": "Новокузнецк",
    "Novorossiysk": "Новороссийск",
    "Novosibirsk": "Новосибирск",
    "Noyabrsk": "Ноябрьск",
    "Obninsk": "Обнинск",
    "Odintsovo": "Одинцово",
    "Omsk": "Омск",
    "Orenburg": "Оренбург",
    "Oryol": "Орёл",
    "Penza": "Пенза",
    "Perm": "Пермь",
    "Petropavlovsk-Kamchatskiy": "Петропавловск-Камчатский",
    "Petrozavodsk": "Петрозаводск",
    "Podolsk": "Подольск",
    "Pskov": "Псков",
    "Pyatigorsk": "Пятигорск",
    "Ramenskoye": "Раменское",
    "Reutov": "Реутов",
    "Rostov-on-Don": "Ростов-на-Дону",
    "Ryazan": "Рязань",
    "Salekhard": "Салехард",
    "Samara": "Самара",
    "Saransk": "Саранск",
    "Saratov": "Саратов",
    "Sergiyev Posad": "Сергиев Посад",
    "Serpukhov": "Серпухов",
    "Sevastopol": "Севастополь",
    "Shchyolkovo": "Щёлково",
    "Simferopol": "Симферополь",
    "Smolensk": "Смоленск",
    "Sochi": "Сочи",
    "St Petersburg": "Санкт-Петербург",
    "Stavropol": "Ставрополь",
    "Sterlitamak": "Стерлитамак",
    "Surgut": "Сургут",
    "Syktyvkar": "Сыктывкар",
    "Taganrog": "Таганрог",
    "Tambov": "Тамбов",
    "Tolyatti": "Тольятти",
    "Tomsk": "Томск",
    "Tuapse": "Туапсе",
    "Tula": "Тула",
    "Tver'": "Тверь",
    "Tyumen": "Тюмень",
    "Ufa": "Уфа",
    "Ulan-Ude": "Улан-Удэ",
    "Ulyanovsk": "Ульяновск",
    "Ussuriysk": "Уссурийск",
    "Veliky Novgorod": "Великий Новгород",
    "Vladikavkaz": "Владикавказ",
    "Vladimir": "Владимир",
    "Vladivostok": "Владивосток",
    "Volgograd": "Волгоград",
    "Vologda": "Вологда",
    "Volzhsky": "Волжский",
    "Voronezh": "Воронеж",
    "Yakutsk": "Якутск",
    "Yaroslavl": "Ярославль",
    "Yekaterinburg": "Екатеринбург",
    "Yoshkar-Ola": "Йошкар-Ола",
    "Yuzhno-Sakhalinsk": "Южно-Сахалинск",
    "Zelenograd": "Зеленоград",
    "Zhukovsky": "Жуковский",
}
