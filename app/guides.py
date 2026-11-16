"""Инструкции для клиентов: подключение и раздельное туннелирование.

Подписка (VLESS + Hysteria2): Happ, Incy, v2RayTun, Hiddify.
AmneziaWG: AmneziaVPN (Android, Windows, macOS, Linux), DefaultVPN (iPhone), AmneziaWG (.conf).

Источники: официальные сайты и магазины приложений, docs.amnezia.org (раздельное
туннелирование), документация Happ (happ.su, dev-docs/routing) и Incy (docs.incy.cc,
incy.gitbook.io). Названия пунктов меню, которые не удалось сверить, описаны общими словами.
Каждый экран — отдельное сообщение (держим заметно меньше лимита Telegram).
"""
from .ui import btn, em, esc, kb, table

ROUTES_BTN = ("Списки сервисов", "routes", "globe")       # раздел со списками для клиентов

# ============================================================== подписка ===
# key: name, платформы, ссылки на установку, как добавить подписку, как подключиться,
# раздельное туннелирование (HTML), есть ли кнопка «Открыть в …» (ключ APPS в sub_server)

SUB_CLIENTS: dict[str, dict] = {
    "happ": {
        "name": "Happ",
        "where": "iPhone и iPad, Android, Android TV, Windows, macOS, Linux",
        "links": [("App Store", "https://apps.apple.com/app/happ-proxy-utility/id6504287215"),
                  ("Сайт Happ", "https://www.happ.su/main"),
                  ("GitHub (Android, ПК)", "https://github.com/Happ-proxy")],
        "deeplink": "happ",
        "add": ("<ol><li>Нажми в боте <b>«Открыть в Happ»</b> — подписка добавится сама.</li>"
                "<li>Или скопируй ссылку подписки (нажми на неё в «Моей подписке»), открой Happ, "
                "нажми <b>➕</b> и выбери вставку из буфера обмена.</li></ol>"),
        "connect": ("Выбери сервер (VLESS или Hysteria2) и нажми большую кнопку подключения. "
                    "Список серверов обновляется сам; вручную — кнопкой обновления подписки."),
        "split": (
            "<h3>Списки сайтов и IP (все платформы)</h3>"
            "<p>В Happ раздельное туннелирование делается <b>профилем маршрутизации</b>: какие "
            "сайты и IP идут через VPN, какие напрямую, какие блокируются. Правила проверяются "
            "сверху вниз — срабатывает первое подходящее.</p>"
            "<ol><li>Открой в боте <b>«Списки сервисов»</b> и отметь, что открывать через VPN.</li>"
            "<li>Нажми кнопку для Happ — бот даст ссылку вида <code>happ://routing/…</code>.</li>"
            "<li>Открой ссылку на устройстве с Happ: профиль добавится (вариант <b>onadd</b> — "
            "добавится и сразу включится). Профиль с тем же именем перезаписывается.</li></ol>"
            "<p>Если ты выбрал сервисы в «Списках сервисов», Happ может получить профиль и сам — "
            "при обновлении подписки.</p>"
            "<h3>По приложениям (Android)</h3>"
            "<p>В настройках Happ есть режим проксирования отдельных приложений (per-app proxy): "
            "выбери приложения, которые идут через VPN, или те, что идут мимо него.</p>"
            "<h3>По приложениям (Windows, macOS)</h3>"
            "<p>В правилах маршрутизации Happ на компьютере можно добавить правило по имени "
            "процесса (тип <code>PROCESS-NAME</code>) — например, только браузер через VPN.</p>"),
    },
    "incy": {
        "name": "Incy",
        "where": "iPhone и iPad, Android, Windows, macOS, Linux",
        "links": [("App Store", "https://apps.apple.com/app/incy/id6756943388"),
                  ("Google Play", "https://play.google.com/store/apps/details?id=llc.itdev.incy"),
                  ("Windows, macOS, Linux", "https://github.com/INCY-DEV/incy-platforms")],
        "deeplink": "incy",
        "add": ("<ol><li>Нажми в боте <b>«Открыть в Incy»</b> — подписка добавится сама "
                "(Incy откроется по ссылке <code>incy://</code>).</li>"
                "<li>Или скопируй ссылку подписки и добавь её в Incy через <b>➕</b> — Incy сам "
                "определит, что это подписка.</li></ol>"),
        "connect": ("Выбери сервер (VLESS или Hysteria2) и подключись. Подписка обновляется "
                    "автоматически."),
        "split": (
            "<h3>Списки сайтов и IP</h3>"
            "<p>В Incy есть <b>профили маршрутизации</b>: трафик делится по доменам и IP на "
            "<i>proxy</i> (через VPN), <i>direct</i> (напрямую) и <i>block</i>, с отдельными DNS "
            "для зарубежных и местных адресов.</p>"
            "<ol><li>Открой в боте <b>«Списки сервисов»</b> и отметь нужные сервисы.</li>"
            "<li>Возьми ссылку для Incy и открой её на устройстве — профиль добавится.</li>"
            "<li>Если сервисы выбраны, профиль может прийти и вместе с подпиской — при её "
            "обновлении.</li></ol>"
            "<h3>По приложениям</h3>"
            "<p>В Incy есть per-app proxy: на Android и компьютере можно пустить через VPN "
            "только выбранные приложения или, наоборот, исключить их из туннеля. Ищи это в "
            "настройках приложения.</p>"),
    },
    "v2raytun": {
        "name": "v2RayTun",
        "where": "iPhone и iPad, Android, Windows, macOS",
        "links": [("App Store", "https://apps.apple.com/app/v2raytun/id6476628951"),
                  ("Google Play",
                   "https://play.google.com/store/apps/details?id=com.v2raytun.android")],
        "deeplink": "v2raytun",
        "add": ("<ol><li>Нажми в боте <b>«Открыть в v2RayTun»</b>.</li>"
                "<li>Или скопируй ссылку подписки, открой v2RayTun, нажми <b>➕</b> и выбери "
                "импорт из буфера обмена.</li></ol>"),
        "connect": ("Выбери сервер и подключись. На Windows перед подключением включи в "
                    "настройках трафика режим туннеля — иначе через VPN пойдут не все программы."),
        "split": (
            "<h3>Сайты и приложения</h3>"
            "<p>В v2RayTun раздельное туннелирование настраивается в разделе маршрутизации: "
            "добавь правило для домена, IP или приложения и выбери, идёт ли оно через VPN или "
            "напрямую. Изменения применяются сразу.</p>"
            "<ul><li>На Android можно исключить отдельные приложения из VPN.</li>"
            "<li>Списки доменов и IP для правил возьми в «Списках сервисов».</li>"
            "<li>Держи в приложении один профиль подписки — с несколькими маршрутизация может "
            "работать неправильно.</li></ul>"),
    },
    "hiddify": {
        "name": "Hiddify",
        "where": "Android, iPhone и iPad, Windows, macOS, Linux",
        "links": [("Сайт Hiddify", "https://hiddify.com"),
                  ("GitHub", "https://github.com/hiddify/hiddify-app/releases"),
                  ("Google Play",
                   "https://play.google.com/store/apps/details?id=app.hiddify.com")],
        "deeplink": "hiddify",
        "add": ("<ol><li>Нажми в боте <b>«Открыть в Hiddify»</b>.</li>"
                "<li>Или скопируй ссылку подписки, открой Hiddify, нажми <b>➕</b> (новый "
                "профиль) и добавь из буфера обмена.</li></ol>"),
        "connect": "Выбери профиль и нажми кнопку подключения в центре экрана.",
        "split": (
            "<h3>По региону</h3>"
            "<p>В настройках маршрутизации Hiddify выбери <b>регион</b> (Россия) — сайты этого "
            "региона пойдут напрямую, остальное — через VPN.</p>"
            "<h3>По приложениям (Android)</h3>"
            "<p>В настройках есть <b>per-app proxy</b>: «только выбранные» приложения через VPN "
            "или «все, кроме выбранных».</p>"
            "<h3>Компьютер</h3>"
            "<p>Встроенного раздельного туннелирования по программам на Windows, macOS и Linux "
            "нет. Для гибких правил по сайтам удобнее Happ или Incy.</p>"),
    },
}

SUB_ORDER = ("happ", "incy", "v2raytun", "hiddify")

SPLIT_COMMON = (
    f"<blockquote>{em('idea')} На сервере выход на российские сайты через VPN может быть "
    f"закрыт. Поэтому российские сервисы (банки, Госуслуги, маркетплейсы) лучше пускать "
    f"<b>напрямую</b>, а через VPN — только то, что нужно.</blockquote>")


def sub_index() -> tuple[str, object]:
    text = (f"<h2>{em('help')} Как подключиться по подписке</h2>"
            f"<p>Подойдёт любое из приложений. Рекомендуем <b>Happ</b> или <b>Incy</b> — в них "
            f"удобнее всего раздельное туннелирование.</p>"
            + table([[f"<b>{c['name']}</b>", esc(c["where"])]
                     for c in (SUB_CLIENTS[k] for k in SUB_ORDER)],
                    head=["Приложение", "Устройства"]))
    return text, kb([btn(SUB_CLIENTS[k]["name"], f"sg:{k}", icon="help") for k in SUB_ORDER[:2]],
                    [btn(SUB_CLIENTS[k]["name"], f"sg:{k}", icon="help") for k in SUB_ORDER[2:]],
                    [btn("Раздельное туннелирование", "sgs", icon="ip_change")],
                    [btn("Моя подписка", "sub", icon="back")])


def sub_guide(key: str) -> tuple[str, object]:
    c = SUB_CLIENTS[key]
    text = (f"<h2>{em('help')} {c['name']}</h2><p>Работает на: {esc(c['where'])}.</p>"
            f"<h3>1. Установи приложение</h3>"
            f"<p>Кнопки ниже ведут в официальные магазины и на сайт разработчика.</p>"
            f"<h3>2. Добавь подписку</h3>{c['add']}"
            f"<h3>3. Подключись</h3><p>{c['connect']}</p>"
            f"<details><summary>{em('question')} Не получается?</summary><ul>"
            f"<li>Обнови подписку в приложении.</li>"
            f"<li>Видишь сервер «Лимит устройств» — удали лишнее устройство в боте "
            f"(«Моя подписка» → «Устройства подписки»).</li>"
            f"<li>Не работает один протокол — попробуй другой (VLESS ↔ Hysteria2).</li>"
            f"<li>Не помогло — нажми <b>«Не работает VPN»</b> в боте.</li></ul></details>"
            f"<footer>{em('lock')} Ссылка подписки — как пароль: не пересылай её другим людям."
            f"</footer>")
    links = [btn(t, url=u, icon="download") for t, u in c["links"]]
    return text, kb(links[:2], links[2:],
                    [btn("Раздельное туннелирование", f"sgs:{key}", icon="ip_change")],
                    [btn("Моя подписка", "sub", icon="subscription"),
                     btn("Назад", "sg", icon="back")])


def sub_split_index() -> tuple[str, object]:
    text = (f"<h2>{em('ip_change')} Раздельное туннелирование</h2>"
            f"<p>Можно пустить через VPN только нужные сервисы, а остальное — напрямую. Так "
            f"быстрее, а российские сайты и приложения не видят VPN.</p>" + SPLIT_COMMON
            + "<p>Выбери приложение — покажу, как это сделать именно в нём.</p>")
    return text, kb([btn(SUB_CLIENTS[k]["name"], f"sgs:{k}", icon="ip_change")
                     for k in SUB_ORDER[:2]],
                    [btn(SUB_CLIENTS[k]["name"], f"sgs:{k}", icon="ip_change")
                     for k in SUB_ORDER[2:]],
                    [btn(ROUTES_BTN[0], ROUTES_BTN[1], icon=ROUTES_BTN[2])],
                    [btn("Назад", "sg", icon="back")])


def sub_split(key: str) -> tuple[str, object]:
    c = SUB_CLIENTS[key]
    text = (f"<h2>{em('ip_change')} {c['name']}: раздельное туннелирование</h2>"
            + c["split"] + SPLIT_COMMON)
    return text, kb([btn(ROUTES_BTN[0], ROUTES_BTN[1], icon=ROUTES_BTN[2])],
                    [btn(f"Подключение в {c['name']}", f"sg:{key}", icon="help"),
                     btn("Назад", "sgs", icon="back")])


# ============================================================ AmneziaWG ===

LOCAL_NETS = ("192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "169.254.0.0/16",
              "100.64.0.0/10", "224.0.0.0/4")


def awg_split_index() -> tuple[str, object]:
    text = (f"<h2>{em('ip_change')} Раздельное туннелирование (AmneziaWG)</h2>"
            f"<p>Можно пустить через VPN только выбранные сервисы или, наоборот, исключить "
            f"сайты и приложения из VPN.</p>"
            + table([["AmneziaVPN · Android", "сайты/IP и приложения, оба режима"],
                     ["AmneziaVPN · Windows", "сайты/IP (оба режима), приложения — только «без VPN»"],
                     ["AmneziaVPN · macOS, Linux, iOS", "только сайты/IP"],
                     ["DefaultVPN · iPhone", "по приложениям нельзя (ограничение iOS)"],
                     ["AmneziaWG · файл .conf", "строка AllowedIPs; на Android — по приложениям"]],
                    head=["Приложение", "Что можно"])
            + SPLIT_COMMON)
    return text, kb([btn("AmneziaVPN: сайты", "gs:amnezia", icon="ip_change"),
                     btn("AmneziaVPN: приложения", "gs:amnezia_apps", icon="ip_change")],
                    [btn("DefaultVPN", "gs:defaultvpn", icon="apple"),
                     btn("AmneziaWG (.conf)", "gs:amneziawg", icon="file")],
                    [btn(ROUTES_BTN[0], ROUTES_BTN[1], icon=ROUTES_BTN[2])],
                    [btn("Назад", "help", icon="back")])


def awg_split(key: str) -> tuple[str, object]:
    back = [btn(ROUTES_BTN[0], ROUTES_BTN[1], icon=ROUTES_BTN[2]),
            btn("Назад", "gs", icon="back")]
    if key == "amnezia":
        nets = "\n".join(LOCAL_NETS)
        text = f"""
<h2>{em('ip_change')} AmneziaVPN: сайты и IP</h2>
<p>Работает на всех платформах, только для IPv4. Правило по IP действует и на сайт, и на приложение сервиса (например, Telegram).</p>
<h3>Режим «Только адреса из списка должны открываться через VPN»</h3>
<p>Рекомендуемый вариант.</p>
<ol>
<li>В боте открой <b>«Списки сервисов»</b>, отметь нужные сервисы и скачай файл для AmneziaVPN (<code>.json</code>).</li>
<li>В AmneziaVPN зайди в параметры раздельного туннелирования сайтов и выбери <b>«Только адреса из списка должны открываться через VPN»</b>.</li>
<li>Нажми <b>⋮</b> и выбери <b>«Добавить импортированные сайты к существующим»</b> или <b>«Заменить список с сайтами»</b>.</li>
<li>Выбери скачанный файл, включи раздельное туннелирование сайтов и подключись.</li>
</ol>
<h3>Режим «Адреса из списка не должны открываться через VPN»</h3>
<p>Подходит, если через VPN нужно всё, кроме локальной сети. Добавь подсети:</p>
<pre>{nets}</pre>
<details>
<summary>{em('question')} Важно</summary>
<ul>
<li>Один домен (например, youtube.com) не поможет: AmneziaVPN один раз превращает его в текущий IP и больше не обновляет. Нужны списки IP-подсетей — они в «Списках сервисов».</li>
<li>Широкие подсети крупных сервисов могут захватить и другие сайты.</li>
<li>Если после включения не подключается — в списке оказалась подсеть с IP нашего сервера, убери её.</li>
<li>Используй свежую версию AmneziaVPN (в версиях до 4.8.8.3 раздельное туннелирование работало с ошибками).</li>
</ul>
</details>
"""
        return text, kb(back)
    if key == "amnezia_apps":
        text = f"""
<h2>{em('ip_change')} AmneziaVPN: приложения</h2>
<h3>Android</h3>
<ol>
<li>Зайди в параметры раздельного туннелирования приложений и выбери режим: выбранные приложения работают <b>через VPN</b> или <b>без VPN</b>.</li>
<li>Отметь приложения и нажми <b>«Добавить выбранные»</b>.</li>
<li>Включи раздельное туннелирование и подключись.</li>
</ol>
<p>Правило для приложения не действует на одноимённый сайт в браузере — браузер это отдельное приложение. Если нужного приложения нет в списке, пойди от обратного: исключи из VPN банки и госприложения.</p>
<h3>Windows</h3>
<ol>
<li>Зайди в параметры раздельного туннелирования приложений и нажми <b>➕</b>.</li>
<li>Выбери <code>.exe</code> программ, которые должны работать <b>без VPN</b> (обратного режима на Windows нет).</li>
<li>Включи раздельное туннелирование приложений и подключись.</li>
</ol>
<p>Найти нужный <code>.exe</code> поможет утилита AppNetworkCounter (NirSoft).</p>
<h3>iPhone, macOS, Linux</h3>
<p>По приложениям нельзя — только по сайтам и IP.</p>
<p>На Android и Windows можно включить сразу оба вида: по сайтам и по приложениям.</p>
"""
        return text, kb(back)
    if key == "defaultvpn":
        text = f"""
<h2>{em('ip_change')} DefaultVPN (iPhone)</h2>
<p>iOS не даёт VPN-приложениям делить трафик по приложениям — это ограничение системы, у AmneziaVPN на iPhone тоже только сайты и IP.</p>
<ul>
<li>Если в настройках DefaultVPN есть раздельное туннелирование сайтов — режимы и импорт файла такие же, как в AmneziaVPN (см. «AmneziaVPN: сайты»).</li>
<li>Если нет — поставь <b>AmneziaWG</b> с файлом <code>.conf</code> и задай в нём список подсетей (см. «AmneziaWG (.conf)»).</li>
<li>Самое гибкое на iPhone — <b>подписка</b> в Happ или Incy: там списки сайтов подключаются одной ссылкой.</li>
</ul>
"""
        return text, kb([btn("AmneziaVPN: сайты", "gs:amnezia", icon="ip_change"),
                         btn("AmneziaWG (.conf)", "gs:amneziawg", icon="file")], back)
    # amneziawg
    text = f"""
<h2>{em('ip_change')} AmneziaWG: файл .conf</h2>
<p>Через VPN идут адреса из строки <code>AllowedIPs</code> в разделе <code>[Peer]</code>. В конфиге из бота там стоит <code>0.0.0.0/0, ::/0</code> — весь трафик.</p>
<h3>Только выбранные сервисы через VPN</h3>
<ol>
<li>В боте открой <b>«Списки сервисов»</b>, отметь сервисы и возьми готовую строку <code>AllowedIPs</code> (или готовый файл).</li>
<li>Открой туннель в AmneziaWG → редактировать и замени строку <code>AllowedIPs</code> на полученную.</li>
<li>Сохрани и подключись заново.</li>
</ol>
<p>Строку <code>DNS</code> не удаляй. Не добавляй в список IP нашего сервера.</p>
<h3>По приложениям (Android)</h3>
<p>В настройках туннеля AmneziaWG на Android можно выбрать приложения: все, все кроме выбранных или только выбранные.</p>
<h3>Windows, macOS, iPhone</h3>
<p>По приложениям нельзя — только через <code>AllowedIPs</code>.</p>
"""
    return text, kb(back)


AWG_SPLIT_KEYS = ("amnezia", "amnezia_apps", "defaultvpn", "amneziawg")
