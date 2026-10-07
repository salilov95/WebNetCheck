"""Разбор причины по слоям: из машинных меток проверок строим вывод «что сломано и где».

Правила идут снизу вверх по стеку: если сломан нижний слой, верхние симптомы
не выдаём как отдельные причины.
"""
from __future__ import annotations

import re

from .model import LAYER_TITLES, LAYERS, Check, Diagnosis, Report, Status
from .util import human_bytes


def _has(r: Report, *tags: str) -> bool:
    return any(t in c.tags for c in r.checks for t in tags)


def _with(r: Report, tag: str) -> list[Check]:
    return [c for c in r.checks if tag in c.tags]


def _fam(r: Report, tag: str, fam: str) -> bool:
    return any(tag in c.tags and c.family == fam for c in r.checks)


def diagnose(r: Report) -> list[Diagnosis]:
    out: list[Diagnosis] = []
    add = lambda sev, title, text, steps=(): out.append(Diagnosis(sev, title, text, list(steps)))  # noqa: E731

    if _has(r, "fatal"):
        c = _with(r, "fatal")[0]
        add(Status.FAIL, "Проверка не запустилась", c.summary)
        return out

    # --- DNS -----------------------------------------------------------------
    dns_dead = False
    if _has(r, "dns_nx_everywhere"):
        add(Status.FAIL, "Имени не существует",
            "Все резолверы отвечают NXDOMAIN. Это не сетевая проблема: опечатка в имени, домен не "
            "продлён или запись удалена.", ["Проверить написание имени", "whois домена / DNS-зону у владельца"])
        dns_dead = True
    elif _has(r, "dns_all_fail"):
        add(Status.FAIL, "DNS не работает вообще",
            "Ни системный резолвер, ни публичные, ни DoH не вернули адрес. Вероятно, нет сети или "
            "весь DNS-трафик (UDP/53 и DoH) закрыт.", ["ipconfig /all — шлюз и DNS-серверы",
                                                         "Проверить доступ в интернет по IP"])
        dns_dead = True
    elif _has(r, "dns_system_broken"):
        add(Status.FAIL, "Сломан локальный/корпоративный DNS",
            "Системный резолвер Windows не разрешает имя, а публичные резолверы и DoH — разрешают. "
            "Проблема в DNS-сервере из настроек сетевого адаптера (или в его форвардинге), а не у сервиса. "
            "Если так отвечает DNS провайдера и только для этого сервиса — имя блокируется на уровне DNS.",
            ["ipconfig /flushdns и повторить", "nslookup <имя> <DNS-сервер> — проверить каждый настроенный",
             "Проверить условную пересылку/фильтрацию на корпоративном DNS"])
        dns_dead = True
    elif _has(r, "dns_bogus"):
        add(Status.FAIL, "DNS возвращает заглушку",
            "Системный резолвер отдаёт 0.0.0.0/127.x вместо реального адреса, а DoH — настоящий. Так "
            "выглядит блокировка на уровне DNS (фильтр провайдера, корпоративный DNS-фильтр, Pi-hole, "
            "антивирус).", ["Сравнить с ответом DoH (в деталях проверки)",
                            "Проверить политику DNS-фильтрации / hosts-файл (C:\\Windows\\System32\\drivers\\etc\\hosts)"])
    elif _has(r, "dns_private_vs_public"):
        add(Status.WARN, "Система и интернет видят разные адреса",
            "Системный DNS отдаёт приватный адрес, публичные — публичный. Если это корпоративный "
            "split-horizon (внутренний вход в сервис) — норма; если нет — подмена DNS.")
    if _has(r, "dns_configured_dead") and not dns_dead:
        c = _with(r, "dns_configured_dead")[0]
        add(c.status, "Один из настроенных DNS-серверов молчит",
            f"{c.summary[:1].upper() + c.summary[1:]}. Имена разрешаются через остальные серверы, но при пустом кэше "
            "Windows может ждать этот сервер и терять секунды на первом обращении. Часто это DNS домашнего "
            "роутера, недоступный при включённом VPN, или устаревшая запись в настройках адаптера.",
            ["ipconfig /all — у какого адаптера прописан этот сервер", "Убрать его или поставить последним"])
    if _has(r, "dns_udp53_blocked") and not dns_dead:
        add(Status.INFO, "Исходящий UDP/53 закрыт",
            "Публичные DNS по UDP/53 не отвечают, но системный резолвер работает. Обычная политика "
            "корпоративной сети: DNS разрешён только через свои серверы.")
    if dns_dead:
        return out

    # --- Прокси / маршрут -------------------------------------------------------
    direct_fail = _has(r, "tcp_main_timeout", "tcp_main_refused", "tcp_main_unreachable")
    proxy_ok = any(c.status == Status.OK and "via_proxy" in c.tags and c.layer in ("tls", "http") for c in r.checks)
    direct_http_ok = any(c.status == Status.OK and "direct" in c.tags and c.layer == "http" for c in r.checks)
    if direct_fail and proxy_ok and not direct_http_ok:
        add(Status.INFO, "Прямого доступа нет, работает через прокси",
            "До цели напрямую не подключиться, а через прокси всё проходит. "
            + ("При этом к другим адресам интернет напрямую есть — закрыты именно адреса сервиса "
               "(блокировка по IP). " if _has(r, "control_ok") else "Для корпоративной сети это ожидаемо. ")
            + "Приложения, не использующие системный прокси (WinHTTP, CLI-утилиты), работать не будут.",
            ["netsh winhttp import proxy source=ie — передать прокси WinHTTP-приложениям",
             "Для CLI: переменные HTTPS_PROXY/NO_PROXY"])
    proxy_fail = [c for c in r.checks if "via_proxy" in c.tags and c.status == Status.FAIL]
    if proxy_fail and direct_http_ok:
        add(Status.WARN, "Через прокси не работает, напрямую — работает",
            f"Прокси не пропускает запрос: {proxy_fail[0].summary}. Проверьте исключения/политику прокси.")

    # --- TCP ---------------------------------------------------------------------
    tcp_dead = False
    main_tcp = [c for c in r.checks if c.layer == "tcp" and any(t.startswith("tcp_main_") for t in c.tags)]
    if main_tcp and not any("tcp_main_ok" in c.tags for c in main_tcp) and not proxy_ok:
        tcp_dead = True
        codes = {t for c in main_tcp for t in c.tags if t.startswith("tcp_main_")}
        port = re.sub(r"\D", "", main_tcp[0].title) or "?"
        if "tcp_main_refused" in codes:
            add(Status.FAIL, f"Порт {port} закрыт",
                "Хост отвечает RST на подключение: адрес жив, но сервис не слушает порт или его "
                "отклоняет фильтр с REJECT.", ["Проверить, что сервис запущен и слушает порт",
                                               "Сравнить с другого сегмента сети"])
        elif _has(r, "icmp_ok", "trace_ok"):
            add(Status.FAIL, f"TCP/{port} фильтруется по пути",
                "ICMP до хоста проходит, а SYN на порт остаётся без ответа: пакеты молча отбрасывает "
                "межсетевой экран (свой, корпоративный или провайдера).",
                ["Test-NetConnection <host> -Port " + port, "Проверить правила исходящего трафика / ACL",
                 "Сравнить с другой сети (мобильный интернет)"])
        elif "tcp_main_unreachable" in codes or _has(r, "icmp_unreachable"):
            add(Status.FAIL, "Нет маршрута до хоста",
                "Стек или маршрутизатор сообщает «хост/сеть недоступны». Смотрите последний ответивший хоп "
                "в трассировке — дальше него пакеты не уходят.", ["route print — маршрут по умолчанию",
                                                                 "tracert <IP> — где обрывается"])
        elif _has(r, "control_ok"):
            last = _last_hop(r)
            add(Status.FAIL, "Адреса сервиса недоступны, интернет работает",
                "К другим адресам в интернете TCP проходит, а к адресам сервиса — нет ни ICMP, ни TCP. "
                "Так выглядит блокировка по IP-адресу на пути; реже — авария самого сервиса."
                + (f" Последний ответивший хоп: {last}." if last else ""),
                ["Проверить с другой сети (мобильный интернет)",
                 "Посмотреть status-страницу сервиса — если там всё в норме, режет сеть",
                 "Сравнить с маршрутом «Через системный прокси», если прокси или VPN включён"])
        else:
            last = _last_hop(r)
            add(Status.FAIL, "Хост недоступен",
                "Ни ICMP, ни TCP не получают ответа. Либо хост выключен, либо весь трафик к нему "
                "отбрасывается." + (f" Последний ответивший хоп: {last}." if last else ""),
                ["Проверить с другой сети", "Уточнить у владельца сервиса, жив ли он"])
    if tcp_dead:
        _ipv6_and_misc(r, add)
        return out

    # --- IPv6 vs IPv4 ------------------------------------------------------------
    _ipv6_and_misc(r, add)

    # --- TLS -----------------------------------------------------------------------
    if _has(r, "tls_sni_filtered"):
        add(Status.FAIL, "Фильтрация по SNI (DPI)",
            "TCP-соединение устанавливается, но рукопожатие с настоящим именем сайта в SNI обрывается, "
            "а с нейтральным именем на тот же IP — проходит. Значит, на пути стоит DPI, который "
            "режет соединения по имени хоста. С сервером всё в порядке."
            + (" QUIC (UDP/443) с этим именем тоже не проходит." if _has(r, "quic_sni_filtered", "quic_blocked") else ""),
            ["Проверить с другой сети (мобильный интернет)", "Корпоративная сеть — запросить исключение для домена",
             "Если это провайдер — обращение в поддержку провайдера"])
    elif _has(r, "tls_intercept"):
        c = _with(r, "tls_intercept")[0]
        add(Status.WARN, "TLS перехватывается",
            f"Сертификат подписан не публичным центром, а средством инспекции трафика ({c.details.get('Издатель', '?')}). "
            "Браузеры с корпоративным корнем доверия работают, а приложения со своим хранилищем "
            "сертификатов (Python, Java, Git, Docker, pinning в мобильных клиентах) — получают ошибку проверки.",
            ["Добавить корпоративный CA в хранилище приложения (SSL_CERT_FILE, git http.sslCAInfo…)",
             "Или попросить исключение домена из TLS-инспекции"])
    elif _has(r, "tls_expired"):
        add(Status.FAIL, "Сертификат истёк", "Проблема на стороне сервиса — сертификат нужно перевыпустить.")
    elif _has(r, "tls_name_mismatch"):
        add(Status.FAIL, "Сертификат не для этого имени",
            "Сервер отдаёт сертификат на другой домен. Причины: ошибка конфигурации сервиса, неверный "
            "IP (DNS указывает не туда) или подмена на пути.", ["Сравнить SAN сертификата и ответы DNS"])
    elif _has(r, "tls_untrusted"):
        add(Status.FAIL, "Недоверенный сертификат",
            "Цепочка не строится до доверенного корня. Если издатель незнаком — возможен перехват; если это "
            "внутренний сервис — не установлен корпоративный CA.")
    if _has(r, "tls13_fail") and _has(r, "tls12_ok"):
        add(Status.WARN, "Ломается только TLS 1.3",
            "TLS 1.2 проходит, TLS 1.3 — нет. Типично для старых DPI/IPS/прокси, не понимающих TLS 1.3, "
            "или фильтров по размеру ClientHello (post-quantum ключи делают его > 1 пакета).",
            ["Обновить прошивку межсетевого экрана/IPS", "Проверить, не режет ли фильтр большие ClientHello"])
    tls_net = [c for c in r.checks if "tls_fail" in c.tags and "tls_sni_filtered" not in c.tags]
    if tls_net and not _has(r, "tls_sni_filtered") and not _has(r, "tls_ok"):
        add(Status.FAIL, "TLS-рукопожатие не проходит",
            f"TCP работает, но TLS обрывается: {tls_net[0].summary}. С нейтральным SNI тоже не работает — "
            "значит, режется не имя, а TLS к этому IP целиком (или сервер не говорит TLS на этом порту).")

    # --- QUIC ----------------------------------------------------------------------
    if _has(r, "quic_sni_filtered", "quic_blocked") and not _has(r, "tls_sni_filtered"):
        hosts = ", ".join(dict.fromkeys(c.target for c in _with(r, "quic_sni_filtered") + _with(r, "quic_blocked")))
        by_sni = _has(r, "quic_sni_filtered")
        add(Status.WARN, "QUIC (HTTP/3) не проходит, TCP — проходит",
            f"По UDP/443 сервер не отвечает ({hosts})"
            + (", хотя с нейтральным именем на тот же адрес отвечает — QUIC режется по SNI. " if by_sni else
               ", хотя к другим серверам QUIC работает. ")
            + "Браузер сначала пробует HTTP/3, ждёт и только потом откатывается на TCP: сайт открывается "
            "с задержкой, видео стартует медленно или подвисает.",
            ["Сравнить с другой сети", "Для проверки отключить QUIC в браузере: chrome://flags → "
             "Experimental QUIC protocol → Disabled, и посмотреть, ушла ли задержка"])
    elif _has(r, "quic_udp443_closed") and _has(r, "udp_ok"):
        add(Status.INFO, "UDP/443 закрыт, остальной UDP работает",
            "QUIC не проходит ни к одному серверу, хотя STUN по UDP отвечает. Сеть режет именно UDP/443 — "
            "браузеры будут работать по TCP, HTTP/3 недоступен.")

    # --- HTTP ----------------------------------------------------------------------
    if _has(r, "http_5xx"):
        c = _with(r, "http_5xx")[0]
        add(Status.FAIL, "Сервис отвечает ошибкой 5xx",
            f"{c.summary}. Сеть до сервиса исправна (DNS, TCP, TLS прошли), проблема в самом сервисе или "
            "его бэкенде/балансировщике.", ["Посмотреть status-страницу сервиса", "Повторить позже"])
    if _has(r, "http_451"):
        add(Status.FAIL, "Недоступно по юридическим причинам",
            "Сервер или промежуточный узел вернул HTTP 451 — ресурс заблокирован по требованию закона.")
    ext = _with(r, "extip_direct")
    where = f" Ваш внешний адрес: {ext[0].summary}." if ext else ""
    direct_403 = any("http_403" in c.tags and "direct" in c.tags for c in r.checks)
    if direct_403 and any("http_ok" in c.tags and "via_proxy" in c.tags for c in r.checks):
        add(Status.WARN, "Сервис не пускает с вашего адреса",
            "Напрямую сервер отвечает 403, а через прокси тот же запрос проходит. Сеть до сервиса исправна — "
            "доступ закрывает сам сервис (или его CDN/WAF) по адресу или стране клиента." + where,
            ["Это ограничение на стороне сервиса, а не блокировка по пути: настройки сети его не снимут"])
    elif _has(r, "http_403") and not _has(r, "http_ok"):
        add(Status.WARN, "Доступ запрещён (403)",
            "Сервер отвечает, но не пускает: гео-ограничение со стороны сервиса, WAF/антибот или блок-страница "
            "прокси. Посмотрите заголовки server/via в деталях — по ним видно, кто именно ответил." + where)
    if _has(r, "http_407"):
        add(Status.WARN, "Прокси требует аутентификацию",
            "Нужно указать учётные данные прокси (или использовать прокси с Kerberos/NTLM из браузера).")
    if _has(r, "http_body_broken") and not _has(r, "content_stall", "content_trunc"):
        add(Status.FAIL, "Ответ главной страницы обрывается",
            "Заголовки приходят, а тело страницы — нет до конца. Смотрите раздел «Целостность».")

    # --- Зависимости ------------------------------------------------------------------
    if _has(r, "deps_fail_main_ok"):
        bad = [h for h in r.hosts if h.status == Status.FAIL]
        sev = Status.FAIL if any(h.source == "профиль" for h in bad) else Status.WARN
        groups: dict[str, list[str]] = {}
        for h in bad:
            cause = h.note.split(":", 1)[0] or "?"
            groups.setdefault("http5xx" if cause.startswith("HTTP") else cause, []).append(h.host)
        cause_text = {
            "proxy": "прокси отказывает в CONNECT (политика/белый список прокси)",
            "dns": "имена не разрешаются (DNS-фильтр или split-DNS)",
            "tcp": "TCP не устанавливается (firewall по адресу)",
            "tls": "TLS обрывается (фильтр по SNI/IP или перехват)",
            "ttfb": "сервер не отвечает после подключения",
            "http5xx": "хосты отвечают 5xx (сбой сервиса, не сети)",
        }
        parts = []
        for cause, hs in groups.items():
            parts.append(f"{cause_text.get(cause, cause)}: {', '.join(hs[:6])}" + (" …" if len(hs) > 6 else ""))
        steps = ["Проверить каждый хост отдельно (вкладка «Хосты»)"]
        if "proxy" in groups:
            steps.insert(0, "Запросить у администраторов прокси разрешение для перечисленных доменов")
        add(sev, "Главная работает, но часть хостов — нет",
            "Страница/сервис будет работать частично — без ресурсов и API с этих хостов. "
            + "; ".join(parts).rstrip(".") + ("" if parts and parts[-1].endswith("…") else "."), steps)

    # --- Контент -----------------------------------------------------------------------
    stalls = _with(r, "content_stall") + _with(r, "content_trunc")
    if stalls:
        ats = []
        for c in stalls:
            for t in c.tags:
                m = re.match(r"(?:stall|trunc)_at_(\d+)", t)
                if m:
                    ats.append(int(m.group(1)))
        near16 = [a for a in ats if 12 * 1024 <= a <= 24 * 1024]
        low_mtu = _has(r, "pmtu_low")
        where = ", ".join(human_bytes(a) for a in ats) or "?"
        if low_mtu:
            add(Status.FAIL, "Обрыв передачи + пониженный MTU",
                f"Крупные объекты обрываются (на {where}), а Path MTU меньше 1500. Типичная MTU black hole: "
                "большие TCP-сегменты не проходят, а ICMP «нужна фрагментация» где-то отфильтрован.",
                ["Временно уменьшить MTU: netsh interface ipv4 set subinterface \"<адаптер>\" mtu=1400 store=active",
                 "Включить MSS clamping на маршрутизаторе/VPN-шлюзе"])
        elif near16 and len(near16) == len(ats):
            add(Status.FAIL, "Передача замирает после ~16 KiB",
                f"DNS, TCP и TLS проходят, HTTP-ответ начинается, но поток останавливается на {where}. "
                "Такой порог характерен для DPI-ограничения по объёму на соединение (так ведут себя "
                "фильтры к части зарубежных хостингов и CDN), реже — для MTU black hole.",
                ["Сравнить с другой сети/VPN", "Проверить Path MTU (включите проверку MTU)",
                 "Если сервис ваш — проверить через другой CDN/хостинг"])
        else:
            add(Status.FAIL, "Объекты обрываются при загрузке",
                f"Загрузка крупных объектов прерывается (на {where}). Нестабильный канал, прокси/антивирус "
                "с ограничением размера или промежуточный фильтр.")
    slow = _with(r, "speed_throttled")
    if slow:
        c = next((x for x in slow if "direct" in x.tags), slow[0])
        via_ok = any("speed_ok" in x.tags and "via_proxy" in x.tags for x in r.checks)
        add(Status.FAIL, "Замедление по имени (SNI)",
            f"Один и тот же объект с одного сервера: с именем {c.target} в SNI — {c.summary}. Сервер, маршрут и "
            "объект одинаковы, отличается только имя, которое видит оборудование на пути. Значит, скорость "
            "режется по имени — сайт открывается, а видео идёт рывками или в низком качестве."
            + (" Через прокси замедления нет." if via_ok else ""),
            ["Сравнить с другой сети (мобильный интернет)", "С сервисом и вашим каналом всё в порядке — "
             "общий тест скорости этого не покажет"])
    if _has(r, "speed_sni_blocked") and not slow:
        c = _with(r, "speed_sni_blocked")[0]
        add(Status.FAIL, f"Соединения с именем {c.target} обрываются",
            f"К тому же серверу с настоящим именем загрузка идёт, а с именем {c.target} в SNI соединение не "
            f"устанавливается: {c.summary}. Блокировка по SNI.", ["Сравнить с другой сети"])
    if _has(r, "content_size_mismatch"):
        add(Status.FAIL, "Размер объекта не совпадает с заявленным",
            "Сервер заявил один Content-Length, а получено другое число байт без ошибки соединения. "
            "Признак модифицирующего прокси/антивируса или битого кэша CDN.")
    if _has(r, "content_tail_mismatch"):
        add(Status.FAIL, "Повторная выборка не совпала",
            "Хвост объекта, запрошенный отдельно через Range, не совпал с полной загрузкой. Либо объект "
            "менялся во время проверки, либо его портит промежуточный узел.")

    # --- UDP -----------------------------------------------------------------------------
    need = next((c.details.get("В этом сервисе по UDP", "") for c in _with(r, "udp_needed")), "")
    direct_impaired = (_has(r, "tls_sni_filtered", "quic_sni_filtered", "quic_blocked", "control_ok",
                            "speed_throttled", "speed_sni_blocked")
                       or any("direct" in c.tags and c.layer in ("tls", "http")
                              and any(t == "tls_fail" or t.startswith("http_err_") for t in c.tags)
                              for c in r.checks))
    if _has(r, "udp_blocked"):
        add(Status.WARN, "UDP наружу не проходит",
            "Ни один STUN-сервер не ответил: исходящий UDP закрыт (корпоративный firewall, гостевая сеть) или "
            "весь трафик завёрнут в туннель только для TCP."
            + (f" В этом сервисе по UDP работают {need} — они работать не будут, даже если сайт и чат открываются."
               if need else " Голосовые и видеозвонки, WebRTC и HTTP/3 работать не будут."),
            ["Проверить правила исходящего UDP на роутере/firewall", "Сравнить с другой сети"])
    elif need and _has(r, "udp_bypasses_proxy"):
        c = _with(r, "udp_bypasses_proxy")[0]
        add(Status.WARN if direct_impaired else Status.INFO, "UDP идёт мимо прокси",
            f"В системе включён прокси, но он переносит только TCP. По UDP работают {need}: этот трафик уходит "
            f"напрямую с адреса {c.details.get('Внешний адрес по UDP', '?')}, а не с адреса прокси "
            f"({c.details.get('Внешний адрес через прокси (TCP)', '?')}). "
            + ("Прямой путь до сервиса при этом ограничен — отсюда типичная картина «сайт и чат работают, "
               "а голоса нет»: соединение зависает на подключении к голосовому серверу."
               if direct_impaired else
               "Пока прямой путь до сервиса свободен, это не мешает."),
            ["HTTP/SOCKS-прокси в настройках системы UDP не переносит: нужен режим, который заворачивает весь "
             "трафик (сетевой адаптер TUN / VPN), а не только браузер",
             "Проверка: после смены режима адрес в строке «UDP наружу (STUN)» должен совпасть с адресом прокси"])
    elif need and _has(r, "udp_ok") and direct_impaired and not _has(r, "udp_via_tunnel"):
        add(Status.WARN, "UDP проходит, но прямой путь до сервиса ограничен",
            f"По UDP работают {need}. Сам UDP наружу открыт, однако доступ к сервису напрямую ограничен (см. выводы "
            "выше), а такие ограничения обычно распространяются и на его UDP-трафик. Проверить голосовой сервер "
            "без входа в аккаунт нельзя, поэтому это косвенный вывод.")

    # --- Прочее --------------------------------------------------------------------------
    if _has(r, "extip_differs"):
        c = _with(r, "extip_differs")[0]
        direct_only = not any("via_proxy" in x.tags for x in r.checks)
        add(Status.INFO, "Браузер и прямое подключение выходят в интернет по-разному",
            f"В системе включён прокси или VPN: через него внешний адрес {c.details.get('Через прокси', '?')}, "
            f"а напрямую — {c.details.get('Напрямую', '?')}. "
            + ("Эта проверка шла напрямую, поэтому её результат может отличаться от того, что видит браузер."
               if direct_only else "Сравните результаты по обоим маршрутам."),
            ["Чтобы проверить путь браузера, выберите маршрут «Через системный прокси» или «Сравнить: прокси и напрямую»"]
            if direct_only else [])
    if _has(r, "icmp_blocked") and (_has(r, "tcp_main_ok") or proxy_ok) and not _has(r, "icmp_unreachable"):
        add(Status.INFO, "ICMP фильтруется — это не проблема",
            "Ping не проходит, но TCP работает. Многие сервисы и сети режут ICMP; на доступность это не влияет.")
    if _has(r, "pmtu_low") and not stalls:
        mtu = next((c.details.get("MTU") for c in _with(r, "pmtu_low")), "?")
        add(Status.INFO, f"Path MTU = {mtu}",
            "Путь с уменьшенным MTU (VPN, PPPoE, туннель). Пока ICMP «нужна фрагментация» проходит — "
            "это работает; при его блокировке возможны зависания крупных передач.")
    if _has(r, "quic_advertised") and not _has(r, "quic_ok", "quic_sni_filtered", "quic_blocked",
                                               "quic_udp443_closed"):
        add(Status.INFO, "Сервис поддерживает HTTP/3 (QUIC)",
            "Браузеры могут ходить по UDP/443. Если в браузере сайт «думает» дольше, чем в этой проверке, — "
            "возможно, UDP/443 режется и браузер ждёт фолбэка на TCP.")
    if _has(r, "tls_expiring"):
        c = _with(r, "tls_expiring")[0]
        add(Status.WARN, "Сертификат скоро истекает",
            f"Срок действия: {c.details.get('Действителен', '?')}. После истечения клиенты получат ошибку TLS.",
            ["Сообщить владельцу сервиса / проверить автопродление (ACME)"])

    # --- API ---------------------------------------------------------------------------------
    api_bad = [c for c in r.checks if c.layer == "api" and c.status == Status.FAIL]
    if api_bad:
        net = [c for c in api_bad if "api_net_fail" in c.tags]
        five = [c for c in api_bad if "api_5xx" in c.tags]
        other = [c for c in api_bad if "api_unexpected" in c.tags]
        if net:
            add(Status.FAIL, "API-эндпоинт недоступен по сети",
                "; ".join(f"{c.title}: {c.summary}" for c in net[:4]))
        if five:
            add(Status.FAIL, "API отвечает 5xx",
                "Маршрут до API жив, но бэкенд возвращает ошибку: "
                + "; ".join(f"{c.title} → {c.summary}" for c in five[:4]) + ".")
        if other:
            add(Status.WARN, "API ответил не тем кодом",
                "Ответ получен, но не совпал с ожиданием профиля (часто — ключ/токен/права): "
                + "; ".join(f"{c.title} → {c.summary}" for c in other[:4]) + ".",
                ["Проверить ключ доступа в переменной окружения", "Сверить ожидаемый код в профиле"])
    if _has(r, "no_aaaa"):
        add(Status.FAIL, "У сервиса нет IPv6-адресов",
            "Записей AAAA нет — по IPv6 сервис недоступен в принципе. Это свойство сервиса, а не вашей сети.")

    # Всё, что упало, но не попало ни в одно правило — показать как есть, чтобы ничего не терялось
    explained = {d.severity for d in out}
    if r.overall == Status.FAIL and Status.FAIL not in explained:
        bad = [c for c in r.checks if c.status == Status.FAIL]
        add(Status.FAIL, "Есть сбойные проверки",
            "; ".join(f"{c.title} ({c.target}): {c.summary}" for c in bad[:5]) + ("…" if len(bad) > 5 else ""))
    if r.overall == Status.WARN and not explained & {Status.FAIL, Status.WARN}:
        warn = [c for c in r.checks if c.status == Status.WARN]
        add(Status.WARN, "Есть замечания",
            "; ".join(f"{c.title} ({c.target}): {c.summary}" for c in warn[:5]) + ("…" if len(warn) > 5 else ""))
    if r.overall == Status.OK and not [d for d in out if d.severity in (Status.FAIL, Status.WARN)]:
        out.insert(0, Diagnosis(Status.OK, "Все проверенные слои в норме",
                                "DNS, транспорт, TLS и HTTP отработали без ошибок"
                                + (", крупные объекты доставляются целиком" if _has(r, "content_ok") else "")
                                + ". Если пользователь всё равно жалуется — проверьте с его машины/сети и в его браузере.",
                                []))
    order = {Status.FAIL: 0, Status.WARN: 1, Status.OK: 2, Status.INFO: 3, Status.SKIP: 4}
    out.sort(key=lambda d: order[d.severity])
    if r.cancelled:
        # прерванный прогон не имеет права на вердикт «всё в норме»
        out = [d for d in out if d.severity != Status.OK]
        done = [LAYER_TITLES[k] for k, _ in LAYERS if any(c.layer == k for c in r.checks)]
        out.insert(0, Diagnosis(Status.INFO, "Проверка прервана",
                                "Успели пройти слои: " + (", ".join(done) or "ни одного")
                                + ". Остальные не проверялись, поэтому итогового вывода нет.", []))
    return out


def _ipv6_and_misc(r: Report, add):
    v6_bad = any(c.family == "IPv6" and c.status == Status.FAIL and c.layer in ("tcp", "tls", "http") for c in r.checks)
    v4_ok = any(c.family == "IPv4" and c.status == Status.OK and c.layer in ("tcp", "http") for c in r.checks)
    v4_bad = any(c.family == "IPv4" and c.status == Status.FAIL and c.layer in ("tcp", "tls", "http") for c in r.checks)
    v6_ok = any(c.family == "IPv6" and c.status == Status.OK and c.layer in ("tcp", "http") for c in r.checks)
    if v6_bad and v4_ok:
        add(Status.WARN, "Сломан IPv6, IPv4 работает",
            "У сервиса есть AAAA, но по IPv6 соединение не устанавливается. Клиенты, которые пробуют IPv6 "
            "первым, получают задержки («Happy Eyeballs» спасает браузеры, но не все приложения).",
            ["Проверить IPv6-маршрут и firewall", "Временный обход: приоритет IPv4 (netsh interface ipv6 set prefixpolicy)"])
    if v4_bad and v6_ok:
        add(Status.WARN, "Сломан IPv4, IPv6 работает",
            "По IPv6 сервис доступен, по IPv4 — нет. Возможна проблема NAT/CGNAT или фильтрация IPv4-адресов.")


def _last_hop(r: Report) -> str:
    answered = [h for h in r.hops if h.ip]
    if not answered:
        return ""
    h = answered[-1]
    return f"#{h.ttl} {h.ip}" + (f" ({h.name})" if h.name else "")
