# nodecheck

Проверка доступности нод Remnawave / Open60 с домашнего интернета. Один контейнер на мини-ПК
(веб-морда + планировщик + проверялка + WireGuard-клиент), VPS — только Caddy и WireGuard-сервер.

```
браузер → VPS (Caddy, HTTPS) → WireGuard → мини-ПК (nodecheck:8000, ttyd:7681) → ноды
```

- `admin.example.com` — admin-токен: плитки с IP, ручные проверки, история, терминал, настройки.
- `status.example.com` — PIN: плитки без IP, проверка одной ноды (кэш 60 с, лимит 5/мин с IP).

## 1. VPS (публичный сервер, на него указывают домены)

Туннель до дома — **обратный SSH** (`ssh -R`): провайдерские DPI его не режут, в отличие от WireGuard
(ТСПУ пропускает handshake и дальше всё режет). WireGuard остался как опция в настройках.

На VPS руками ничего ставить не нужно: приложение по SSH само добавит `GatewayPorts clientspecified`
в `sshd_config` и пробросит на VPS свои порты `18000` (приложение) и `17681` (терминал) на адрес,
который виден nginx из docker (`172.18.0.1`, gateway docker-сети nginx). Nginx проксирует домены туда —
образец `deploy/nginx-nodecheck.conf.template`. Сертификат: `certbot certonly --standalone` с
pre/post-hook, останавливающими nginx на 15 с. В DNS: A-записи обоих доменов → IP VPS.

## 2. Мини-ПК (Debian 12)

```bash
sudo -i
curl -fsSL https://get.docker.com | sh && usermod -aG docker <пользователь>
modprobe wireguard && echo wireguard >> /etc/modules

mkdir -p /opt/nodecheck && cd /opt/nodecheck     # распаковать сюда nodecheck.tar.gz
cp .env.example .env && nano .env                # ADMIN_TOKEN, PIN, домены, TTYD_USER
docker-compose up -d --build
docker-compose logs app | grep -E 'ADMIN_TOKEN|PIN'  # если не задавали в .env
```

## 3. Первая настройка (из домашней сети, по IP)

Открой `http://<IP мини-ПК>:8000`, войди admin-токеном → **Настройки**:

1. **Источники нод** — токены Remnawave и Open60 → «Проверить подключение» → «Сохранить».
2. **Туннель** — транспорт `ssh`, `VPS: IP для SSH`, логин `root`, пароль → «Сохранить» → **«Настроить VPS автоматически»**.
   Через 20–60 с обнови страницу: «туннель активен», а «Проверить с VPS» покажет, что VPS видит приложение.
   Туннель перезапускается watchdog'ом каждые 30 с, если упал; лог — на той же странице.
   В режиме `wireguard` та же кнопка ставит WireGuard на VPS и пишет `[Peer]` (работает только там, где провайдер его не режет).
3. **Исходящий VPS** — IP, логин, пароль; тип `ssh` → «Сохранить» → «Проверить» должно показать IP VPS.
4. Открой `https://admin.example.com` — дальше всё оттуда.

## Настройки

| Блок | Что |
|---|---|
| Планировщик | интервалы sync / проверки / очереди, воркеры, попытки, таймауты, срок истории; кнопки «Запустить сейчас» |
| Источники нод | URL и токены Remnawave и Open60, URL пробы |
| Туннель | транспорт ssh / wireguard; автонастройка VPS по SSH; статус, лог, «Проверить с VPS», перезапуск |
| Исходящий VPS | хост/порт/логин/пароль второго VPS; типы: `ssh` (поднимается `ssh -D`, SOCKS), `socks5`, `http`; «Проверить» показывает внешний IP |
| Экспорт статусов | URL + токен бэкендов Remnawave и Open60; после каждой проверки туда уходит JSON (через исходящий VPS, если включён) |
| Доступ | смена admin-токена и PIN, время жизни cookie, URL ttyd |

Все настройки живут в SQLite (`data/nodecheck.db`), меняются без перезапуска, история изменений внизу страницы.

## Цвета

- зелёный — проба через прокси прошла (или, если прокси-порта нет, SSH отвечает)
- жёлтый — SSH отвечает, прокси нет (ТСПУ режет порты / squid лежит)
- красный — не отвечает ничего
- серый — нет результата свежее трёх интервалов проверки

## Экспорт: формат

```json
POST <url>   Authorization: Bearer <token>
{"vantage":"home","ts":1730000000,
 "results":[{"ip":"1.2.3.4","name":"…","state":"green","ssh_ok":true,"ssh_status":"SSH OK",
             "proxy_ok":true,"proxy_status":"PROXY OK 120ms","latency_ms":120,"ts":1730000000}]}
```

## Обновление

```bash
cd /opt/nodecheck && git pull && docker-compose up -d --build
```
Туннель при перезапуске контейнера поднимается сам из `wireguard/wg0.conf`.

## Если туннель не поднимается

```bash
docker-compose exec app wg show
docker-compose exec app ping -c 3 10.8.0.1
docker-compose logs app --tail 50
```
Ручной вариант — положить `wg0.conf` в `./wireguard/` и `docker-compose restart app`.
