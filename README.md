# Hysteria WUI

Панель для одного сервера [Hysteria 2](https://v2.hysteria.network/): пользователи и ссылки подключения, правила для сайтов, YAML-настройки. Контейнер сам получает сертификат Let's Encrypt.

## Быстрый запуск на новом сервере

Нужны Linux x86-64, [Docker Engine с Compose](https://docs.docker.com/engine/install/) и домен, A/AAAA-запись которого указывает на сервер. Откройте входящие `80/tcp`, `443/tcp` и `443/udp`. Эти порты должны быть свободны; домен не должен проходить через CDN, который мешает HTTP-01 или UDP/443.

1. Подключитесь к серверу по SSH. Скачайте два файла релиза:

   ```bash
   mkdir -p ~/hysteria-wui && cd ~/hysteria-wui
   curl -fsSLo compose.yaml https://raw.githubusercontent.com/ReanSn0w/hysteria-wui/v1.0.0/compose.yaml
   curl -fsSLo .env https://raw.githubusercontent.com/ReanSn0w/hysteria-wui/v1.0.0/.env.example
   chmod 600 .env
   ```

2. Откройте настройки: `nano .env`. Замените значения после `=` на свои:

   ```dotenv
   HWUI_DOMAIN=vpn.example.com
   HWUI_ACME_EMAIL=admin@example.com
   HWUI_ADMIN_USER=admin
   HWUI_ADMIN_PASSWORD=replace-with-a-long-random-password
   HWUI_PANEL_PATH=/replace-with-a-private-panel-path
   HWUI_DECOY_URL=https://example.com
   ```

   `HWUI_DOMAIN` — ваш домен; `HWUI_ACME_EMAIL` — почта для сертификата; `HWUI_ADMIN_USER` и `HWUI_ADMIN_PASSWORD` — вход в панель. `HWUI_PANEL_PATH` — придуманный вами скрытый путь с начальным `/`. `HWUI_DECOY_URL` — адрес сайта-приманки вида `https://example.com` без пути. Сохраните файл: `Ctrl+O`, Enter, `Ctrl+X`.

3. Создайте каталог данных и запустите контейнер:

   ```bash
   sudo install -d -m 0700 runtime runtime/certs runtime/acme
   sudo docker compose config --quiet
   sudo docker compose up -d
   sudo docker compose logs --tail=50 hysteria-wui
   ```

4. Откройте `https://vpn.example.com/replace-with-a-private-panel-path/login`, подставив свой домен и путь. Войдите с логином и паролем из `.env`, затем добавьте первого пользователя. До этого Hysteria будет остановлена — это нормально.

## Повседневные команды

Выполняйте их из `~/hysteria-wui`:

```bash
sudo docker compose pull && sudo docker compose up -d  # обновить образ
sudo docker compose logs -f hysteria-wui                 # смотреть журнал
```

Данные хранятся в `runtime/` рядом с `compose.yaml`; сохраняйте резервную копию `runtime/`, `.env` и `compose.yaml`. Для изменения переменных в `.env` выполните `sudo docker compose up -d --force-recreate`. Если у вас уже есть установка с Docker volume, не создавайте пустой `runtime/` поверх неё: сначала перенесите данные.

Проект распространяется по [лицензии MIT](LICENSE).
