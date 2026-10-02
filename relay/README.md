# Hysteria UDP Relay

Минимальный UDP-посредник для схемы:

```text
клиент Hysteria 2 -> relay:443/udp -> основной Hysteria 2:443/udp -> интернет
```

Relay не расшифровывает QUIC и не завершает TLS, поэтому ему не нужны домен и сертификат. Каждый клиентский `IP:port` получает отдельную UDP-сессию к upstream.

Целевая платформа образа — `linux/amd64`; она явно задана и в Compose, и в CI. Локальная сборка на ARM Mac также должна указывать `--platform linux/amd64` и будет запускаться через эмуляцию.

## Запуск на промежуточном сервере

1. Скачайте `compose.yaml` и `.env.example` из каталога `relay/` нужного тега релиза.
2. Скопируйте `.env.example` в `.env` и укажите реальный `домен:порт` основного Hysteria 2:

   ```dotenv
   HYSTERIA_RELAY_UPSTREAM=vpn.example.com:443
   HYSTERIA_RELAY_PORT=443
   HYSTERIA_RELAY_IDLE_TIMEOUT=5m
   ```

3. Откройте на relay-сервере входящий UDP-порт и запустите:

   ```bash
   sudo docker compose config --quiet
   sudo docker compose up -d
   sudo docker compose logs --tail=50 hysteria-relay
   ```

В клиенте замените только адрес и порт сервера на relay. SNI оставьте равным домену основного Hysteria 2, а проверку TLS-сертификата не отключайте.

Для локальной сборки из корня репозитория:

```bash
docker build --platform linux/amd64 -f relay/Dockerfile -t hysteria-relay:local .
```

## Ограничения

- Relay пересылает только внешний UDP/QUIC. TCP-маскарад основного сервера через него недоступен.
- `HYSTERIA_RELAY_IDLE_TIMEOUT` закрывает сессию без пакетов в обе стороны. Для редкого трафика увеличьте его; меньшие значения быстрее освобождают UDP-сокеты.
- Upstream-адрес разрешается при старте. После изменения DNS перезапустите контейнер.
- Relay не скрывает адрес промежуточного сервера от основного: upstream видит его IP как источник UDP-пакетов.
