# Go Auditd Shipper

Простой шиппер аудит-логов Linux (auditd) на языке Go. 
Считывает логи из `/var/log/audit/audit.log`, парсит их и отправляет в формате GELF по UDP или выводит в stdout.

## Возможности

- Чтение логов auditd с поддержкой доконального чтения (tail + offset)
- Сохранение позиции в файле (`offset.state`) для восстановления после перезапуска
- Парсинг сообщений auditd с помощью [`github.com/elastic/go-libaudit`](https://github.com/elastic/go-libaudit)
- Отправка событий в Graylog через GELF (UDP)
- Поддержка батчинга событий по номеру последовательности (`sequence`)

## Поддерживаемые выходы (output)

- `gelf_udp://host:port` — отправка в Graylog через UDP
- (Планируется) `gelf_tcp://host:port`
- Если не указан `--output`, события выводятся в `stdout` в JSON

## Зависимости

- Go 1.19+
- `auditd` должен быть запущен и писать в `/var/log/audit/audit.log`
- Пакеты:
  - `github.com/elastic/go-libaudit/auparse`
  - `github.com/nxadm/tail`
  - `github.com/Graylog2/go-gelf/gelf`

## Сборка

```shell
go build .
```

## Запуск

```shell
# stdout output
./go-audit-shipper --log /var/log/audit/audit.log 
# Gelf over UDP
./go-audit-shipper --log test.log --output gelf_udp://graylog.example.org:12201
# Show all commands
./go-audit-shipper help
```