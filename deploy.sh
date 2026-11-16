#!/usr/bin/env bash
# Установка и обновление бота на сервере.
#
#   curl -fsSL https://raw.githubusercontent.com/AxellorWave/amnezia-control/master/deploy.sh -o deploy.sh
#   sudo bash deploy.sh                # установка (спросит данные для .env)
#   sudo bash deploy.sh --update       # обновление без вопросов
#   sudo bash deploy.sh --reconfigure  # заново заполнить .env
#   sudo bash deploy.sh --uninstall    # удалить контейнер бота (VPN не трогается)
#
# Без вопросов: NONINTERACTIVE=1 BOT_TOKEN=... ADMIN_IDS=... VPN_HOST=... bash deploy.sh
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/amnezia-bot}"
REPO_URL="${REPO_URL:-https://github.com/AxellorWave/amnezia-control.git}"
BRANCH="${BRANCH:-master}"
NONINTERACTIVE="${NONINTERACTIVE:-0}"
BOT_CONTAINER="amnezia-bot"

# переменные, которые спрашиваем, и их значения по умолчанию
ASK_VARS=(BOT_TOKEN ADMIN_IDS VPN_HOST SERVER_NAME MAX_DEVICES CUSTOM_EMOJI SUB_PORT
          HWID_REQUIRED BACKUP_EVERY_DAYS BACKUP_KEEP)
declare -A DEFAULTS=([SERVER_NAME]=vpn [MAX_DEVICES]=5 [CUSTOM_EMOJI]=1 [SUB_PORT]=2096
                     [HWID_REQUIRED]=0 [BACKUP_EVERY_DAYS]=0 [BACKUP_KEEP]=7)
declare -A VALUES=()

# ================================================================ вывод ===
if [[ -t 1 ]]; then
  C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[34m'; C_C=$'\e[36m'; C_0=$'\e[0m'; C_BOLD=$'\e[1m'
else
  C_R=; C_G=; C_Y=; C_B=; C_C=; C_0=; C_BOLD=
fi
step()  { printf '\n%s==>%s %s%s%s\n' "$C_B" "$C_0" "$C_BOLD" "$*" "$C_0"; }
info()  { printf '   %s\n' "$*"; }
ok()    { printf '   %s✔%s %s\n' "$C_G" "$C_0" "$*"; }
warn()  { printf '   %s!%s %s\n' "$C_Y" "$C_0" "$*" >&2; }
die()   { printf '%s✘ %s%s\n' "$C_R" "$*" "$C_0" >&2; exit 1; }

usage() {
  cat <<EOF
Установка бота в ${INSTALL_DIR}.

  bash deploy.sh                установить или обновить (при первой установке спросит данные)
  bash deploy.sh --update       обновить код и пересобрать без вопросов
  bash deploy.sh --reconfigure  заново заполнить .env (текущие значения — по умолчанию)
  bash deploy.sh --uninstall    остановить и удалить контейнер бота (VPN-контейнеры не трогаются)
  bash deploy.sh -h             эта справка

Переменные: INSTALL_DIR, REPO_URL, BRANCH, NONINTERACTIVE=1 (+ BOT_TOKEN, ADMIN_IDS, VPN_HOST, ...).
EOF
}

# =============================================================== ввод ===
TTY=/dev/tty
have_tty() { [[ "$NONINTERACTIVE" != 1 ]] && { : <"$TTY"; } 2>/dev/null; }

# ask "Вопрос" default -> ответ в REPLY
ask() {
  local q="$1" def="${2:-}" ans
  if ! have_tty; then REPLY="$def"; return; fi
  if [[ -n "$def" ]]; then printf '   %s?%s %s [%s]: ' "$C_C" "$C_0" "$q" "$def" >"$TTY"
  else printf '   %s?%s %s: ' "$C_C" "$C_0" "$q" >"$TTY"; fi
  IFS= read -r ans <"$TTY" || ans=""
  REPLY="${ans:-$def}"
}

ask_secret() {
  local q="$1" def="${2:-}" ans shown=""
  if ! have_tty; then REPLY="$def"; return; fi
  [[ -n "$def" ]] && shown=" [оставить текущий: Enter]"
  printf '   %s?%s %s%s: ' "$C_C" "$C_0" "$q" "$shown" >"$TTY"
  IFS= read -rs ans <"$TTY" || ans=""
  printf '\n' >"$TTY"
  REPLY="${ans:-$def}"
}

# yes_no "Вопрос" y|n
yes_no() {
  local def="$2" hint
  [[ "$def" == y ]] && hint="Д/н" || hint="д/Н"
  if ! have_tty; then [[ "$def" == y ]]; return; fi
  while true; do
    printf '   %s?%s %s [%s]: ' "$C_C" "$C_0" "$1" "$hint" >"$TTY"
    local a; IFS= read -r a <"$TTY" || a=""
    a="${a,,}"; [[ -z "$a" ]] && a="$def"
    case "$a" in y|yes|д|да) return 0 ;; n|no|н|нет) return 1 ;; esac
  done
}

# ========================================================== валидация ===
valid_token()   { [[ "$1" =~ ^[0-9]{5,}:[A-Za-z0-9_-]{30,}$ ]]; }
valid_admins()  { [[ "$1" =~ ^[0-9]+(,[0-9]+)*$ ]]; }
valid_int()     { [[ "$1" =~ ^[0-9]+$ ]]; }
valid_bool()    { [[ "$1" == 0 || "$1" == 1 ]]; }
valid_port()    { valid_int "$1" && (( $1 >= 1 && $1 <= 65535 )); }
valid_days()    { [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]]; }
is_ip()         { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
valid_host()    { is_ip "$1" || [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]]; }
valid_name()    { [[ -n "$1" && "$1" != *$'\n'* && ${#1} -le 40 ]]; }

validate() {   # validate VAR value
  case "$1" in
    BOT_TOKEN) valid_token "$2" ;;
    ADMIN_IDS) valid_admins "$2" ;;
    VPN_HOST) valid_host "$2" ;;
    SERVER_NAME) valid_name "$2" ;;
    MAX_DEVICES|BACKUP_KEEP) valid_int "$2" ;;
    CUSTOM_EMOJI|HWID_REQUIRED) valid_bool "$2" ;;
    SUB_PORT) valid_port "$2" ;;
    BACKUP_EVERY_DAYS) valid_days "$2" ;;
    *) return 0 ;;
  esac
}

# ============================================================ .env ===
env_get() {   # env_get FILE VAR
  [[ -f "$1" ]] || return 0
  sed -n "s/^[[:space:]]*$2=//p" "$1" | tail -n1
}

# Записать .env на основе .env.example: комментарии сохраняются, значения подставляются,
# закомментированные строки "# VAR=..." раскомментируются, если значение задано.
write_env() {   # write_env EXAMPLE OUT
  local example="$1" out="$2" tmp line var seen=" "
  tmp="$(mktemp)"
  if [[ -f "$example" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      if [[ "$line" =~ ^[[:space:]]*#?[[:space:]]*([A-Z][A-Z0-9_]*)= ]]; then
        var="${BASH_REMATCH[1]}"
        if [[ -n "${VALUES[$var]+x}" && "$seen" != *" $var "* ]]; then
          printf '%s=%s\n' "$var" "${VALUES[$var]}" >>"$tmp"
          seen+="$var "
          continue
        fi
      fi
      printf '%s\n' "$line" >>"$tmp"
    done <"$example"
  fi
  for var in "${!VALUES[@]}"; do
    [[ "$seen" == *" $var "* ]] || printf '%s=%s\n' "$var" "${VALUES[$var]}" >>"$tmp"
  done
  install -m 600 "$tmp" "$out"
  rm -f "$tmp"
}

# =========================================================== сеть ===
public_ip() {
  local ip
  for u in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
    ip="$(curl -fsS -4 --max-time 6 "$u" 2>/dev/null | tr -d '[:space:]' || true)"
    is_ip "$ip" && { printf '%s' "$ip"; return; }
  done
}

check_token() {   # печатает username бота или пусто
  curl -fsS --max-time 10 "https://api.telegram.org/bot$1/getMe" 2>/dev/null \
    | sed -n 's/.*"username":"\([^"]*\)".*/\1/p'
}

check_domain() {   # check_domain HOST SERVER_IP
  local host="$1" sip="$2" resolved
  is_ip "$host" && return 0
  command -v dig >/dev/null || return 0
  resolved="$(dig +short A "$host" @8.8.8.8 2>/dev/null | grep -E '^[0-9.]+$' | tr '\n' ' ' || true)"
  if [[ -z "$resolved" ]]; then
    warn "Домен $host пока не резолвится (dig @8.8.8.8). Создайте A-запись на ${sip:-IP сервера}."
  elif [[ -n "$sip" && " $resolved" != *" $sip "* ]]; then
    warn "A-запись $host → ${resolved% } , а IP сервера — $sip. Проверьте DNS."
  else
    ok "Домен $host → ${resolved% }"
  fi
}

# ======================================================== система ===
need_root() {
  if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null || die "Запустите от root."
    [[ -f "$0" ]] || die "Запустите от root: sudo bash deploy.sh"
    exec sudo -E bash "$0" "$@"
  fi
}

detect_os() {
  [[ -f /etc/os-release ]] && . /etc/os-release
  case "${ID:-}${ID_LIKE:-}" in
    *debian*|*ubuntu*) ok "Система: ${PRETTY_NAME:-$ID}" ;;
    *) warn "Система ${PRETTY_NAME:-неизвестна} не проверялась — продолжаю как для Debian/Ubuntu." ;;
  esac
}

apt_install() {
  command -v apt-get >/dev/null || die "Нет apt-get — установите вручную: $*"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null
}

install_packages() {
  local missing=()
  command -v git >/dev/null || missing+=(git)
  command -v curl >/dev/null || missing+=(curl)
  command -v dig >/dev/null || missing+=(dnsutils)
  command -v ss >/dev/null || missing+=(iproute2)
  if ((${#missing[@]})); then
    info "Ставлю: ${missing[*]}"
    apt_install "${missing[@]}"
  fi
  ok "git, curl, dig на месте"
}

amnezia_present() {
  command -v docker >/dev/null && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^amnezia-'
}

install_docker() {
  if command -v docker >/dev/null; then
    ok "Docker уже установлен: $(docker --version 2>/dev/null)"
    amnezia_present && info "Найдены контейнеры Amnezia — Docker не переустанавливаю и не обновляю."
  else
    info "Docker не найден — ставлю официальным скриптом get.docker.com"
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker >/dev/null 2>&1 || true
    ok "Docker установлен"
  fi
  if ! docker compose version >/dev/null 2>&1; then
    info "Ставлю плагин docker compose"
    apt_install docker-compose-plugin 2>/dev/null || apt_install docker-compose-v2 \
      || die "Не удалось поставить docker compose: https://docs.docker.com/compose/install/linux/"
  fi
  ok "$(docker compose version)"
}

fetch_repo() {
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Обновляю код в $INSTALL_DIR"
    git -C "$INSTALL_DIR" fetch -q origin "$BRANCH"
    git -C "$INSTALL_DIR" checkout -q "$BRANCH"
    git -C "$INSTALL_DIR" pull -q --ff-only origin "$BRANCH" \
      || warn "git pull не прошёл (локальные изменения?) — продолжаю с текущим кодом"
  elif [[ -e "$INSTALL_DIR" && -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]]; then
    die "$INSTALL_DIR уже существует и это не git-репозиторий. Укажите другой INSTALL_DIR."
  else
    info "Клонирую $REPO_URL → $INSTALL_DIR"
    git clone -q -b "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
  fi
  mkdir -p "$INSTALL_DIR/data"
  ok "Код: $(git -C "$INSTALL_DIR" log -1 --format='%h %s')"
}

# ======================================================= настройка ===
# Значение переменной: окружение > текущий .env > значение по умолчанию.
initial_value() {   # initial_value VAR ENVFILE
  local v="${!1:-}"
  [[ -z "$v" ]] && v="$(env_get "$2" "$1")"
  [[ -z "$v" ]] && v="${DEFAULTS[$1]:-}"
  printf '%s' "$v"
}

prompt_var() {   # prompt_var VAR "Вопрос" default [secret]
  local var="$1" q="$2" def="$3" secret="${4:-}"
  while true; do
    if [[ -n "$secret" ]]; then ask_secret "$q" "$def"; else ask "$q" "$def"; fi
    if validate "$var" "$REPLY"; then VALUES[$var]="$REPLY"; return; fi
    have_tty || die "$var: неверное или пустое значение «$REPLY»"
    warn "Неверное значение, попробуйте ещё раз."
  done
}

configure() {
  local envf="$INSTALL_DIR/.env" sip uname
  step "Настройка .env"
  sip="$(public_ip || true)"
  [[ -n "$sip" ]] && info "Внешний IP сервера: $sip"

  info "Токен бота — у @BotFather (/newbot)."
  prompt_var BOT_TOKEN "BOT_TOKEN" "$(initial_value BOT_TOKEN "$envf")" secret
  uname="$(check_token "${VALUES[BOT_TOKEN]}" || true)"
  if [[ -n "$uname" ]]; then ok "Бот: @$uname"; BOT_USERNAME="$uname"
  else warn "Не удалось проверить токен через api.telegram.org (нет связи или неверный токен)."; fi

  info "Ваш Telegram ID — у @userinfobot. Несколько админов — через запятую."
  prompt_var ADMIN_IDS "ADMIN_IDS" "$(initial_value ADMIN_IDS "$envf")"

  info "Адрес сервера. Лучше домен (A-запись на IP сервера): при смене IP достаточно поменять DNS."
  local host_def; host_def="$(initial_value VPN_HOST "$envf")"; host_def="${host_def:-$sip}"
  prompt_var VPN_HOST "VPN_HOST (домен или IP)" "$host_def"
  if is_ip "${VALUES[VPN_HOST]}"; then
    warn "Указан IP: после смены IP конфиги придётся выдавать заново, Hysteria2 — только с самоподписанным сертификатом."
  else
    check_domain "${VALUES[VPN_HOST]}" "$sip"
  fi

  prompt_var SERVER_NAME "Имя сервера в приложениях" "$(initial_value SERVER_NAME "$envf")"
  prompt_var MAX_DEVICES "Лимит устройств на человека" "$(initial_value MAX_DEVICES "$envf")"
  info "Кастомные эмодзи работают, только если у владельца бота есть Telegram Premium (иначе бот сам переключится на обычные)."
  prompt_var CUSTOM_EMOJI "Кастомные эмодзи (1 — да, 0 — нет)" "$(initial_value CUSTOM_EMOJI "$envf")"
  prompt_var SUB_PORT "Порт сервера подписок (TCP)" "$(initial_value SUB_PORT "$envf")"
  prompt_var HWID_REQUIRED "Отдавать подписку только клиентам с HWID (1/0)" "$(initial_value HWID_REQUIRED "$envf")"
  prompt_var BACKUP_EVERY_DAYS "Полная копия админам раз в N дней (0 — выкл.)" "$(initial_value BACKUP_EVERY_DAYS "$envf")"
  prompt_var BACKUP_KEEP "Сколько копий хранить" "$(initial_value BACKUP_KEEP "$envf")"

  # прочие значения из текущего .env не теряем
  if [[ -f "$envf" ]]; then
    local line var
    while IFS= read -r line; do
      [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || continue
      var="${BASH_REMATCH[1]}"
      [[ -n "${VALUES[$var]+x}" ]] || VALUES[$var]="${BASH_REMATCH[2]}"
    done <"$envf"
    cp -p "$envf" "$envf.bak"
    info "Старый .env сохранён в .env.bak"
  fi
  write_env "$INSTALL_DIR/.env.example" "$envf"
  ok ".env записан (права 600)"
}

# ========================================================== порты ===
check_ports() {
  step "Порты"
  command -v ss >/dev/null || { warn "ss не найден — проверка портов пропущена"; return; }
  local busy p
  for p in 80/tcp 443/tcp 443/udp "${VALUES[SUB_PORT]:-2096}/tcp"; do
    local port="${p%/*}" proto="${p#*/}" flag="-lnt"
    [[ "$proto" == udp ]] && flag="-lnu"
    busy="$(ss "$flag"p "( sport = :$port )" 2>/dev/null | tail -n +2 | head -n1 || true)"
    if [[ -n "$busy" ]]; then
      local who; who="$(sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p' <<<"$busy")"
      case "$p" in
        80/tcp) warn "80/tcp занят (${who:-?}) — Let's Encrypt для Hysteria2/подписок не сможет выпустить сертификат." ;;
        443/tcp) warn "443/tcp занят (${who:-?}) — для VLESS (Xray) придётся выбрать другой порт." ;;
        443/udp) warn "443/udp занят (${who:-?}) — для Hysteria2 придётся выбрать другой порт." ;;
        *) [[ "$who" == python* ]] && ok "$p — уже слушает бот" || warn "$p занят (${who:-?}) — сервер подписок не запустится, смените SUB_PORT." ;;
      esac
    else
      ok "$p свободен"
    fi
  done
}

open_firewall() {
  local port="${VALUES[SUB_PORT]:-2096}"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    if yes_no "Включён ufw. Открыть ${port}/tcp для подписок?" y; then
      ufw allow "${port}/tcp" >/dev/null && ok "ufw: ${port}/tcp открыт"
    fi
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    if yes_no "Включён firewalld. Открыть ${port}/tcp для подписок?" y; then
      firewall-cmd -q --permanent --add-port="${port}/tcp" && firewall-cmd -q --reload \
        && ok "firewalld: ${port}/tcp открыт"
    fi
  else
    info "ufw/firewalld не включены. Не забудьте файрвол в панели хостинга."
  fi
  info "Порты VPN-протоколов бот предложит открыть сам после их установки (раздел «Протоколы»)."
}

# ========================================================= запуск ===
start_bot() {
  step "Сборка и запуск"
  (cd "$INSTALL_DIR" && docker compose up -d --build)
  info "Жду запуска…"
  local i
  for i in $(seq 1 30); do
    sleep 2
    if docker logs "$BOT_CONTAINER" 2>&1 | grep -qE "Start polling|Run polling|Протоколы:"; then break; fi
  done
  if [[ "$(docker inspect -f '{{.State.Running}}' "$BOT_CONTAINER" 2>/dev/null)" == true ]]; then
    ok "Контейнер $BOT_CONTAINER работает"
  else
    warn "Контейнер $BOT_CONTAINER не запущен — смотрите логи ниже"
  fi
  printf '%s--- последние строки лога ---%s\n' "$C_C" "$C_0"
  docker logs --tail 20 "$BOT_CONTAINER" 2>&1 || true
}

summary() {
  local uname="${BOT_USERNAME:-}"
  [[ -z "$uname" ]] && uname="$(check_token "$(env_get "$INSTALL_DIR/.env" BOT_TOKEN)" || true)"
  step "Готово"
  [[ -n "$uname" ]] && info "Откройте бота: ${C_BOLD}https://t.me/${uname}${C_0} и отправьте /start"
  info "Дальше: Админка → «Протоколы» → установить AmneziaWG / VLESS / Hysteria2."
  cat <<EOF

   Логи:        cd $INSTALL_DIR && docker compose logs -f
   Перезапуск:  cd $INSTALL_DIR && docker compose restart
   Обновление:  bash $INSTALL_DIR/deploy.sh --update
   Настройки:   bash $INSTALL_DIR/deploy.sh --reconfigure
   Данные:      $INSTALL_DIR/data (база, конфиги протоколов, резервные копии)
                $INSTALL_DIR/.env (токен — никому не передавайте)
EOF
}

uninstall() {
  step "Удаление бота"
  info "VPN-контейнеры (amnezia-*, vpnbot-*) не трогаются — VPN продолжит работать."
  yes_no "Остановить и удалить контейнер $BOT_CONTAINER?" n || { info "Отменено."; exit 0; }
  if [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
    (cd "$INSTALL_DIR" && docker compose down) || true
  fi
  docker rm -f "$BOT_CONTAINER" >/dev/null 2>&1 || true
  ok "Контейнер бота удалён"
  if [[ -d "$INSTALL_DIR" ]] && yes_no "Удалить и $INSTALL_DIR вместе с данными (база, копии, .env)?" n; then
    if yes_no "Точно? Это необратимо — сначала сохраните data/ и .env" n; then
      rm -rf "$INSTALL_DIR" && ok "$INSTALL_DIR удалён"
    fi
  else
    info "Данные остались в $INSTALL_DIR"
  fi
}

# ============================================================ main ===
main() {
  local mode=install
  case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    --update) mode=update ;;
    --reconfigure) mode=reconfigure ;;
    --uninstall) mode=uninstall ;;
    "") ;;
    *) usage; die "Неизвестный параметр: $1" ;;
  esac
  need_root "$@"

  printf '%s%sУстановка VPN-бота%s\n' "$C_BOLD" "$C_C" "$C_0"
  [[ "$mode" == uninstall ]] && { uninstall; exit 0; }

  step "Система"
  detect_os
  install_packages
  install_docker

  step "Код бота"
  fetch_repo

  local envf="$INSTALL_DIR/.env"
  if [[ "$mode" == update ]]; then
    [[ -f "$envf" ]] || die "Нет $envf — запустите без --update для первичной настройки"
    NONINTERACTIVE=1
  elif [[ "$mode" == reconfigure || ! -f "$envf" ]]; then
    configure
  elif yes_no "Найден .env. Оставить текущие настройки?" y; then
    ok "Настройки не меняю"
  else
    configure
  fi
  for v in "${ASK_VARS[@]}"; do
    [[ -n "${VALUES[$v]+x}" ]] || VALUES[$v]="$(env_get "$envf" "$v")"
  done

  check_ports
  [[ "$mode" == update ]] || open_firewall
  start_bot
  summary
}

if [[ "${DEPLOY_LIB_ONLY:-0}" != 1 ]]; then
  main "$@"
fi
