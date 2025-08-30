#!/bin/bash
#
# Script de instalação Filebeat 7.10.2 OSS
# Compatível com: Ubuntu/Debian amd64
# <erivandosena@gmail.com>
#
# DISTRIBUIÇÕES SUPORTADAS:
# ✓ Ubuntu: 20.04 LTS, 22.04 LTS, 24.04 LTS
# ✓ Debian: 10 (Buster), 11 (Bullseye), 12 (Bookworm)
#
# Destino: Stack ELK no cluster K8S
# Data: 30-08-2025
# Versão: 2.0
#
# Uso:
#   cd /root
#   wget -O install-filebeat.sh [URL_DO_SCRIPT]
#   bash install-filebeat.sh
#   # opcional:
#   export INDEX_PREFIX=vm
# ============================== PARÂMETROS ===============================
set -e

# VM monitorada
# VM monitorada
VM_HOSTNAME="$(hostname -s)"
VM_IP="$(hostname -I | awk '{print $1}')"
VM_ROLE="vm_${VM_HOSTNAME%%[0-9]*}"
INDEX_PREFIX="${INDEX_PREFIX:-vm}"
VM_OS="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Ubuntu GNU/Linux}")"
VM_KERNEL="$(uname -r)"

# Cluster K8S - ELK Stack
LOGSTASH_HOST="${LOGSTASH_HOST:-10.130.1.115}"
LOGSTASH_PORT="${LOGSTASH_PORT:-5044}"
ELASTICSEARCH_HOST="${ELASTICSEARCH_HOST:-10.130.1.114}"
ELASTICSEARCH_PORT="${ELASTICSEARCH_PORT:-9200}"

# Ambiente e Datacenter
ENVIRONMENT="${ENVIRONMENT:-production}"
DATACENTER="${DATACENTER:-observabilidade}"
CLUSTER_NAME="${CLUSTER_NAME:-external}"

# Filebeat
FILEBEAT_VERSION="7.10.2"
FILEBEAT_HTTP_HOST="${FILEBEAT_HTTP_HOST:-0.0.0.0}"
FILEBEAT_HTTP_PORT="${FILEBEAT_HTTP_PORT:-5066}"

# Performance
BULK_MAX_SIZE="${BULK_MAX_SIZE:-2048}"
WORKER_COUNT="${WORKER_COUNT:-2}"
COMPRESSION_LEVEL="${COMPRESSION_LEVEL:-3}"
CONNECTION_TIMEOUT="${CONNECTION_TIMEOUT:-30s}"
QUEUE_EVENTS="${QUEUE_EVENTS:-4096}"
QUEUE_FLUSH_MIN="${QUEUE_FLUSH_MIN:-512}"
QUEUE_FLUSH_TIMEOUT="${QUEUE_FLUSH_TIMEOUT:-5s}"

# Log
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-7}"
LOG_MAX_SIZE_MB="${LOG_MAX_SIZE_MB:-10}"
IGNORE_OLDER_HOURS="${IGNORE_OLDER_HOURS:-48h}"
DOCKER_IGNORE_OLDER_HOURS="${DOCKER_IGNORE_OLDER_HOURS:-24h}"

# Monitoring (X-Pack) opcional — para stack 100% OSS, deixe como false
ENABLE_XPACK_MONITORING="${ENABLE_XPACK_MONITORING:-false}"

# Desabilitar prompts interativos
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1
export UCF_FORCE_CONFFOLD=1
export UCF_FORCE_CONFFNEW=1

echo 'libc6 libraries/restart-without-asking boolean true' | debconf-set-selections >/dev/null 2>&1 || true
echo 'filebeat filebeat/restart-services boolean true' | debconf-set-selections >/dev/null 2>&1 || true

echo "=== Instalação do Filebeat $FILEBEAT_VERSION ==="
echo "VM: $(hostname) - $(uname -a)"
echo "Data: $(date)"
echo

# Root?
if [[ $EUID -ne 0 ]]; then
  echo "Este script deve ser executado como root"; exit 1
fi

# Detectar distro
DISTRIB_ID=""; DISTRIB_VERSION=""
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  DISTRIB_ID="$ID"
  DISTRIB_VERSION="$VERSION_ID"
fi
echo "Distribuição detectada: $DISTRIB_ID $DISTRIB_VERSION"

# ============================== CONECTIVIDADE ===============================
echo "Verificando conectividade com Logstash..."
if timeout 5 bash -c "</dev/tcp/$LOGSTASH_HOST/$LOGSTASH_PORT" 2>/dev/null; then
  echo "Logstash OK ($LOGSTASH_HOST:$LOGSTASH_PORT)"
else
  echo "Aviso: Sem conexão ao Logstash ($LOGSTASH_HOST:$LOGSTASH_PORT)"
fi

echo "Verificando conectividade com Elasticsearch..."
if timeout 5 bash -c "</dev/tcp/$ELASTICSEARCH_HOST/$ELASTICSEARCH_PORT" 2>/dev/null; then
  echo "Elasticsearch OK ($ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT)"
else
  echo "Aviso: Sem conexão ao Elasticsearch ($ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT)"
fi
echo

# ============================== ESTADO ATUAL ===============================
FILEBEAT_INSTALLED=false
FILEBEAT_VERSION_OK=false
FILEBEAT_SERVICE_OK=false

if command -v filebeat >/dev/null 2>&1; then
  FILEBEAT_INSTALLED=true
  CURRENT_VERSION="$(dpkg-query -W -f='${Version}' filebeat 2>/dev/null | cut -d- -f1 || echo "unknown")"
  if [[ "$CURRENT_VERSION" == "$FILEBEAT_VERSION" ]]; then
    FILEBEAT_VERSION_OK=true
    echo "Filebeat $FILEBEAT_VERSION já está instalado"
  else
    echo "Filebeat instalado mas versão incorreta: $CURRENT_VERSION (esperado: $FILEBEAT_VERSION)"
  fi
else
  echo "Filebeat não está instalado"
fi

if systemctl is-active --quiet filebeat 2>/dev/null; then
  FILEBEAT_SERVICE_OK=true
  echo "Serviço Filebeat está ativo"
else
  echo "Serviço Filebeat não está ativo"
fi

# ============================== APT & DEPENDÊNCIAS ===============================
UPDATE_NEEDED=true
if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
  if [[ $(find /var/lib/apt/periodic/update-success-stamp -mmin -360 2>/dev/null) ]]; then
    UPDATE_NEEDED=false
    echo "Sistema atualizado recentemente, pulando apt update"
  fi
fi
apt_update_main_or_warn() {
  if [[ "$UPDATE_NEEDED" != "true" ]]; then return 0; fi
  echo "Atualizando índices APT (main only)..."
  if ! apt-get update -q \
       -o Dir::Etc::sourcelist=/etc/apt/sources.list \
       -o Dir::Etc::sourceparts=/dev/null \
       -o APT::Get::List-Cleanup=0; then
    echo "Aviso: 'apt-get update' (main) falhou; prosseguindo com índices existentes."
  fi
}
apt_update_main_or_warn

echo "Verificando dependências..."
MISSING_PACKAGES=()
REQUIRED_PACKAGES=(wget curl gnupg ca-certificates lsb-release acl)

# apt-transport-https para distros antigas
if [[ "$DISTRIB_ID" == "ubuntu" ]]; then
  if dpkg --compare-versions "$DISTRIB_VERSION" lt "22.04"; then
    REQUIRED_PACKAGES+=(apt-transport-https)
  fi
elif [[ "$DISTRIB_ID" == "debian" ]]; then
  if dpkg --compare-versions "$DISTRIB_VERSION" lt "12"; then
    REQUIRED_PACKAGES+=(apt-transport-https)
  fi
fi

# netcat (nome varia)
if ! command -v nc >/dev/null 2>&1; then
  if [[ "$DISTRIB_ID" == "debian" ]]; then
    REQUIRED_PACKAGES+=(netcat-openbsd)
  else
    REQUIRED_PACKAGES+=(netcat)
  fi
fi

for pkg in "${REQUIRED_PACKAGES[@]}"; do
  dpkg -s "$pkg" >/dev/null 2>&1 || MISSING_PACKAGES+=("$pkg")
done
if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then
  echo "Instalando dependências: ${MISSING_PACKAGES[*]}"
  apt-get install -y "${MISSING_PACKAGES[@]}"
else
  echo "Todas as dependências já estão instaladas"
fi

apt-get install -y iproute2 || true     # fornece 'ss'
command -v netstat >/dev/null || apt-get install -y net-tools || true  # fornece 'netstat'

# ============================== REPO ELASTIC 7.x ===============================
REPO_CONFIGURED=false
if [[ -f /usr/share/keyrings/elastic-keyring.gpg ]] && [[ -f /etc/apt/sources.list.d/elastic-7.x.list ]]; then
  if grep -q "artifacts.elastic.co/packages/7.x/apt" /etc/apt/sources.list.d/elastic-7.x.list; then
    REPO_CONFIGURED=true
    echo "Repositório Elastic 7.x já configurado"
  fi
fi

if [[ "$REPO_CONFIGURED" == "false" ]]; then
  echo "Configurando repositório Elastic 7.x..."
  mkdir -p /usr/share/keyrings
  if ! wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor --batch --yes -o /usr/share/keyrings/elastic-keyring.gpg; then
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor --batch --yes -o /usr/share/keyrings/elastic-keyring.gpg
  fi
  [[ -f /usr/share/keyrings/elastic-keyring.gpg ]] || { echo "Erro: GPG do Elastic não importada"; exit 1; }
  echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" > /etc/apt/sources.list.d/elastic-7.x.list
  apt-get update -q \
    -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/elastic-7.x.list \
    -o Dir::Etc::sourceparts=/dev/null \
    -o APT::Get::List-Cleanup=0
  echo "Repositório Elastic 7.x configurado"
fi

# ============================== INSTALAÇÃO DO FILEBEAT ===============================
if [[ "$FILEBEAT_VERSION_OK" == "false" ]]; then
  if [[ "$FILEBEAT_INSTALLED" == "true" ]]; then
    echo "Removendo versão incorreta do Filebeat..."
    systemctl is-active --quiet filebeat && systemctl stop filebeat || true
    systemctl is-enabled --quiet filebeat 2>/dev/null && systemctl disable filebeat || true
    [[ -f /etc/filebeat/filebeat.yml ]] && cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.backup.$(date +%Y%m%d_%H%M%S)
    apt-get remove --purge -y filebeat
    apt-get autoremove -y
    rm -rf /etc/filebeat /var/lib/filebeat
  fi

  echo "Instalando Filebeat $FILEBEAT_VERSION..."
  apt-get install -y "filebeat=${FILEBEAT_VERSION}*"
  command -v filebeat >/dev/null 2>&1 || { echo "Erro: Falha na instalação do Filebeat"; exit 1; }
  apt-mark hold filebeat
  echo "Filebeat $FILEBEAT_VERSION instalado"
fi

# ============================== USUÁRIO / PERMISSÕES ===============================
if [[ ! -d /var/log/filebeat ]]; then
  mkdir -p /var/log/filebeat && chown root:root /var/log/filebeat && chmod 755 /var/log/filebeat
fi

if ! id -u filebeat >/dev/null 2>&1; then
  echo "Criando usuário filebeat..."
  useradd --system --home /usr/share/filebeat --shell /bin/false filebeat
else
  echo "Usuário filebeat já existe"
fi

PERMISSIONS_UPDATED=false
groups filebeat | grep -q '\badm\b' || { usermod -aG adm filebeat; PERMISSIONS_UPDATED=true; }
if getent group docker >/dev/null 2>&1; then
  groups filebeat | grep -q '\bdocker\b' || { usermod -aG docker filebeat; PERMISSIONS_UPDATED=true; }
fi

ACL_NEEDS_UPDATE=false
getfacl /var/log 2>/dev/null | grep -q "user:filebeat:r-x" || ACL_NEEDS_UPDATE=true
if [[ "$PERMISSIONS_UPDATED" == "true" || "$ACL_NEEDS_UPDATE" == "true" ]]; then
  echo "Configurando ACLs..."
  setfacl -R -m u:filebeat:rx /var/log 2>/dev/null || true
  setfacl -R -d -m u:filebeat:rx /var/log 2>/dev/null || true
  if [[ -d /var/lib/docker/containers ]]; then
    setfacl -R -m u:filebeat:rx /var/lib/docker/containers/ 2>/dev/null || true
    setfacl -R -d -m u:filebeat:rx /var/lib/docker/containers/ 2>/dev/null || true
  fi
  for f in /var/log/syslog /var/log/auth.log /var/log/kern.log /var/log/daemon.log; do
    [[ -e "$f" ]] && setfacl -m u:filebeat:r "$f" 2>/dev/null || true
  done
else
  echo "Permissões já estão corretas"
fi

# ============================== DETECÇÃO DE SERVIÇOS ===============================
DOCKER_EXISTS=false
systemctl list-unit-files 2>/dev/null | grep -q docker.service && { DOCKER_EXISTS=true; echo "Docker detectado"; } || echo "Docker não encontrado"

CONTAINERD_EXISTS=false
systemctl list-unit-files 2>/dev/null | grep -q containerd.service && { CONTAINERD_EXISTS=true; echo "containerd detectado"; } || echo "containerd não encontrado"

# ============================== CONFIGURAÇÃO FILEBEAT ===============================
CONFIG_NEEDS_UPDATE=false
if [[ ! -f /etc/filebeat/filebeat.yml ]]; then
  CONFIG_NEEDS_UPDATE=true
  echo "Arquivo de configuração não existe"
else
  EXPECTED_LOGSTASH="$LOGSTASH_HOST:$LOGSTASH_PORT"
  EXPECTED_INDEX="$INDEX_PREFIX-system-logs"
  if ! grep -q "$EXPECTED_LOGSTASH" /etc/filebeat/filebeat.yml 2>/dev/null \
     || ! grep -q "$EXPECTED_INDEX" /etc/filebeat/filebeat.yml 2>/dev/null \
     || ! grep -q "$VM_HOSTNAME" /etc/filebeat/filebeat.yml 2>/dev/null; then
    CONFIG_NEEDS_UPDATE=true
    echo "Configuração precisa ser atualizada"
  else
    echo "Configuração já está correta"
  fi
fi

# Bloco opcional de monitoring X-Pack
MONITORING_SNIPPET=""
if [[ "$ENABLE_XPACK_MONITORING" == "true" ]]; then
  MONITORING_SNIPPET=$(cat <<EOFM
# ============================== Monitoramento (X-Pack) ===============================
monitoring.enabled: true
monitoring.elasticsearch:
  hosts: ["${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}"]
EOFM
)
fi

if [[ "$CONFIG_NEEDS_UPDATE" == "true" ]]; then
  echo "Aplicando configuração do Filebeat..."
  if [[ -f /etc/filebeat/filebeat.yml ]]; then
    cp -a /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak.$(date +%F_%H%M%S)
    rm -f /etc/filebeat/filebeat.yml
  fi

  cat > /etc/filebeat/filebeat.yml << EOF
################### Filebeat Configuration for VM #####################
# Arquivo: /etc/filebeat/filebeat.yml
# VM $VM_OS
# Destino: Stack ELK no cluster K8S / Logstash
#######################################################################

# ============================== Inputs ===============================
filebeat.inputs:
  # --- Logs do sistema Debian/Ubuntu ---
  - type: log
    enabled: true
    paths:
      - /var/log/syslog
      - /var/log/auth.log
      - /var/log/kern.log
      - /var/log/daemon.log
      - /var/log/messages
      - /var/log/dpkg.log
      - /var/log/apt/history.log
    ignore_older: $IGNORE_OLDER_HOURS
    fields:
      index_name: "$INDEX_PREFIX-system-logs"
      source_type: "system_log"
      host_type: "$VM_ROLE"
      environment: "$ENVIRONMENT"
      cluster: "$CLUSTER_NAME"
      service_name: "$VM_HOSTNAME"
    fields_under_root: true
    processors:
      - add_tags:
          tags: ["system", "debian", "${VM_ROLE}"]

  # --- Logs de autenticação SSH ---
  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
    fields:
      index_name: "$INDEX_PREFIX-security-logs"
      source_type: "auth_log"
      log_type: "security"
      host_type: "$VM_ROLE"
      environment: "$ENVIRONMENT"
      cluster: "$CLUSTER_NAME"
      service_name: "$VM_HOSTNAME"
    fields_under_root: true
    processors:
      - add_tags:
          tags: ["security", "auth", "ssh"]
      - add_tags:
          tags: ["ssh_success"]
          when:
            contains:
              message: "Accepted"
      - add_tags:
          tags: ["ssh_failed", "security_alert"]
          when:
            contains:
              message: "Failed"

  # --- Logs do NFS Server ---
  - type: log
    enabled: true
    paths:
      - /var/log/nfs*
      - /var/log/rpc*
    ignore_older: $IGNORE_OLDER_HOURS
    fields:
      index_name: "$INDEX_PREFIX-service-logs"
      source_type: "nfs_log"
      log_type: "service"
      host_type: "$VM_ROLE"
      environment: "$ENVIRONMENT"
      cluster: "$CLUSTER_NAME"
      service_name: "${VM_ROLE}"
    fields_under_root: true
    processors:
      - add_tags:
          tags: ["nfs", "storage", "service"]

  # --- Logs de containers Docker ---
  - type: log
    enabled: ${DOCKER_EXISTS}
    paths:
      - /var/lib/docker/containers/*/*-json.log
    exclude_files: ['\\.gz$']
    json.keys_under_root: true
    json.add_error_key: true
    json.message_key: log
    ignore_older: $DOCKER_IGNORE_OLDER_HOURS
    fields:
      index_name: "$INDEX_PREFIX-docker-logs"
      source_type: "docker"
      log_type: "container"
      host_type: "$VM_ROLE"
      environment: "$ENVIRONMENT"
      cluster: "$CLUSTER_NAME"
    fields_under_root: true
    processors:
      - add_docker_metadata:
          host: "unix:///var/run/docker.sock"
      - add_tags:
          tags: ["docker", "container"]

  # --- Logs do containerd ---
  - type: log
    enabled: ${CONTAINERD_EXISTS}
    paths:
      - /var/log/containers/*.log
      - /var/log/containerd/*.log
    symlinks: true
    exclude_files: ['\\.gz$']
    ignore_older: $DOCKER_IGNORE_OLDER_HOURS
    fields:
      index_name: "$INDEX_PREFIX-containerd-logs"
      source_type: "containerd"
      log_type: "container"
      host_type: "$VM_ROLE"
      environment: "$ENVIRONMENT"
      cluster: "$CLUSTER_NAME"
    fields_under_root: true
    processors:
      - add_tags:
          tags: ["containerd", "container"]

  # --- Logs de aplicações específicas (ajuste conforme necessário) ---
  - type: log
    enabled: true
    paths:
      - /var/log/apache2/*.log
      - /var/log/nginx/*.log
    exclude_files: ['\\.gz$']
    ignore_older: $DOCKER_IGNORE_OLDER_HOURS
    fields:
      index_name: "$INDEX_PREFIX-webserver-logs"
      source_type: "webserver"
      log_type: "access"
      host_type: "$VM_ROLE"
      environment: "$ENVIRONMENT"
      cluster: "$CLUSTER_NAME"
    fields_under_root: true
    processors:
      - add_tags:
          tags: ["webserver", "http"]

  # --- Monitoramento de arquivos de configuração críticos ---
  - type: log
    enabled: true
    paths:
      - /etc/exports
      - /etc/fstab
      - /etc/hosts
      - /etc/resolv.conf
    fields:
      index_name: "$INDEX_PREFIX-config-logs"
      source_type: "config_file"
      log_type: "configuration"
      host_type: "$VM_ROLE"
      environment: "$ENVIRONMENT"
      cluster: "$CLUSTER_NAME"
      config_monitoring: true
    fields_under_root: true
    close_inactive: 5m
    scan_frequency: 60s
    processors:
      - add_tags:
          tags: ["config", "monitoring"]

# ============================== Módulos desabilitados ===============================
filebeat.config.modules:
  path: \${path.config}/modules.d/*.yml
  reload.enabled: false

# ============================== Processadores Globais ===============================
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_fields:
      target: ''
      fields:
        vm_hostname: "$VM_HOSTNAME"
        vm_ip: "$VM_IP"
        vm_os: "$VM_OS"
        vm_kernel: "$VM_KERNEL"
        vm_role: "$VM_ROLE"
        datacenter: "$DATACENTER"
        deployment_type: "external_vm"
        monitoring_source: "filebeat"
  - drop_fields:
      fields: ["agent.ephemeral_id", "agent.hostname", "agent.id", "agent.version", "ecs.version"]
      ignore_missing: true

# ============================== Output -> Logstash ===============================
output.logstash:
  hosts: ["$LOGSTASH_HOST:$LOGSTASH_PORT"]
  loadbalance: true
  # bulk_max_size: $BULK_MAX_SIZE
  # worker: $WORKER_COUNT
  # compression_level: $COMPRESSION_LEVEL
  # timeout: $CONNECTION_TIMEOUT
  # ssl:
  #   verification_mode: false
  #   supported_protocols: ["TLSv1.2", "TLSv1.3"]
  bulk_max_size: $BULK_MAX_SIZE
  worker: $WORKER_COUNT
  compression_level: $COMPRESSION_LEVEL
  timeout: $CONNECTION_TIMEOUT

# ============================== Logging do Filebeat ===============================
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: $LOG_RETENTION_DAYS
  permissions: 0644
  rotateeverybytes: $((LOG_MAX_SIZE_MB * 1024 * 1024))

# ============================== Monitoramento / HTTP ===============================
${MONITORING_SNIPPET}

http:
  enabled: true
  host: "${FILEBEAT_HTTP_HOST}"
  port: ${FILEBEAT_HTTP_PORT}

# ============================== Performance ===============================
queue.mem:
  events: $QUEUE_EVENTS
  flush.min_events: $QUEUE_FLUSH_MIN
  flush.timeout: $QUEUE_FLUSH_TIMEOUT
EOF

  echo "Configuração aplicada"
fi

# ============================== VALIDAÇÃO / SERVIÇO ===============================
echo "Validando configuração..."
if ! filebeat test config -c /etc/filebeat/filebeat.yml; then
  echo "Erro na configuração do Filebeat"
  filebeat test config -c /etc/filebeat/filebeat.yml -v
  exit 1
fi
echo "Configuração válida"

echo "Testando conectividade com Logstash..."
if filebeat test output -c /etc/filebeat/filebeat.yml; then
  echo "Conectividade com Logstash OK"
else
  echo "Aviso: Problema na conectividade com Logstash"
fi

SERVICE_NEEDS_RESTART=false
systemctl is-enabled --quiet filebeat 2>/dev/null || { systemctl daemon-reload; systemctl enable filebeat; SERVICE_NEEDS_RESTART=true; }
[[ "$CONFIG_NEEDS_UPDATE" == "true" || "$FILEBEAT_SERVICE_OK" == "false" ]] && SERVICE_NEEDS_RESTART=true
# systemctl daemon-reload
# systemctl enable --now filebeat 2>/dev/null || true

if [[ "$SERVICE_NEEDS_RESTART" == "true" ]]; then
  echo "Reiniciando serviço Filebeat..."
  systemctl is-active --quiet filebeat && systemctl stop filebeat || true
  sleep 2
  pkill -f filebeat >/dev/null 2>&1 || true
  systemctl start filebeat
  echo "Verificando inicialização..."
  for i in {1..10}; do
    sleep 2
    if systemctl is-active --quiet filebeat; then
      echo "Filebeat iniciado (tentativa $i)"; break
    fi
    [[ $i -eq 10 ]] && { echo "ERRO: Filebeat falhou ao iniciar"; journalctl -u filebeat --no-pager --lines=20; exit 1; }
    echo "Tentativa $i: Aguardando inicialização..."
  done
else
  # Verificar status
  sleep 4
  if systemctl is-active --quiet filebeat; then
    echo "✓ Filebeat iniciado"
    systemctl status filebeat --no-pager --lines=5
    echo "Serviço já está rodando corretamente"
  fi
fi

# ============================== MONITOR SCRIPT / CRON ===============================
MONITOR_SCRIPT="/usr/local/bin/check-filebeat.sh"
if [[ ! -f "$MONITOR_SCRIPT" ]] || ! grep -q "filebeat test" "$MONITOR_SCRIPT" 2>/dev/null; then
  echo "Criando script de monitoramento..."
  cat > "$MONITOR_SCRIPT" << 'EOF'
#!/bin/bash
echo "=== Status do Filebeat ==="
systemctl status filebeat --no-pager --lines=3
echo
echo "=== Últimas 10 linhas do log ==="
tail -10 /var/log/filebeat/filebeat 2>/dev/null || echo "Log não encontrado"
echo
echo "=== Teste de configuração ==="
filebeat test config -c /etc/filebeat/filebeat.yml
echo
echo "=== Teste de conectividade ==="
filebeat test output -c /etc/filebeat/filebeat.yml
EOF
  chmod +x "$MONITOR_SCRIPT"
  echo "Script de monitoramento criado"
fi

if ! crontab -l 2>/dev/null | grep -q "/usr/local/bin/check-filebeat.sh"; then
  echo "Configurando monitoramento automático. [AGUARDE...]"
  ( crontab -l 2>/dev/null || true; \
    echo "*/5 * * * * /usr/local/bin/check-filebeat.sh >/dev/null 2>&1" \
  ) | crontab - || echo "Aviso: falha ao aplicar crontab (prosseguindo)"
  echo "Crontab configurado"
fi

# ============================== VERIFICAÇÃO FINAL ===============================
HTTP_OK=false
if ss -lntp 2>/dev/null | grep -q ":${FILEBEAT_HTTP_PORT}" || netstat -lntp 2>/dev/null | grep -q ":${FILEBEAT_HTTP_PORT}"; then
  HTTP_OK=true
  echo "Endpoint HTTP disponível em http://${VM_IP}:${FILEBEAT_HTTP_PORT}/"
else
  echo "Aviso: Endpoint HTTP não respondeu na porta ${FILEBEAT_HTTP_PORT}"
fi

echo "Executando verificação final de saúde..."
sleep 3
FINAL_STATUS="SUCCESS"
systemctl is-active --quiet filebeat || FINAL_STATUS="ERROR"
filebeat test config -c /etc/filebeat/filebeat.yml >/dev/null 2>&1 || [[ "$FINAL_STATUS" == "ERROR" ]] || FINAL_STATUS="WARNING"

echo
echo "======================================================="
case $FINAL_STATUS in
  SUCCESS) echo "=== INSTALAÇÃO CONCLUÍDA ===" ;;
  WARNING) echo "=== INSTALAÇÃO CONCLUÍDA COM AVISOS ===" ;;
  ERROR)   echo "=== INSTALAÇÃO FALHOU ===" ;;
esac
echo "======================================================="

echo "Filebeat $FILEBEAT_VERSION - Status: $FINAL_STATUS"
echo
echo "Resumo da execução:"
echo "  - Instalação realizada: $([ "$FILEBEAT_VERSION_OK" == "false" ] && echo "SIM" || echo "NÃO")"
echo "  - Configuração atualizada: $([ "$CONFIG_NEEDS_UPDATE" == "true" ] && echo "SIM" || echo "NÃO")"
echo "  - Serviço reiniciado: $([ "$SERVICE_NEEDS_RESTART" == "true" ] && echo "SIM" || echo "NÃO")"
echo "  - Distribuição: $DISTRIB_ID $DISTRIB_VERSION"
echo
echo "Parâmetros:"
echo "  - VM: $VM_HOSTNAME ($VM_IP) — Função: $VM_ROLE"
echo "  - Logstash: $LOGSTASH_HOST:$LOGSTASH_PORT"
echo "  - Elasticsearch: $ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT"
echo "  - Ambiente: $ENVIRONMENT / $DATACENTER"
echo "  - Docker: $([ "$DOCKER_EXISTS" == "true" ] && echo "HABILITADO" || echo "DESABILITADO")"
echo "  - Containerd: $([ "$CONTAINERD_EXISTS" == "true" ] && echo "HABILITADO" || echo "DESABILITADO")"
echo
echo "Comandos úteis:"
echo "  - Status: systemctl status filebeat"
echo "  - Logs: tail -f /var/log/filebeat/filebeat"
echo "  - Restart: systemctl restart filebeat"
echo "  - Monitor: /usr/local/bin/check-filebeat.sh"
echo "  - Métricas: http://$VM_IP:$FILEBEAT_HTTP_PORT/stats"
echo
case $FINAL_STATUS in
  SUCCESS) echo "✓ Pronto. Script idempotente executado (IBS).";;
  WARNING) echo "[!] Concluído com avisos — verifique: journalctl -u filebeat -f";;
  ERROR)   echo "✗ Erro — verifique: journalctl -u filebeat --no-pager ; filebeat test config ; filebeat test output"; exit 1;;
esac
