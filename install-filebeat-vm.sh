#!/bin/bash
#
# Script de instalação Filebeat 7.10.2 versão OSS
# Compatível com: Ubuntu/Debian amd64
# Destino: Stack ELK no cluster K8S
# Data: 20-08-2025
# Versão: 1.0
#
# Como usar:
# cd /root
# wget -O install-filebeat-vm.sh [URL_DO_SCRIPT]
# chmod +x install-filebeat-vm.sh
# ./install-filebeat-vm.sh
# export INDEX_PREFIX=vm-teste

# ============================== PARÂMETROS DE CONFIGURAÇÃO ===============================
# Ajustar parâmetros (VM monitorada) conforme ambiente se preferir

# VM monitorada
VM_HOSTNAME="$(hostname -s)"
VM_IP="$(hostname -I | awk '{print $1}')"
VM_ROLE="vm_${VM_HOSTNAME%%[0-9]*}"
INDEX_PREFIX="${INDEX_PREFIX:-vm}"
VM_OS="Ubuntu GNU/Linux"
VM_KERNEL="5.x-generic"

# Cluster K8S - ELK Stack
LOGSTASH_HOST="10.130.1.115"
LOGSTASH_PORT="5044"
ELASTICSEARCH_HOST="10.130.1.114"
ELASTICSEARCH_PORT="9200"

# Ambiente e Datacenter
ENVIRONMENT="production"
DATACENTER="observabilidade"
CLUSTER_NAME="external"

# Configurações do Filebeat
FILEBEAT_VERSION="7.10.2"
FILEBEAT_HTTP_HOST="0.0.0.0"
FILEBEAT_HTTP_PORT="5066"

# Configurações de Performance
BULK_MAX_SIZE="2048"
WORKER_COUNT="2"
COMPRESSION_LEVEL="3"
CONNECTION_TIMEOUT="30s"
QUEUE_EVENTS="4096"
QUEUE_FLUSH_MIN="512"
QUEUE_FLUSH_TIMEOUT="5s"

# Configurações de Log
LOG_RETENTION_DAYS="7"
LOG_MAX_SIZE_MB="10"
IGNORE_OLDER_HOURS="48h"
DOCKER_IGNORE_OLDER_HOURS="24h"

# ============================== INÍCIO DO SCRIPT ===============================

set -e

echo "=== Instalação do Filebeat $FILEBEAT_VERSION ==="
echo "VM: $(hostname) - $(uname -a)"
echo "Data: $(date)"
echo

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
   echo "Este script deve ser executado como root"
   exit 1
fi

# Verificar conectividade com o Logstash
echo "Verificando conectividade com Logstash..."
if nc -z $LOGSTASH_HOST $LOGSTASH_PORT 2>/dev/null; then
    echo "✓ Conectividade com Logstash OK ($LOGSTASH_HOST:$LOGSTASH_PORT)"
else
    echo "Aviso: Não foi possível conectar com Logstash ($LOGSTASH_HOST:$LOGSTASH_PORT)"
    echo "Continuando a instalação..."
fi

# Verificar conectividade com Elasticsearch
echo "Verificando conectividade com Elasticsearch..."
if nc -z $ELASTICSEARCH_HOST $ELASTICSEARCH_PORT 2>/dev/null; then
    echo "✓ Conectividade com Elasticsearch OK ($ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT)"
else
    echo "Aviso: Não foi possível conectar com Elasticsearch ($ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT)"
    echo "Continuando a instalação..."
fi

echo

# Atualizar sistema
echo "Atualizando sistema Debian..."
apt-get update -q

# Instalar dependências
echo "Instalando dependências..."
apt-get install -y wget curl gnupg ca-certificates lsb-release apt-transport-https netcat

# Importar chave pública da Elastic no keyring e evitar apt-key que é obsoleto
install -d /usr/share/keyrings
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | sudo gpg --dearmor --batch --yes -o /usr/share/keyrings/elastic-keyring.gpg

# Adicionar repositório Elastic 7.x para instalar Filebeat 7.10.2
echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" \
| sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Atualizar índices
apt-get update -q

# Instalar Filebeat 7.10.2
apt-get install -y filebeat=$FILEBEAT_VERSION
sudo apt-mark hold filebeat

# Atualizar cache do apt
apt-get update -q

# Impedir atualizações automáticas do Filebeat
echo "Impedindo atualizações automáticas..."
apt-mark hold filebeat

# Backup da configuração original
echo "Fazendo backup da configuração original..."
cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.original

# Criar diretórios necessários
echo "Criando diretórios necessários..."
mkdir -p /var/log/filebeat
chown root:root /var/log/filebeat
chmod 755 /var/log/filebeat

# Dar acesso seguro em nível de pasta aos logs para o Filebeat (com herança)
echo "Ajustando acesso do Filebeat aos logs (modo seguro, pasta e herança)..."

# Garantir pacote de ACL disponível
if ! command -v setfacl >/dev/null 2>&1; then
  apt-get update -q
  apt-get install -y acl
fi

# Adicionar o usuário filebeat ao grupo 'adm' (leitura típica de /var/log)
if id -u filebeat >/dev/null 2>&1; then
  usermod -aG adm filebeat || true
else
  echo "Aviso: usuário 'filebeat' não encontrado ainda; seguirá quando o serviço for criado."
fi

# Aplicar ACLs em /var/log para leitura/execução pelo usuário filebeat
if id -u filebeat >/dev/null 2>&1; then
  # Permite o filebeat listar pastas e ler arquivos existentes
  setfacl -R -m u:filebeat:rx /var/log
  # Default ACL: novos arquivos/pastas herdam leitura/execução para filebeat
  setfacl -R -d -m u:filebeat:rx /var/log

  # Dar leitura explícita nos arquivos de log mais comuns (se existirem)
  for f in /var/log/syslog /var/log/auth.log /var/log/kern.log /var/log/daemon.log; do
    [[ -e "$f" ]] && setfacl -m u:filebeat:r "$f"
  done
else
  echo "Aviso: 'filebeat' ainda não existe; ACL herdada em /var/log já configurada. Assim que o usuário for criado, herda acesso."
fi

# (Opcional) Garantir leitura de grupo para *.log existentes sem alterar todo o /var/log
find /var/log -type f -name "*.log" -exec chmod g+r {} \; 2>/dev/null || true

# Verificar se Docker existe
DOCKER_EXISTS=false
if systemctl list-unit-files | grep -q docker.service; then
    DOCKER_EXISTS=true
    echo "✓ Docker detectado"
else
    echo "ℹ Docker não encontrado"
fi

# Verificar se containerd existe
CONTAINERD_EXISTS=false
if systemctl list-unit-files | grep -q containerd.service; then
    CONTAINERD_EXISTS=true
    echo "✓ containerd detectado"
else
    echo "ℹ containerd não encontrado"
fi

echo

# Aplicar configuração do Filebeat
echo "Aplicando configuração do Filebeat..."
cat > /etc/filebeat/filebeat.yml << EOF
################### Filebeat Configuration for VM #####################
# Arquivo: /etc/filebeat/filebeat.yml
# VM $VM_OS
# Destino: Stack ELK no cluster K8S / Logstash
#######################################################################

# ============================== Inputs ===============================
filebeat.inputs:
  # --- Logs do sistema Debian ---
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
    enabled: $DOCKER_EXISTS
    paths:
      - /var/lib/docker/containers/*/*-json.log
    exclude_files: ['\.gz$']
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
      - decode_json_fields:
          fields: ["message"]
          target: "json"
          when:
            has_fields: ["message"]

  # --- Logs do containerd ---
  - type: log
    enabled: $CONTAINERD_EXISTS
    paths:
      - /var/log/containers/*.log
      - /var/log/containerd/*.log
    symlinks: true
    exclude_files: ['\.gz$']
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

  # --- Logs de aplicações específicas (ajustar conforme necessário) ---
  - type: log
    enabled: true
    paths:
      - /var/log/apache2/*.log
      - /var/log/nginx/*.log
    exclude_files: ['\.gz$']
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

  # Limpeza de campos desnecessários
  - drop_fields:
      fields: ["agent.ephemeral_id", "agent.hostname", "agent.id", "agent.version", "ecs.version"]
      ignore_missing: true

# ============================== Output -> Logstash ===============================
output.logstash:
  hosts: ["$LOGSTASH_HOST:$LOGSTASH_PORT"]  # Logstash no cluster K8S
  loadbalance: true
  bulk_max_size: $BULK_MAX_SIZE
  worker: $WORKER_COUNT
  compression_level: $COMPRESSION_LEVEL
  ttl: $CONNECTION_TIMEOUT
  timeout: $CONNECTION_TIMEOUT

# ============================== Logging do Filebeat ===============================
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: $LOG_RETENTION_DAYS
  permissions: 0644
  rotateeverybytes: $((LOG_MAX_SIZE_MB * 1024 * 1024))  # ${LOG_MAX_SIZE_MB}MB

# ============================== Monitoramento ===============================
## === Quando usar Elasticsearch (X-Pack Monitoring) ===
## Habilite estas linhas se sua stack for Elasticsearch:
monitoring.enabled: true
monitoring.elasticsearch:
 hosts: ["${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}"]  # Elasticsearch no K8S

## === Quando usar com OpenSearch (ou ambiente sem X-Pack) ===
## Habilite estas linhas se sua stack for OpenSearch:
http:
  enabled: true
  host: "${FILEBEAT_HTTP_HOST}"      # 0.0.0.0 no script
  port: ${FILEBEAT_HTTP_PORT}        # 5066 no script

# ============================== Performance ===============================
queue.mem:
  events: $QUEUE_EVENTS
  flush.min_events: $QUEUE_FLUSH_MIN
  flush.timeout: $QUEUE_FLUSH_TIMEOUT

# ============================== Configurações de Segurança ===============================
ssl.verification_mode: none  # Para ambiente interno
ssl.supported_protocols: ["TLSv1.2", "TLSv1.3"]
EOF

# Verificar sintaxe da configuração
echo "Verificando configuração do Filebeat..."
if filebeat test config -c /etc/filebeat/filebeat.yml; then
    echo "✓ Configuração válida"
else
    echo "Erro na configuração do Filebeat"
    echo "Detalhes do erro:"
    filebeat test config -c /etc/filebeat/filebeat.yml -v
    exit 1
fi

# Testar conexão com Logstash
echo "Testando conexão com Logstash..."
if filebeat test output -c /etc/filebeat/filebeat.yml; then
    echo "✓ Conexão com Logstash OK"
else
    echo "Aviso: Problema na conexão com Logstash"
fi

# Habilitar e iniciar serviço
echo "Habilitando e REINICIANDO serviço Filebeat..."
systemctl daemon-reload
systemctl enable filebeat
systemctl restart filebeat

# Verificar status
sleep 3
if systemctl is-active --quiet filebeat; then
    echo "✓ Filebeat iniciado"
    systemctl status filebeat --no-pager --lines=5
else
    echo "Erro ao iniciar Filebeat"
    echo "=== Logs de erro ==="
    journalctl -u filebeat --no-pager --lines=10
    exit 1
fi

# Verificar endpoint HTTP (quando habilitado)
if grep -qE '^\s*http:\s*$' /etc/filebeat/filebeat.yml; then
  if ss -lntp | grep -q ":${FILEBEAT_HTTP_PORT}"; then
    echo "✓ Endpoint HTTP disponível em http://${VM_IP}:${FILEBEAT_HTTP_PORT}/"
  else
    echo "✗ Endpoint HTTP não respondeu na porta ${FILEBEAT_HTTP_PORT}"
  fi
fi

echo

# Criar script de monitoramento
echo "Criando script de monitoramento..."
cat > /usr/local/bin/check-filebeat.sh << 'EOF'
#!/bin/bash
echo "=== Status do Filebeat ==="
systemctl status filebeat --no-pager --lines=3
echo
echo "=== Últimas 10 linhas do log ==="
tail -10 /var/log/filebeat/filebeat
echo
echo "=== Teste de configuração ==="
filebeat test config -c /etc/filebeat/filebeat.yml
echo
echo "=== Teste de conexão ==="
filebeat test output -c /etc/filebeat/filebeat.yml
EOF

chmod +x /usr/local/bin/check-filebeat.sh

# Criar entrada no crontab para verificação
echo "Configurando monitoramento automático..."
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/check-filebeat.sh >/dev/null 2>&1") | crontab -

echo
echo "=== INSTALAÇÃO CONCLUÍDA ==="
echo "Filebeat $FILEBEAT_VERSION instalado e configurado!"
echo
echo "Parâmetros utilizados:"
echo "  - VM: $VM_HOSTNAME ($VM_IP)"
echo "  - Logstash: $LOGSTASH_HOST:$LOGSTASH_PORT"
echo "  - Elasticsearch: $ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT"
echo "  - Ambiente: $ENVIRONMENT"
echo "  - Datacenter: $DATACENTER"
echo
echo "Comandos úteis:"
echo "  - Status: systemctl status filebeat"
echo "  - Logs: tail -f /var/log/filebeat/filebeat"
echo "  - Restart: systemctl restart filebeat"
echo "  - Monitoramento: /usr/local/bin/check-filebeat.sh"
echo
echo "Configurações:"
echo "  - Config: /etc/filebeat/filebeat.yml"
echo "  - Logs: /var/log/filebeat/"
echo "  - Métricas HTTP: http://$VM_IP:$FILEBEAT_HTTP_PORT/stats"
echo
echo "Os logs da VM serão enviados para os seguintes índices:"
echo "  - ${INDEX_PREFIX}-system-logs-YYYY.MM.DD"
echo "  - ${INDEX_PREFIX}-security-logs-YYYY.MM.DD"
echo "  - ${INDEX_PREFIX}-service-logs-YYYY.MM.DD"
echo "  - ${INDEX_PREFIX}-docker-logs-YYYY.MM.DD (se Docker estiver presente)"
echo "  - ${INDEX_PREFIX}-containerd-logs-YYYY.MM.DD (se containerd estiver presente)"
echo "  - ${INDEX_PREFIX}-webserver-logs-YYYY.MM.DD (se Apache/Nginx estiver presente)"
echo "  - ${INDEX_PREFIX}-config-logs-YYYY.MM.DD (monitoramento de arquivos de configuração)"
