#!/bin/bash
#
# Script de instalação do Filebeat 7.10.2 OSS em VM
# Compatível com: Ubuntu/Debian 5.10.0-9-amd64
# Destino: Stack ELK no cluster K8S
#
# Como usar:
# cd /root
# wget -O install-filebeat-vm.sh [URL_DO_SCRIPT]
# chmod +x install-filebeat-vm.sh
# ./install-filebeat-vm.sh
#
# Autor: Erivando Sena<erivandosena@gmail.com>
# Data: 2023-10-20
# Versão: 1.0

# Ajuste aos hosts reais (Domains/IP/port)
# Logstash (input Beats) do cluster K8S – 10.130.1.115:5044
# Elasticsearch (API HTTP/REST) – 10.130.1.114:9200
# IP VM monitorada (nfs-conteirner no caso deste template) – 10.130.0.253
# Endpoint HTTP de métricas do Filebeat — bind 0.0.0.0 (porta padrão 5066)
# Socket local do Docker para enriquecer eventos — unix:///var/run/docker.sock

set -e

echo "=== Instalação do Filebeat 7.10.2 ==="
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
if nc -z 10.130.1.115 5044 2>/dev/null; then
    echo "✓ Conectividade com Logstash OK (10.130.1.115:5044)"
else
    echo "Aviso: Não foi possível conectar com Logstash (10.130.1.115:5044)"
    echo "Continuando a instalação..."
fi

# Verificar conectividade com Elasticsearch
echo "Verificando conectividade com Elasticsearch..."
if nc -z 10.130.1.114 9200 2>/dev/null; then
    echo "✓ Conectividade com Elasticsearch OK (10.130.1.114:9200)"
else
    echo "Aviso: Não foi possível conectar com Elasticsearch (10.130.1.114:9200)"
    echo "Continuando a instalação..."
fi

echo

# Atualizar sistema
echo "Atualizando sistema Debian..."
apt-get update -q

# # Instalar dependências
# echo "Instalando dependências..."
# apt-get install -y wget curl gnupg apt-transport-https ca-certificates netcat

# # Adicionar repositório Elastic
# echo "Adicionando repositório Elastic..."
# wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
# echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-7.x.list

# # Atualizar cache do apt
# apt-get update -q


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
apt-get install -y filebeat=7.10.2

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

# Dar permissão de leitura para todos nos logs essenciais
chmod 644 /var/log/syslog
chmod 644 /var/log/auth.log
chmod 644 /var/log/daemon.log

# Verificar se mudou
ls -la /var/log/{syslog,auth.log,daemon.log}

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
cat > /etc/filebeat/filebeat.yml << 'EOF'
################### Filebeat Configuration for VM #####################
# Arquivo: /etc/filebeat/filebeat.yml
# VM Debian 5.10.0-9-amd64
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
    ignore_older: 48h
    fields:
      index_name: "nfs-system-logs"
      source_type: "system_log"
      host_type: "nfs_server"
      environment: "production"
      cluster: "external"
      service_name: "nfs-conteirner"
    fields_under_root: true
    processors:
      - add_tags:
          tags: ["system", "debian", "nfs-server"]

  # --- Logs de autenticação SSH ---
  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
    fields:
      index_name: "nfs-security-logs"
      source_type: "auth_log"
      log_type: "security"
      host_type: "nfs_server"
      environment: "production"
      cluster: "external"
      service_name: "nfs-conteirner"
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
    ignore_older: 48h
    fields:
      index_name: "nfs-service-logs"
      source_type: "nfs_log"
      log_type: "service"
      host_type: "nfs_server"
      environment: "production"
      cluster: "external"
      service_name: "nfs-server"
    fields_under_root: true
    processors:
      - add_tags:
          tags: ["nfs", "storage", "service"]

  # --- Logs de containers Docker (se existir) ---
  - type: log
    enabled: $DOCKER_EXISTS
    paths:
      - /var/lib/docker/containers/*/*-json.log
    exclude_files: ['\.gz$']
    json.keys_under_root: true
    json.add_error_key: true
    json.message_key: log
    ignore_older: 24h
    fields:
      index_name: "nfs-docker-logs"
      source_type: "docker"
      log_type: "container"
      host_type: "nfs_server"
      environment: "production"
      cluster: "external"
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

  # --- Logs do containerd (se existir) ---
  - type: log
    enabled: $CONTAINERD_EXISTS
    paths:
      - /var/log/containers/*.log
      - /var/log/containerd/*.log
    symlinks: true
    exclude_files: ['\.gz$']
    ignore_older: 24h
    fields:
      index_name: "nfs-containerd-logs"
      source_type: "containerd"
      log_type: "container"
      host_type: "nfs_server"
      environment: "production"
      cluster: "external"
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
    ignore_older: 24h
    fields:
      index_name: "nfs-webserver-logs"
      source_type: "webserver"
      log_type: "access"
      host_type: "nfs_server"
      environment: "production"
      cluster: "external"
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
      index_name: "nfs-config-logs"
      source_type: "config_file"
      log_type: "configuration"
      host_type: "nfs_server"
      environment: "production"
      cluster: "external"
      config_monitoring: true
    fields_under_root: true
    close_inactive: 5m
    scan_frequency: 60s
    processors:
      - add_tags:
          tags: ["config", "monitoring"]

# ============================== Módulos desabilitados ===============================
filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

# ============================== Processadores Globais ===============================
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_fields:
      target: ''
      fields:
        vm_hostname: "nfs-conteirner"
        vm_ip: "10.130.0.253"
        vm_os: "Debian GNU/Linux"
        vm_kernel: "5.10.0-9-amd64"
        vm_role: "nfs_server"
        datacenter: "observabilidade"
        deployment_type: "external_vm"
        monitoring_source: "filebeat"

  # Limpeza de campos desnecessários
  - drop_fields:
      fields: ["agent.ephemeral_id", "agent.hostname", "agent.id", "agent.version", "ecs.version"]
      ignore_missing: true

# ============================== Output -> Logstash ===============================
output.logstash:
  hosts: ["10.130.1.115:5044"]  # Logstash no cluster K8S C2
  loadbalance: true
  bulk_max_size: 2048
  worker: 2
  compression_level: 3
  ttl: 30s
  timeout: 30s

# ============================== Logging do Filebeat ===============================
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
  rotateeverybytes: 10485760  # 10MB

# ============================== Monitoramento ===============================
monitoring.enabled: false
# monitoring.elasticsearch:
#   hosts: ["10.130.1.114:9200"]  # Elasticsearch no cluster K8S C2

# opcional: métricas via HTTP (para Prometheus/Metricbeat módulo "beat")
http.enabled: true
http.host: 0.0.0.0

# ============================== Performance ===============================
queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 5s

# ============================== Configurações de Segurança ===============================
ssl.verification_mode: none  # Para ambiente interno
ssl.supported_protocols: ["TLSv1.2", "TLSv1.3"]
EOF

# Substituir variáveis na configuração
sed -i "s/\$DOCKER_EXISTS/$DOCKER_EXISTS/g" /etc/filebeat/filebeat.yml
sed -i "s/\$CONTAINERD_EXISTS/$CONTAINERD_EXISTS/g" /etc/filebeat/filebeat.yml

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
echo "Habilitando e iniciando serviço Filebeat..."
systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat

# Verificar status
sleep 3
if systemctl is-active --quiet filebeat; then
    echo "✓ Filebeat iniciado"
    systemctl status filebeat --no-pager --lines=5
else
    echo "Erro ao iniciar Filebeat"
    echo "=== Logs de erro ==="
    journalctl -u filebeat --no-pager --lines=10
    echo "=== Status detalhado ==="
    systemctl status filebeat --no-pager --lines=10
    exit 1
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
echo "Filebeat 7.10.2 instalado e configurado!"
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
echo "  - Logstash: 10.130.1.115:5044"
echo "  - Elasticsearch: 10.130.1.114:9200"
echo
echo "Os logs da VM serão enviados para os seguintes índices:"
echo "  - nfs-system-logs-YYYY.MM.DD"
echo "  - nfs-security-logs-YYYY.MM.DD"
echo "  - nfs-service-logs-YYYY.MM.DD"
echo "  - nfs-docker-logs-YYYY.MM.DD (se Docker estiver presente)"
echo "  - nfs-containerd-logs-YYYY.MM.DD (se containerd estiver presente)"
echo "  - nfs-webserver-logs-YYYY.MM.DD (se Apache/Nginx estiver presente)"
echo "  - nfs-config-logs-YYYY.MM.DD (monitoramento de arquivos de configuração)"
echo "Fim"
