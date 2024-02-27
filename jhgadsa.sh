#!/bin/bash
# Support 20.04/22.04/23.04

function try_commands {
  local commands=("$@")
  local retry_count=0
  local max_retries=5

  for cmd in "${commands[@]}"; do
    if [[ $cmd == *"sudo apt-get"* ]]; then
      echo "O comando contém 'sudo apt-get'. Encerrando a execução se falhar."
      $cmd || {
        exit_status=$?
        echo "Comando Falhou: $cmd"
        exit $exit_status
      }
    else
      echo "Executando comando: $cmd"
      until $cmd; do
        exit_status=$?
        retry_count=$((retry_count+1))
        if [ $retry_count -ge $max_retries ]; then
          echo "Comando Falhou Depois de $max_retries Tentativas: $cmd"
          return $exit_status
        fi
        echo "Comando Falhou! Tentativa: $retry_count/$max_retries: $cmd"
        sleep 2
      done
    fi
  done

  echo " -> Comando(s) Executado com Sucesso!"
  return 0
}

ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

Domain=$(echo $ServerName | cut -d "." -f2-)
DKIMSelector=$(echo $ServerName | awk -F[.:] '{print $1}')
ServerIP=$(wget -qO- http://ip-api.com/line\?fields=query)

echo "::Atualizando root"
try_commands "sudo DEBIAN_FRONTEND=noninteractive sudo apt-get update -y" "sudo DEBIAN_FRONTEND=noninteractive sudo apt-get install ca-certificates curl gnupg -y" "sudo mkdir -p /etc/apt/keyrings"
sudo DEBIAN_FRONTEND=noninteractive sudo apt-get update -y && sudo DEBIAN_FRONTEND=noninteractive sudo apt-get install wget curl jq python3-certbot-dns-cloudflare opendkim opendkim-tools -y

echo "::Configurando Variaveis Cloudflare"
try_commands "sudo mkdir -p /root/.secrets" "sudo chmod 0700 /root/.secrets/" "sudo touch /root/.secrets/cloudflare.cfg" "sudo chmod 0400 /root/.secrets/cloudflare.cfg"

sudo cat <<EOF > /root/.secrets/cloudflare.cfg
dns_cloudflare_email = $CloudflareEmail
dns_cloudflare_api_key = $CloudflareAPI
EOF

sudo cat <<EOF > /etc/hosts
127.0.0.1 localhost
127.0.0.1 $ServerName
$ServerIP $ServerName
EOF

sudo cat <<EOF > /etc/hostname
$ServerName
EOF

sudo hostnamectl set-hostname "$ServerName"

echo "::Gerando Certificado SSL"
try_commands "sudo certbot certonly --non-interactive --agree-tos --register-unsafely-without-email --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.cfg --dns-cloudflare-propagation-seconds 30 --rsa-key-size 4096 -d $ServerName"
try_commands "sudo mkdir -p /etc/opendkim" "sudo mkdir -p /etc/opendkim/keys"
try_commands "sudo chmod -R 777 /etc/opendkim/" "sudo chown -R opendkim:opendkim /etc/opendkim/"

sudo cat <<EOF > /etc/default/opendkim
RUNDIR=/run/opendkim
SOCKET="inet:9982@localhost"
USER=opendkim
GROUP=opendkim
PIDFILE=\$RUNDIR/\$NAME.pid
EXTRAAFTER=
EOF

sudo cat <<EOF > /etc/opendkim.conf
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes
Canonicalization        relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
UserID                  opendkim:opendkim
Socket                  inet:9982@localhost
RequireSafeKeys false
EOF

sudo cat <<EOF > /etc/opendkim/TrustedHosts
127.0.0.1
localhost
$ServerName
*.$Domain
EOF

try_commands "sudo opendkim-genkey -b 2048 -s $DKIMSelector -d $ServerName -D /etc/opendkim/keys/"

sudo cat <<EOF > /etc/opendkim/KeyTable
$DKIMSelector._domainkey.$ServerName $ServerName:$DKIMSelector:/etc/opendkim/keys/$DKIMSelector.private
EOF

sudo cat <<EOF > /etc/opendkim/SigningTable
*@$ServerName $DKIMSelector._domainkey.$ServerName
EOF

echo "::Pre-configurando Postfix"
try_commands "sudo chmod -R 777 /etc/opendkim/" "sudo chown -R opendkim:opendkim /etc/opendkim/"
try_commands "sudo cp /etc/opendkim/keys/$DKIMSelector.txt /root/dkim.txt" "sudo chmod -R 777 /root/dkim.txt"

sleep 3

debconf-set-selections <<< "postfix postfix/mailname string '"$ServerName"'"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
debconf-set-selections <<< "postfix postfix/destinations string '"$ServerName", localhost'"

echo "::Instalando Postfix"
try_commands "sudo sudo apt-get install --assume-yes postfix"

sudo cat <<EOF > /etc/postfix/access.recipients
$ServerName OK
EOF

sudo cat <<EOF > /etc/postfix/main.cf
myhostname = $ServerName
smtpd_banner = \$myhostname ESMTP \$mail_name (root)
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2
milter_protocol = 2
max_queue_lifetime = 1200
milter_default_action = accept
smtpd_milters = inet:localhost:9982
non_smtpd_milters = inet:localhost:9982
smtpd_recipient_restrictions =
  permit_mynetworks,
  check_recipient_access hash:/etc/postfix/access.recipients,
  permit_sasl_authenticated,
  reject_unauth_destination
smtpd_tls_cert_file=/etc/letsencrypt/live/$ServerName/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/$ServerName/privkey.pem
smtpd_tls_security_level=may
smtp_tls_CApath=/etc/ssl/certs
smtp_tls_security_level=may
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mydestination = $ServerName, localhost
relayhost =
mynetworks = $ServerName 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all
EOF

service opendkim restart
service postfix restart
 
echo "::Instalando NodeJS"
curl -fsSL https://deb.nodesource.com/setup_21.x | sudo DEBIAN_FRONTEND=noninteractive -E bash
sudo DEBIAN_FRONTEND=noninteractive sudo apt-get install -y nodejs 

echo "::Baixando Aplicação e Executando Aplicação"
sudo wget -O cloudflare.js https://gist.githubusercontent.com/wnbcorrea/270438b60c31f7aaf14a495d121dda57/raw/5dcc32082c06a96a46ea1b095bde75bc9e412dc8/cloudflare.js
sudo wget -O server.js https://gist.githubusercontent.com/wnbcorrea/3d6b04528d2e7649af70ac7892a4ace5/raw/3e4afd66dadd063af4c196bbd504cec003941de7/server.js
sudo wget -O package.json https://gist.githubusercontent.com/wnbcorrea/14069a0a3038a841776d281a3f57a967/raw/3f85650812ce54ced2a0666bf800c068fe20a395/package.json

sudo chmod 777 cloudflare.js && sudo chmod 777 server.js && sudo chmod 777 package.json

sleep 3

sudo npm i --silent -g pm2
sudo npm --silent install 

sudo node cloudflare.js $CloudflareEmail $CloudflareAPI $Domain $DKIMSelector $ServerIP

sleep 5

sudo pm2 start server.js -- $ServerName
sudo pm2 startup 
sudo pm2 save

(crontab -l ; echo "*/30 * * * * sudo postsuper -d ALL bounced corrupt deferred") | crontab -

sleep 3

 echo "INSTALAÇÂO CONCLUIDA"
