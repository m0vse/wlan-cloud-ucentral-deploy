#!/bin/sh
set -eu

acme_store=/var/lib/docker/volumes/openwifi_letsencrypt_certs/_data/acme.json
hostname=openwifi.shinesystems.co.uk
cert_dir=/opt/openwifi/docker-compose/certs
compose_dir=/opt/openwifi/docker-compose
temporary_dir=$(mktemp -d /tmp/openwifi-cert-sync.XXXXXX)
trap 'rm -rf "$temporary_dir"' EXIT

/usr/local/sbin/extract-openwifi-acme \
  "$acme_store" \
  "$hostname" \
  "$temporary_dir/websocket-cert.pem" \
  "$temporary_dir/websocket-key.pem"

openssl x509 -in "$temporary_dir/websocket-cert.pem" -noout -checkend 86400

if cmp -s "$temporary_dir/websocket-cert.pem" "$cert_dir/websocket-cert.pem" && \
   cmp -s "$temporary_dir/websocket-key.pem" "$cert_dir/websocket-key.pem"; then
  exit 0
fi

install -o root -g root -m 0644 "$temporary_dir/websocket-cert.pem" "$cert_dir/websocket-cert.pem"
install -o root -g root -m 0600 "$temporary_dir/websocket-key.pem" "$cert_dir/websocket-key.pem"

cd "$compose_dir"
docker compose \
  --env-file .env.letsencrypt \
  -f docker-compose.lb.letsencrypt.yml \
  -f docker-compose.lb.letsencrypt.local.yml \
  restart owgw
