#!/bin/sh

# Construir container limpo para testar copia de arquivos
# e execucao de programas para auxiliar na construcao da imagem

# Variaveis
    NAME="pysniff-test"
    LOCAL="$NAME.intranet.br"
    TZ="America/Sao_Paulo"
    IMAGE=debian:bookworm

# Remover atual:
    (
        docker stop  $NAME
        docker rm    $NAME
        docker rm -f $NAME
    ) 2>/dev/null

# Criar e rodar:
    docker run \
        -d --restart=unless-stopped \
        \
        --name=$NAME -h $LOCAL \
        --tmpfs /run:rw,noexec,nosuid,size=32m \
        \
        --network network_public \
        --ip=10.231.0.166 \
        --ip6=2001:db8:10:231::166 \
        \
        --user=root \
        --cap-add=ALL \
        \
        --env UUID=AF7DFBD9-97BE-49DF-8277-67CAE7CF0A90 \
        \
        -e REDIS_HOST=redis-cache \
        -e REDIS_PORT=6379 \
        \
        $IMAGE \
            sleep 9999999999


    # /usr/bin/supervisord --nodaemon -u root -d /run -c /etc/supervisor/supervisord.conf

exit 0


