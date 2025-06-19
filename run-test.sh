#!/bin/sh

# Rodar container

# Variaveis
    NAME="pysniff-https"
    LOCAL="$NAME.intranet.br"
    TZ="America/Sao_Paulo"
    #IMAGE=debian:bookworm
    IMAGE=pysniff
    DATADIR=/storage/$NAME

# Remover atual:
    (
        docker stop  $NAME
        docker rm    $NAME
        docker rm -f $NAME
    ) 2>/dev/null

# IPs locais
    LOCAL_IPV4=$(ip -o -4 ro get 1.2.3.4 | sed 's#.*src.##g' | awk '{print $1}')
    LOCAL_IPV6=$(ip -o -6 ro get 2000::1 | sed 's#.*src.##g' | awk '{print $1}')

# Criar e rodar:
    mkdir -p $DATADIR
    docker run \
        -d --restart=unless-stopped \
        --name=$NAME -h $LOCAL \
        --network host \
        \
        --user=root \
        --cap-add=ALL \
        \
        --add-host redis-cache:10.231.255.151 \
        \
        -e REDIS_HOST=redis-cache \
        -e REDIS_PORT=6379 \
        --env LOCAL_IPV4="$LOCAL_IPV4" \
        --env LOCAL_IPV6="$LOCAL_IPV6" \
        \
        --tmpfs /run:rw,noexec,nosuid,size=32m \
        --mount type=bind,source=$DATADIR,destination=/data,readonly=false \
        \
        \
        $IMAGE


exit 0

