#!/bin/sh

# Parar e remover atual
    dps | grep pysniff | awk '{print $1}' | while read did; do
        docker stop $did;
        docker rm   $did;
    done 2>/dev/null

# Destruir imagem
    docker rmi pysniff 2>/dev/null

# Limpar cache
    docker system prune -f

