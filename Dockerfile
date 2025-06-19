
#=========================================================================
#
# Container para projeto de captura de pacotes para analise atrasada
#
#=========================================================================

# Base em Debian 12
FROM debian:bookworm

# Variaveis globais de ambiente
ENV \
    MAINTAINER="Patrick Brandao <patrickbrandao@gmail.com>" \
    TERM=xterm \
    SHELL=/bin/bash \
    TZ=America/Sao_Paulo \
    PS1='\[\033[0;99m\][\[\033[0;96m\]\u\[\033[0;99m\]@\[\033[0;92m\]\h\[\033[0;99m\]] \[\033[1;38m\]\w\[\033[0;99m\] \$\[\033[0m\] ' \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8 \
    DEBIAN_FRONTEND=noninteractive

# Preparar base do Debian
RUN ( \
    apt-get -y update; \
    apt-get -y upgrade; \
    apt-get -y dist-upgrade; \
    apt-get -y autoremove; \
    \
    echo "# Pacotes basicos"; \
    apt-get -y install \
        bash bsdextrautils bsdutils \
        coreutils debianutils file findutils grep sed \
        util-linux procps tzdata mawk;  \
    \
    echo "# Pacotes de criptografia"; \
    apt-get -y install \
        ca-certificates openssl; \
    \
    echo "# Pacotes de compressao"; \
    apt-get -y install \
        tar gzip zip unzip bzip2 xz-utils zstd; \
    \
    echo "# Pacotes de rede"; \
    apt-get -y install \
        wget hostname iproute2 iputils-ping \
        curl traceroute net-tools; \
    \
    echo "# Pacotes de servicos de rede"; \
    apt-get -y install \
        openssh-client snmp lighttpd nginx; \
    \
    echo "# Pacotes de captura de pacotes"; \
    apt-get -y install \
        tcpdump libpcap-dev; \
    \
    echo "# Pacotes de servicos diversos"; \
    apt-get -y install \
        cron; \
    \
)

# Instalar supervisor e pacotes python3
RUN ( \
    echo "# Instalando supervisor de processos"; \
    apt-get -y install \
        supervisor; \
    \
    echo "# Instalando python3 e pacotes"; \
    apt-get -y install \
        python3 \
            python3-pip \
            python3-pip-whl \
            python3-distutils \
            python3-dev \
            python3-setuptools \
            python3-wheel \
            python3-scapy \
            python3-redis; \
    \
    mkdir /src; \
)

# Copiar programa
COPY src/* /src/

# Ajustes
RUN ( \
    chmod +x /src/*; \
    cp /src/service.conf /etc/supervisor/conf.d/service.conf; \
)

# Entrypoint
ENTRYPOINT ["/src/entrypoint.sh"]

# CMD
CMD ["/usr/bin/supervisord","--nodaemon","-u","root","-d","/run","-c","/etc/supervisor/supervisord.conf"]

