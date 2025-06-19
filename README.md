
# Container para captura de pacotes para analise e fingerprint

Container Docker com software em Python para captura de pacotes de rede (PCAP).
Faz interpretação dos cabeçalhos IP, TCP e UDP e produz um conjunto JSON com os dados.
Armazena em REDIS.

Software construido para auxiliar aplicações WEB rodando em diferentes níveis de produndidade
a terem acesso aos pacotes IPs das conexões e coletar detalhes profundos (MSS, TLS, fingerprint).

## Pre-requisito:

	Rode um container do REDIS com o nome "redis-cache" e leia os scripts build.sh e run-test.sh antes de rodar.

## Construir e rodar container:

	sh build.sh
	sh run-test.sh

## Montagens e mapeamentos para modo read-only do container puro:

	tmpfs em /run, minimo 32m
	/storage/pysniff  ->  inside: /data

## Variaveis de ambiente:

	REDIS_HOST=x.x.x.x        # ip ou nome do servidor REDIS
	REDIS_PORT=6379           # porta redis, padrao 6379
	REDIS_DB=0                # banco de dados do redis
	REDIS_TTL=60              # ttl dos registros (segundos)
	REDIS_KEYPREFIX="packet"  # prefixo do nome da chave

	INTERFACE=eth0            # interface de captura

	FILTER="tcp port 443 or udp port 443"

	# IP local para considerar resposta como parte da conexao do cliente:
	LOCAL_IPV4="192.168.0.2"
	LOCAL_IPV6="2001:db8::2"


## Argumentos e valores default para CMD '/src/sniff.py ....'

	--redis-host redis-cacche
	--redis-port 6379
	--redis-db 0
	--redis-ttl 60
	--interface eth0
	--local-ipv4 192.168.0.2
	--local-ipv6 2001:db8::2
	--filter "tcp port 443 or udp port 443",
	--verbose
	--no-store


