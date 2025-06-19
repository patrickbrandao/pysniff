#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Programa para captura de pacotes IP e armazenamento em Redis
Desenvolvido para Python 3.12
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw
import redis

# Variaveis globais
REDIS_HOST = "redis-cache"
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_TTL = 60
REDIS_KEYPREFIX = "packet"
INTERFACE = "eth0"
LOCAL_IPV4 = "192.168.0.2"
LOCAL_IPV6 = "2001:db8::2"
FILTER = "tcp port 443 or udp port 443"
VERBOSE = False
STORE = True

# Conexao Redis global
redis_connection = None


def redis_connect():
    """
    Conecta ao servidor Redis usando as configuracoes globais.
    Em caso de falha, o programa e abortado com erro fatal.
    
    Argumentos: Nenhum
    Retorno: Nenhum (define a conexao global redis_connection)
    """
    global redis_connection
    try:
        redis_connection = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=False
        )
        # Testa a conexao
        redis_connection.ping()
        print(f"Conectado ao Redis em {REDIS_HOST}:{REDIS_PORT}")
    except Exception as e:
        print(f"ERRO FATAL: Nao foi possivel conectar ao Redis: {e}")
        sys.exit(1)


def capture_start():
    """
    Inicia a captura de pacotes na interface especificada usando o filtro configurado.
    Todos os pacotes capturados sao enviados para a funcao capture_packet_process.
    
    Argumentos: Nenhum
    Retorno: Nenhum
    """
    print(f"Iniciando captura na interface {INTERFACE}")
    print(f"Filtro aplicado: {FILTER}")
    print(f"Modo verbose: {VERBOSE}")
    print(f"Armazenamento: {STORE}")
    
    try:
        sniff(iface=INTERFACE, filter=FILTER, prn=capture_packet_process)
    except KeyboardInterrupt:
        print("\nCaptura interrompida pelo usuario")
        sys.exit(0)
    except Exception as e:
        print(f"ERRO na captura: {e}")
        sys.exit(1)


def capture_packet_process(packet):
    """
    Processa pacotes capturados, filtrando apenas pacotes IP (IPv4 ou IPv6) 
    transportando TCP ou UDP. Os demais pacotes sao ignorados.
    
    Argumentos:
        packet: Pacote capturado pelo Scapy
    
    Retorno: Nenhum
    """
    # Verificar se e um pacote IP (IPv4 ou IPv6)
    if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
        return
    
    # Verificar se transporta TCP ou UDP
    if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
        return
    
    # Se verbose estiver ativo, exibir pacote
    if VERBOSE:
        capture_packet_show(packet)
    
    # Se store estiver ativo, armazenar no Redis
    if STORE:
        capture_packet_store(packet)


def capture_packet_show(packet):
    """
    Exibe informacoes detalhadas do pacote capturado na saida padrao (STDOUT).
    Mostra versao IP, IPs origem/destino, protocolo, portas, tamanhos e timestamp.
    Para TCP mostra detalhes do cabecalho, para UDP mostra length e checksum.
    
    Argumentos:
        packet: Pacote capturado pelo Scapy
    
    Retorno: Nenhum
    """
    timestamp = datetime.now()
    
    # Determinar versao IP e extrair informacoes
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        ip_version = 4
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
    else:  # IPv6
        ip_layer = packet[IPv6]
        ip_version = 6
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
    
    # Determinar protocolo de transporte
    if packet.haslayer(TCP):
        transport_layer = packet[TCP]
        protocol = "TCP"
        src_port = int(transport_layer.sport)
        dst_port = int(transport_layer.dport)
    else:  # UDP
        transport_layer = packet[UDP]
        protocol = "UDP"
        src_port = int(transport_layer.sport)
        dst_port = int(transport_layer.dport)
    
    # Calcular tamanhos
    packet_size = len(packet)
    
    if packet.haslayer(Raw):
        payload_size = len(packet[Raw])
    else:
        payload_size = 0
    
    if protocol == "TCP":
        header_length = int(transport_layer.dataofs) * 4
        segment_size = len(bytes(transport_layer))
        content_size = segment_size - header_length
    else:  # UDP
        header_length = 8  # UDP header sempre tem 8 bytes
        segment_size = int(transport_layer.len)
        content_size = segment_size - header_length
    
    print(f"\n{'='*60}")
    print(f"Timestamp: {timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')}")
    print(f"IP Version: IPv{ip_version}")
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")
    print(f"Protocol: {protocol}")
    print(f"Source Port: {src_port}")
    print(f"Destination Port: {dst_port}")
    print(f"Packet Size: {packet_size} bytes")
    print(f"Segment Size: {segment_size} bytes")
    print(f"Payload Size: {payload_size} bytes")
    print(f"Content Size: {content_size} bytes")
    
    if protocol == "TCP":
        # Detalhes do cabecalho TCP
        seq_num = int(transport_layer.seq) if transport_layer.seq is not None else 0
        ack_num = int(transport_layer.ack) if transport_layer.ack is not None else 0
        win_size = int(transport_layer.window) if transport_layer.window is not None else 0
        flags_value = int(transport_layer.flags) if transport_layer.flags is not None else 0
        checksum_value = int(transport_layer.chksum) if transport_layer.chksum is not None else 0
        urgent_ptr = int(transport_layer.urgptr) if transport_layer.urgptr is not None else 0
        
        print(f"\nTCP Header Details:")
        print(f"  Header Length: {header_length} bytes")
        print(f"  Sequence Number: {seq_num}")
        print(f"  Acknowledgment Number: {ack_num}")
        print(f"  Window Size: {win_size}")
        print(f"  Flags: 0x{flags_value:02x}")
        print(f"    URG: {(flags_value >> 5) & 1}")
        print(f"    ACK: {(flags_value >> 4) & 1}")
        print(f"    PSH: {(flags_value >> 3) & 1}")
        print(f"    RST: {(flags_value >> 2) & 1}")
        print(f"    SYN: {(flags_value >> 1) & 1}")
        print(f"    FIN: {flags_value & 1}")
        print(f"  Checksum: 0x{checksum_value:04x}")
        print(f"  Urgent Pointer: {urgent_ptr}")
        
    else:  # UDP
        length_value = int(transport_layer.len) if transport_layer.len is not None else 0
        checksum_value = int(transport_layer.chksum) if transport_layer.chksum is not None else 0
        
        print(f"\nUDP Header Details:")
        print(f"  Header Length: {header_length} bytes")
        print(f"  Length: {length_value}")
        print(f"  Checksum: 0x{checksum_value:04x}")


def capture_packet_store(packet):
    """
    Armazena o pacote capturado em uma chave do Redis no formato de lista.
    O nome da chave e baseado no prefixo configurado, IP e porta.
    Se o IP origem for local, usa IP/porta de destino para a chave.
    
    Argumentos:
        packet: Pacote capturado pelo Scapy
    
    Retorno: Nenhum
    """
    if redis_connection is None:
        return
    
    timestamp = datetime.now()
    timestamp_secs = int(timestamp.timestamp())
    timestamp_micro = timestamp.microsecond
    
    # Determinar versao IP e extrair informacoes
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        ip_version = 4
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
    else:  # IPv6
        ip_layer = packet[IPv6]
        ip_version = 6
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
    
    # Determinar protocolo de transporte
    if packet.haslayer(TCP):
        transport_layer = packet[TCP]
        protocol = "tcp"
        src_port = int(transport_layer.sport)
        dst_port = int(transport_layer.dport)
    else:  # UDP
        transport_layer = packet[UDP]
        protocol = "udp"
        src_port = int(transport_layer.sport)
        dst_port = int(transport_layer.dport)
    
    # Determinar chave baseada no IP local
    if src_ip == LOCAL_IPV4 or src_ip == LOCAL_IPV6:
        key_ip = dst_ip
        key_port = dst_port
    else:
        key_ip = src_ip
        key_port = src_port
    
    redis_key = f"{REDIS_KEYPREFIX}_{key_ip}_{key_port}"
    
    # Calcular tamanhos
    packet_size = len(packet)
    packet_raw = bytes(packet)
    
    if packet.haslayer(Raw):
        payload_size = len(packet[Raw])
    else:
        payload_size = 0
    
    # Dados base do JSON
    packet_data = {
        'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'),
        'timestamp_secs': timestamp_secs,
        'timestamp_micro': timestamp_micro,
        'packet_size': packet_size,
        'payload_size': payload_size,
        'ip_version': ip_version,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'src_port': src_port,
        'dst_port': dst_port,
        'data': packet_raw.hex(),
        'tcp_header': '',
        'tcp_info': {},
        'udp_header': '',
        'udp_info': {},
        'transport_data': ''
    }
    
    # Processar dados especificos do protocolo
    if protocol == "tcp":
        # Extrair cabecalho TCP
        tcp_header_bytes = bytes(transport_layer)[:int(transport_layer.dataofs) * 4]
        packet_data['tcp_header'] = tcp_header_bytes.hex()
        
        # Calcular content_size
        header_length = int(transport_layer.dataofs) * 4
        segment_size = len(bytes(transport_layer))
        content_size = segment_size - header_length
        packet_data['content_size'] = content_size
        
        # Dados de transporte (payload TCP)
        if len(bytes(transport_layer)) > header_length:
            transport_data = bytes(transport_layer)[header_length:]
            packet_data['transport_data'] = transport_data.hex()
        
        # Informacoes do cabecalho TCP
        flags_value = int(transport_layer.flags) if transport_layer.flags is not None else 0
        seq_num = int(transport_layer.seq) if transport_layer.seq is not None else 0
        ack_num = int(transport_layer.ack) if transport_layer.ack is not None else 0
        win_size = int(transport_layer.window) if transport_layer.window is not None else 0
        checksum_value = int(transport_layer.chksum) if transport_layer.chksum is not None else 0
        urgent_ptr = int(transport_layer.urgptr) if transport_layer.urgptr is not None else 0
        
        packet_data['tcp_info'] = {
            'header_lenght': header_length,
            'checksum': f"{checksum_value:04x}",
            'seq_number': seq_num,
            'ack_number': ack_num,
            'win_size': win_size,
            'flags': f"{flags_value:02x}",
            'flag_urg': (flags_value >> 5) & 1,
            'flag_ack': (flags_value >> 4) & 1,
            'flag_rst': (flags_value >> 2) & 1,
            'flag_syn': (flags_value >> 1) & 1,
            'flag_fin': flags_value & 1,
            'urgent_pointer': urgent_ptr,
            'option': '',
            'option_mss': 0,
            'option_sackok': '',
            'option_timestamp': '',
            'option_wScale': 0
        }
        
    else:  # UDP
        # Extrair cabecalho UDP (8 bytes)
        udp_header_bytes = bytes(transport_layer)[:8]
        packet_data['udp_header'] = udp_header_bytes.hex()
        
        # Calcular content_size
        header_length = 8
        segment_size = int(transport_layer.len) if transport_layer.len is not None else 0
        content_size = segment_size - header_length
        packet_data['content_size'] = content_size
        
        # Dados de transporte (payload UDP)
        if len(bytes(transport_layer)) > 8:
            transport_data = bytes(transport_layer)[8:]
            packet_data['transport_data'] = transport_data.hex()
        
        # Informacoes do cabecalho UDP
        checksum_value = int(transport_layer.chksum) if transport_layer.chksum is not None else 0
        
        packet_data['udp_info'] = {
            'header_lenght': header_length,
            'checksum': f"{checksum_value:04x}"
        }
    
    try:
        # Adicionar na lista do Redis
        redis_connection.rpush(redis_key, json.dumps(packet_data))
        # Atualizar TTL
        redis_connection.expire(redis_key, REDIS_TTL)
    except Exception as e:
        print(f"ERRO ao armazenar no Redis: {e}")


def help():
    """
    Exibe o texto de ajuda no terminal (STDOUT) e encerra o programa.
    Descreve as variaveis de ambiente e argumentos do programa.
    
    Argumentos: Nenhum
    Retorno: Nenhum (encerra o programa)
    """
    help_text = """
CAPTURADOR DE PACOTES IP COM REDIS

Este programa captura pacotes IP (IPv4/IPv6) transportando TCP ou UDP
e armazena as informacoes em um servidor Redis.

VARIAVEIS DE AMBIENTE:
  REDIS_HOST        Endereco do servidor Redis (padrao: redis-cache)
  REDIS_PORT        Porta do servidor Redis (padrao: 6379)
  REDIS_DB          Database do Redis (padrao: 0)
  REDIS_TTL         Tempo de vida das chaves em segundos (padrao: 60)
  REDIS_KEYPREFIX   Prefixo das chaves Redis (padrao: packet)
  INTERFACE         Interface de rede para captura (padrao: eth0)
  LOCAL_IPV4        Endereco IPv4 local (padrao: 192.168.0.2)
  LOCAL_IPV6        Endereco IPv6 local (padrao: 2001:db8::2)
  FILTER            Filtro de captura (padrao: tcp port 443 or udp port 443)

ARGUMENTOS:
  --redis-host      Endereco do servidor Redis
  --redis-port      Porta do servidor Redis
  --redis-db        Database do Redis
  --redis-ttl       Tempo de vida das chaves em segundos
  --redis-keyprefix Prefixo das chaves Redis
  --interface       Interface de rede para captura
  --local-ipv4      Endereco IPv4 local
  --local-ipv6      Endereco IPv6 local
  --filter          Filtro de captura de pacotes
  -v, --verbose     Ativa modo verboso (exibe pacotes na tela)
  -n, --no-store    Desativa armazenamento no Redis
  -h, --help        Exibe esta ajuda

EXEMPLOS:
  python3 capturador.py --interface wlan0 --verbose
  python3 capturador.py --redis-host 192.168.1.100 --filter "port 80"
  REDIS_HOST=meu-redis python3 capturador.py --verbose

REQUISITOS:
  - Python 3.12
  - Bibliotecas: scapy, redis
  - Permissoes de administrador para captura de pacotes
  - Servidor Redis acessivel
"""
    print(help_text)
    sys.exit(0)


def parse_arguments():
    """
    Analisa os argumentos da linha de comando e atualiza as variaveis globais.
    
    Argumentos: Nenhum
    Retorno: Nenhum (atualiza variaveis globais)
    """
    global REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_TTL, REDIS_KEYPREFIX
    global INTERFACE, LOCAL_IPV4, LOCAL_IPV6, FILTER, VERBOSE, STORE
    
    parser = argparse.ArgumentParser(add_help=False)
    
    # Argumentos de ajuda
    parser.add_argument('-h', '--help', action='store_true')
    
    # Argumentos Redis
    parser.add_argument('--redis-host', type=str)
    parser.add_argument('--redis-port', type=int)
    parser.add_argument('--redis-db', type=int)
    parser.add_argument('--redis-ttl', type=int)
    parser.add_argument('--redis-keyprefix', type=str)
    
    # Argumentos de captura
    parser.add_argument('--interface', type=str)
    parser.add_argument('--local-ipv4', type=str)
    parser.add_argument('--local-ipv6', type=str)
    parser.add_argument('--filter', type=str)
    
    # Argumentos de comportamento
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-n', '--no-store', action='store_true')
    
    args = parser.parse_args()
    
    # Verificar ajuda
    if args.help:
        help()
    
    # Atualizar variaveis globais com argumentos
    if args.redis_host is not None:
        REDIS_HOST = args.redis_host
    if args.redis_port is not None:
        REDIS_PORT = args.redis_port
    if args.redis_db is not None:
        REDIS_DB = args.redis_db
    if args.redis_ttl is not None:
        REDIS_TTL = args.redis_ttl
    if args.redis_keyprefix is not None:
        REDIS_KEYPREFIX = args.redis_keyprefix
    if args.interface is not None:
        INTERFACE = args.interface
    if args.local_ipv4 is not None:
        LOCAL_IPV4 = args.local_ipv4
    if args.local_ipv6 is not None:
        LOCAL_IPV6 = args.local_ipv6
    if args.filter is not None:
        FILTER = args.filter
    
    if args.verbose:
        VERBOSE = True
    if args.no_store:
        STORE = False


def load_environment_variables():
    """
    Carrega variaveis de ambiente e atualiza as variaveis globais.
    
    Argumentos: Nenhum
    Retorno: Nenhum (atualiza variaveis globais)
    """
    global REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_TTL, REDIS_KEYPREFIX
    global INTERFACE, LOCAL_IPV4, LOCAL_IPV6, FILTER
    
    # Carregar variaveis de ambiente
    if 'REDIS_HOST' in os.environ:
        REDIS_HOST = os.environ['REDIS_HOST']
    if 'REDIS_PORT' in os.environ:
        REDIS_PORT = int(os.environ['REDIS_PORT'])
    if 'REDIS_DB' in os.environ:
        REDIS_DB = int(os.environ['REDIS_DB'])
    if 'REDIS_TTL' in os.environ:
        REDIS_TTL = int(os.environ['REDIS_TTL'])
    if 'REDIS_KEYPREFIX' in os.environ:
        REDIS_KEYPREFIX = os.environ['REDIS_KEYPREFIX']
    if 'INTERFACE' in os.environ:
        INTERFACE = os.environ['INTERFACE']
    if 'LOCAL_IPV4' in os.environ:
        LOCAL_IPV4 = os.environ['LOCAL_IPV4']
    if 'LOCAL_IPV6' in os.environ:
        LOCAL_IPV6 = os.environ['LOCAL_IPV6']
    if 'FILTER' in os.environ:
        FILTER = os.environ['FILTER']


def main():
    """
    Funcao principal do programa.
    Carrega variaveis de ambiente, processa argumentos e inicia a captura.
    
    Argumentos: Nenhum
    Retorno: Nenhum
    """
    print("Capturador de Pacotes IP com Redis")
    print("=" * 40)
    
    # 1. Carregar variaveis de ambiente
    load_environment_variables()
    
    # 2. Processar argumentos da linha de comando
    parse_arguments()
    
    # 3. Conectar ao Redis se necessario
    if STORE:
        redis_connect()
    
    # 4. Iniciar captura
    capture_start()


if __name__ == "__main__":
    main()
