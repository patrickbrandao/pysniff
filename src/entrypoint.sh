#!/bin/sh

# Script a executar no entrypoint do 'docker run'
# para prepara ambiente local para rodar programas

# Argumento CMD
	EXEC_CMD="$@"

# Funcoes
	initlogfile="/data/log/init.log"
	lastlogfile="/data/log/last.log"
	_log(){ now=$(date "+%Y-%m-%d-%T"); echo "$now|$@" >> $initlogfile; }
	[ -f "$initlogfile" ] && mv "$initlogfile" "$lastlogfile" 2>/dev/null
	[ -d /data/log ] || mkdir -p /data/log

	_abort(){  _log "$@"; _logitr "Erro fatal: $1"; exit $2; }
	_logit(){  _log "$@"; /bin/echo -ne "\033[0;90m[$(date '+%y%m%d %T')]\033[0m "; [ "$1" = "-n" ] && /bin/echo -ne "\x1B[96m$2\033[0m" || /bin/echo -e "\x1B[96m$1\033[0m"; }
	_logity(){ _log "$@"; /bin/echo -ne "\033[0;90m[$(date '+%y%m%d %T')]\033[0m "; [ "$1" = "-n" ] && /bin/echo -ne "\x1B[93m$2\033[0m" || /bin/echo -e "\x1B[93m$1\033[0m"; }
	_logitg(){ _log "$@"; /bin/echo -ne "\033[0;90m[$(date '+%y%m%d %T')]\033[0m "; [ "$1" = "-n" ] && /bin/echo -ne "\x1B[92m$2\033[0m" || /bin/echo -e "\x1B[92m$1\033[0m"; }
	_logitr(){ _log "$@"; /bin/echo -ne "\033[0;90m[$(date '+%y%m%d %T')]\033[0m "; [ "$1" = "-n" ] && /bin/echo -ne "\x1B[91m$2\033[0m" || /bin/echo -e "\x1B[91m$1\033[0m"; }
	_logitp(){ _log "$@"; /bin/echo -ne "\033[0;90m[$(date '+%y%m%d %T')]\033[0m "; [ "$1" = "-n" ] && /bin/echo -ne "\x1B[95m$2\033[0m" || /bin/echo -e "\x1B[95m$1\033[0m"; }
	_logita(){ _log "$@"; /bin/echo -ne "\033[0;90m[$(date '+%y%m%d %T')]\033[0m "; [ "$1" = "-n" ] && /bin/echo -ne "\033[0;90m$2\033[0m" || /bin/echo -e "\033[0;90m$1\033[0m"; }

	_logit "entrypoint.sh: iniciando preparativos"

        -e REDIS_HOST=redis-cache \
        -e REDIS_PORT=6379 \


# Variaveis de ambiente uniformizadas
	# - padronizar
	[ "$SUPERVISOR_ENABLE" = "no" ] || SUPERVISOR_ENABLE=yes
	[ "x$REDIS_HOST" = "x" ] && REDIS_HOST="redis-cache"
	[ "x$REDIS_PORT" = "x" ] && REDIS_PORT="6379"

	# - exportar
	export SUPERVISOR_ENABLE="$SUPERVISOR_ENABLE"
	export REDIS_HOST="$REDIS_HOST"
	export REDIS_PORT="$REDIS_PORT"

	# - logar para informativo
	_logit "ENV SUPERVISOR_ENABLE=$SUPERVISOR_ENABLE"
	_logit "ENV REDIS_HOST=$REDIS_HOST"
	_logit "ENV REDIS_PORT=$REDIS_PORT"

	# - salvar
	(
		echo
		echo "export SUPERVISOR_ENABLE='$SUPERVISOR_ENABLE'"
		echo
		echo "export REDIS_HOST='$REDIS_HOST'"
		echo "export REDIS_PORT='$REDIS_PORT'"
		echo
	) > /run/env.conf

	# Rodar programa principal do container
	if [ "$SUPERVISOR_ENABLE" = "yes" ]; then
		# Acionando supervisor
		_logit "entrypoint.sh: preparando supervisor"
		EXEC_CMD="/usr/bin/supervisord --nodaemon -u root -d /run -c /etc/supervisor/supervisord.conf"
	else
		# Sem supervisor...
		_logit "entrypoint.sh: supervisor desativado"
	    if [ "x$EXEC_CMD" = "x" ]; then
	        _log "CMD default: [sleep 252288000]"
		    EXEC_CMD="sleep 252288000"
	    else
	    	_log "CMD defined: [$EXEC_CMD]"
	    fi

	fi

    FULLCMD="exec $EXEC_CMD"
	_log "Start CMD: [$EXEC_CMD] [$FULLCMD]"
    eval $FULLCMD
	stdno="$?"


exit 0


