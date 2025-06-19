#!/bin/sh

# Criar imagem de base debian para programas admin4
	echo "# Criando imagem pysniff"
	find . | grep DS_Store | while read x; do rm -v $x; done
	docker build . -t pysniff

exit 0
