# Makefile — Proxy SOCKS5 + protocolo de monitoreo (SMP)
# Targets:
#   make            -> compila servidor (socks5d) y cliente (socks5-mgmt)
#   make server     -> sólo el servidor
#   make client     -> sólo el cliente de monitoreo
#   make clean      -> borra objetos y binarios
#
# Módulos provistos por la cátedra: selector.c, buffer.c, stm.c, netutils.c
# (y parser.c / parser_utils.c disponibles como referencia, no compilados aquí).

CC      ?= cc
STD      = -std=c11
WARN     = -Wall -Wextra -pedantic
# _DEFAULT_SOURCE: Linux/glibc | _POSIX_C_SOURCE: POSIX | __EXTENSIONS__: Solaris
CFLAGS  ?= $(STD) $(WARN) -g -O2 -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -D__EXTENSIONS__
CPPFLAGS = -Isrc
LDFLAGS ?=
LDLIBS  ?= -lpthread

BIN_DIR  = bin
OBJ_DIR  = obj

SERVER_BIN = $(BIN_DIR)/socks5d
CLIENT_BIN = $(BIN_DIR)/socks5-mgmt

SERVER_SRC = \
	src/main.c \
	src/selector.c \
	src/buffer.c \
	src/stm.c \
	src/netutils.c \
	src/socks5.c \
	src/socks5_parsers.c \
	src/dns.c \
	src/mgmt.c \
	src/args.c \
	src/logger.c \
	src/metrics.c \
	src/users.c \
	src/config.c

CLIENT_SRC = src/client.c

SERVER_OBJ = $(SERVER_SRC:%.c=$(OBJ_DIR)/%.o)
CLIENT_OBJ = $(CLIENT_SRC:%.c=$(OBJ_DIR)/%.o)

.PHONY: all server client clean

all: server client

server: $(SERVER_BIN)
client: $(CLIENT_BIN)

$(SERVER_BIN): $(SERVER_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(CLIENT_BIN): $(CLIENT_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	$(RM) -r $(OBJ_DIR) $(BIN_DIR)
