# jproto build (GCC 16, OpenSSL 3.6+, liburing; RandomX vendored)
CC      ?= gcc
CXX     ?= g++
CFLAGS  ?= -O2 -std=gnu23 -Wall -Wextra
INC     := -Iinclude -Ivendor/RandomX/src
LIBS    := -lcrypto

RX_DIR   := vendor/RandomX
RX_LIB   := $(RX_DIR)/build/librandomx.a

CSRCS := src/crypto.c src/framing.c src/net.c src/onion.c src/jppow.c
LIBOBJS := $(patsubst src/%.c,build/obj/%.o,$(CSRCS))

all: build/obj build/libjproto.a build/jpc build/t_all tests

build/obj build/lib build:
	mkdir -p $@

build/obj/%.o: src/%.c | build/obj
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

$(RX_LIB):
	cmake -B $(RX_DIR)/build -DCMAKE_POSITION_INDEPENDENT_CODE=ON $(RX_DIR) >/dev/null
	cmake --build $(RX_DIR)/build -j$$(nproc) >/dev/null

build/libjppow.so: src/jppow.c $(RX_LIB) | build/lib
	$(CC) $(CFLAGS) -fPIC -shared src/jppow.c $(INC) -o $@ -L$(RX_DIR)/build -lrandomx -lstdc++ -lpthread

build/libjproto.a: $(LIBOBJS)
	ar rcs $@ $(LIBOBJS)

# CLI-клиент (минимум: keygen/ping/dir; транспорт — блокирующий)
build/jpc: tools/jpc.c $(LIBOBJS) | build
	$(CC) $(CFLAGS) $(INC) tools/jpc.c $(LIBOBJS) -o $@ $(LIBS)

# общие тесты
build/t_crypto: tests/t_crypto.c src/crypto.c | build
	$(CC) $(CFLAGS) $(INC) tests/t_crypto.c src/crypto.c -o $@ $(LIBS)
build/t_framing: tests/t_framing.c src/framing.c | build
	$(CC) $(CFLAGS) $(INC) tests/t_framing.c src/framing.c -o $@
build/t_onion: tests/t_onion.c src/onion.c src/crypto.c | build
	$(CC) $(CFLAGS) $(INC) tests/t_onion.c src/onion.c src/crypto.c -o $@ $(LIBS)
build/t_pow: tests/t_pow.c build/libjppow.so
	$(CC) $(CFLAGS) $(INC) tests/t_pow.c -o $@ build/libjppow.so -L$(RX_DIR)/build -lrandomx -lcrypto -Wl,-rpath,$$PWD/build -Wl,-rpath,$$PWD/$(RX_DIR)/build

tests: build/t_crypto build/t_framing build/t_onion build/t_shm build/t_uring build/t_pow
	build/t_crypto && build/t_framing && build/t_onion && build/t_shm && build/t_uring && build/t_pow

build/t_shm: tests/t_shm.c src/shm.c | build
	$(CC) $(CFLAGS) $(INC) tests/t_shm.c src/shm.c -o $@ -lpthread
build/t_uring: tests/t_uring.c src/net_uring.c src/net.c src/framing.c | build
	$(CC) $(CFLAGS) $(INC) tests/t_uring.c src/net_uring.c src/net.c src/framing.c -o $@ $$(pkg-config --cflags --libs liburing)

# ---- docker: ноды федераций в контейнерах, клиенты — с хоста ----
docker-build:
	sudo docker compose -f docker/compose.yml build

docker-up:
	sudo docker compose -f docker/compose.yml up -d

docker-logs:
	sudo docker compose -f docker/compose.yml logs -f

docker-down:
	sudo docker compose -f docker/compose.yml down

# E2E мин: host-клиент `jpc ping` → контейнер fedA (HELLO + SEED)
e2e-ping: build/jpc
	build/jpc ping --node 127.0.0.1:9101

clean:
	rm -rf build

.PHONY: all tests clean docker-build docker-up docker-logs docker-down e2e-ping
