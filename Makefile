# jproto build (GCC 16, OpenSSL 3.6+, liburing; RandomX vendored)
CC      ?= gcc
CXX     ?= g++
CFLAGS  ?= -O2 -std=gnu23 -Wall -Wextra
INC     := -Iinclude -Ivendor/RandomX/src
LIBS    := -lcrypto

RX_DIR   := vendor/RandomX
RX_LIB   := $(RX_DIR)/build/librandomx.a

# jppow живёт отдельным .so (ctypes/C-dlopen); в статике либы его не включаем
CSRCS := src/crypto.c src/framing.c src/net.c src/onion.c src/client.c src/secchan.c
POW_SRC := src/jppow.c
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
build/t_onion: tests/t_onion.c src/onion.c src/client.c src/crypto.c | build
	$(CC) $(CFLAGS) $(INC) tests/t_onion.c src/onion.c src/client.c src/crypto.c -o $@ $(LIBS)
build/t_secchan: tests/t_secchan.c src/secchan.c src/crypto.c src/framing.c src/net.c | build
	$(CC) $(CFLAGS) $(INC) tests/t_secchan.c src/secchan.c src/crypto.c src/framing.c src/net.c -o $@ $(LIBS) -lpthread
build/t_pow: tests/t_pow.c build/libjppow.so
	$(CC) $(CFLAGS) $(INC) tests/t_pow.c -o $@ build/libjppow.so -L$(RX_DIR)/build -lrandomx -lcrypto -Wl,-rpath,$$PWD/build -Wl,-rpath,$$PWD/$(RX_DIR)/build

tests: build/t_crypto build/t_framing build/t_onion build/t_shm build/t_uring build/t_secchan build/t_pow
	build/t_crypto && build/t_framing && build/t_onion && build/t_shm && build/t_uring && build/t_secchan && build/t_pow

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

# E2E чат: два jchat-клиента (secchan + onion v2 + PoW) через fedA
e2e-chat:
	python/.venv/bin/python tools/e2e_chat.py 127.0.0.1:9101

# ---- dev-чат: docker-ноды + 2 ручных клиента (scripts/jchat.sh) -------------
PYV    := python/.venv/bin/python
JCHAT  := scripts/jchat.sh

$(PYV):
	python3 -m venv python/.venv
	$(PYV) -m pip install -q -r python/requirements.txt

docker-restart: docker-build docker-up    ## пересборка образа + перезапуск нод

net: docker-up                            ## = docker-up (нода в докере)

chat-alice:   ## клиент №1 (идентичность dev/alice.json, нода fedA)
	$(JCHAT) alice

chat-bob:     ## клиент №2 (dev/bob.json; NODE=host:port чтобы к другой ноде)
	$(JCHAT) bob $(NODE)

chat-c:       ## клиент №3 у fedC (для кросс-федерации A→C)
	$(JCHAT) carl 127.0.0.1:9103

id:           ## карточки идентичностей dev/*.json (addr + размер pk)
	@for f in dev/*.json; do [ -f "$$f" ] || continue; \
		$(PYV) -c "import json; d=json.load(open('$$f')); print(f\"$$f  addr={d['addr'][:16]}…  pk={len(d['pk_kem'])//2}B\")"; done

cards:        ## публичные карточки dev/*.card (можно передавать собеседнику)
	@mkdir -p dev
	@for f in dev/[a-z]*.json; do [ -f "$$f" ] || { echo "нет dev/*.json (make chat-alice создаст)"; break; }; \
		n=$$(basename $$f .json); PYTHONPATH=python $(PYV) -m jproto_ref.chat card $$f > dev/$$n.card; \
		echo "dev/$$n.card → /to dev/$$n.card"; done

status:       ## /status всех нод федерации
	@for p in 9201 9202 9203; do echo "== fed$$(printf %d $$((p-9200))):"; \
		curl -sf http://127.0.0.1:$$p/status | $(PYV) -c "import json,sys;d=json.load(sys.stdin);print({k:d[k] for k in ('round','seff','bits_min','retention_est_h','n_active','local_recs','global_recs') if k in d})"; done

clean:
	rm -rf build

.PHONY: all tests clean docker-build docker-up docker-restart docker-logs docker-down e2e-ping e2e-chat chat-alice chat-bob chat-c id status net
