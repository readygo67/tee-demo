.PHONY: build start stop run test clean

build:
	./build-runtime.sh release
	./build-host.sh
	./build-loader.sh

start:
	./daemon.sh start

stop:
	./daemon.sh stop

run:
	./client.sh 2 3

test:
	./test.sh

clean:
	cargo clean
	rm -rf target
