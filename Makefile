build-docker:
	docker build . -t synack-analyzer

build:
	ldconfig -p | grep libpcap.so.0.8 || ( echo 'Library libpcap.so.0.8 not found. On Debian based distro package libpcap0.8-dev can be used.'; exit 1) && cargo build --release

run-docker-help:
	docker run -it synack-analyzer --help

run-docker:
	# NOT tested on rootless docker setup
	docker run --init --network=host -it synack-analyzer \
		--disable-dumping \
		--interface any \
		--immediate-mode \
		--metrics-port 8080 \
		--threshold-synack-ms 3
