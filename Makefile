.PHONY: default server client deps fmt clean all release-all assets client-assets server-assets contributors

BUILDTAGS=debug
default: all

deps: assets
	go mod download
	go mod tidy

server: deps
	go build -tags '$(BUILDTAGS)' -o bin/ngrokd ./main/ngrokd

fmt:
	go fmt ./...

client: deps
	go build -tags '$(BUILDTAGS)' -o bin/ngrok ./main/ngrok

assets: client-assets server-assets

bin/go-bindata:
	@mkdir -p bin
	@if ! command -v go-bindata >/dev/null 2>&1; then \
		go install github.com/jayluxferro/go-bindata/go-bindata@latest; \
	fi
	@if [ ! -f bin/go-bindata ]; then \
		cp $$(go env GOPATH)/bin/go-bindata bin/go-bindata 2>/dev/null || true; \
	fi

client-assets: bin/go-bindata
	@mkdir -p client/assets
	bin/go-bindata -nomemcopy -pkg=assets -tags=$(BUILDTAGS) \
		-debug=$(if $(findstring debug,$(BUILDTAGS)),true,false) \
		-o=client/assets/assets_$(BUILDTAGS).go \
		assets/client/...

server-assets: bin/go-bindata
	@mkdir -p server/assets
	bin/go-bindata -nomemcopy -pkg=assets -tags=$(BUILDTAGS) \
		-debug=$(if $(findstring debug,$(BUILDTAGS)),true,false) \
		-o=server/assets/assets_$(BUILDTAGS).go \
		assets/server/...

release-client: BUILDTAGS=release
release-client: client

release-server: BUILDTAGS=release
release-server: server

release-all: fmt release-client release-server

all: fmt client server

clean:
	go clean -cache
	rm -rf bin/
	rm -rf client/assets/ server/assets/

contributors:
	echo "Contributors to ngrok, both large and small:\n" > CONTRIBUTORS
	git log --raw | grep "^Author: " | sort | uniq | cut -d ' ' -f2- | sed 's/^/- /' | cut -d '<' -f1 >> CONTRIBUTORS
