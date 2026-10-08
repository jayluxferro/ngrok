.PHONY: default server client bot deps bot-deps fmt clean all release-all release-bot assets client-assets server-assets contributors

BUILDTAGS ?= debug
export BUILDTAGS
default: all

deps: assets
	go mod download
	@go mod tidy 2>&1 | grep -v "pkg/mod" || true

# The bot embeds no assets and imports none of the assets packages, so it
# must not ride `deps` (deps generates the client/server assets first);
# its dependency chain is the module download and nothing else.
bot-deps:
	go mod download
	@go mod tidy 2>&1 | grep -v "pkg/mod" || true

server: deps
	go build -tags '$(BUILDTAGS)' -o bin/ngrokd ./main/ngrokd

fmt:
	@go list ./... 2>&1 | grep -v 'pkg/mod' | grep -v 'outside main module' | xargs -I {} go fmt {} 2>/dev/null || true

client: deps
	go build -tags '$(BUILDTAGS)' -o bin/ngrok ./main/ngrok

bot: bot-deps
	go build -tags '$(BUILDTAGS)' -o bin/ngrok-bot ./main/ngrok-bot

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

# The release tag is harmless for the bot (nothing asset-bearing to embed);
# kept for consistency with the other release targets.
release-bot: BUILDTAGS=release
release-bot: bot

release-all: fmt release-client release-server

all: fmt client server

clean:
	go clean -cache
	rm -rf bin/
	rm -rf client/assets/ server/assets/

contributors:
	echo "Contributors to ngrok, both large and small:\n" > CONTRIBUTORS
	git log --raw | grep "^Author: " | sort | uniq | cut -d ' ' -f2- | sed 's/^/- /' | cut -d '<' -f1 >> CONTRIBUTORS
