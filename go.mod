module ngrok

go 1.23.0

// quic-go is pinned at v0.54.0 because that is the newest release declaring
// go 1.23 -- the toolchain pin above (v0.55+ needs go 1.24). Upgrading it
// rides the next deliberate toolchain upgrade, not an incidental `go get`
// (SPEC-CLUSTER7 review gate 5).
require (
	github.com/alecthomas/log4go v0.0.0-20180109082532-d146e6b86faa
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/gorilla/websocket v1.5.3
	github.com/inconshreveable/go-vhost v1.0.0
	github.com/inconshreveable/mousetrap v1.1.0
	github.com/nsf/termbox-go v1.1.1
	github.com/quic-go/quic-go v0.54.0
	github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9
	github.com/xtaci/smux/v2 v2.1.0
	gopkg.in/inconshreveable/go-update.v0 v0.0.0-20150814200126-d8b0b1d421aa
	gopkg.in/yaml.v3 v3.0.1
)

require cel.dev/cel-go v0.32.0

require (
	cel.dev/expr v0.25.3 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/kr/binarydist v0.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-runewidth v0.0.30 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/exp v0.0.0-20240823005443-9b4947da3948 // indirect
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/tools v0.36.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
