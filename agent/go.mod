module github.com/frp-admin/frp-admin/agent

go 1.26.5

require (
	github.com/frp-admin/frp-admin/contracts v0.0.0
	github.com/pelletier/go-toml/v2 v2.4.3
	go.etcd.io/bbolt v1.5.0
	golang.org/x/sys v0.45.0
	google.golang.org/grpc v1.83.1
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

replace github.com/frp-admin/frp-admin/contracts => ../contracts
