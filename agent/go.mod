module github.com/frp-admin/frp-admin/agent

go 1.26.5

require (
	github.com/frp-admin/frp-admin/contracts v0.0.0
	github.com/pelletier/go-toml/v2 v2.2.4
	go.etcd.io/bbolt v1.4.0
	google.golang.org/grpc v1.82.1
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
)

replace github.com/frp-admin/frp-admin/contracts => ../contracts
