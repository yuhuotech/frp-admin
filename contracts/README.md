# Contracts

This module is the only wire contract shared by the control plane and agents.
It intentionally contains no database or UI models.

Generate Go bindings with:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
./scripts/generate.sh
```

Run `buf lint` and `buf breaking --against <main-branch-git-url>` in CI.

## Certificate rotation contract

Rotation is initiated only inside an authenticated `Connect` stream. The agent
sends `CertificateRotationRequest`; the gateway signs its CSR and correlates
`RotateCertificate.request_id` on the same node session. A rotated certificate
must contain the node ID as a DNS SAN and
`spiffe://frp-admin/{role}/{nodeID}` as a URI SAN, use a new serial, preserve
client-auth usage, and match the CSR public key. The current Agent capability
does not rotate trust roots: a response containing a CA different from the
locally pinned CA is rejected.
