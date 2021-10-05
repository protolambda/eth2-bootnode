# Eth2 bootnode

Minimal bootnode utility, with ENR options, geth discv5 logging, and persisted local node DB. 

And a minimal HTTP endpoint, to serve the local ENR, in common base64 ENR representation, on the `/enr` route.

Options:
```
  --priv                      Private key, in raw hex encoded format (default: ? (no private key data)) (type: P2P Private key)
  --enr-ip                    IP to put in ENR (default: <nil>) (type: ip)
  --enr-udp                   UDP port to put in ENR (default: 0) (type: uint16)
  --listen-ip                 Listen IP. (default: 0.0.0.0) (type: ip)
  --listen-udp                Listen UDP port. Will try ENR port otherwise. (default: 0) (type: uint16)
  --api-addr                  Address to bind HTTP API server to. API is disabled if empty. (default: 0.0.0.0:8000) (type: string)
  --node-db                   Path to dv5 node DB. Memory DB if empty. (type: string)
  --bootnodes                 Optionally befriend other bootnodes (type: stringSlice)
  --color                     Log with colors (default: true) (type: bool)
  --level                     Log level (default: debug) (type: string)
```

[Docker: `protolambda/eth2-bootnode`](https://hub.docker.com/repository/docker/protolambda/eth2-bootnode)

## License

MIT, see [`LICENSE`](./LICENSE) file.
