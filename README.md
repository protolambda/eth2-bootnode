# Eth2 bootnode

Minimal bootnode utility, with ENR options, geth discv5 logging, and persisted local node DB. 

Options:
```
      --attnets bytes8         Attnet bitfield, as bytes. (default 0000000000000000)
      --bootnodes strings      Optionally befriend other bootnodes
      --color                  Log with colors (default true)
      --enr-ip ip              IP to put in ENR
      --enr-udp uint16         UDP port to put in ENR
      --fork-version bytes4    Eth2 fork version (default 00000000)
      --level string           Log level (default "debug")
      --listen-ip ip           Listen IP. (default 0.0.0.0)
      --listen-udp uint16      Listen UDP port. Will try ENR port otherwise.
      --node-db string         Path to dv5 node DB. Memory DB if empty.
      --priv P2P Private key   Private key, in raw hex encoded format (default ? (no private key data))
```


## License

MIT, see [`LICENSE`](./LICENSE) file.
