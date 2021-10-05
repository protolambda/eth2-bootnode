package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	gcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/protolambda/ask"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type P2pPrivKeyFlag struct {
	Priv *crypto.Secp256k1PrivateKey
}

func (f P2pPrivKeyFlag) String() string {
	if f.Priv == nil {
		return "? (no private key data)"
	}
	secpKey := f.Priv
	keyBytes, err := secpKey.Raw()
	if err != nil {
		return "? (invalid private key)"
	}
	return hex.EncodeToString(keyBytes)
}

func (f *P2pPrivKeyFlag) Set(value string) error {
	// No private key if no data
	if value == "" {
		f.Priv = nil
		return nil
	}
	var priv *crypto.Secp256k1PrivateKey
	var err error
	priv, err = ParsePrivateKey(value)
	if err != nil {
		return fmt.Errorf("could not parse private key: %v", err)
	}
	f.Priv = priv
	return nil
}

func (f *P2pPrivKeyFlag) Type() string {
	return "P2P Private key"
}

func ParsePrivateKey(v string) (*crypto.Secp256k1PrivateKey, error) {
	if strings.HasPrefix(v, "0x") {
		v = v[2:]
	}
	privKeyBytes, err := hex.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key, expected hex string: %v", err)
	}
	var priv crypto.PrivKey
	priv, err = crypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key, invalid private key (Secp256k1): %v", err)
	}
	key := (priv).(*crypto.Secp256k1PrivateKey)
	key.Curve = gcrypto.S256()              // Temporary hack, so libp2p Secp256k1 is recognized as geth Secp256k1 in disc v5.1
	if !key.Curve.IsOnCurve(key.X, key.Y) { // TODO: should we be checking this?
		return nil, fmt.Errorf("invalid private key, not on curve")
	}
	return key, nil
}

func ParseEnode(v string) (*enode.Node, error) {
	addr := new(enode.Node)
	err := addr.UnmarshalText([]byte(v))
	if err != nil {
		return nil, err
	}
	return addr, nil
}

func ParseEnrBytes(v string) ([]byte, error) {
	if strings.HasPrefix(v, "enr:") {
		v = v[4:]
		if strings.HasPrefix(v, "//") {
			v = v[2:]
		}
	}
	return base64.RawURLEncoding.DecodeString(v)
}

func ParseEnr(v string) (*enr.Record, error) {
	data, err := ParseEnrBytes(v)
	if err != nil {
		return nil, err
	}
	var record enr.Record
	if err := rlp.Decode(bytes.NewReader(data), &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func EnrToEnode(record *enr.Record, verifySig bool) (*enode.Node, error) {
	idSchemeName := record.IdentityScheme()

	if verifySig {
		if err := record.VerifySignature(enode.ValidSchemes[idSchemeName]); err != nil {
			return nil, err
		}
	}

	return enode.New(enode.ValidSchemes[idSchemeName], record)
}

func ParseEnrOrEnode(v string) (*enode.Node, error) {
	if strings.HasPrefix(v, "enode://") {
		return ParseEnode(v)
	} else {
		enrAddr, err := ParseEnr(v)
		if err != nil {
			return nil, err
		}
		enodeAddr, err := EnrToEnode(enrAddr, true)
		if err != nil {
			return nil, err
		}
		return enodeAddr, nil
	}
}

type BootnodeCmd struct {
	Priv       P2pPrivKeyFlag `ask:"--priv" help:"Private key, in raw hex encoded format"`
	ENRIP      net.IP         `ask:"--enr-ip" help:"IP to put in ENR"`
	ENRUDP     uint16         `ask:"--enr-udp" help:"UDP port to put in ENR"`
	ListenIP   net.IP         `ask:"--listen-ip" help:"Listen IP."`
	ListenUDP  uint16         `ask:"--listen-udp" help:"Listen UDP port. Will try ENR port otherwise."`
	APIAddr    string         `ask:"--api-addr" help:"Address to bind HTTP API server to. API is disabled if empty."`
	NodeDBPath string         `ask:"--node-db" help:"Path to dv5 node DB. Memory DB if empty."`
	Bootnodes  []string       `ask:"--bootnodes" help:"Optionally befriend other bootnodes"`
	Color      bool           `ask:"--color" help:"Log with colors"`
	Level      string         `ask:"--level" help:"Log level"`
}

func (b *BootnodeCmd) Help() string {
	return "Run bootnode."
}

func (b *BootnodeCmd) Default() {
	b.ListenIP = net.IPv4zero
	b.Color = true
	b.Level = "debug"
	b.APIAddr = "0.0.0.0:8000"
}

func (c *BootnodeCmd) Run(ctx context.Context, args ...string) error {
	bootNodes := make([]*enode.Node, 0, len(c.Bootnodes))
	for i := 0; i < len(c.Bootnodes); i++ {
		dv5Addr, err := ParseEnrOrEnode(c.Bootnodes[i])
		if err != nil {
			return fmt.Errorf("bootnode %d is bad: %v", i, err)
		}
		bootNodes = append(bootNodes, dv5Addr)
	}

	if c.Priv.Priv == nil {
		return fmt.Errorf("need p2p priv key")
	}

	ecdsaPrivKey := (*ecdsa.PrivateKey)(c.Priv.Priv)

	if c.ListenUDP == 0 {
		c.ListenUDP = c.ENRUDP
	}

	udpAddr := &net.UDPAddr{
		IP:   c.ListenIP,
		Port: int(c.ListenUDP),
	}

	localNodeDB, err := enode.OpenDB(c.NodeDBPath)
	if err != nil {
		return err
	}
	localNode := enode.NewLocalNode(localNodeDB, ecdsaPrivKey)
	if c.ENRIP != nil {
		localNode.SetStaticIP(c.ENRIP)
	}
	if c.ENRUDP != 0 {
		localNode.SetFallbackUDP(int(c.ENRUDP))
	}

	fmt.Println(localNode.Node().String())

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	lvl, err := log.LvlFromString(c.Level)
	if err != nil {
		return err
	}
	gethLogger := log.New()
	outHandler := log.StreamHandler(os.Stdout, log.TerminalFormat(c.Color))
	gethLogger.SetHandler(log.LvlFilterHandler(lvl, outHandler))

	// Optional HTTP server, to read the ENR from
	var srv *http.Server
	if c.APIAddr != "" {
		router := http.NewServeMux()
		srv = &http.Server{
			Addr:    c.APIAddr,
			Handler: router,
		}
		router.HandleFunc("/enr", func(w http.ResponseWriter, req *http.Request) {
			gethLogger.Info("received ENR API request", "remote", req.RemoteAddr)
			w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
			w.WriteHeader(200)
			enr := localNode.Node().String()
			if _, err := io.WriteString(w, enr); err != nil {
				gethLogger.Error("failed to respond to request from", "remote", req.RemoteAddr, "err", err)
			}
		})

		go func() {
			gethLogger.Info("starting API server, ENR reachable on: http://" + srv.Addr + "/enr")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				gethLogger.Error("API server listen failure", "err", err)
			}
		}()
	}

	cfg := discover.Config{
		PrivateKey:   ecdsaPrivKey,
		NetRestrict:  nil,
		Bootnodes:    bootNodes,
		Unhandled:    nil, // Not used in dv5
		Log:          gethLogger,
		ValidSchemes: enode.ValidSchemes,
	}
	udpV5, err := discover.ListenV5(conn, localNode, cfg)
	if err != nil {
		return err
	}
	defer udpV5.Close()
	<-ctx.Done()

	// Close API server
	if srv != nil {
		ctx, _ := context.WithTimeout(context.Background(), time.Second*5)
		if err := srv.Shutdown(ctx); err != nil {
			log.Error("Server shutdown failed", "err", err)
		}
	}
	return nil
}

func main() {
	loadedCmd, err := ask.Load(&BootnodeCmd{})
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		cancel()
		time.Sleep(time.Second)
	}()

	if cmd, err := loadedCmd.Execute(ctx, nil, os.Args[1:]...); err == ask.UnrecognizedErr {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	} else if err == ask.HelpErr {
		_, _ = fmt.Fprintln(os.Stderr, cmd.Usage(false))
		os.Exit(0)
	} else if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	} else if cmd == nil {
		_, _ = fmt.Fprintln(os.Stderr, "failed to load command")
		os.Exit(1)
	}
	os.Exit(0)
}
