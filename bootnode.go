package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/protolambda/ask"
	"github.com/protolambda/rumor/control/actor/flags"
	"github.com/protolambda/rumor/p2p/addrutil"
	"github.com/protolambda/zrnt/eth2/beacon"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type BootnodeCmd struct {
	Priv                 flags.P2pPrivKeyFlag `ask:"--priv" help:"Private key, in raw hex encoded format"`
	ENRIP                net.IP               `ask:"--enr-ip" help:"IP to put in ENR"`
	ENRUDP               uint16               `ask:"--enr-udp" help:"UDP port to put in ENR"`
	ListenIP             net.IP               `ask:"--listen-ip" help:"Listen IP."`
	ListenUDP            uint16               `ask:"--listen-udp" help:"Listen UDP port. Will try ENR port otherwise."`
	APIAddr              string               `ask:"--api-addr" help:"Address to bind HTTP API server to. API is disabled if empty."`
	NodeDBPath           string               `ask:"--node-db" help:"Path to dv5 node DB. Memory DB if empty."`
	Attnets              beacon.AttnetBits    `ask:"--attnets" help:"Attnet bitfield, as bytes."`
	Bootnodes            []string             `ask:"--bootnodes" help:"Optionally befriend other bootnodes"`
	ForkVersion          beacon.Version       `ask:"--fork-version" help:"Eth2 fork version"`
	GenesiValidatorsRoot beacon.Root          `ask:"--genesis-validators-root" help:"Used to compute a nice fork digest, zeroes is acceptable pre-genesis for bootnodes"`
	Color                bool                 `ask:"--color" help:"Log with colors"`
	Level                string               `ask:"--level" help:"Log level"`
}

func (b *BootnodeCmd) Help() string {
	return "Run bootnode."
}

func (b *BootnodeCmd) Default() {
	b.ListenIP = net.IPv4zero
	b.Color = true
	b.Level = "debug"
	b.APIAddr = "0.0.0.0:8000"
	b.ForkVersion = beacon.Version{}       // zeroes is mainnet
	b.GenesiValidatorsRoot = beacon.Root{} // zeroes is ok for pre-genesis
}

func (c *BootnodeCmd) Run(ctx context.Context, args ...string) error {
	bootNodes := make([]*enode.Node, 0, len(c.Bootnodes))
	for i := 0; i < len(c.Bootnodes); i++ {
		dv5Addr, err := addrutil.ParseEnrOrEnode(c.Bootnodes[i])
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
	localNode.Set(addrutil.NewAttnetsENREntry(&c.Attnets))

	localNode.Set(addrutil.NewEth2DataEntry(&beacon.Eth2Data{
		ForkDigest:      beacon.ComputeForkDigest(c.ForkVersion, c.GenesiValidatorsRoot),
		NextForkVersion: c.ForkVersion,
		NextForkEpoch:   ^beacon.Epoch(0),
	}))

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
	}()

	if cmd, isHelp, err := loadedCmd.Execute(ctx, os.Args[1:]...); err != nil {
		_, _ = os.Stderr.WriteString(err.Error())
	} else if isHelp {
		_, _ = os.Stderr.WriteString(cmd.Usage())
	}
}
