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
	"github.com/protolambda/rumor/p2p/types"
	"github.com/protolambda/zrnt/eth2/beacon"
	"net"
	"os"
	"os/signal"
	"syscall"
)

type BootnodeCmd struct {
	Priv        flags.P2pPrivKeyFlag `ask:"--priv" help:"Private key, in raw hex encoded format"`
	ENRIP       net.IP               `ask:"--enr-ip" help:"IP to put in ENR"`
	ENRUDP      uint16               `ask:"--enr-udp" help:"UDP port to put in ENR"`
	ListenIP    net.IP               `ask:"--listen-ip" help:"Listen IP."`
	ListenUDP   uint16               `ask:"--listen-udp" help:"Listen UDP port. Will try ENR port otherwise."`
	NodeDBPath  string               `ask:"--node-db" help:"Path to dv5 node DB. Memory DB if empty."`
	Attnets     types.AttnetBits     `ask:"--attnets" help:"Attnet bitfield, as bytes."`
	Bootnodes   []string             `ask:"--bootnodes" help:"Optionally befriend other bootnodes"`
	ForkVersion beacon.Version       `ask:"--fork-version" help:"Eth2 fork version"`
	Color       bool                 `ask:"--color" help:"Log with colors"`
	Level       string               `ask:"--level" help:"Log level"`
}

func (b *BootnodeCmd) Help() string {
	return "Run bootnode."
}

func (b *BootnodeCmd) Default() {
	b.ListenIP = net.IPv4zero
	b.Color = true
	b.Level = "debug"
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

	localNode.Set(addrutil.NewEth2DataEntry(&types.Eth2Data{
		ForkDigest:      beacon.ComputeForkDigest(c.ForkVersion, beacon.Root{}),
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
