package main

import (
	"flag"
	"fmt"
	"nethogs4go/common/libpcap"
	"time"
	"github.com/pkg/profile"
)

var (
	dev string
	pid int64
)

func init() {
	flag.StringVar(&dev, "dev", "ens33", "iface")
	flag.Int64Var(&pid, "pid", 0, "pid")
	flag.Parse()
}

func main() {
	go func() {
		for {
						timeStr := time.Now().Format("20060102150405")
						profile_path := fmt.Sprintf("profile/%s", timeStr)
						p := profile.Start(profile.CPUProfile,  
										profile.ProfilePath(profile_path),  
										profile.NoShutdownHook,  
		)
		time.Sleep(30 * time.Second)
		p.Stop()
		time.Sleep(30 * time.Second)
		}
	}()

	libpcap.InitProcRules(uint64(pid))

	go libpcap.CaptureChild(dev)

	var lastTxIpv4, lastTxIpv6, lastRxIpv4, lastRxIpv6 uint64
	for {
		time.Sleep(300 * time.Second)
		fmt.Printf("FLow: %d, %d, %d, %d, tx5=%d, rx5=%d\n",
			libpcap.TxIpv4, libpcap.TxIpv6, libpcap.RxIpv4, libpcap.RxIpv6,
			(libpcap.TxIpv4+libpcap.TxIpv6-lastTxIpv4-lastTxIpv6)/300,
			(libpcap.RxIpv4+libpcap.RxIpv6-lastRxIpv4-lastRxIpv6)/300)
		lastTxIpv4 = libpcap.TxIpv4
		lastTxIpv6 = libpcap.TxIpv6
		lastRxIpv4 = libpcap.RxIpv4
		lastRxIpv6 = libpcap.RxIpv6
	}
}
