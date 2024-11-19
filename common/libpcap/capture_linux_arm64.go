package libpcap

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"slices"
	"sync/atomic"
)

func CaptureChild(device string) error {
	inter, err := net.InterfaceByName(device)
	if err != nil {
		fmt.Printf(fmt.Sprintf("net.InterfaceByName error: %v\n", err))
		return err
	}

	addrs, err := inter.Addrs()
	if err != nil {
		fmt.Printf("inter.Addrs() error: %v\n", err)
		return err
	}

	var ipv4Addr net.IP
	var ipv6Addr net.IP
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				if ip4 := ip.To4(); ip4 != nil {
					ipv4Addr = ip4
					continue
				}

				if ip6 := ip.To16(); ip6 != nil && ip6[0] != 0xfe {
					ipv6Addr = ip6
				}
			}
		}
	}

	handle, err := pcap.OpenLive(device, 2048, false, pcap.BlockForever)
	if err != nil {
		fmt.Printf("pcap.OpenLive %s failed: %v\n", device, err)
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case packet := <-packets:
			{
				var packetSize uint64
				var isSend bool
				var isIpv4 bool
				ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
				if ipv4Layer != nil {
					ip, _ := ipv4Layer.(*layers.IPv4)
					if slices.Equal(ip.SrcIP, ipv4Addr) {
						isSend = true
					} else if slices.Equal(ip.DstIP, ipv4Addr) {
						isSend = false
					} else {
						continue
					}
					packetSize = uint64(len(ip.Payload)) + uint64(len(ip.Contents))
					isIpv4 = true
				} else {
					ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
					if ipv6Layer == nil {
						continue
					}
					ip, _ := ipv6Layer.(*layers.IPv6)
					if slices.Equal(ip.SrcIP, ipv6Addr) {
						isSend = true
					} else if slices.Equal(ip.DstIP, ipv6Addr) {
						isSend = false
					} else {
						continue
					}
					packetSize = uint64(len(ip.Payload)) + uint64(len(ip.Contents))
					isIpv4 = false
				}

				var port uint64
				tcp := packet.Layer(layers.LayerTypeTCP)
				if tcp != nil {
					packet := tcp.(*layers.TCP)
					if isSend {
						port = uint64(packet.SrcPort)
					} else {
						port = uint64(packet.DstPort)
					}

					if isIpv4 {
						if _, ok := PcapRuleManager.Get().Tcp4Map[port]; !ok {
							if isSend {
								PcapRuleManager.Get().UnknowTcp4Send[port] += packetSize
							} else {
								PcapRuleManager.Get().UnknowTcp4Recv[port] += packetSize
							}
							continue
						}
					} else {
						if _, ok := PcapRuleManager.Get().Tcp6Map[port]; !ok {
							if isSend {
								PcapRuleManager.Get().UnknowTcp6Send[port] += packetSize
							} else {
								PcapRuleManager.Get().UnknowTcp6Recv[port] += packetSize
							}
							continue
						}
					}
				} else {
					udp := packet.Layer(layers.LayerTypeUDP)
					if udp != nil {
						packet := udp.(*layers.UDP)
						if isSend {
							port = uint64(packet.SrcPort)
						} else {
							port = uint64(packet.DstPort)
						}

						if isIpv4 {
							if _, ok := PcapRuleManager.Get().Udp4Map[port]; !ok {
								if isSend {
									PcapRuleManager.Get().UnknowUdp4Send[port] += packetSize
								} else {
									PcapRuleManager.Get().UnknowUdp4Recv[port] += packetSize
								}
								continue
							}
						} else {
							if _, ok := PcapRuleManager.Get().Udp6Map[port]; !ok {
								if isSend {
									PcapRuleManager.Get().UnknowUdp6Send[port] += packetSize
								} else {
									PcapRuleManager.Get().UnknowUdp6Recv[port] += packetSize
								}
								continue
							}
						}
					} else {
						continue
					}
				}

				if isSend {
					if isIpv4 {
						atomic.AddUint64(&TxIpv4, packetSize)
					} else {
						atomic.AddUint64(&TxIpv6, packetSize)
					}
				} else {
					if isIpv4 {
						atomic.AddUint64(&RxIpv4, packetSize)
					} else {
						atomic.AddUint64(&RxIpv6, packetSize)
					}
				}
			}
		}
	}
}
