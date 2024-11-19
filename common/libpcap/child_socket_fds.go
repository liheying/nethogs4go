package libpcap

import (
  "bufio"
  "strings"
  "path/filepath"
  "fmt"
  "os"
  "strconv"
  "time"
  "io/ioutil"
  "sync/atomic"
)

var TxIpv4 uint64
var RxIpv4 uint64
var TxIpv6 uint64
var RxIpv6 uint64

var label = "socket:["

type NetPcapMap struct {
  InodeMap map[uint64]uint64
  Udp4Map map[uint64]uint64
  Tcp4Map map[uint64]uint64
  Tcp6Map map[uint64]uint64
  Udp6Map map[uint64]uint64

  UnknowTcp4Recv map[uint64]uint64
  UnknowTcp4Send map[uint64]uint64
  UnknowTcp6Recv map[uint64]uint64
  UnknowTcp6Send map[uint64]uint64
  UnknowUdp4Recv map[uint64]uint64
  UnknowUdp4Send map[uint64]uint64
  UnknowUdp6Recv map[uint64]uint64
  UnknowUdp6Send map[uint64]uint64
}

func NewNetPcapMap() *NetPcapMap {
	var proc NetPcapMap
	proc.InodeMap = make(map[uint64]uint64)
	proc.Udp4Map = make(map[uint64]uint64)
	proc.Tcp4Map = make(map[uint64]uint64)
	proc.Tcp6Map = make(map[uint64]uint64)
	proc.Udp6Map = make(map[uint64]uint64)

  proc.UnknowTcp4Recv = make(map[uint64]uint64)
  proc.UnknowTcp4Send = make(map[uint64]uint64)
  proc.UnknowTcp6Recv = make(map[uint64]uint64)
  proc.UnknowTcp6Send = make(map[uint64]uint64)
  proc.UnknowUdp4Recv = make(map[uint64]uint64)
  proc.UnknowUdp4Send = make(map[uint64]uint64)
  proc.UnknowUdp6Recv = make(map[uint64]uint64)
  proc.UnknowUdp6Send = make(map[uint64]uint64)

  return &proc
}

const NetPcapArrayCount = 3

type NetPcapMapArray struct {
  InodeArray [NetPcapArrayCount]*NetPcapMap
  index uint64
}

func (array *NetPcapMapArray) Get() *NetPcapMap {
  index := atomic.LoadUint64(&array.index)
  return array.InodeArray[index]
}

func (array *NetPcapMapArray) Set(nmap *NetPcapMap) {
  curr_index := array.index
  pre_index := (array.index - 1 + NetPcapArrayCount) % NetPcapArrayCount
  new_index := (array.index + 1) % NetPcapArrayCount
  array.InodeArray[new_index] = nmap
  atomic.StoreUint64(&array.index, new_index)
  
  if array.InodeArray[curr_index] != nil && array.InodeArray[pre_index] != nil {
    first := array.InodeArray[pre_index]
    second := array.InodeArray[curr_index]
    for k, v := range first.UnknowTcp4Recv {
      if _, ok := second.Tcp4Map[k]; ok {
        atomic.AddUint64(&RxIpv4, v)
      }
    }
  
    for k, v := range first.UnknowTcp4Send {
      if _, ok := second.Tcp4Map[k]; ok {
        atomic.AddUint64(&TxIpv4, v)
      }
    }
  
    for k, v := range first.UnknowTcp6Recv {
      if _, ok := second.Tcp6Map[k]; ok {
        atomic.AddUint64(&RxIpv6, v)
      }
    }
  
    for k, v := range first.UnknowTcp6Send {
      if _, ok := second.Tcp6Map[k]; ok {
        atomic.AddUint64(&TxIpv6, v)
      }
    }

    for k, v := range first.UnknowUdp4Recv {
      if _, ok := second.Udp4Map[k]; ok {
        atomic.AddUint64(&RxIpv4, v)
      }
    }
  
    for k, v := range first.UnknowUdp4Send {
      if _, ok := second.Udp4Map[k]; ok {
        atomic.AddUint64(&TxIpv4, v)
      }
    }
  
    for k, v := range first.UnknowUdp6Recv {
      if _, ok := second.Udp6Map[k]; ok {
        atomic.AddUint64(&RxIpv6, v)
      }
    }
  
    for k, v := range first.UnknowUdp6Send {
      if _, ok := second.Udp6Map[k]; ok {
        atomic.AddUint64(&TxIpv6, v)
      }
    }
  }
}

var PcapRuleManager NetPcapMapArray

func InitAllChild(ppid uint64, pcapMap *NetPcapMap) {
	files, err := filepath.Glob("/proc/[0-9]*/status")
  if err != nil {
		fmt.Printf("FindAllChild failed: %v\n", err)
    return
  }

	for _, fpath := range files {
    file, err := os.Open(fpath)
    if err != nil {
      fmt.Printf("open %s failes.\n", fpath)
      continue
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    var pid uint64
    var parent_pid uint64
  FOR:
    for scanner.Scan() {
      if strings.Contains(scanner.Text(), "PPid") {
        splitted := strings.Fields(scanner.Text())
        if len(splitted) == 2 {
          parent_pid, _ = strconv.ParseUint(splitted[1], 10, 0)
          if parent_pid == ppid {
            results := UpdateChild(pid)
            for k, _ := range results {
              pcapMap.InodeMap[k] = 0
            }
          }
        }
        break FOR
      }

      if strings.Contains(scanner.Text(), "Pid") {
        splitted := strings.Fields(scanner.Text())
        if len(splitted) == 2 {
          pid, _ = strconv.ParseUint(splitted[1], 10, 0)
        }
      }
    }
  }
}

func InitProcRules(pid uint64) {
  updateProcRules(pid)

  go updateProcRoutine(pid)
}

func updateProcRules(pid uint64) {
	procMap := NewNetPcapMap()

  results := UpdateChild(pid)
	for k, _ := range results {
		procMap.InodeMap[k] = 0
	}

	InitAllChild(pid, procMap)

  LoadProcNet(procMap)

  PcapRuleManager.Set(procMap)
}

func updateProcRoutine(pid uint64) {
  for {
    time.Sleep(3 * time.Second)

    updateProcRules(pid)
  }
}

func UpdateChild(pid uint64) map[uint64]uint64 {
  results := make(map[uint64]uint64, 0)
	path := fmt.Sprintf("/proc/%d/fd/[0-9]*", pid)
  files, err := filepath.Glob(path)
  if err != nil {
		fmt.Printf("UpdateChild %d failed: %v\n", pid, err)
    return results
  }
  for _, fpath := range files {
    name, _ := os.Readlink(fpath)
		if !strings.HasPrefix(name, label) {
			continue
		}
    inode := name[len(label) : len(name)-1]
    int_inode, _ := strconv.ParseUint(inode, 10, 64)
    if int_inode != 0 {
      results[int_inode] = 0
    }
  }

  fmt.Printf("Proc id: %d, socket: %d\n", pid, len(results))
  return results
}

func parseNetworkLines(fpath string) ([]string, error) {
	data, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	return lines[1 : len(lines)-1], nil
}

func parseOneLine(line string) (string, string, uint64) {
  words := strings.Fields(line)
  localAddr := words[1]
  remoteAddr := words[2]
  inode, _ := strconv.ParseUint(words[9], 10, 0)
  return localAddr, remoteAddr, inode
}

func parseAddr4(addr string) (uint64, uint64) {
  ipstr := strings.Split(addr, ":")
	if len(ipstr) != 2 {
		return 0, 0
	}

  port, _ := strconv.ParseUint(ipstr[1], 16, 0)
  ip, _ := strconv.ParseUint(ipstr[0], 16, 0)
  return ip, port
}

func LoadProcNet(pcapMap *NetPcapMap) {
  data, _ := parseNetworkLines("/proc/net/tcp")
	for _, line := range data {
    localAddr, _, inode := parseOneLine(line)
    if inode == 0 {
      continue
    }
    if _, ok := pcapMap.InodeMap[inode]; ok {
      _, port := parseAddr4(localAddr)
      if port != 0 {
        pcapMap.Tcp4Map[port] = inode
      }
    }
	}

  data, _ = parseNetworkLines("/proc/net/udp")
  for _, line := range data {
    localAddr, _, inode:= parseOneLine(line)
    if inode == 0 {
      continue
    }
    if _, ok := pcapMap.InodeMap[inode]; ok {
      _, port := parseAddr4(localAddr)
      if port != 0 {
        pcapMap.Udp4Map[port] = inode
      }
    }
  }

  data, _ = parseNetworkLines("/proc/net/tcp6")
	for _, line := range data {
    localAddr, _, inode := parseOneLine(line)
    if inode == 0 {
      continue
    }
    if _, ok := pcapMap.InodeMap[inode]; ok {
      _, port := parseAddr4(localAddr)
      if port != 0 {
        pcapMap.Tcp6Map[port] = inode
      }
    }
	}

  data, _ = parseNetworkLines("/proc/net/udp6")
  for _, line := range data {
    localAddr, _, inode:= parseOneLine(line)
    if inode == 0 {
      continue
    }
    if _, ok := pcapMap.InodeMap[inode]; ok {
      _, port := parseAddr4(localAddr)
      if port != 0 {
        pcapMap.Udp6Map[port] = inode
      }
    }
  }
}