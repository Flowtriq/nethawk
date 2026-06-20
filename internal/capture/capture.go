package capture

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Snapshot struct {
	Timestamp   time.Time         `json:"timestamp"`
	Interface   string            `json:"interface"`
	PPS         uint64            `json:"pps"`
	BPS         uint64            `json:"bps"`
	PeakPPS     uint64            `json:"peak_pps"`
	PeakBPS     uint64            `json:"peak_bps"`
	TCP         float64           `json:"tcp_pct"`
	UDP         float64           `json:"udp_pct"`
	ICMP        float64           `json:"icmp_pct"`
	Other       float64           `json:"other_pct"`
	UniqueIPs   int               `json:"unique_src_ips"`
	TopSources  []IPCount         `json:"top_sources"`
	TopPorts    []PortCount       `json:"top_ports"`
	AvgPktSize  int               `json:"avg_pkt_size"`
	Severity    string            `json:"severity"`
	AttackType  string            `json:"attack_type,omitempty"`
	History     []uint64          `json:"-"`
}

type IPCount struct {
	IP    string `json:"ip"`
	Count uint64 `json:"count"`
}

type PortCount struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Count    uint64 `json:"count"`
	Percent  float64 `json:"percent"`
}

func (s *Snapshot) JSON() string {
	b, _ := json.Marshal(s)
	return string(b)
}

type Capture struct {
	iface     string
	threshold int
	handle    *pcap.Handle
	stop      chan struct{}
	ticker    chan Snapshot
	mu        sync.Mutex

	// per-second counters (reset each tick)
	packets   uint64
	bytes     uint64
	tcpCount  uint64
	udpCount  uint64
	icmpCount uint64
	otherCount uint64
	totalSize uint64

	// tracked across ticks
	peakPPS   uint64
	peakBPS   uint64
	srcIPs    map[string]uint64
	dstPorts  map[portKey]uint64
	history   []uint64 // last 60 seconds of PPS
	uptime    time.Time
}

type portKey struct {
	Port     uint16
	Protocol string
}

func New(iface string, threshold int) (*Capture, error) {
	handle, err := pcap.OpenLive(iface, 128, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap open: %w", err)
	}

	return &Capture{
		iface:     iface,
		threshold: threshold,
		handle:    handle,
		stop:      make(chan struct{}),
		ticker:    make(chan Snapshot, 1),
		srcIPs:    make(map[string]uint64),
		dstPorts:  make(map[portKey]uint64),
		history:   make([]uint64, 0, 60),
		uptime:    time.Now(),
	}, nil
}

func (c *Capture) Start() {
	go c.aggregate()

	src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	src.NoCopy = true

	for {
		select {
		case <-c.stop:
			return
		default:
		}

		pkt, err := src.NextPacket()
		if err != nil {
			continue
		}
		c.processPacket(pkt)
	}
}

func (c *Capture) processPacket(pkt gopacket.Packet) {
	c.mu.Lock()
	defer c.mu.Unlock()

	size := uint64(pkt.Metadata().Length)
	c.packets++
	c.bytes += size
	c.totalSize += size

	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		c.otherCount++
		return
	}

	var srcIP string
	if ipv4, ok := netLayer.(*layers.IPv4); ok {
		srcIP = ipv4.SrcIP.String()
	} else if ipv6, ok := netLayer.(*layers.IPv6); ok {
		srcIP = ipv6.SrcIP.String()
	}

	if srcIP != "" {
		if len(c.srcIPs) < 100000 {
			c.srcIPs[srcIP]++
		} else if _, exists := c.srcIPs[srcIP]; exists {
			c.srcIPs[srcIP]++
		}
	}

	// Check ICMP first (it has no transport layer)
	if pkt.Layer(layers.LayerTypeICMPv4) != nil || pkt.Layer(layers.LayerTypeICMPv6) != nil {
		c.icmpCount++
		return
	}

	transportLayer := pkt.TransportLayer()
	if transportLayer == nil {
		c.otherCount++
		return
	}

	switch t := transportLayer.(type) {
	case *layers.TCP:
		c.tcpCount++
		key := portKey{Port: uint16(t.DstPort), Protocol: "TCP"}
		c.dstPorts[key]++
	case *layers.UDP:
		c.udpCount++
		key := portKey{Port: uint16(t.DstPort), Protocol: "UDP"}
		c.dstPorts[key]++
	default:
		c.otherCount++
	}
}

func (c *Capture) aggregate() {
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-c.stop:
			return
		case <-tick.C:
			c.mu.Lock()
			snap := c.buildSnapshot()
			c.resetCounters()
			c.mu.Unlock()

			select {
			case c.ticker <- snap:
			default:
			}
		}
	}
}

func (c *Capture) buildSnapshot() Snapshot {
	total := c.tcpCount + c.udpCount + c.icmpCount + c.otherCount
	if total == 0 {
		total = 1
	}

	if c.packets > c.peakPPS {
		c.peakPPS = c.packets
	}
	bps := c.bytes * 8
	if bps > c.peakBPS {
		c.peakBPS = bps
	}

	c.history = append(c.history, c.packets)
	if len(c.history) > 60 {
		c.history = c.history[len(c.history)-60:]
	}

	avgSize := 0
	if c.packets > 0 {
		avgSize = int(c.totalSize / c.packets)
	}

	snap := Snapshot{
		Timestamp:  time.Now(),
		Interface:  c.iface,
		PPS:        c.packets,
		BPS:        bps,
		PeakPPS:    c.peakPPS,
		PeakBPS:    c.peakBPS,
		TCP:        float64(c.tcpCount) / float64(total) * 100,
		UDP:        float64(c.udpCount) / float64(total) * 100,
		ICMP:       float64(c.icmpCount) / float64(total) * 100,
		Other:      float64(c.otherCount) / float64(total) * 100,
		UniqueIPs:  len(c.srcIPs),
		TopSources: topIPs(c.srcIPs, 5),
		TopPorts:   topPorts(c.dstPorts, 5, total),
		AvgPktSize: avgSize,
		History:    make([]uint64, len(c.history)),
	}
	copy(snap.History, c.history)

	snap.Severity, snap.AttackType = classify(snap, c.threshold)

	return snap
}

func (c *Capture) resetCounters() {
	c.packets = 0
	c.bytes = 0
	c.tcpCount = 0
	c.udpCount = 0
	c.icmpCount = 0
	c.otherCount = 0
	c.totalSize = 0
	// srcIPs and dstPorts persist across ticks for cumulative view
	// but we cap them to prevent unbounded growth
	if len(c.srcIPs) > 50000 {
		c.srcIPs = make(map[string]uint64)
	}
	if len(c.dstPorts) > 10000 {
		c.dstPorts = make(map[portKey]uint64)
	}
}

func (c *Capture) Stop() {
	select {
	case <-c.stop:
	default:
		close(c.stop)
		c.handle.Close()
	}
}

func (c *Capture) Ticker() <-chan Snapshot {
	return c.ticker
}

func (c *Capture) Interface() string {
	return c.iface
}

func (c *Capture) Uptime() time.Duration {
	return time.Since(c.uptime)
}

func classify(s Snapshot, threshold int) (string, string) {
	pps := s.PPS
	t := uint64(threshold)

	if pps < t {
		return "NORMAL", ""
	}

	attackType := ""
	if s.UDP > 80 {
		// check for amplification patterns
		for _, p := range s.TopPorts {
			if p.Protocol == "UDP" && p.Percent > 50 {
				switch p.Port {
				case 53:
					attackType = "DNS Amplification"
				case 123:
					attackType = "NTP Amplification"
				case 11211:
					attackType = "Memcached Amplification"
				case 1900:
					attackType = "SSDP Amplification"
				case 389:
					attackType = "LDAP Amplification"
				case 161:
					attackType = "SNMP Amplification"
				case 19:
					attackType = "CharGEN Amplification"
				default:
					attackType = "UDP Flood"
				}
			}
		}
		if attackType == "" {
			attackType = "UDP Flood"
		}
	} else if s.TCP > 80 {
		attackType = "SYN Flood"
		for _, p := range s.TopPorts {
			if p.Protocol == "TCP" && p.Percent > 50 {
				attackType = fmt.Sprintf("TCP Flood (port %d)", p.Port)
			}
		}
	} else if s.ICMP > 50 {
		attackType = "ICMP Flood"
	} else {
		attackType = "Volumetric"
	}

	if pps >= t*5 {
		return "CRITICAL", attackType
	}
	if pps >= t*2 {
		return "HIGH", attackType
	}
	return "MEDIUM", attackType
}

func ListInterfaces() ([]string, error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	var result []string
	for _, i := range ifaces {
		addrs := ""
		for _, a := range i.Addresses {
			if addrs != "" {
				addrs += ", "
			}
			addrs += a.IP.String()
		}
		if addrs != "" {
			result = append(result, fmt.Sprintf("%-16s %s", i.Name, addrs))
		} else {
			result = append(result, i.Name)
		}
	}
	return result, nil
}

func DefaultInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		return i.Name, nil
	}
	return "", fmt.Errorf("no active network interface found")
}

func topIPs(m map[string]uint64, n int) []IPCount {
	if len(m) == 0 {
		return nil
	}
	// simple selection of top N
	result := make([]IPCount, 0, n)
	for i := 0; i < n; i++ {
		var maxIP string
		var maxCount uint64
		for ip, count := range m {
			if count > maxCount {
				found := false
				for _, r := range result {
					if r.IP == ip {
						found = true
						break
					}
				}
				if !found {
					maxIP = ip
					maxCount = count
				}
			}
		}
		if maxIP != "" {
			result = append(result, IPCount{IP: maxIP, Count: maxCount})
		}
	}
	return result
}

func topPorts(m map[portKey]uint64, n int, total uint64) []PortCount {
	if len(m) == 0 {
		return nil
	}
	if total == 0 {
		total = 1
	}
	result := make([]PortCount, 0, n)
	for i := 0; i < n; i++ {
		var maxKey portKey
		var maxCount uint64
		for key, count := range m {
			if count > maxCount {
				found := false
				for _, r := range result {
					if r.Port == key.Port && r.Protocol == key.Protocol {
						found = true
						break
					}
				}
				if !found {
					maxKey = key
					maxCount = count
				}
			}
		}
		if maxCount > 0 {
			result = append(result, PortCount{
				Port:     maxKey.Port,
				Protocol: maxKey.Protocol,
				Count:    maxCount,
				Percent:  float64(maxCount) / float64(total) * 100,
			})
		}
	}
	return result
}
