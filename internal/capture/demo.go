package capture

import (
	"fmt"
	"math"
	"math/rand"
	"time"
)

// DemoCapture generates realistic simulated traffic data for demos and screenshots.
type DemoCapture struct {
	threshold int
	stop      chan struct{}
	ticker    chan Snapshot
	uptime    time.Time
	history   []uint64
	tick      int
}

func NewDemo(threshold int) *DemoCapture {
	return &DemoCapture{
		threshold: threshold,
		stop:      make(chan struct{}),
		ticker:    make(chan Snapshot, 1),
		uptime:    time.Now(),
		history:   make([]uint64, 0, 60),
	}
}

func (d *DemoCapture) Start() {
	t := time.NewTicker(800 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case <-d.stop:
			return
		case <-t.C:
			snap := d.generate()
			select {
			case d.ticker <- snap:
			default:
			}
		}
	}
}

func (d *DemoCapture) Stop() {
	select {
	case <-d.stop:
	default:
		close(d.stop)
	}
}

func (d *DemoCapture) Ticker() <-chan Snapshot {
	return d.ticker
}

func (d *DemoCapture) Interface() string {
	return "eth0"
}

func (d *DemoCapture) Uptime() time.Duration {
	return time.Since(d.uptime)
}

func (d *DemoCapture) generate() Snapshot {
	d.tick++

	// Simulate a traffic pattern: normal baseline with a ramp-up attack around tick 15-30
	var basePPS uint64
	var attackActive bool

	switch {
	case d.tick < 8:
		// Normal baseline traffic
		basePPS = 2000 + uint64(rand.Intn(1500))
	case d.tick < 12:
		// Traffic starts climbing
		ramp := float64(d.tick-8) / 4.0
		basePPS = 2000 + uint64(float64(8000)*ramp) + uint64(rand.Intn(2000))
	case d.tick < 25:
		// Attack in full swing
		attackActive = true
		wave := math.Sin(float64(d.tick)*0.4) * 20000
		basePPS = 55000 + uint64(wave) + uint64(rand.Intn(15000))
	case d.tick < 30:
		// Attack tapering
		ramp := float64(30-d.tick) / 5.0
		basePPS = 2000 + uint64(float64(50000)*ramp) + uint64(rand.Intn(3000))
	default:
		// Back to normal
		basePPS = 1800 + uint64(rand.Intn(1200))
	}

	// Protocol distribution shifts during attack
	var tcp, udp, icmp, other float64
	if attackActive {
		udp = 87.0 + rand.Float64()*4
		tcp = 6.0 + rand.Float64()*2
		icmp = 1.0 + rand.Float64()*1
		other = 100 - tcp - udp - icmp
	} else {
		tcp = 48.0 + rand.Float64()*8
		udp = 28.0 + rand.Float64()*6
		icmp = 3.0 + rand.Float64()*3
		other = 100 - tcp - udp - icmp
	}
	if other < 0 {
		other = 0
	}

	// Source IPs
	uniqueIPs := 40 + rand.Intn(30)
	if attackActive {
		uniqueIPs = 600 + rand.Intn(400)
	}

	avgPkt := 200 + rand.Intn(300)
	if attackActive {
		avgPkt = 2800 + rand.Intn(1500) // amplification = large packets
	}

	bps := basePPS * uint64(avgPkt) * 8

	d.history = append(d.history, basePPS)
	if len(d.history) > 60 {
		d.history = d.history[len(d.history)-60:]
	}

	var peakPPS uint64
	var peakBPS uint64
	for _, h := range d.history {
		if h > peakPPS {
			peakPPS = h
		}
		hbps := h * uint64(avgPkt) * 8
		if hbps > peakBPS {
			peakBPS = hbps
		}
	}

	sources := d.demoSources(attackActive)
	ports := d.demoPorts(attackActive)

	snap := Snapshot{
		Timestamp:  time.Now(),
		Interface:  "eth0",
		PPS:        basePPS,
		BPS:        bps,
		PeakPPS:    peakPPS,
		PeakBPS:    peakBPS,
		TCP:        tcp,
		UDP:        udp,
		ICMP:       icmp,
		Other:      other,
		UniqueIPs:  uniqueIPs,
		TopSources: sources,
		TopPorts:   ports,
		AvgPktSize: avgPkt,
		History:    make([]uint64, len(d.history)),
	}
	copy(snap.History, d.history)

	snap.Severity, snap.AttackType = classify(snap, d.threshold)

	return snap
}

func (d *DemoCapture) demoSources(attack bool) []IPCount {
	if attack {
		return []IPCount{
			{IP: "45.134.26.108", Count: 12400 + uint64(rand.Intn(3000))},
			{IP: "193.32.162.71", Count: 9800 + uint64(rand.Intn(2000))},
			{IP: "185.220.101.34", Count: 7200 + uint64(rand.Intn(2000))},
			{IP: "91.218.114.9", Count: 4100 + uint64(rand.Intn(1500))},
			{IP: "23.129.64.213", Count: 2900 + uint64(rand.Intn(1000))},
		}
	}
	return []IPCount{
		{IP: "10.0.1.5", Count: 340 + uint64(rand.Intn(200))},
		{IP: "10.0.1.12", Count: 280 + uint64(rand.Intn(150))},
		{IP: "172.16.0.8", Count: 190 + uint64(rand.Intn(100))},
		{IP: "10.0.1.3", Count: 120 + uint64(rand.Intn(80))},
		{IP: fmt.Sprintf("192.168.1.%d", 20+rand.Intn(200)), Count: 60 + uint64(rand.Intn(50))},
	}
}

func (d *DemoCapture) demoPorts(attack bool) []PortCount {
	if attack {
		return []PortCount{
			{Port: 53, Protocol: "UDP", Count: 45000, Percent: 72.4},
			{Port: 123, Protocol: "UDP", Count: 5000, Percent: 8.1},
			{Port: 443, Protocol: "TCP", Count: 3800, Percent: 6.2},
			{Port: 80, Protocol: "TCP", Count: 1200, Percent: 1.9},
			{Port: 1900, Protocol: "UDP", Count: 900, Percent: 1.5},
		}
	}
	return []PortCount{
		{Port: 443, Protocol: "TCP", Count: 420, Percent: 38.2},
		{Port: 80, Protocol: "TCP", Count: 280, Percent: 25.5},
		{Port: 22, Protocol: "TCP", Count: 140, Percent: 12.7},
		{Port: 53, Protocol: "UDP", Count: 95, Percent: 8.6},
		{Port: 3306, Protocol: "TCP", Count: 45, Percent: 4.1},
	}
}
