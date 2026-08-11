package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type StructuredPacketMatrix struct {
	ID        uint64 `json:"id"`
	Time      int64  `json:"time"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	TTL       int    `json:"ttl"`
	Version   int    `json:"version"`
	Proto     string `json:"proto"`
	SPort     int    `json:"sport"`
	DPort     int    `json:"dport"`
	Flags     string `json:"flags"`
	Hex       string `json:"hex"`
	AsciiDump string `json:"ascii"`
}

type ThreadSafeMetricsRegistry struct {
	sync.RWMutex
	MetricsMap           map[string]uint64
	UniqueIPAddressesMap map[string]bool
	HighPortActivityMap  map[int]uint64
	TotalBytesProcessed  uint64
}

func main() {
	registry := &ThreadSafeMetricsRegistry{
		MetricsMap:           make(map[string]uint64),
		UniqueIPAddressesMap: make(map[string]bool),
		HighPortActivityMap:  make(map[int]uint64),
	}

	rawLineInputChannel := make(chan string, 5000)
	var processingWaitGroup sync.WaitGroup

	// Worker Routine Pool Configuration (3 Parallel Decoders)
	for workerIndex := 0; workerIndex < 3; workerIndex++ {
		processingWaitGroup.Add(1)
		go func(id int) {
			defer processingWaitGroup.Done()
			for rawJSONLine := range rawLineInputChannel {
				var dataFrame StructuredPacketMatrix
				err := json.Unmarshal([]byte(rawJSONLine), &dataFrame)
				if err != nil {
					continue
				}

				registry.Lock()
				registry.MetricsMap[dataFrame.Proto]++
				registry.UniqueIPAddressesMap[dataFrame.Src] = true
				registry.UniqueIPAddressesMap[dataFrame.Dst] = true
				registry.HighPortActivityMap[dataFrame.DPort]++
				registry.TotalBytesProcessed += uint64(len(dataFrame.Hex) / 2)
				registry.Unlock()

				formattedTime := time.Unix(0, dataFrame.Time*int64(time.Millisecond))
				fmt.Printf("\033[1;31m[NODE]\033[0m %s | \033[1;34m%s\033[0m | %s:%d -> %s:%d | Payload: \033[0;32m%s\033[0m\n",
					formattedTime.Format("15:04:05.000"), dataFrame.Proto, dataFrame.Src, dataFrame.SPort, dataFrame.Dst, dataFrame.DPort, dataFrame.AsciiDump)
			}
		}(workerIndex)
	}

	// Secondary Monitoring Thread Tracking System Health Diagnostics
	go func() {
		statusMetricsUpdateTicker := time.NewTicker(5 * time.Second)
		for range statusMetricsUpdateTicker.C {
			registry.RLock()
			fmt.Printf("\n\033[1;35m======================= SYSTEM PIPELINE HEALTH METRICS =======================\n"+
				"[DIAGNOSTICS] Total Packets Captured Matrix: TCP [%d] | UDP [%d]\n"+
				"[DIAGNOSTICS] Tracked Active Network Nodes: %d Endpoints\n"+
				"[DIAGNOSTICS] Cumulative Bandwidth Absorbed Into System Buffer: %d Raw Bytes\n"+
				"==============================================================================\033[0m\n\n",
				registry.MetricsMap["TCP"], registry.MetricsMap["UDP"], len(registry.UniqueIPAddressesMap), registry.TotalBytesProcessed)
			registry.RUnlock()
		}
	}()

	systemIOReaderScanner := bufio.NewScanner(os.Stdin)
	for systemIOReaderScanner.Scan() {
		textLineBuffer := systemIOReaderScanner.Text()
		if len(textLineBuffer) > 0 && textLineBuffer[0] == '{' {
			rawLineInputChannel <- textLineBuffer
		}
	}

	close(rawLineInputChannel)
	processingWaitGroup.Wait()
}
