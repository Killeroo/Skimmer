/* Skimmer - Lightweight port scanner
*  Based off: github.com/anvie/port-scanner
TODO: CamelCase for function names
*/

package main

import (
	"fmt"
	"net"
	"time"
	"sync"
	"log"
	//"flag"
	//"github.com/daviddengcn/go-colortext"
)

//const UNKNOWN_PORT = "<unknown>"
//const var KNOWN_PORTS[] = map[int] string {
//	80: "HTTP",
	
//}

// Initialise flags here : https://github.com/google/gopacket/blob/a5fcaa8c680ece28c600516a76d05f5b19eb46bc/examples/pcapdump/main.go#L23

// Rename?
type ScanDetails struct {
	host string
	threads int // default
	timeout time.Duration //? //default
	startPort int // default
	endPort int // really? //default
}

// Initialise flag variables here

//https://gist.github.com/montanaflynn/b59c058ce2adc18f31d6

// Scans a host for open ports and returns
// the results in an array
func scan () []int { // hosts string[]
	openPorts := []int{}
	lock := sync.Mutex{}
	thread := make(chan bool, 4)

	for port := 0; port <= 3000; port++ {
		thread <- true // what is
		go func (port int) {
			if isPortOpen(port) {
				lock.Lock()
				openPorts = append(openPorts, port)
				lock.Unlock()
			}
			<- thread
		}(port)

		// whats this?
		for i := 0; i < cap(thread); i++ {
			thread <- true
		}
	}

	return openPorts
}

func isPortOpen (port int) bool {
	// First try #####
	addr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", "127.0.0.1", port))
	if err != nil {
		return false
	}
	
	// Then try ####
	conn, err := net.DialTimeout("tcp", addr.String(), 1000)

	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

func showOpenPorts () {
	// Takes an array
}

func main() {
	// call scan save to array
	log.Println()
	openports := scan()

	for index, ports := range openports {
		log.Printf("%d : %d", index, ports)
	}
	// display array
}