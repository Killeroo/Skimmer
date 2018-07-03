/* Skimmer - Lightweight port scanner
*  Based off: github.com/anvie/port-scanner
https://www.google.com/search?q=skimmer+animal&client=firefox-b-ab&tbm=isch&source=iu&ictx=1&fir=GSXSVjrBk_RjRM%253A%252CdKCRDpEtyJu9GM%252C_&usg=__z9iOwUH5L913S3TPr7X6gXvEqMg%3D&sa=X&ved=0ahUKEwjO-5z33oLcAhUDeMAKHe7aCzcQ9QEIlAEwAw#imgrc=GSXSVjrBk_RjRM:

Add color
Add list of ports and descriptions..
Move known_ports into own file and rename
Add summary details upon completion
Icon?

stretch goals:
lookup address before scan starts to save time
check UDP as well
add stealthy options
*/

package main

import (
	"fmt"
	"net"
	"sync"
	"log"
	"github.com/briandowns/spinner"

	//https://github.com/fatih/color.git?
	"flag"
	"time"
)

// Kill me
//https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
//https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
var KNOWN_PORTS = map[int] string { // Convert to lower caps // Rename to wellknown ports?
	0: "reserved",
	1: "tcpmux",
	2: "compressnet",
	3: "compressnet",
	5: "rje",
	7: "echo",
	9: "discard",
	11: "systat",
	13: "daytime",
	17: "qotd",
	18: "msp",
	19: "chargen",
	20: "ftp-data",
	21: "ftp",
	22: "ssh",
	23: "telnet",
	25: "smtp",
	33: "dsp",
	37: "time",
	38: "rap",
	39: "rlp",
	41: "graphics",
	42: "nameserver",
	43: "whois",
	45: "mpm",
	46: "mpm-snd",
	49: "tacacs",
	50: "re-mail-ck",
	52: "xns-time",
	53: "dns",
	54: "xns-ch",
	56: "xns-auth",
	57: "Any private terminal access",
	58: "xns-mail",
	63: "whois++",
	64: "covia",
	65: "tacacs-ds",
	66: "sql-net",
	67: "bootps",
	68: "bootpc",
	69: "tftp",
	70: "gopher",
	71-74: "netrjs",
	75: "Any private dial out service",
	77: "Any private Remote job entry",
	79: "finger",
	80: "http",
	87: "Any private terminal link",
	88: "Kerberos",
	90: "dnsix",
	101: "hostname",
	102: "iso-tsap",
	104: "acr-nema",
	105: "cso",
	107: "rtelnet",
	108: "snagas",
	109: "pop2",
	110: "pop3",
	111: "sunrpc",
	113: "ident",
	115: "sftp",
	117: "uucp-path",
	118: "sqlserv",
	119: "nntp",
	123: "ntp",
	135: "epmap",
	137: "netbios-ns",
	138: "netbios-dgm",
	139: "netbios-ssn",
	143: "imap",
	152: "bftp",
	153: "sgmp",
	156: "sqlsrv",
	158: "pcmail-srv",
	161: "snmp",
	162: "snmptrap",

}

var KNOWN_PORTS_DETAILS = map[int] string {
	1: "TCP Port Service Multiplexer (HISTORIC)",
	5: "Remote Job Entry",
	17: "Quote of the Day",
	19: "Character Generator Protocol",
	20: "File Transfer Protocol, data connection",
	21: "File Transfer Protocol, command connection",
	22: "Secure Socket Shell",
	25: "Simple Mail Transfer Protocol",
	38: "Route Access Protocol",
	39: "Resource Location Protocol",
	49: "Terminal Access Controller Access-Control System Plus, Login Host Protocol",
	52: "Xerox Network Systems, time protocol",
	53: "Domain Name System",
	54: "Xerox Network Systems, clearinghouse",
	56: "Xerox Network Systems, authentication",
	69: "Trivial File Transfer Protocol",
	71-74: "Remote Job Entry",
	80: "Hyper Text Transfer Protocol",
	90: "Department of Defence (DoD) Network Security for Information Exchange",
	101: "Network Information Server",
	102: "International Organisation for Standardization (ISO) Transport Service Access Point",
	104: "Digital Imaging and Commuinications in Medicine",
	107: "Remote User Telnet Service",
	108: "IBM Systems Network Architecture (SNA) gateway access server",
	109: "Post Office Protocol Version 2",
	110: "Post Office Protocol Version 3",
	111: "Open Network Computing REmote Procedure Call",
}

const iconText =
`
    /.)
   /)\|
  //)/ 
 /'"^"  [SKIMMER] - lightweight port scanner 
`

// Stores info about scan operation
type ScanData struct {
	address   string
	threads   int
	timeout   int
	startPort int
	endPort   int
}

// Scans ports of a host, operation info is provided by ScanData struct
// First results array, thread lock and synchronization channel are created
// then every port in specified range is looped through and tested
// And the open ports are returned in the form of an int array
// https://gobyexample.com/channel-synchronization
// http://guzalexander.com/2013/12/06/golang-channels-tutorial.html
func scanPorts (data ScanData) []int {
	openPorts := []int{}
	lock := sync.Mutex{}
	thread := make(chan bool, data.threads) // Make channel to synchronize goroutines

	for port := data.startPort; port <= data.endPort; port++ {
		thread <- true // Signify thread is done?
		go func (port int) {
			if isPortOpen(data.address, port) {
				lock.Lock()
				openPorts = append(openPorts, port)
				lock.Unlock()
			}
			<- thread // Wait for other channels to be finish
		}(port)

	}

	// Explain what these are
	for i := 0; i < cap(thread); i++ {
		// Tell main method everything is done
		thread <- true
	}

	return openPorts
}

// Checks if a port is open, first resolves address
// then attempts to connect using tcp
// Returns bool based on connection success
func isPortOpen (address string, port int) bool {
	addr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", address, port))
	if err != nil {
		return false
	}


	conn, err := net.DialTimeout("tcp", addr.String(), 1000)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// Display all open ports and references any known port types
// using the KNOWN_PORTS map
func displayOpenPorts (ports []int) {
	for _, port := range ports {
		if portName, ok := KNOWN_PORTS[port]; ok {
			fmt.Printf("%d: [%s]\n", port, portName)
		} else {
			fmt.Printf("%d: [unknown]\n", port)
		}
	}
}

func main() {
	// Setup flag, log, spinner and scan data
	fmt.Println(iconText)
	log.SetPrefix("[SKIMMER] ")
	log.SetFlags(0)
	address := flag.String("address", "", "Address to scan")
	threads := flag.Int("threads", 4,"Number of threads to use when scanning")
	timeout := flag.Int("timeout", 1000, "Timeout for each connection attempt")
	allPorts := flag.Bool("all", true, "Scan all possible ports")
	knownPorts := flag.Bool("known", false,"Scan only well-known ports (0-1024)")
	registeredPorts := flag.Bool("registered", false, "Scan registered port range (1024-49151)")
	flag.Parse()
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond) //36
	//s.Prefix = "Scanning..."
	s.FinalMSG = "Complete!\n\n"
	var data ScanData
	data.address = *address
	data.threads = *threads
	data.timeout = *timeout
	if *allPorts {
		data.startPort = 0
		data.endPort = 50000
	} else if *knownPorts {
		data.startPort = 0
		data.endPort = 1024
	} else if *registeredPorts {
		data.startPort = 1025
		data.endPort = 50000
	}

	// Bail if we have no address set
	if *address == "" {
		log.Fatal("No address specified")
	}

	// Scan ports and save results in array
	log.Printf("Scanning ports [%d-%d] @ %s ... \n", data.startPort, data.endPort, data.address)
	s.Start()
	results := scanPorts(data)
	s.Stop()

	// display array
	displayOpenPorts(results)
}