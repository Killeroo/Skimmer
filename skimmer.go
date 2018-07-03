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

	//https://github.com/fatih/color.git?
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

	}

	// whats this?
	//https://gobyexample.com/channel-synchronization
	// Explain what these are
	for i := 0; i < cap(thread); i++ {
		thread <- true
	}

	return openPorts
}

func isPortOpen (port int) bool {
	// First try #####
	// Lookup inputted address to actual address
	addr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", "127.0.0.1", port))
	if err != nil {
		return false
	}
	
	// Then try ####
	// try and connect
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