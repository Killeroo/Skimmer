/* Skimmer - Lightweight port scanner
*  Based off: github.com/anvie/port-scanner
https://www.google.com/search?q=skimmer+animal&client=firefox-b-ab&tbm=isch&source=iu&ictx=1&fir=GSXSVjrBk_RjRM%253A%252CdKCRDpEtyJu9GM%252C_&usg=__z9iOwUH5L913S3TPr7X6gXvEqMg%3D&sa=X&ved=0ahUKEwjO-5z33oLcAhUDeMAKHe7aCzcQ9QEIlAEwAw#imgrc=GSXSVjrBk_RjRM:

Add color
Add list of ports and descriptions..
Move known_ports into own file and rename
Add summary details upon completion
Icon?
cleanup

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
	"github.com/briandowns/spinner" // Doesnt work on windows?

	//https://github.com/fatih/color.git?
	"flag"
	"time"
)

// Kill me
//https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
//https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Well-known_ports
// Move to own file
var KNOWN_PORTS = map[int] string { // Convert to lower caps // Rename to wellknown ports?
	0: "Reserved",
	1: "TCPMUX",
	5: "Remote Job Entry",
	7: "Echo Protocol",
	9: "Discard Protocol",
	11: "SYSTAT Service",
	13: "Daytime Protocol",
	17: "QOTD (Quote of the Day) Protocol",
	18: "Message Send Protocol",
	19: "Character Generator Protocol",
	20: "File Transfer Protocol (FTP) data transfer",
	21: "File Transfer Protocol (FTP) control (command)",
	22: "Secure Shell (SSH)",
	23: "Telnet Protocol",
	25: "Simple Mail Transfer Protocol (SMTP)",
	37: "Time Protocol",
	38: "Remote Access Protocol (RAP)",
	39: "Resource Location Protocol (RLP)",
	42: "Host Name Server Protocol",
	43: "WHOIS Protocol",
	49: "TACACS Login Host Protocol",
	50: "Remote Mail Checking Protocol",
	52: "Xerox Network Systems (XNS) Time Protocol",
	53: "Domain Name System (DNS)",
	54: "Xerox Network Systems (XNS) clearinghouse",
	56: "Xerox Network Systems (XNS) authentication",
	57: "Any private terminal access",
	58: "Xerox Network Systems (XNS) mail",
	66: "SQL-NET",
	67: "Bootstrap Protocol (BOOTP) Server",
	68: "Bootstrap Protocol (BOOTP) Client",
	69: "Trivial File Transfer Protocol (TFTP)",
	70: "Gopher Protocol",
	71-74: "NETJRS Protocol",
	75: "Any private dial out service",
	77: "Any private Remote job entry",
	79: "Finger Protocol",
	80: "Hyper Text Transfer Protocol (HTTP)",
	81: "TorPark onion routing",
	82: "TorPark control",
	87: "Any private terminal link",
	88: "Kerberos authentication system",
	90: "DNSIX (DoD Network Security for Information Exchange",
	101: "NIC host name",
	102: "ISO Transport Service Access Point (TSAP)",
	104: "Digital Imaging and Communications in Medicine (DISCOM)",
	105: "CCSO Nameserver",
	107: "Remote User Telnet Service (RTelnet)",
	108: "IBM Systems Network Architecture (SNA) gateway access server",
	109: "Post Office Protocol, version 2 (POP2)",
	110: "Post Office Protocol, version 3 (POP3)",
	111: "Open Network Computing Remote Procedure Call (ONC RPC or SunRPC)",
	113: "Authentication Service (auth)",
	115: "Simple File Transfer Protocol (SFTP)",
	117: "UUCP Mapping Project",
	118: "Structured Query Language (SQL) Services",
	119: "Network News Transfer Protocol (NNTP)",
	123: "Network Time Protocol (NTP)",
	135: "Microsoft End Point Mapper (EPMAP)",
	137: "NetBIOS Name Service",
	138: "NetBIOS Datagram Service",
	139: "NetBIOS Session Service",
	143: "Internet MEssage ACcess Protocol (IMAP)",
	152: "Background File Transfer Program (BFTP)",
	153: "Simple Gateway Monitoring Protocol (SGMP)",
	156: "Structured Query Language (SQL) Services",
	158: "Distributed Mail System Protocol (DMSP or PcMail)",
	161: "Simple Network Management Protocol (SNMP)",
	162: "Simple Network Management Protocol Trap (SNMPTRAP)",
	170: "Printer Server",
	177: "X Display Manager Control Protocol (XDMCP)",
	179: "Border Gateway Protocol (BGP)",
	194: "Internet Relay Chat (IRC)",
	199: "SNMP multiplexing protocol (SMUX)",
	201: "AppleTalk Routing Maintenance",
	209: "Quick Mail Transfer Protocol",
	210: "ANSI Z39.50",
	213: "Internetwork Packet Exchange (IPX)",
	218: "Message posting protocol (MPP)",
	220: "Internet Message Access Protocol (IMAP) version 3",
	225-241: "Reserved",
	249-255: "Reserved",
	259: "Efficient Short Remote Operations (ESRO)",
	262: "Arcisdms",
	264: "Border Gateway Multicast Protocol (BGMP)",
	280: "http-mgmt", // RENAME
	308: "Novastor Online Backup",
	311: "Mac OS X Server Admin",
	318: "PKIX Time Stamp Protocol (TSP)",
	319: "Precision Time Protocol (PTP) event messages",
	320: "Precision Time Protocol (PTP) general messages",
	350: "Mapping of Airline Traffic over Internet Protocol (MATIP) type A",
	351: "Mapping of Airline Traffic over Internet Protocol (MATIP) type B",
	356: "cloanto-net-1 (used by Cloanto Amiga Explorer and VMs)", // RENAME
	366: "On-Demand Mail Relay (ODMR)",
	369: "Rpc2portmap", // RENAME
	370: "codaauth2 - Coda authentication server",
	371: "ClearCase albd",
	383: "HP data alarm manager",
	384: "A Remote Network Server System",
	387: "AppleTalk Update-based Routing Protocol (AURP)",
	389: "Lightweight Directory Access Protocol (LDAP)",
	399: "Digital Equipment Corporation DECnet (Phase V+) over TCP/IP",
	401: "Uninterruptible power supply (UPS)",
	427: "Service Location Protocol (SLP)",
	433: "NNSP, part of Network News Transfer Protocol (NNTP)",
	434: "Mobile IP Agent",
	443: "Hypertext Transfer Protocol over TLS/SSL (HTTPS)",
	444: "Simple Network Paging Protocol (SNPP)",
	445: "Microsoft-DS (Directory Services) Active Directory",
	464: "Kerberos Change/Set password",
	465: "Authenticated SMTP over TLS/SSL (SMTPS)",
	475: "tcpnethaspsrv, Aladdin Knowledge Systems Hasp services",
	497: "Retrospect",
	500: "Internet Security Association and Key Management Protocol (ISAKMP) / Internet Key Exchange (IKE)",
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