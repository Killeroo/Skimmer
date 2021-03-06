/* Skimmer - Lightweight port scanner
*  Based off: github.com/anvie/port-scanner
*/
//https://github.com/drael/GOnetstat/blob/master/gonetstat.go
//https://github.com/stvp/go-udp-testing/blob/master/udp.go

package main

import (
	"fmt"
	"net"
	"sync"
	"log"
	"flag"
	"os"
	"time"
	
	"github.com/gosuri/uiprogress"
	"github.com/fatih/color"
)

// List of known port names
var knownPortNames = map[int] string {
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
	502: "Modbus Protocol",
	504: "Citadel Multiservice Protocol",
	510: "FirstClass Protocol (FCP)",
	512: "Rexec, Remote Process Execution",
	513: "rlogin",
	514: "Remote Shell",
	515: "Line Printer Daemon (LPD)",
	517: "Talk",
	518: "NTalk",
	520: "Extended Filename Server (EFS)",
	521: "Routing Information Protocol Next Generation (RIPng)",
	524: "NetWare Core Protocol (NCP)",
	525: "Timeserver",
	530: "Remote Procedure Call (RPC)",
	532: "netnews",
	533: "netwall, For Emergency Broadcasts",
	540: "Unix-to-Unix Copy Protocol (UUCP)",
	542: "commerse (Commerse Application)",
	543: "klogin, Kerberos login",
	544: "kshell, Kerberos Remote shell",
	546: "DHCPv6 client",
	547: "DHCPv6 server",
	548: "Apple Filing Protocol (AFP) over TCP",
	550: "new-rwho, new-who",
	554: "Real Time Streaming Protocol (RTSP)",
	556: "Remotefs, RFS, rfs_server",
	560: "rmonitor, Remote Monitor",
	561: "monitor",
	563: "NNTP over TLS/SSL (NNTPS)",
	587: "email message submission (SMTP)",
	591: "FileMaker 6.0 (and later) Web Sharing",
	593: "HTTP RPC Ep Map",
	601: "Reliable Syslog Service",
	604: "TUNNEL profile",
	623: "ASF Remote Management and Control Protocol (ASF-RMCP)",
	625: "Open Directory Proxy (ODProxy)",
	631: "Internet Printing Protocol (IPP)",
	635: "RLZ DBase",
	636: "Lightweight Directory Access Protocol over TLS/SSL (LDAPS)",
	639: "Multicast Source Discovery Protocol (MSDP)",
	641: "SupportSoft Nexus Remote Command (control/listening)",
	643: "SANity",
	646: "Label Distribution Protocol (LDP)",
	647: "DHCP Failover Protocol",
	648: "Registry Registrar Protocol (RRP)",
	651: "IEEE-MMS",
	653: "SupportSoft Nexus Remote Command (data)",
	654: "Media Management System (MMS) Media Management Protocol (MMP)",
	655: "Tinc VPN daemon",
	657: "IBM Remote Monitoring and Control (RMC) protocol",
	660: "Mac OS X Server administration (version 10.4 and earlier)",
	666: "Doom server (first online first-person shooter)",
}

const iconText =
`
    /.)
   /)\|
  //)/ 
 /'"^"  [SKIMMER] - lightweight port scanner 
`

// Program flags/arguments
var address = flag.String("address", "", "Address to scan")
var threads = flag.Int("threads", 4,"Number of threads to use when scanning")
var timeout = flag.Int("timeout", 1000, "Timeout for each connection attempt")
var allPorts = flag.Bool("all", true, "Scan all possible ports")
var knownPorts = flag.Bool("known", false,"Scan only well-known ports (0-1024)")
var registeredPorts = flag.Bool("registered", false, "Scan registered port range (1024-49151)")
var privatePorts = flag.Bool("private", false, "Scan private port range (49152-65535)")

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
// All open ports are returned in the form of an int array
func scanPorts (data ScanData) []int {
	openPorts := []int{} // Stores all open ports
	lock := sync.Mutex{} // Mutex lock to make sure openPorts list is accessed one thread at a time
	thread := make(chan bool, data.threads) // Go channel to pass data between threads
	open2Ports := []int{} // Stores all open ports

	// Setup progress bar
	uiprogress.Start()
	bar := uiprogress.AddBar(data.endPort - data.startPort)
	bar.AppendCompleted()
	bar.PrependElapsed()

	// Loop through each port in specified range
	for port := data.startPort; port <= data.endPort; port++ {
		thread <- true // Pass message to any go channels

		// Create go routine to check if port is open in new thread
		// Check if port is open in new thread
		go func (port int) {
			if isTCPPortOpen(data.address, port) {
				lock.Lock()
				openPorts = append(openPorts, port)
				lock.Unlock()
			}


			if isUDPPortOpen(data.address, port) {
				lock.Lock()
				open2Ports = append(open2Ports, port)
				lock.Unlock()
			}

			<- thread // Block goroutine till we recieve value on channel
		}(port)

		bar.Incr()
	}

	// Stop progress bar
	uiprogress.Stop()

	for _, port := range open2Ports {
		fmt.Println(port)
	}

	for i := 0; i < cap(thread); i++ {
	    // Signal all remaining goroutines to stop 
		thread <- true
	}

	return openPorts
}

// Checks if a port is open, first resolves address
// then attempts to connect using tcp
// Returns bool based on connection success
func isTCPPortOpen (address string, port int) bool {
	addr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", address, port))
	if err != nil {
		return false
	}

	conn, err := net.DialTimeout("tcp", addr.String(), time.Duration(*timeout))
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// Similar to the previous isTCPPortOpen function, this function checks if a UDP
// port is open at a particular address, the internals work in a similar way as before
func isUDPPortOpen (address string, port int) bool {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", address, port))
	if err != nil {
		return false
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// Display all open ports and references any known port types
// using the knownPortNames map
func displayOpenPorts (ports []int) {
	// Specify colors
	portColor := color.New(color.FgHiGreen)
	systemColor := color.New(color.FgHiYellow)
	registeredColor := color.New(color.FgHiCyan)
	privateColor := color.New(color.FgHiMagenta)

	for _, port := range ports {

		// Port number first
		portColor.Printf(" [%d] ", port)

		// Type of port
		fmt.Printf("[TCP] ")

		// Display port type label
		if port > 49151 {
			privateColor.Printf("[private] ")
		} else if port > 1023 {
			registeredColor.Printf("[registered] ")
		} else {
			systemColor.Printf("[system] ")
		}

		// Display name if port has one
		if portName, ok := knownPortNames[port]; ok {
			fmt.Printf("[%s]\n", portName)
		} else {
			fmt.Printf("\n")
		}
	}
}

// Displays help message
func usage() {
	flag.PrintDefaults()
}

func init() {
	// Setup flag and log
	fmt.Println(iconText)
	log.SetPrefix("[SKIMMER] ")
	log.SetFlags(0)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	// Load scanData from flags
	var data ScanData
	data.address = *address
	data.threads = *threads
	data.timeout = *timeout
	if *allPorts {
		data.startPort = 0
		data.endPort = 65535
	}
	if *knownPorts {
		data.startPort = 0
		data.endPort = 1023
	}
	if *registeredPorts {
		data.startPort = 1025
		data.endPort = 49151
	}
	if *privatePorts {
		data.startPort = 49152
		data.endPort = 65535
	}

	// Bail if we have no address set
	if *address == "" {
		c := color.New(color.FgHiYellow, color.Underline)
		fmt.Printf("No address, specify an address to scan by typing ")
		c.Printf("'skimmer --address 127.0.0.1' \n")

		os.Exit(1)
	}

	// Scan ports and save results in array
	log.Printf("Scanning ports [%d-%d] @ %s using %d threads... \n", data.startPort, data.endPort, data.address, data.threads)
	results := scanPorts(data)

	// display array
	displayOpenPorts(results)

	// display results message
	log.Printf("%d open TCP ports on %s \n", len(results), data.address)
}