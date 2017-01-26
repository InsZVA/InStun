// pair.go
// This file describe a stun-pair to process stun message with
// 2 hosts each with only one ip address.
//
package instun

import (
	"flag"
	"net"
	"strconv"
	"strings"
	"encoding/binary"
	"bytes"
	"log"
	"time"
	"errors"
)

var (
	FlagAlternate = flag.Bool("A", false,
	"if this flag exist, the server run as a alternate server")
	FlagIP = flag.String("-ip", "192.168.1.113",
	"the ip address of the primary server")
	FlagPort = flag.Int("-port", 3478,
	"the primary port for primay server")
	FlagAlternateIP = flag.String("-alterip", "192.168.1.114",
	"the ip address of the alternate server")
	FlagAlternatePort = flag.Int("-alterport", 3479,
	"the alternate port")
	FlagCommunicateIP = flag.String("-commip", "192.168.1.113",
	"the primary ip for communication, LAN IP recommended")
	FlagCommunicatePort = flag.Int("-commport", 1346,
	"the port for primay and alternate to communicate\n" +
	"this port is the port primay server listen on")
)

var (
	comm net.Conn
	connect = make(chan bool)

	ERROR_ALTERNATE_SERVER_NOT_RUNNING = errors.New("Alternate server not running")
)

func init() {
	if !flag.Parsed() {
		flag.Parse()
	}

	if *FlagAlternate {
		log.Print("Connecting to primary server...")
		priAddr, err := net.ResolveTCPAddr("tcp4", *FlagIP+ ":" + strconv.Itoa(*FlagCommunicatePort))
		if err != nil {
			panic("Primary server address error!")
		}
		comm, err = net.DialTCP("tcp4", nil, priAddr)
		if err != nil {
			panic("When alternate server want to connect to primay, " +
			"an error occur:" + err.Error())
		}
		log.Println("OK")
		/*go*/ alterHandler(comm)
	} else {
		lAddr, err := net.ResolveTCPAddr("tcp4", *FlagCommunicateIP+ ":" + strconv.Itoa(*FlagCommunicatePort))
		if err != nil {
			panic("When primary server want to listen on communication, " +
				"an error occur:" + err.Error())
		}
		listener, err := net.ListenTCP("tcp4", lAddr)
		log.Println("Listen for alternate server connect...")
		go func () {
			for {
				conn, err := listener.Accept()
				if err != nil {
					debug(err)
					continue
				}

				t := strings.Split(conn.RemoteAddr().String(), ":")
				if t[0] != *FlagAlternateIP {
					go conn.Close()
					continue
				}

				log.Println("Alternate server connected.")
				comm = conn
				<- connect // wait for close and reconnect
			}
		} ()
	}
}

func alterHandler(comm net.Conn) {
	buff := make([]byte, 1024)
START:
	// Usually udp is fast so I use no queue
	for n, e := comm.Read(buff); e == nil; n, e = comm.Read(buff) {
		if n < 8 {
			continue
		}
		reader := bytes.NewReader(buff[:n])
		rip := make(net.IP, 4)
		var lport, rport uint16
		reader.Read(rip)
		binary.Read(reader, binary.BigEndian, &rport)
		binary.Read(reader, binary.BigEndian, &lport)

		laddr, err := net.ResolveUDPAddr("udp4", *FlagAlternateIP+ ":" + strconv.Itoa(int(lport)))
		if err != nil {
			debug(err)
			continue
		}
		raddr, err := net.ResolveUDPAddr("udp4", rip.String() + ":" + strconv.Itoa(int(rport)))
		if err != nil {
			debug(err)
			continue
		}

		dst, err := net.DialUDP("udp4", laddr, raddr)
		if err != nil {
			debug(err)
			continue
		}
		if _, err = dst.Write(buff[8:n]); err != nil {
			debug(err)
			continue
		}
	}
	comm.Close()

RECONNECT:
	priAddr, err := net.ResolveTCPAddr("tcp4", *FlagIP+ ":" + strconv.Itoa(*FlagCommunicatePort))
	if err != nil {
		// Impossible go here
		panic("You are fucking my program???")
	}
	// Re-connect
	comm, err = net.DialTCP("tcp4", nil, priAddr)
	if err != nil {
		log.Println("When alternate server want to re-connect to primay, " +
			"an error occur:" + err.Error())
		time.Sleep(time.Millisecond)
		goto RECONNECT
	}
	goto START
}

type AlternateConn struct {
	rip net.IP // IPv4
	rport uint16
	lport uint16
}

func (ac *AlternateConn) Write(b []byte) (int, error) {
	buff := make([]byte, 8)
	copy(buff, ac.rip.To4())
	binary.BigEndian.PutUint16(buff[4:], ac.rport)
	binary.BigEndian.PutUint16(buff[6:], ac.lport)
	if comm == nil {
		log.Println(ERROR_ALTERNATE_SERVER_NOT_RUNNING)
		return 0, ERROR_ALTERNATE_SERVER_NOT_RUNNING
	}
	if n, e := comm.Write(append(buff, b...)); e != nil {
		log.Println(ERROR_ALTERNATE_SERVER_NOT_RUNNING)
		comm = nil
		connect <- true // Re-accept, alternate server need reconnect
		return 0, ERROR_ALTERNATE_SERVER_NOT_RUNNING
	} else {
		return n, nil
	}
}

func (ac *AlternateConn) Read(b []byte) (int, error) {
	return 0, nil
}

func (ac *AlternateConn) Close() error {
	return nil
}

func (ac *AlternateConn) LocalAddr() net.Addr {
	return nil
}

func (ac *AlternateConn) RemoteAddr() net.Addr {
	return nil
}

func (ac *AlternateConn) SetDeadline(t time.Time) error {
	return nil
}

func (ac *AlternateConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (ac *AlternateConn) SetWriteDeadline(t time.Time) error {
	return nil
}

