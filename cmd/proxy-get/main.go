package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/mastercactapus/proxyprotocol"
)

func parseHostPort(s string) (net.IP, int, error) {
	addr, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, err
	}
	srcPort, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid port '%s': %w", portStr, err)
	}
	if srcPort < 1 || srcPort > 65535 {
		return nil, 0, fmt.Errorf("invalid port '%d': must be between 1-65535", srcPort)
	}

	srcIP := net.ParseIP(addr)
	if srcIP == nil {
		return nil, 0, fmt.Errorf("invalid IP '%s'", addr)
	}

	return srcIP, srcPort, nil
}

func parseAddr(prefix, typ, val string) net.Addr {
	switch typ {
	case "tcp":
		ip, port, err := parseHostPort(val)
		if err != nil {
			log.Fatalf("invalid %s: %v", prefix, err)
		}
		return &net.TCPAddr{IP: ip, Port: port}
	case "udp":
		ip, port, err := parseHostPort(val)
		if err != nil {
			log.Fatalf("invalid %s: %v", prefix, err)
		}
		return &net.UDPAddr{IP: ip, Port: port}
	case "unix":
		return &net.UnixAddr{Net: "unixpacket", Name: val}
	}
	log.Fatalf("invalid %s-type '%s'", prefix, typ)
	return nil
}

func main() {
	log.SetFlags(log.Lshortfile)
	version := flag.Int("v", 2, "Version to use for GET request. Set to `0` to disable PROXY header.")
	src := flag.String("src", "127.0.0.1:123", "Source address to use.")
	srcType := flag.String("src-type", "tcp", "Source address type (can be tcp, udp, or unix -- v2 only).")
	dst := flag.String("dst", "127.0.1.1:456", "Destination address to use.")
	dstType := flag.String("dst-type", "tcp", "Destination address type (can be tcp, udp, or unix -- v2 only).")
	local := flag.Bool("local", false, "Indicate local request (v2 only).")
	flag.Parse()

	if *version == 1 {
		*srcType = "tcp"
		*dstType = "tcp"
	}

	srcAddr := parseAddr("src", *srcType, *src)
	dstAddr := parseAddr("dst", *dstType, *dst)
	switch *version {
	case 1:
		http.DefaultClient.Transport = &http.Transport{
			Dial: func(n, addr string) (net.Conn, error) {
				c, err := net.Dial(n, addr)
				if err != nil {
					return nil, fmt.Errorf("dial: %w", err)
				}
				s := srcAddr.(*net.TCPAddr)
				d := dstAddr.(*net.TCPAddr)
				hdr := &proxyprotocol.HeaderV1{
					SrcIP:    s.IP,
					SrcPort:  s.Port,
					DestIP:   d.IP,
					DestPort: d.Port,
				}

				_, err = hdr.WriteTo(c)
				if err != nil {
					c.Close()
					return nil, fmt.Errorf("write v1 header: %w", err)
				}

				return c, nil
			},
		}
	case 2:
		http.DefaultClient.Transport = &http.Transport{
			Dial: func(n, addr string) (net.Conn, error) {
				c, err := net.Dial(n, addr)
				if err != nil {
					return nil, fmt.Errorf("dial: %w", err)
				}

				hdr := &proxyprotocol.HeaderV2{
					Command: proxyprotocol.CmdProxy,
					Src:     srcAddr,
					Dest:    dstAddr,
				}
				if *local {
					hdr.Command = proxyprotocol.CmdLocal
				}

				_, err = hdr.WriteTo(c)
				if err != nil {
					c.Close()
					return nil, fmt.Errorf("write v2 header: %w", err)
				}
				return c, nil
			},
		}
	case 0:
		// do nothing
	default:
		log.Fatal("Invalid value for -v flag.")
	}

	resp, err := http.Get(flag.Arg(0))
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	defer resp.Body.Close()
	log.Println(resp.StatusCode, resp.Status)
	io.Copy(os.Stdout, resp.Body)
}
