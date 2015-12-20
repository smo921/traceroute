package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"golang.org/x/net/ipv4"
)

func printUsage(name string) {
	fmt.Printf("Usage: %s <target>\n", name)
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return uint16(^s)
}

func pkt(dst string, ttl int) []byte {
	h := ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + 10,
		TTL:      ttl,
		Protocol: syscall.IPPROTO_UDP,
		Dst:      net.ParseIP(dst),
	}
	icmp := []byte{
		8, // type: echo request
		0, // code: not used by echo request
		0, // checksum (16 bit), we fill in below
		0,
		0, // identifier (16 bit). zero allowed.
		0,
		0, // sequence number (16 bit). zero allowed.
		0,
		0xC0, // Optional data. ping puts time packet sent here
		0xDE,
	}
	cs := csum(icmp)
	icmp[2] = byte(cs)
	icmp[3] = byte(cs >> 8)

	out, err := h.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	return append(out, icmp...)
}

func getSock() (read, write int, err error) {
	write, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	read, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return -1, -1, err
	}

	return read, write, nil
}

func getAddr(hname string) *syscall.SockaddrInet4 {
	a := net.ParseIP(hname).To4()
	return &syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{a[0], a[1], a[2], a[3]},
	}
}

func readICMP(sock int) {
	fmt.Println("Running readICMP")

	data := make([]byte, 1024)
	fmt.Println("ICMP Reading from socket")
	n, from, err := syscall.Recvfrom(sock, data, 1024)
	if err != nil {
		fmt.Printf("ICMP Error reading from socket: %v\n", err)
	}

	fmt.Printf("ICMP Read from socket: From: %v, %d bytes, %v\n", from, n, data)
	fmt.Printf("ICMP Read: % X\n", data[:n])

}

func trace(target string, ttl int) error {
	fmt.Printf("Tracing %s, ttl: %d\n", target, ttl)
	addrs, err := net.LookupHost(target)
	if err != nil {
		fmt.Printf("Error looking up target: %v\n", err)
		return err
	}
	wsock, rsock, err := getSock()
	if err != nil {
		fmt.Printf("Error getting socket: %v\n", err)
		return err
	}
	addr := getAddr(addrs[0])
	p := pkt(addrs[0], ttl)
	err = syscall.Sendto(wsock, p, 0, addr)
	readICMP(rsock)
	return nil
}

func main() {
	fmt.Println("Main Program: ", os.Args[0])
	if len(os.Args) < 2 {
		printUsage(os.Args[0])
		return
	}

	target := os.Args[1]
	trace(target, 3)

}
