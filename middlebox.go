package main

import (
  "syscall"
  "fmt"
  "log"
  "net"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
)

// Convert a uint16 to host byte order (big endian)
func Htons(v uint16) int {
  return int((v << 8) | (v >> 8))
}

func main() {
  // Receive on all protocols (ETH_P_ALL)
  sd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, Htons(syscall.ETH_P_ALL))

  if err != nil {
    panic(err)
  }
  defer syscall.Close(sd)
  buf := make([]byte, 65536)

  _, _, err = syscall.Recvfrom(sd, buf, 0)
  if err != nil {
    panic(err)
  }
  // Form packet from incoming buffer
  packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)

  fmt.Println(packet) // Print showing read contents TODO: Remove on prod.

  // If TCP packet, modify fields to be correct receiving response L4S flags, and forward back to source
  if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
    ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
    // If DSCP not set, support L4S
    if ip.TOS == 0 {
      ip.TOS = 1
    }
    // ip.DstIP = net.IPv4(128, 135, 98, 173)
    tcp, _ := tcpLayer.(*layers.TCP)
    tcp.NS = true
    tcp.CWR = true
    tcp.ECE = true

    fmt.Println(packet) // Print showing modified contents TODO: Remove on prod.

    // Craft modified packet to forward
    sndBuff := gopacket.NewSerializeBuffer()
    options := gopacket.SerializeOptions{
      FixLengths:       true,
    }
    if err = gopacket.SerializePacket(sndBuff, options, packet); err != nil {
      panic(err)
    }

    sndPkt := sndBuff.Bytes()
    hex := fmt.Sprintf("%x", sndPkt)
    fmt.Println(sndPkt)
    fmt.Println(hex)

    fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
    addr := syscall.SockaddrInet4{
      Port: int(tcp.DstPort),
      Addr: [4]byte{ip.DstIP[0], ip.DstIP[1], ip.DstIP[2], ip.DstIP[3]},
      // Addr: [4]byte{128, 135, 98, 173},
    }
    err = syscall.Sendto(fd, sndPkt, 0, &addr)
    if err != nil {
      log.Fatal("Sendto:", err)
    }
    // TODO: Write client to try readint packet recv'd at port
  }
}