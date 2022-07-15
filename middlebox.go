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
    eth, _ := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
    // If DSCP not set, support L4S
    if ip.TOS == 0 {
      ip.TOS = 1
    }
    // Below, messing around with setting header fields to different values
    ip.SrcIP = ip.DstIP
    ip.DstIP = net.IPv4(10, 150, 111, 252)
    eth.SrcMAC = eth.DstMAC
    eth.DstMAC = net.HardwareAddr{0xf4, 0x5c, 0x89, 0xba, 0xe6, 0x63}
    tcp, _ := tcpLayer.(*layers.TCP)
    tcp.DstPort = 9090
    tcp.NS = true
    tcp.CWR = true
    tcp.ECE = true
    tcp.SYN = true
    tcp.ACK = false
    tcp.PSH = false

    // Craft modified packet to forward w/ SerializePacket
    sndBuff := gopacket.NewSerializeBuffer()
    options := gopacket.SerializeOptions{
      FixLengths:       true,
    }
    if err = gopacket.SerializePacket(sndBuff, options, packet); err != nil {
      panic(err)
    }

    // Convert packet into raw bytes
    sndPkt := sndBuff.Bytes()
    // hex := fmt.Sprintf("%x", sndPkt)
    // fmt.Println(sndPkt)
    // fmt.Println(hex)

    // Below: Sanity check converting raw bytes into packet and printing
    mod_packet := gopacket.NewPacket(sndPkt, layers.LayerTypeEthernet, gopacket.Default)
    fmt.Println(mod_packet)

    // Setting up socket and sending
    fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
    addr := syscall.SockaddrInet4{
      // Port: int(tcp.DstPort),
      Port: 9090,
      // Addr: [4]byte{ip.DstIP[0], ip.DstIP[1], ip.DstIP[2], ip.DstIP[3]}, // TODO: This line *should* be the one used in deployment
      // Addr: [4]byte{128, 135, 98, 173},
      Addr: [4]byte{10, 150, 111, 252},
    }
    err = syscall.Sendto(fd, sndPkt, 0, &addr)
    if err != nil {
      log.Fatal("Sendto:", err)
    }
    // TODO: Write client to try readint packet recv'd at port
    // TODO: Try sending to Chase changing the src/dst MAC to be own and Chase, and also src/dst IP to be local own and Chase
  }
}