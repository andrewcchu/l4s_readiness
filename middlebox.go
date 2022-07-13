package main

import (
  "syscall"
  "fmt"
  "github.com/google/gopacket"
  _ "github.com/google/gopacket/layers"
)

// Convert a uint16 to host byte order (big endian)
func Htons(v uint16) int {
  return int((v << 8) | (v >> 8))
}

func main() {
  sd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, Htons(syscall.ETH_P_ALL), syscall.IPPROTO_ICMP)
  if err != nil {
    panic(err)
  }
  defer syscall.Close(sd)
  buf := make([]byte, 65536)

  _, _, err = syscall.Recvfrom(sd, buf, 0)
  if err != nil {
      panic(err)
  }
  packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)

  for _, layer := range packet.Layers() {
      fmt.Println("Layer: ", layer.LayerType())
  }
}
