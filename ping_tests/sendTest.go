// https://stackoverflow.com/questions/59173693/how-to-set-tos-field-in-ip-header-for-a-tcp-connection-using-golang

package main

import (
  "fmt"
  "net"
  "golang.org/x/net/ipv4"
  "bufio"
)

const addr = "127.0.0.1"
const port = "1024"

func main () {
  conn, err := net.Dial("tcp4", addr+":"+port)
  if err != nil {
    fmt.Println(err)
  }
  writer := bufio.NewWriter(conn)
  iph := &ipv4.Header{
    Version:  ipv4.Version,
    Len:      ipv4.HeaderLen,
    TOS:      0x02, // DSCP CS0, ECN 00 (Default for ToS)
    TotalLen: ipv4.HeaderLen,
    TTL:      1,
    Protocol: 4,
    Dst:      net.ParseIP(addr).To4(),
  }
  data, err := iph.Marshal()
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(data)
  writer.Write(data)
  writer.Flush()
//time.Sleep(1*time.Nanosecond)
}