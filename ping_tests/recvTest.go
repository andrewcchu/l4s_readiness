package main

import (
  "fmt"
  "net"
  "golang.org/x/net/ipv4"
  "bufio"
)

func main () {
  ln, err := net.Listen("tcp4", "127.0.0.1:1024")
  if err != nil {
    fmt.Println("Error: ", err.Error())
  }
  defer ln.Close()
  for {
    c, err := ln.Accept()
    if err != nil {
        // error handling
    }
    if err := ipv4.NewConn(c).SetTOS(0x28); err != nil {
      fmt.Println("Error: ", err.Error())
    }
    go func(c net.Conn) {
      defer c.Close()
      p := make([]byte, 1200)
      _, err := bufio.NewReader(c).Read(p)
      if err != nil {
          fmt.Println(err)
          return
      }
      iph, _ := ipv4.ParseHeader(p)
      fmt.Print(iph)
    }(c)
  }
}