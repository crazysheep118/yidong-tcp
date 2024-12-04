package main

import (
"bytes"
"encoding/binary"
"flag"
"fmt"
"log"
"os"
"os/signal"
"sync"
"syscall"

"github.com/google/gopacket"
"github.com/google/gopacket/layers"
"github.com/google/gopacket/pcap"
"github.com/upekshe/netfilterqueue"
)

var (
windowSize     int
windowScale    int
confusionTimes int
editTimes      sync.Map
)

func clearWindowScale(tcp *layers.TCP) {
newOptions := []layers.TCPOption{}
for _, opt := range tcp.Options {
  if opt.OptionType != layers.TCPOptionKindWindowScale {
   newOptions = append(newOptions, opt)
  }
}
tcp.Options = newOptions
}

func modifyWindow(pkt *netfilterqueue.Packet) {
defer func() {
  if r := recover(); r != nil {
   log.Println("Recovered in modifyWindow:", r)
  }
}()

packet := gopacket.NewPacket(pkt.Data, layers.LayerTypeIPv4, gopacket.Default)
ipLayer := packet.Layer(layers.LayerTypeIPv4)
tcpLayer := packet.Layer(layers.LayerTypeTCP)

if ipLayer == nil || tcpLayer == nil {
  pkt.Accept()
  return
}

ip, _ := ipLayer.(*layers.IPv4)
tcp, _ := tcpLayer.(*layers.TCP)

key := fmt.Sprintf("%s_%d", ip.DstIP.String(), tcp.DstPort)
sa := false

switch tcp.SYN && tcp.ACK {
case true:
  editTimes.Store(key, 1)
  clearWindowScale(tcp)
  tcp.Window = uint16(windowSize)
  sa = true
case false:
  value, _ := editTimes.LoadOrStore(key, 1)
  counter := value.(int)
  if counter <= 6 {
   tcp.Window = uint16(windowSize)
  } else {
   tcp.Window = 28960
  }
  editTimes.Store(key, counter+1)
}

// Recalculate checksums
ip.SetNetworkLayerForChecksum(tcp)
buffer := gopacket.NewSerializeBuffer()
opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
if err := gopacket.SerializeLayers(buffer, opts, ip, tcp); err != nil {
  log.Println("Failed to serialize layers:", err)
  pkt.Drop()
  return
}

pkt.SetPayload(buffer.Bytes())
pkt.Accept()

if sa {
  go sendPayloads(ip, tcp)
}
}

func sendPayloads(ip *layers.IPv4, tcp *layers.TCP) {
if confusionTimes < 1 {
  return
}

handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
if err != nil {
  log.Println("Failed to open device:", err)
  return
}
defer handle.Close()

for i := 1; i <= confusionTimes; i++ {
  winSize := windowSize
  if i == confusionTimes {
   winSize = 65535
  }

  ackPacket := &layers.TCP{
   SrcPort: tcp.DstPort,
   DstPort: tcp.SrcPort,
   ACK:     true,
   Seq:     tcp.Ack + uint32(i),
   Window:  uint16(winSize),
   Options: []layers.TCPOption{
    {OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{byte(windowScale)}},
   },
  }

  ipPacket := &layers.IPv4{
   SrcIP:    ip.DstIP,
   DstIP:    ip.SrcIP,
   Protocol: layers.IPProtocolTCP,
  }

  buffer := gopacket.NewSerializeBuffer()
  opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
  if err := gopacket.SerializeLayers(buffer, opts, ipPacket, ackPacket); err != nil {
   log.Println("Failed to serialize ack packet:", err)
   return
  }

  if err := handle.WritePacketData(buffer.Bytes()); err != nil {
   log.Println("Failed to send ack packet:", err)
  }
}
}

func main() {
queueNum := flag.Int("queue", -1, "iptables Queue Num")
windowSizeFlag := flag.Int("window_size", 17, "TCP Window Size")
windowScaleFlag := flag.Int("window_scale", 7, "TCP Window Scale")
confusionTimesFlag := flag.Int("confusion_times", 7, "Confusion Times")
flag.Parse()

if *queueNum == -1 || *windowSizeFlag == 0 {
  flag.Usage()
  os.Exit(1)
}

windowSize = *windowSizeFlag
windowScale = *windowScaleFlag
confusionTimes = *confusionTimesFlag

nfq, err := netfilterqueue.New(*queueNum)
if err != nil {
  log.Fatalf("Failed to create netfilter queue: %v", err)
}

log.Println("Starting netfilter_queue process...")
go func() {
  if err := nfq.Run(modifyWindow); err != nil {
   log.Fatalf("Failed to process packets: %v", err)
  }
}()

sigs := make(chan os.Signal, 1)
signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
<-sigs

log.Println("Exiting...")
nfq.Close()
}