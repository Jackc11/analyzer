package analyzer

import (
	"bytes"
	"go_packet/config"
	"log/slog"
	"net"
	"os"
	"os/signal"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type PacketRead struct {
	conf       *config.Config
	source     *gopacket.PacketSource
	fileWriter *bytes.Buffer
	pcapWriter *pcapgo.Writer
}

func CreatePacketRead(conf *config.Config) *PacketRead {
	var pr PacketRead
	pr.conf = conf

	devices, err := pcap.FindAllDevs()
	if err != nil {
		slog.Error("Could not find devices", slog.String("err", err.Error()))
		os.Exit(1)
	}

	var pcapDeviceName string
	for _, device := range devices {
		if device.Description == pr.conf.DeviceName || device.Name == pr.conf.DeviceName {
			pcapDeviceName = device.Name
			break
		}
	}

	if pcapDeviceName == "" {
		slog.Error("Could not find matching pcap device for description", slog.String("desc", pr.conf.DeviceName))
		for _, d := range devices {
			slog.Info("Available device", slog.String("name", d.Name), slog.String("desc", d.Description))
		}
		os.Exit(1)
	} else {
		slog.Info("Using interface:", slog.String("device", pcapDeviceName))
	}

	handle, err := pcap.OpenLive(pcapDeviceName, int32(conf.Snaplen), true, pcap.BlockForever)
	if err != nil {
		slog.Error("Could not OpenLive", slog.String("err", err.Error()))
		os.Exit(1)
	}

	pr.source = gopacket.NewPacketSource(handle, handle.LinkType())

	pr.fileWriter = bytes.NewBuffer(nil)
	pr.pcapWriter = pcapgo.NewWriterNanos(pr.fileWriter)
	err = pr.pcapWriter.WriteFileHeader(uint32(conf.Snaplen), handle.LinkType())
	if err != nil {
		slog.Error("Could not write pcap header", slog.String("err", err.Error()))
		os.Exit(1)
	}

	return &pr
}

func isSameIpAddress(filter config.FilterConfig, ip4 *layers.IPv4) bool {
	for _, addr := range filter.Address {
		if ip4.SrcIP.Equal(net.ParseIP(addr)) || ip4.DstIP.Equal(net.ParseIP(addr)) {
			return true
		}
	}
	return false
}

func (pr *PacketRead) WriteLoopbackTraffic(packet gopacket.Packet) {
	err := pr.pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	if err != nil {
		slog.Error("Failed to write packet", slog.String("err", err.Error()))
	} else {
		slog.Info("Stored packet", slog.Any("packet", packet))
	}
}

func (pr *PacketRead) WriteTcpTraffic(packet gopacket.Packet) bool {
	err := pr.pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	if err != nil {
		slog.Error("Fehler beim Schreiben des Pakets", slog.String("err", err.Error()))
	}
	slog.Debug("Passendes Paket erfasst")

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.FIN || tcp.RST {
			slog.Info("Found FIN/RST. Finishing to capture...")
			err := os.WriteFile(pr.conf.PcapName, pr.fileWriter.Bytes(), 0644)
			if err != nil {
				slog.Error("Failed to write packet", slog.String("err", err.Error()))
			}
			return false
		}
	}
	return true
}

func (pr *PacketRead) Run() bool {
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go func() {
		<-stopChan
		os.WriteFile(pr.conf.PcapName, pr.fileWriter.Bytes(), 0644)
		slog.Info("PCAP saved.")
		os.Exit(0)
	}()

	slog.Info("Starting to capture traffic")

	for packet := range pr.source.Packets() {
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ip4, _ := ip4Layer.(*layers.IPv4)

			if pr.conf.IsLoopBack {
				if ip4.SrcIP.IsLoopback() || ip4.DstIP.IsLoopback() {
					pr.WriteLoopbackTraffic(packet)
				}
			} else {
				if isSameIpAddress(pr.conf.Filter, ip4) {
					res := pr.WriteTcpTraffic(packet)
					if !res {
						slog.Info("Finished capturing. Captured bytes:", slog.Int("bytes", pr.fileWriter.Len()))
						return false
					}
				}
			}
		}
	}

	return true
}
