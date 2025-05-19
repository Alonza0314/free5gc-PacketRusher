package gnb

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"my5G-RANTester/config"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	logger "github.com/Alonza0314/logger-go"
	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/sctp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	sGnbN2Ip   = "10.0.2.2"
	sGnbN3Ip   = "10.0.2.2"
	ngapPPID   = 0x3c000000
	sRanULTeid = "00000003"
	sRanDLTeid = "\x00\x00\x00\x02"
	ueIp       = "10.60.0.1"
	one4Ip     = "1.1.1.1"
)

func sRanActionUsage() {
	logger.Info("SRAN", "************************************")
	logger.Info("SRAN", "* Usage: ping <dest_ip> -c <times> *")
	logger.Info("SRAN", "*        exit                      *")
	logger.Info("SRAN", "************************************")
}

func connectN2(cfg config.Config) (*sctp.SCTPConn, error) {
	getNgapIp := func(amfIP, ranIP string, amfPort, ranPort int) (amfAddr, ranAddr *sctp.SCTPAddr, err error) {
		ips := []net.IPAddr{}
		if ip, err1 := net.ResolveIPAddr("ip", amfIP); err1 != nil {
			err = fmt.Errorf("Error resolving address '%s': %v", amfIP, err1)
			return nil, nil, err
		} else {
			ips = append(ips, *ip)
		}
		amfAddr = &sctp.SCTPAddr{
			IPAddrs: ips,
			Port:    amfPort,
		}
		ips = []net.IPAddr{}
		if ip, err1 := net.ResolveIPAddr("ip", ranIP); err1 != nil {
			err = fmt.Errorf("Error resolving address '%s': %v", ranIP, err1)
			return nil, nil, err
		} else {
			ips = append(ips, *ip)
		}
		ranAddr = &sctp.SCTPAddr{
			IPAddrs: ips,
			Port:    ranPort,
		}
		return amfAddr, ranAddr, nil
	}

	connectToAmf := func(amfIP, ranIP string, amfPort, ranPort int) (*sctp.SCTPConn, error) {
		amfAddr, ranAddr, err := getNgapIp(amfIP, ranIP, amfPort, ranPort)
		if err != nil {
			return nil, err
		}
		conn, err := sctp.DialSCTP("sctp", ranAddr, amfAddr)
		if err != nil {
			return nil, err
		}
		info, err := conn.GetDefaultSentParam()
		if err != nil {
			return nil, fmt.Errorf("conn GetDefaultSentParam error in ConnectToAmf: %+v", err)
		}
		info.PPID = ngapPPID
		err = conn.SetDefaultSentParam(info)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}

	conn, err := connectToAmf(cfg.AMFs[0].Addr().String(), sGnbN2Ip, int(cfg.AMFs[0].Port()), int(cfg.GNodeB.ControlIF.Port()))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func ngSetup(n2Conn *sctp.SCTPConn) error {
	var n int
	var recvMsg = make([]byte, 2048)

	buildNGSetupRequest := func() (pdu ngapType.NGAPPDU) {

		pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
		pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

		initiatingMessage := pdu.InitiatingMessage
		initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeNGSetup
		initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject

		initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentNGSetupRequest
		initiatingMessage.Value.NGSetupRequest = new(ngapType.NGSetupRequest)

		nGSetupRequest := initiatingMessage.Value.NGSetupRequest
		nGSetupRequestIEs := &nGSetupRequest.ProtocolIEs

		// GlobalRANNodeID
		ie := ngapType.NGSetupRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDGlobalRANNodeID
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.NGSetupRequestIEsPresentGlobalRANNodeID
		ie.Value.GlobalRANNodeID = new(ngapType.GlobalRANNodeID)

		globalRANNodeID := ie.Value.GlobalRANNodeID
		globalRANNodeID.Present = ngapType.GlobalRANNodeIDPresentGlobalGNBID
		globalRANNodeID.GlobalGNBID = new(ngapType.GlobalGNBID)

		globalGNBID := globalRANNodeID.GlobalGNBID
		globalGNBID.PLMNIdentity.Value = aper.OctetString("\x02\xf8\x39")
		globalGNBID.GNBID.Present = ngapType.GNBIDPresentGNBID
		globalGNBID.GNBID.GNBID = new(aper.BitString)

		gNBID := globalGNBID.GNBID.GNBID

		*gNBID = aper.BitString{
			Bytes:     []byte{0x45, 0x46, 0x47},
			BitLength: 24,
		}
		nGSetupRequestIEs.List = append(nGSetupRequestIEs.List, ie)

		// RANNodeName
		ie = ngapType.NGSetupRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDRANNodeName
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.NGSetupRequestIEsPresentRANNodeName
		ie.Value.RANNodeName = new(ngapType.RANNodeName)

		rANNodeName := ie.Value.RANNodeName
		rANNodeName.Value = "free5GC"
		nGSetupRequestIEs.List = append(nGSetupRequestIEs.List, ie)
		// SupportedTAList
		ie = ngapType.NGSetupRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDSupportedTAList
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.NGSetupRequestIEsPresentSupportedTAList
		ie.Value.SupportedTAList = new(ngapType.SupportedTAList)

		supportedTAList := ie.Value.SupportedTAList

		// SupportedTAItem in SupportedTAList
		supportedTAItem := ngapType.SupportedTAItem{}
		supportedTAItem.TAC.Value = aper.OctetString("\x00\x00\x01")

		broadcastPLMNList := &supportedTAItem.BroadcastPLMNList
		// BroadcastPLMNItem in BroadcastPLMNList
		broadcastPLMNItem := ngapType.BroadcastPLMNItem{}
		broadcastPLMNItem.PLMNIdentity.Value = aper.OctetString("\x02\xf8\x39")

		sliceSupportList := &broadcastPLMNItem.TAISliceSupportList
		// SliceSupportItem in SliceSupportList
		sliceSupportItem := ngapType.SliceSupportItem{}
		sliceSupportItem.SNSSAI.SST.Value = aper.OctetString("\x01")
		// optional
		sliceSupportItem.SNSSAI.SD = new(ngapType.SD)
		sliceSupportItem.SNSSAI.SD.Value = aper.OctetString("\xfe\xdc\xba")

		sliceSupportList.List = append(sliceSupportList.List, sliceSupportItem)

		broadcastPLMNList.List = append(broadcastPLMNList.List, broadcastPLMNItem)

		supportedTAList.List = append(supportedTAList.List, supportedTAItem)

		nGSetupRequestIEs.List = append(nGSetupRequestIEs.List, ie)

		// PagingDRX
		ie = ngapType.NGSetupRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDDefaultPagingDRX
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.NGSetupRequestIEsPresentDefaultPagingDRX
		ie.Value.DefaultPagingDRX = new(ngapType.PagingDRX)

		pagingDRX := ie.Value.DefaultPagingDRX
		pagingDRX.Value = ngapType.PagingDRXPresentV128
		nGSetupRequestIEs.List = append(nGSetupRequestIEs.List, ie)

		return pdu
	}

	getNGSetupRequest := func(gnbId []byte, bitlength uint64, name string) ([]byte, error) {
		message := buildNGSetupRequest()
		// GlobalRANNodeID
		ie := message.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List[0]
		gnbID := ie.Value.GlobalRANNodeID.GlobalGNBID.GNBID.GNBID
		gnbID.Bytes = gnbId
		gnbID.BitLength = bitlength
		// RANNodeName
		ie = message.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List[1]
		ie.Value.RANNodeName.Value = name

		return ngap.Encoder(message)
	}

	// send Master RAN NGSetupRequest Msg
	sendMsg, err := getNGSetupRequest([]byte("\x00\x03\x04"), 24, "SRAN")
	if err != nil {
		return err
	}
	_, err = n2Conn.Write(sendMsg)
	if err != nil {
		return err
	}

	// receive Master RAN NGSetupResponse Msg
	n, err = n2Conn.Read(recvMsg)
	if err != nil {
		return err
	}
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	if err != nil {
		return err
	}
	if ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup {
		return nil
	}
	return fmt.Errorf("NGSetupResponse is not successful")
}

func connectN3(cfg config.Config) (*net.UDPConn, error) {
	connectToUpf := func(enbIP, upfIP string, gnbPort, upfPort int) (*net.UDPConn, error) {
		upfAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", upfIP, upfPort))
		if err != nil {
			return nil, err
		}
		gnbAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", enbIP, gnbPort))
		if err != nil {
			return nil, err
		}
		return net.DialUDP("udp", gnbAddr, upfAddr)
	}

	conn, err := connectToUpf(sGnbN3Ip, cfg.AMFs[0].Addr().String(), int(cfg.GNodeB.DataIF.Port()), int(cfg.GNodeB.DataIF.Port()))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type pingStats struct {
	transmitted int
	received    int
	startTime   time.Time
	rtts        []float64
}

func (ps *pingStats) print(destIP string, sourceIP string) {
	var sum, min, max, mdev float64
	if len(ps.rtts) > 0 {
		min = ps.rtts[0]
		max = ps.rtts[0]
		for _, rtt := range ps.rtts {
			sum += rtt
			if rtt < min {
				min = rtt
			}
			if rtt > max {
				max = rtt
			}
		}
	}
	avg := sum / float64(len(ps.rtts))

	var sumSquares float64
	for _, rtt := range ps.rtts {
		sumSquares += (rtt - avg) * (rtt - avg)
	}
	if len(ps.rtts) > 0 {
		mdev = math.Sqrt(sumSquares / float64(len(ps.rtts)))
	}

	lossRate := float64(ps.transmitted-ps.received) / float64(ps.transmitted) * 100
	totalTime := time.Since(ps.startTime).Milliseconds()

	fmt.Printf("\n--- %s ping statistics ---\n", destIP)
	if lossRate == 0 {
		fmt.Printf("%d packets transmitted, %d received, 0%% packet loss, time %dms\n",
			ps.transmitted, ps.received, totalTime)
	} else {
		fmt.Printf("%d packets transmitted, %d received, %.1f%% packet loss, time %dms\n",
			ps.transmitted, ps.received, lossRate, totalTime)
	}
	if ps.received > 0 {
		fmt.Printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
			min, avg, max, mdev)
	}
}

func ping(destIp string, cfg config.Config, stats *pingStats) error {
	calculateIpv4HeaderChecksum := func(hdr *ipv4.Header) uint32 {
		var Checksum uint32
		Checksum += uint32((hdr.Version<<4|(20>>2&0x0f))<<8 | hdr.TOS)
		Checksum += uint32(hdr.TotalLen)
		Checksum += uint32(hdr.ID)
		Checksum += uint32((hdr.FragOff & 0x1fff) | (int(hdr.Flags) << 13))
		Checksum += uint32((hdr.TTL << 8) | (hdr.Protocol))

		src := hdr.Src.To4()
		Checksum += uint32(src[0])<<8 | uint32(src[1])
		Checksum += uint32(src[2])<<8 | uint32(src[3])
		dst := hdr.Dst.To4()
		Checksum += uint32(dst[0])<<8 | uint32(dst[1])
		Checksum += uint32(dst[2])<<8 | uint32(dst[3])
		return ^(Checksum&0xffff0000>>16 + Checksum&0xffff)
	}

	// Connect to N3
	n3Conn, err := connectN3(cfg)
	if err != nil {
		return err
	}
	defer n3Conn.Close()

	gtpHdr, err := hex.DecodeString(fmt.Sprintf("32ff0034%s00000000", sRanULTeid))
	if err != nil {
		return err
	}
	icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	if err != nil {
		return err
	}

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		Protocol: 1,
		Flags:    0,
		TotalLen: 48,
		TTL:      64,
		Src:      net.ParseIP(ueIp).To4(),
		Dst:      net.ParseIP(one4Ip).To4(),
		ID:       1,
	}
	ipv4hdr.Checksum = int(calculateIpv4HeaderChecksum(&ipv4hdr))
	ipv4HdrBuf, err := ipv4hdr.Marshal()
	if err != nil {
		return err
	}
	tt := append(gtpHdr, ipv4HdrBuf...)

	icmpMsg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: 1,
			Data: icmpData,
		},
	}
	b, err := icmpMsg.Marshal(nil)
	if err != nil {
		return err
	}
	b[2] = 0xaf
	b[3] = 0x88
	_, err = n3Conn.Write(append(tt, b...))
	if err != nil {
		return err
	}
	n3Conn.Close()

	recvConn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(sGnbN3Ip).To4(),
		Port: 2152,
	})
	if err != nil {
		return err
	}
	defer recvConn.Close()

	recvMsg := make([]byte, 2048)
	err = recvConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		return err
	}

	pingStart := time.Now()

	stats.transmitted++
	n, err := recvConn.Read(recvMsg)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			logger.Error("PING", "Request timeout")
			return nil
		}
		return err
	}

	if n >= 48 {
		stats.received++
		ttl := recvMsg[36]
		rtt := float64(time.Since(pingStart).Microseconds()) / 1000.0
		stats.rtts = append(stats.rtts, rtt)

		fmt.Printf("64 bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n",
			destIp, stats.transmitted, ttl, rtt)
	}

	return nil
}

func SranAction(cfg config.Config) {
	// Connect to AMF
	n2Conn, err := connectN2(cfg)
	if err != nil {
		logger.Error("GNB", fmt.Sprintf("Failed to connect to AMF: %v", err))
		return
	}
	defer n2Conn.Close()

	// NG setup
	if err := ngSetup(n2Conn); err != nil {
		logger.Error("GNB", fmt.Sprintf("Failed to setup NG: %v", err))
		return
	}

	// GTP/ICMP test
	reader := bufio.NewReader(os.Stdin)
	sRanActionUsage()
	for {
		fmt.Print("SRAN> ")
		input, _ := reader.ReadString('\n')
		if input == "\n" {
			continue
		}
		input = strings.TrimSpace(input)
		parts := strings.Split(input, " ")
		switch parts[0] {
		case "ping":
			if len(parts) != 4 || parts[2] != "-c" {
				logger.Error("SRAN", "Invalid ping command format")
				sRanActionUsage()
				continue
			}

			n, err := strconv.Atoi(parts[3])
			if err != nil {
				logger.Error("SRAN", fmt.Sprintf("Failed to convert '-c' argument to int: %v", err))
				continue
			}

			stats := &pingStats{
				startTime: time.Now(),
			}

			fmt.Printf("PING %s (%s) from %s: 56(84) bytes of data.\n", parts[1], parts[1], ueIp)
			for i := 0; i < n; i++ {
				if err := ping(parts[1], cfg, stats); err != nil {
					logger.Error("SRAN", fmt.Sprintf("Failed to ping: %v", err))
					continue
				}
				if i != n-1 {
					time.Sleep(1 * time.Second)
				}
			}

			stats.print(parts[1], ueIp)
		case "exit":
			return
		default:
			logger.Error("SRAN", "Invalid input")
			sRanActionUsage()
		}
	}
}
