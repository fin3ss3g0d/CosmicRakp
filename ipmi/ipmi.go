package ipmi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	PAYLOAD_RMCPPLUSOPEN_REQ = 0x10
	PAYLOAD_RAKP1            = 0x12
	PAYLOAD_RAKP2            = 0x13
)

var RMCP_ERRORS = map[uint8]string{
	1:    "Insufficient resources to create new session (wait for existing sessions to timeout)",
	2:    "Invalid Session ID",
	3:    "Invalid payload type",
	4:    "Invalid authentication algorithm",
	5:    "Invalid integrity algorithm",
	6:    "No matching authentication payload",
	7:    "No matching integrity payload",
	8:    "Inactive Session ID",
	9:    "Invalid role",
	0xa:  "Unauthorised role or privilege level requested",
	0xb:  "Insufficient resources to create a session at the requested role",
	0xc:  "Invalid username length",
	0xd:  "Unauthorized name",
	0xe:  "Unauthorized GUID",
	0xf:  "Invalid integrity check value",
	0x10: "Invalid confidentiality algorithm",
	0x11: "No cipher suite match with proposed security algorithms",
	0x12: "Illegal or unrecognized parameter",
}

// SessionData represents the IPMI session data
type SessionData struct {
	ConsoleSessionID []byte
	BMCSessionID     []byte
}

type RAKP2Data struct {
	ConsoleSessionID []byte // length 4
	BMCRandomID      []byte // length 16
	BMCGUID          []byte // length 16
	HMACSHA1         []byte // length 20
}

type RAKP2 struct {
	RMCPVersion                 uint8
	RMCPPadding                 uint8
	RMCPSequence                uint8
	RMCPMType                   uint8 // Extracted manually
	RMCPClass                   uint8 // Extracted manually
	SessionAuthType             uint8
	SessionPayloadEncrypted     uint8 // Extracted manually
	SessionPayloadAuthenticated uint8 // Extracted manually
	SessionPayloadType          uint8 // Extracted manually
	SessionID                   uint32
	SessionSequence             uint32
	MessageLength               uint16
	Ignored1                    uint8
	ErrorCode                   uint8
	Ignored2                    uint16
	Data                        []byte
}

type OpenSessionReply struct {
	RMCPVersion                 uint8
	RMCPPadding                 uint8
	RMCPSequence                uint8
	RMCPMessageType             uint8 // Extracted manually
	RMCPMessageClass            uint8 // Extracted manually
	SessionAuthType             uint8
	SessionPayloadEncrypted     uint8 // Extracted manually
	SessionPayloadAuthenticated uint8 // Extracted manually
	SessionPayloadType          uint8 // Extracted manually
	SessionID                   uint32
	SessionSequence             uint32
	MessageLength               uint16
	Ignored1                    uint8
	ErrorCode                   uint8
	Ignored2                    uint16
	Data                        []byte
}

func CreateUDPConnection(ipAddress string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", ipAddress+":623")
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// createIPMISessionOpenRequest prepares the IPMI session open request packet
func createIPMISessionOpenRequest(consoleSessionID []byte) ([]byte, error) {
	// RMCP Header
	head := []byte{0x06, 0x00, 0xff, 0x07, 0x06, PAYLOAD_RMCPPLUSOPEN_REQ, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// Additional Data
	data := append([]byte{0x00, 0x00, 0x00, 0x00}, consoleSessionID...)
	data = append(data, []byte{
		0x00, 0x00, 0x00, 0x08,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x08,
		0x01, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x08,
		0x01, 0x00, 0x00, 0x00,
	}...)

	// Combine Header and Data
	var packet bytes.Buffer
	packet.Write(head)
	binary.Write(&packet, binary.LittleEndian, uint16(len(data)))
	packet.Write(data)

	return packet.Bytes(), nil
}

func SendIPMISessionOpenRequest(conn *net.UDPConn, consoleSessionID []byte, maxAttempts int, retryDelay time.Duration, readTimeout time.Duration) (*OpenSessionReply, error) {
	// create IPMI session open request packet
	packet, err := createIPMISessionOpenRequest(consoleSessionID)
	if err != nil {
		return nil, err
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		_, err = conn.Write(packet)
		if err != nil {
			return nil, err
		}

		conn.SetReadDeadline(time.Now().Add(readTimeout))
		replyData := make([]byte, 1024)
		n, _, err := conn.ReadFromUDP(replyData)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Printf("No response to IPMI open session request, attempt %d\n", attempt)
				time.Sleep(retryDelay)
				continue
			}
			return nil, err
		}

		reply, err := processOpenSessionReply(replyData[:n])
		if err != nil {
			fmt.Printf("Could not understand the response to the open session request, attempt %d\n", attempt)
			time.Sleep(retryDelay)
			continue
		}

		if len(reply.Data) < 8 {
			fmt.Printf("Refused IPMI open session request, waiting for %s, attempt %d\n", retryDelay.String(), attempt)
			time.Sleep(retryDelay)
			continue
		}

		return reply, nil
	}

	return nil, fmt.Errorf("Max attempts reached")
}

func processOpenSessionReply(data []byte) (*OpenSessionReply, error) {
	if len(data) < 23 { // At least 23 bytes required to parse the OpenSessionReply
		return nil, fmt.Errorf("Insufficient data length")
	}

	reply := &OpenSessionReply{}
	buf := bytes.NewBuffer(data)

	var rmcpTotal, sessionTotal uint8

	binary.Read(buf, binary.LittleEndian, &reply.RMCPVersion)
	binary.Read(buf, binary.LittleEndian, &reply.RMCPPadding)
	binary.Read(buf, binary.LittleEndian, &reply.RMCPSequence)
	binary.Read(buf, binary.LittleEndian, &rmcpTotal)
	binary.Read(buf, binary.LittleEndian, &reply.SessionAuthType)
	binary.Read(buf, binary.LittleEndian, &sessionTotal)
	binary.Read(buf, binary.LittleEndian, &reply.SessionID)
	binary.Read(buf, binary.LittleEndian, &reply.SessionSequence)
	binary.Read(buf, binary.LittleEndian, &reply.MessageLength)
	binary.Read(buf, binary.LittleEndian, &reply.Ignored1)
	binary.Read(buf, binary.LittleEndian, &reply.ErrorCode)
	binary.Read(buf, binary.LittleEndian, &reply.Ignored2)
	reply.Data = buf.Bytes()

	// Manually extract bit-fields
	reply.RMCPMessageType = rmcpTotal & 0x01
	reply.RMCPMessageClass = rmcpTotal >> 1

	reply.SessionPayloadEncrypted = sessionTotal & 0x01
	reply.SessionPayloadAuthenticated = (sessionTotal >> 1) & 0x01
	reply.SessionPayloadType = sessionTotal >> 2

	return reply, nil
}

func createIPMIRAKP1(bmcSessionID []byte, consoleRandomID []byte, username string) []byte {
	var head = []byte{
		0x06, 0x00, 0xff, 0x07, // RMCP Header
		0x06,          // RMCP+ Authentication Type
		PAYLOAD_RAKP1, // Payload Type
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	var zeroPadding = []byte{0x00, 0x00, 0x00, 0x00}
	var usernameLen = byte(len(username))

	data := append(zeroPadding, bmcSessionID...)
	data = append(data, consoleRandomID...)
	data = append(data, []byte{0x14, 0x00, 0x00, usernameLen}...)
	data = append(data, []byte(username)...)

	var buffer bytes.Buffer
	buffer.Write(head)
	binary.Write(&buffer, binary.LittleEndian, uint16(len(data)))
	buffer.Write(data)

	return buffer.Bytes()
}

func SendIPMIRAKP1Request(conn *net.UDPConn, bmcSessionID []byte, consoleRandomID []byte, username string, maxAttempts int, retryDelay time.Duration) (*RAKP2, error) {
	// Create IPMI RAKP1 packet
	packet := createIPMIRAKP1(bmcSessionID, consoleRandomID, username)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		_, err := conn.Write(packet)
		if err != nil {
			return nil, err
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		replyData := make([]byte, 1024)
		n, _, err := conn.ReadFromUDP(replyData)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Printf("No response to IPMI RAKP1 request, attempt %d\n", attempt)
				time.Sleep(retryDelay)
				continue
			}
			return nil, err
		}

		reply, err := processRAKP1Reply(replyData[:n])
		if err != nil {
			fmt.Printf("Could not understand the response to the RAKP1 request, attempt %d\n", attempt)
			time.Sleep(retryDelay)
			continue
		}

		if len(reply.Data) < 56 {
			return nil, fmt.Errorf("No hash data")
		}

		return reply, nil
	}

	return nil, fmt.Errorf("Max attempts reached")
}

func processRAKP1Reply(data []byte) (*RAKP2, error) {
	if len(data) < 23 { // At least 23 bytes required to parse the RAKP2
		return nil, fmt.Errorf("Insufficient data length")
	}

	reply := &RAKP2{}
	buf := bytes.NewBuffer(data)

	var rmcpTotal, sessionTotal uint8

	binary.Read(buf, binary.LittleEndian, &reply.RMCPVersion)
	binary.Read(buf, binary.LittleEndian, &reply.RMCPPadding)
	binary.Read(buf, binary.LittleEndian, &reply.RMCPSequence)
	binary.Read(buf, binary.LittleEndian, &rmcpTotal)
	binary.Read(buf, binary.LittleEndian, &reply.SessionAuthType)
	binary.Read(buf, binary.LittleEndian, &sessionTotal)
	binary.Read(buf, binary.LittleEndian, &reply.SessionID)
	binary.Read(buf, binary.LittleEndian, &reply.SessionSequence)
	binary.Read(buf, binary.LittleEndian, &reply.MessageLength)
	binary.Read(buf, binary.LittleEndian, &reply.Ignored1)
	binary.Read(buf, binary.LittleEndian, &reply.ErrorCode)
	binary.Read(buf, binary.LittleEndian, &reply.Ignored2)
	reply.Data = buf.Bytes()

	// Manually extract bit-fields
	reply.RMCPMType = rmcpTotal & 0x01 // Extract the last bit
	reply.RMCPClass = rmcpTotal >> 1   // Shift and extract the remaining 7 bits

	reply.SessionPayloadEncrypted = sessionTotal & 0x01
	reply.SessionPayloadAuthenticated = (sessionTotal >> 1) & 0x01
	reply.SessionPayloadType = sessionTotal >> 2

	return reply, nil
}

func CreateRAKPHMACSHA1Salt(conSid, bmcSid, conRid []byte, bmcRid, bmcGid string, authLevel uint8, username string) []byte {
	var buffer bytes.Buffer

	// Adding Console Session ID
	buffer.Write(conSid)

	// Adding BMC Session ID
	buffer.Write(bmcSid)

	// Adding Console Random ID
	buffer.Write(conRid)

	// Adding BMC Random ID
	buffer.WriteString(bmcRid)

	// Adding BMC GUID
	buffer.WriteString(bmcGid)

	// Adding Auth Level
	binary.Write(&buffer, binary.LittleEndian, authLevel)

	// Adding Username Length
	usernameLength := uint8(len(username))
	binary.Write(&buffer, binary.LittleEndian, usernameLength)

	// Adding Username
	buffer.WriteString(username)

	return buffer.Bytes()
}

func getRMCPError(errorCode uint8) (string, bool) {
	message, exists := RMCP_ERRORS[errorCode]
	return message, exists
}

func ipmiError(message string) {
	// Handle your error here; for this example, we'll just print it.
	fmt.Println("IPMI Error:", message)
}

func CheckRAKPErrors(rakp *RAKP2, username string) error {
	if rakp.ErrorCode == 2 {
		errMsg := fmt.Sprintf("Returned a Session ID error for username %s", username)
		ipmiError(errMsg)
		time.Sleep(1 * time.Second)
		return fmt.Errorf(errMsg)
	}
	if rakp.ErrorCode != 0 {
		errorMessage, ok := getRMCPError(rakp.ErrorCode)
		if !ok {
			errorMessage = "Unknown error code"
		}
		errMsg := fmt.Sprintf("Returned error code %d for username %s: %s", rakp.ErrorCode, username, errorMessage)
		ipmiError(errMsg)
		return fmt.Errorf(errMsg)
	}
	if rakp.Ignored1 != 0 {
		errMsg := fmt.Sprintf("Returned error code %d for username %s", rakp.Ignored1, username)
		ipmiError(errMsg)
		return fmt.Errorf(errMsg)
	}
	return nil
}

// CheckBogusHash checks if the given SHA1 hash is bogus.
func CheckBogusHash(sha1Hash string) error {
	if sha1Hash == "0000000000000000000000000000000000000000" {
		return errors.New("Returned a bogus SHA1 hash")
	}
	return nil
}
