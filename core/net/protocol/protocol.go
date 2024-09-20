// Package protocol defines constants, types, and structures for SOCKS5-like protocols.
package protocol

// Constants for SOCKS5-like protocols
const (
	CmdConnect = 1 // Command for TCP/IP stream connection
	CmdBind    = 2 // Command for TCP/IP port binding
	CmdUDP     = 3 // Command for UDP port association
)

const (
	DstPortSize = 2 // Destination port size in bytes

	// Address types
	AtypIPv4   = 1 // IPv4 address type
	AtypDomain = 3 // Domain name address type
	AtypIPv6   = 4 // IPv6 address type
)

// Header interface defines methods for protocol headers
type Header interface {
	Bytes() []byte // Returns the byte representation of the header
	Size() int     // Returns the size of the header in bytes
}

// AddressHeader represents the address and port of a destination
// These are common fields of SOCKS5-like protocols
type AddressHeader struct {
	Atyp    byte              // Address type (IPv4, Domain, or IPv6)
	DstAddr []byte            // Destination address
	DstPort [DstPortSize]byte // Destination port
}

// NewAddressHeader creates a new AddressHeader with the given parameters
func NewAddressHeader(atyp byte, dstAddr []byte, dstPort [DstPortSize]byte) *AddressHeader {
	return &AddressHeader{
		Atyp:    atyp,
		DstAddr: dstAddr,
		DstPort: dstPort,
	}
}

// Size returns the total size of the AddressHeader in bytes
func (ah *AddressHeader) Size() int {
	size := 1 + len(ah.DstAddr) + DstPortSize
	if ah.Atyp == AtypDomain {
		size++ // Add 1 byte for domain name length
	}
	return size
}

// Bytes returns the byte representation of the AddressHeader
func (ah *AddressHeader) Bytes() []byte {
	result := make([]byte, 0, ah.Size())
	result = append(result, ah.Atyp)
	if ah.Atyp == AtypDomain {
		result = append(result, byte(len(ah.DstAddr)))
	}
	result = append(result, ah.DstAddr...)
	result = append(result, ah.DstPort[:]...)
	return result
}

// BasicHeader represents the version and command of a SOCKS5-like request
type BasicHeader struct {
	Version byte // Protocol version
	Cmd     byte // Command (Connect, Bind, or UDP)
}

// Size returns the size of the BasicHeader in bytes
func (bh *BasicHeader) Size() int {
	return 2
}

// Bytes returns the byte representation of the BasicHeader
func (bh *BasicHeader) Bytes() []byte {
	return []byte{bh.Version, bh.Cmd}
}

// CommonHeader contains common fields for SOCKS5-like protocols
type CommonHeader struct {
	BasicHeader
	AddressHeader
}

// Bytes returns the byte representation of the CommonHeader
func (ch *CommonHeader) Bytes() []byte {
	result := make([]byte, 0, ch.Size())
	result = append(result, ch.BasicHeader.Bytes()...)
	result = append(result, ch.AddressHeader.Bytes()...)
	return result
}

// Size returns the total size of the CommonHeader in bytes
func (ch *CommonHeader) Size() int {
	return ch.BasicHeader.Size() + ch.AddressHeader.Size()
}
