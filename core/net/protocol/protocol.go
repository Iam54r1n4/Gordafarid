package protocol

// Constants for SOCKS5-like protocols
const (
	CmdConnect = 1
	CmdBind    = 2
	CmdUDP     = 3
)
const (
	DstPortSize = 2 // Destination port size in bytes

	// Address types
	AtypIPv4   = 1 // IPv4 address
	AtypDomain = 3 // Domain name
	AtypIPv6   = 4 // IPv6 address
)

type Header interface {
	Bytes() []byte
	Size() int
}

// AddressHeader represents the address and port of a destination, these are common fields of SOCKS5-like protocols
type AddressHeader struct {
	Atyp    byte
	DstAddr []byte
	DstPort [DstPortSize]byte
}

func NewAddressHeader(atyp byte, dstAddr []byte, dstPort [DstPortSize]byte) *AddressHeader {
	return &AddressHeader{
		Atyp:    atyp,
		DstAddr: dstAddr,
		DstPort: dstPort,
	}
}

func (ah *AddressHeader) Size() int {
	return 1 + len(ah.DstAddr) + DstPortSize
}

func (ah *AddressHeader) Bytes() []byte {
	result := make([]byte, 0, 1+len(ah.DstAddr)+DstPortSize)
	result = append(result, ah.Atyp)
	if ah.Atyp == AtypDomain {
		result = append(result, byte(len(ah.DstAddr)))
	}
	result = append(result, ah.DstAddr...)
	result = append(result, ah.DstPort[:]...)
	return result
}

// BasicHeaader represents the version and command of a SOCKS5-like request
type BasicHeaader struct {
	Version byte
	Cmd     byte
}

func (bh *BasicHeaader) Size() int {
	return 2
}

func (bh BasicHeaader) Bytes() []byte {
	return []byte{bh.Version, bh.Cmd}
}

// CommonHeader contains common fields for SOCKS5-like protocols
type CommonHeader struct {
	BasicHeaader
	AddressHeader
}

func (ch *CommonHeader) Bytes() []byte {
	result := make([]byte, 0, ch.Size())
	result = append(result, ch.BasicHeaader.Bytes()...)
	result = append(result, ch.AddressHeader.Bytes()...)
	return result
}

func (ch *CommonHeader) Size() int {
	return ch.BasicHeaader.Size() + ch.AddressHeader.Size()
}
