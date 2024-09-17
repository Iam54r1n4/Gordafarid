package socks

import "github.com/Iam54r1n4/Gordafarid/core/net/utils"

type greetingHeader struct {
	version  byte
	nMethods byte
	methods  []byte
}
type userPassAuthHeader struct {
	version  byte
	uLen     byte
	username []byte
	pLen     byte
	password []byte
}
type requestHeader struct {
	version byte
	cmd     byte
	rsv     byte
	atyp    byte
	dstAddr []byte
	dstPort [utils.DestinationPortSize]byte
}
