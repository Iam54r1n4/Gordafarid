// Package socks implements the SOCKS5 proxy protocol.
package socks

import (
	"context"
	"net"
)

type Socks5 struct {
	ctx          context.Context
	conn         net.Conn
	gretting     greetingHeader
	userPassAuth userPassAuthHeader
	request      requestHeader
}

func NewSocks5(ctx context.Context, c net.Conn) *Socks5 {
	return &Socks5{
		ctx:  ctx,
		conn: c,
	}
}
