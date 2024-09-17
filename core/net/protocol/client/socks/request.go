package socks

import (
	"errors"
	"fmt"

	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

// handleSocks5Request processes the SOCKS5 request from the client
// It reads the requested address type, address, and port
func (s *Socks5) handleSocks5Request() error {
	// Read version, command, and reserved byte
	buf := make([]byte, 3)
	if _, err := utils.ReadWithContext(s.ctx, s.conn, buf); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadRequest, err)
	}
	if buf[0] != socks5Version || buf[1] != 1 {
		return errors.Join(proxy_error.ErrSocks5UnsupportedVersionOrCommand, fmt.Errorf("unsupported socks request:\nVersion: %d\nCommand: %d", buf[0], buf[1]))
	}
	s.request.version = buf[0]
	// TODO verify cmd and define const cmds
	s.request.cmd = buf[1]
	s.request.rsv = buf[2]

	// Read address type
	if _, err := utils.ReadWithContext(s.ctx, s.conn, buf[:1]); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadAddressType, err)
	}

	s.request.atyp = buf[0]
	var err error
	s.request.dstAddr, err = utils.ReadAddress(s.ctx, s.conn, s.request.atyp)
	if err != nil {
		return err
	}
	s.request.dstPort, err = utils.ReadPort(s.ctx, s.conn)
	if err != nil {
		return err
	}
	return nil
}

// sendSocks5SuccessResponse sends a success response to the client
func (s *Socks5) sendSocks5SuccessResponse() error {
	res := []byte{socks5Version, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err := s.conn.Write(res); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToSendSuccessResponse, err)
	}
	return nil
}
