package socks

// This package doesn't implement the client handshake because it is not needed for the current implementation.

// func (c *Conn) clientHandshake(ctx context.Context) error {
// 	if c.GetHandshakeComplete() {
// 		return nil
// 	}
// 	var err error
// 	if err = c.clientSendGreeting(ctx); err != nil {
// 		return err
// 	}
// 	if err = c.clientHandleGreetingResponse(ctx); err != nil {
// 		return err
// 	}
// 	if err = c.clientSendRequest(ctx); err != nil {
// 		return err
// 	}
// 	return nil
// }

// func (c *Conn) clientSendGreeting(ctx context.Context) error {
// 	_, err := utils.WriteWithContext(ctx, c.Conn, c.greeting.Bytes())
// 	return err
// }

// func (c *Conn) clientHandleGreetingResponse(ctx context.Context) error {
// 	buf := make([]byte, 2)
// 	if _, err := utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
// 		return err
// 	}
// 	if buf[0] != socks5Version {
// 		return errors.Join(errSocks5UnsupportedVersion, fmt.Errorf("sent version: %d", buf[0]))
// 	}
// 	return nil
// }

// func (c *Conn) clientSendRequest(ctx context.Context) error {
// 	_, err := utils.WriteWithContext(ctx, c.Conn, c.request.Bytes())
// 	return err
// }
