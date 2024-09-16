package utils

import (
	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

func Socks5Auth(cfg *config.Config, username, password []byte) error {
	p, ok := cfg.Credentials[string(username)]
	if !ok {
		return proxy_error.ErrSocks5AuthIncorrectUsername
	}
	if string(password) == p {
		return nil
	}
	return proxy_error.ErrSocks5AuthIncorrectUsername
}
