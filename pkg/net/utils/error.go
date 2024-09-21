package utils

import "errors"

var (
	// Read network addresses errors
	errUnsupportedAddressType = errors.New("unsupported the address type")
	errUnableToReadIpv4       = errors.New("unable to read the IPv4 address")
	errUnableToReadIpv6       = errors.New("unable to read the IPv6 address")
	errUnableToReadDomain     = errors.New("unable to read the domain name")
	errUnableToReadPort       = errors.New("unable to read the port")

	errTransfererror = errors.New("data transfer failed between client and server")
)
