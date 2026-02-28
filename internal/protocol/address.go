package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// AddrType 定义
const (
	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04
)

// ReadAddress 读取 SOCKS5 格式的目标地址
// 返回: 完整地址字符串 (host:port), 地址类型, IP(如果是域名则为nil), error
func ReadAddress(r io.Reader) (string, byte, net.IP, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, nil, err
	}
	addrType := atyp[0]

	var host string
	var ip net.IP

	switch addrType {
	case AddrTypeIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, nil, err
		}
		ip = append(net.IP(nil), b[:]...)
		host = ip.String()
	case AddrTypeDomain:
		var lb [1]byte
		if _, err := io.ReadFull(r, lb[:]); err != nil {
			return "", 0, nil, err
		}
		domainLen := int(lb[0])
		if domainLen <= 0 || domainLen > 255 {
			return "", 0, nil, fmt.Errorf("invalid domain length: %d", domainLen)
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", 0, nil, err
		}
		host = string(domain)
	case AddrTypeIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, nil, err
		}
		ip = append(net.IP(nil), b[:]...)
		host = ip.String()
	default:
		return "", 0, nil, fmt.Errorf("unknown address type: %d", addrType)
	}

	// 2. 读取端口
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return "", 0, nil, err
	}
	port := binary.BigEndian.Uint16(pb[:])

	return net.JoinHostPort(host, strconv.Itoa(int(port))), addrType, ip, nil
}

// WriteAddress 将地址写入 Writer (SOCKS5 格式)
// 输入 rawAddr 为 "host:port"
func WriteAddress(w io.Writer, rawAddr string) error {
	host, portStr, err := net.SplitHostPort(rawAddr)
	if err != nil {
		return err
	}
	portInt, err := strconv.Atoi(portStr)
	if err != nil || portInt < 0 || portInt > 65535 {
		return fmt.Errorf("invalid port: %q", portStr)
	}

	if i := strings.IndexByte(host, '%'); i >= 0 {
		// Zone identifiers are not representable in SOCKS5 IPv6 address encoding.
		host = host[:i]
	}
	ip := net.ParseIP(host)

	// 构建缓冲
	buf := make([]byte, 0, 300)

	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, AddrTypeIPv4)
			buf = append(buf, ip4...)
		} else {
			ip16 := ip.To16()
			if ip16 == nil {
				return fmt.Errorf("invalid ipv6: %q", host)
			}
			buf = append(buf, AddrTypeIPv6)
			buf = append(buf, ip16...)
		}
	} else {
		buf = append(buf, AddrTypeDomain)
		if len(host) > 255 {
			return errors.New("domain too long")
		}
		buf = append(buf, byte(len(host)))
		buf = append(buf, []byte(host)...)
	}

	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(portInt))
	buf = append(buf, portBytes[:]...)

	_, err = w.Write(buf)
	return err
}
