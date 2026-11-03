package radiusd

import (
	"encoding/binary"
	"errors"
)

// EAP（RFC 3748）と EAP-TLS（RFC 5216・9190）の形。

const (
	eapRequest  = 1
	eapResponse = 2
	eapSuccess  = 3
	eapFailure  = 4

	eapTypeIdentity = 1
	eapTypeNak      = 3
	eapTypeTLS      = 13

	tlsFlagLength = 0x80
	tlsFlagMore   = 0x40
	tlsFlagStart  = 0x20
)

type eapPacket struct {
	Code byte
	ID   byte
	Type byte // Request・Response だけ
	Data []byte
}

func parseEAP(b []byte) (eapPacket, error) {
	if len(b) < 4 {
		return eapPacket{}, errors.New("eap: short")
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < 4 || n > len(b) {
		return eapPacket{}, errors.New("eap: bad length")
	}
	p := eapPacket{Code: b[0], ID: b[1]}
	if p.Code == eapRequest || p.Code == eapResponse {
		if n < 5 {
			return eapPacket{}, errors.New("eap: no type")
		}
		p.Type, p.Data = b[4], b[5:n]
	}
	return p, nil
}

func (p eapPacket) encode() []byte {
	n := 4
	if p.Code == eapRequest || p.Code == eapResponse {
		n += 1 + len(p.Data)
	}
	b := make([]byte, n)
	b[0], b[1] = p.Code, p.ID
	binary.BigEndian.PutUint16(b[2:4], uint16(n))
	if n > 4 {
		b[4] = p.Type
		copy(b[5:], p.Data)
	}
	return b
}

// tlsFragment は EAP-TLS の中身（flags・長さ・TLS のデータ）。
type tlsFragment struct {
	Flags byte
	Total int // L のときの全体の長さ
	Data  []byte
}

func parseTLSData(b []byte) (tlsFragment, error) {
	if len(b) < 1 {
		return tlsFragment{}, errors.New("eap-tls: no flags")
	}
	f := tlsFragment{Flags: b[0]}
	b = b[1:]
	if f.Flags&tlsFlagLength != 0 {
		if len(b) < 4 {
			return tlsFragment{}, errors.New("eap-tls: short length")
		}
		f.Total = int(binary.BigEndian.Uint32(b[:4]))
		b = b[4:]
	}
	f.Data = b
	return f, nil
}

func (f tlsFragment) encode() []byte {
	var b []byte
	b = append(b, f.Flags)
	if f.Flags&tlsFlagLength != 0 {
		b = binary.BigEndian.AppendUint32(b, uint32(f.Total))
	}
	return append(b, f.Data...)
}
