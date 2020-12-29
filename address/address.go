// ZooBC lib
//
// Copyright © 2020 Quasisoft Limited - Hong Kong
//
// ZooBC is architected by Roberto Capodieci & Barton Johnston
//             contact us at roberto.capodieci[at]blockchainzoo.com
//             and barton.johnston[at]blockchainzoo.com
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// package address handle the address decoding and encoding in zoobc format
package address

import (
	"encoding/base32"
	"golang.org/x/crypto/sha3"
	"strings"
)

// EncodeZbcID encode the publicKey to zoobc address
// publicKey is constrained to 32 bytes and address's length will be 66
func EncodeZbcID(prefix string, publicKey []byte) (string, error) {
	var (
		result string
		buffer = make([]byte, 35)
	)
	if len(prefix) != PrefixLength {
		return result, ErrInvalidPrefixLength
	}
	prefix = strings.ToUpper(prefix)
	if len(publicKey) != InputPublicKeyLength {
		return result, ErrInvalidInputLength
	}
	copy(buffer, publicKey)
	for i := 0; i < 3; i++ {
		buffer[32+i] = prefix[i]
	}
	var checksum = sha3.Sum256(buffer)
	for i := 0; i < 3; i++ {
		buffer[32+i] = checksum[i]
	}
	segs := []string{prefix}
	b32Str := base32.StdEncoding.EncodeToString(buffer) // rfc4648
	for i := 0; i < 7; i++ {
		segs = append(segs, b32Str[i*8:(i*8)+8])
	}
	return strings.Join(segs, "_"), nil
}

// DecodeZbcID decode the provided zbcID (zoobc address) and fill to provided publicKey
// publicKey is constrained to 32 bytes and zbcID's length 66
func DecodeZbcID(zbcID string, publicKey []byte) error {
	var (
		err error
	)
	if len(zbcID) != ZbcIDLength {
		return ErrInvalidZbcIDLength
	}
	var splitted = strings.Split(zbcID, "_")
	var prefix, segs = splitted[0], splitted[1:]
	if len(prefix) != PrefixLength {
		return ErrInvalidPrefixLength
	}
	if len(segs) != ZbcIDDataSegment {
		return ErrInvalidDataSegment
	}
	for i := 0; i < len(segs); i++ {
		if len(segs[i]) != ZbcIDDataSegmentLength {
			return ErrInvalidDataSegmentLength
		}
	}
	b32Str := strings.Join(segs, "")
	buffer, err := base32.StdEncoding.DecodeString(b32Str)
	if err != nil {
		return err
	}
	inputChecksum := make([]byte, 3)
	for i := 0; i < 3; i++ {
		inputChecksum[i] = buffer[i+32]
	}
	for i := 0; i < 3; i++ {
		buffer[32+i] = prefix[i]
	}
	checksum := sha3.Sum256(buffer)
	for i := 0; i < 3; i++ {
		if checksum[i] != inputChecksum[i] {
			return ErrChecksumNotMatch
		}
	}
	copy(publicKey, buffer[:32])
	return nil
}
