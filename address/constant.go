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
package address

import "errors"

const (
	PrefixLength           = 3
	InputPublicKeyLength   = 32
	ZbcIDLength            = 66
	ZbcIDDataSegment       = 7
	ZbcIDDataSegmentLength = 8
)

var (
	// errors
	ErrInvalidPrefixLength     = errors.New("ErrInvalidPrefixLength")
	ErrInvalidInputLength      = errors.New("ErrInvalidInputLength")
	ErrInvalidZbcIDLength      = errors.New("ErrInvalidZbcIDLength")
	ErrInvalidZbcIDDataSegment = errors.New("ErrInvalidZbcIDDataSegment")
	// ErrInvalidDataSegment must have exactly 7 data segments
	ErrInvalidDataSegment = errors.New("ErrInvalidDataSegment")
	// ErrInvalidDataSegmentLength each segment must be 8 char long
	ErrInvalidDataSegmentLength = errors.New("ErrInvalidDataSegmentLength")
	ErrChecksumNotMatch         = errors.New("ErrChecksumNotMatch")
)
