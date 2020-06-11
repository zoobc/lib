package address

import "errors"

const (
	PrefixLength     = 3
	InputPublicKeyLength = 32
	ZbcIDLength      = 66
	ZbcIDDataSegment      = 7
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
	ErrChecksumNotMatch = errors.New("ErrChecksumNotMatch")
)