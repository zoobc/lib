package address

import (
	"encoding/base32"
	"fmt"
	"golang.org/x/crypto/sha3"
	"reflect"
	"testing"
)
var hashSuccess = sha3.Sum256([]byte("this can be anything"))

func TestEncodeZbcID(t *testing.T) {
	type args struct {
		prefix    string
		publicKey []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
		err error
	}{
		{
			name:    "Success",
			args:    args{
				prefix:    "ZBC",
				publicKey: hashSuccess[:] ,
			},
			want:    "ZBC_GNPAA4JV_CYCEZ6I3_LSOWKKQJ_KIMAXS6P_XNAKU4TT_4HLAQBYY_UCSL6QUT",
			wantErr: false,
		},
		{
			name:    "InvalidPrefixLength",
			args:    args{
				prefix:    "ZB",
				publicKey: hashSuccess[:] ,
			},
			want:    "",
			wantErr: true,
			err:     ErrInvalidPrefixLength,
		},
		{
			name:    "InvalidInputLength",
			args:    args{
				prefix:    "ZBC",
				publicKey: hashSuccess[:30] ,
			},
			want:    "",
			wantErr: true,
			err:     ErrInvalidInputLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeZbcID(tt.args.prefix, tt.args.publicKey)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("EncodeZbcID() error = %v, wantErr %v", err, tt.wantErr)
				}
				if err != tt.err {
					t.Errorf("EncodeZbcID() wantErr: %v\tgotErr: %v", err, tt.err)
				}
				return
			}
			if got != tt.want {
				t.Errorf("EncodeZbcID() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func ExampleEncodeZbcID() {
	pubKey := sha3.Sum256([]byte("your public key"))
	id, err := EncodeZbcID("ZBC", pubKey[:])
	if err != nil {
		fmt.Printf("error occured: %v\n", err)
	}
	fmt.Printf("%s", id)
	// Output: ZBC_4FAIBHLR_RSTERRKF_ZOOK7HFT_R7C3CXLU_PXGSWYBJ_ZYOR727G_6NQE2QGD
}

func TestDecodeZbcID(t *testing.T) {

	type args struct {
		zbcID string
		pubKey []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
		err error
	}{
		{
			name:    "Success",
			args:    args{
				zbcID: "ZBC_GNPAA4JV_CYCEZ6I3_LSOWKKQJ_KIMAXS6P_XNAKU4TT_4HLAQBYY_UCSL6QUT",
				pubKey: make([]byte, 32),
			},
			want:    hashSuccess[:],
			wantErr: false,
		},
		{
			name:    "InvalidZbcID Length",
			args:    args{
				zbcID: "ZBC_GNPAA4JV_CYCEZ6I3_LSOWKKQJ_KIMAXS6P_XNAKU4TT_4HLAQBYY_UCSL6QU",
				pubKey: make([]byte, 32),
			},
			want:    hashSuccess[:],
			wantErr: true,
			err:     ErrInvalidZbcIDLength,
		},
		{
			name:    "Fail - wrong prefix length",
			args:    args{
				zbcID: "ZOOO_GNPAA4BJV_CYCEZ6I3_LSOWKKQJ_KIMAXS6P_XNAKU4TT_4HLAQBYY_UCSL6Q",
				pubKey: make([]byte, 32),
			},
			want:    make([]byte, 32),
			wantErr: true,
			err:     ErrInvalidPrefixLength,
		},
		{
			name:    "Fail - invalid data segment",
			args:    args{
				zbcID: "ZOO_GNPAA4VBJVA_CYCEZB6I3A_LSOWKKQJA_KIMAXS6PA_XNAKU4TTA_4HLAQBYYA",
				pubKey: make([]byte, 32),
			},
			want:    make([]byte, 32),
			wantErr: true,
			err:     ErrInvalidDataSegment,
		},
		{
			name:    "Fail - invalid data segment length",
			args:    args{
				zbcID: "ZOO_GNPAA4BJV_CYCEZ6I3_LSOWKKQJ_KIMAXS6P_XNAKU4TT_4HLAQBYY_UCSL6QU",
				pubKey: make([]byte, 32),
			},
			want:    make([]byte, 32),
			wantErr: true,
			err:     ErrInvalidDataSegmentLength,
		},
		{
			name:    "Fail - illegal base32 RFC 4648 character",
			args:    args{
				zbcID: "ZBC_GNPA8BJV_CYCEZ6I3_LSOWKKQJ_KIMAXS6P_XNAKU4TT_4HLAQBYY_UCSL6QUT",
				pubKey: make([]byte, 32),
			},
			want:   make([]byte, 32),
			wantErr: true,
			err: base32.CorruptInputError(4), // index of error char excluding prefix -> GNPA-(8)
		},
		{
			name:    "Fail - wrong checksum",
			args:    args{
				zbcID: "ZBC_GNPA7BJV_CYCEZ6I3_LSOWKKQJ_KIMAXS6P_XNAKU4TT_4HLAQBYY_UCSL6QUT",
				pubKey: make([]byte, 32),
			},
			want:    make([]byte, 32),
			wantErr: true,
			err:     ErrChecksumNotMatch, // index of error char excluding prefix -> GNPA-(8)
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DecodeZbcID(tt.args.zbcID, tt.args.pubKey)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("DecodeZbcID() error = %v, wantErr %v", err, tt.wantErr)
				}
				if err != tt.err {
					t.Errorf("EncodeZbcID() wantErr: %v\tgotErr: %v", err, tt.err)
				}
				return
			}
			if !reflect.DeepEqual(tt.args.pubKey, tt.want) {
				t.Errorf("DecodeZbcID() got = %v, want %v", tt.args.pubKey, tt.want)
			}
		})
	}
}

func ExampleDecodeZbcID() {
	var publicKey = make([]byte, 32)
	err := DecodeZbcID("ZBC_4FAIBHLR_RSTERRKF_ZOOK7HFT_R7C3CXLU_PXGSWYBJ_ZYOR727G_6NQE2QGD", publicKey)
	if err != nil {
		fmt.Printf("an error occured: %v", err)
	}
	fmt.Printf("%v", publicKey)
	// Output: [225 64 128 157 113 140 166 72 197 69 203 156 175 156 179 143 197 177 93 116 125 205 43 96 41 206 29 31 235 230 243 96]
}