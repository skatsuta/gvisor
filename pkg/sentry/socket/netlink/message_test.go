// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package message_test

import (
	"bytes"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink"
)

type dummyNetlinkMsg struct {
	Foo uint16
}

func TestParseMessage(t *testing.T) {
	tests := []struct {
		desc  string
		input []byte

		header  linux.NetlinkMessageHeader
		dataMsg interface{}
		restLen int
		ok      bool
	}{
		{
			desc: "valid",
			input: []byte{
				0x14, 0x00, 0x00, 0x00, // Length
				0x01, 0x00, // Type
				0x02, 0x00, // Flags
				0x03, 0x00, 0x00, 0x00, // Seq
				0x04, 0x00, 0x00, 0x00, // PortID
				0x30, 0x31, 0x00, 0x00, // Data message with 2 bytes padding
			},
			header: linux.NetlinkMessageHeader{
				Length: 20,
				Type:   1,
				Flags:  2,
				Seq:    3,
				PortID: 4,
			},
			dataMsg: &dummyNetlinkMsg{
				Foo: 0x3130,
			},
			restLen: 0,
			ok:      true,
		},
		{
			desc: "valid with next message",
			input: []byte{
				0x14, 0x00, 0x00, 0x00, // Length
				0x01, 0x00, // Type
				0x02, 0x00, // Flags
				0x03, 0x00, 0x00, 0x00, // Seq
				0x04, 0x00, 0x00, 0x00, // PortID
				0x30, 0x31, 0x00, 0x00, // Data message with 2 bytes padding
				0xFF, // Next message (rest)
			},
			header: linux.NetlinkMessageHeader{
				Length: 20,
				Type:   1,
				Flags:  2,
				Seq:    3,
				PortID: 4,
			},
			dataMsg: &dummyNetlinkMsg{
				Foo: 0x3130,
			},
			restLen: 1,
			ok:      true,
		},
		{
			desc: "not aligned",
			input: []byte{
				0x04, 0x00, 0x00, 0x00, // Length
				0x01, 0x00, // Type
				0x02, 0x00, // Flags
				0x03, 0x00, 0x00, 0x00, // Seq
				0x04, 0x00, 0x00, 0x00, // PortID
				0x30, 0x31, 0x00, // Data message missing 1 byte padding
			},
			ok: false,
		},
		{
			desc: "header.Length too short",
			input: []byte{
				0x04, 0x00, 0x00, 0x00, // Length
				0x01, 0x00, // Type
				0x02, 0x00, // Flags
				0x03, 0x00, 0x00, 0x00, // Seq
				0x04, 0x00, 0x00, 0x00, // PortID
				0x30, 0x31, 0x00, 0x00, // Data message with 2 bytes padding
			},
			ok: false,
		},
		{
			desc: "header.Length too long",
			input: []byte{
				0xFF, 0xFF, 0x00, 0x00, // Length
				0x01, 0x00, // Type
				0x02, 0x00, // Flags
				0x03, 0x00, 0x00, 0x00, // Seq
				0x04, 0x00, 0x00, 0x00, // PortID
				0x30, 0x31, 0x00, 0x00, // Data message with 2 bytes padding
			},
			ok: false,
		},
		{
			desc: "header incomplete",
			input: []byte{
				0x04, 0x00, 0x00, 0x00, // Length
			},
			ok: false,
		},
		{
			desc:  "empty message",
			input: []byte{},
			ok:    false,
		},
	}
	for _, test := range tests {
		gotMsg, gotRest, gotOk := netlink.ParseMessage(test.input)
		if gotOk != test.ok {
			t.Errorf("%v: gotOk = %v; want %v", test.desc, gotOk, test.ok)
		} else if test.ok {
			if !reflect.DeepEqual(gotMsg.Header(), test.header) {
				t.Errorf("%v: gotHdr = %+v; want %+v", test.desc, gotMsg.Header(), test.header)
			}

			gotDataMsg := reflect.New(reflect.ValueOf(test.dataMsg).Type().Elem()).Interface()
			_, dataOk := gotMsg.GetData(gotDataMsg)
			if !dataOk {
				t.Errorf("%v: GetData.ok = %v; want true", test.desc, dataOk)
			} else if !reflect.DeepEqual(gotDataMsg, test.dataMsg) {
				t.Errorf("%v: GetData.msg = %+v; want %+v", test.desc, gotDataMsg, test.dataMsg)
			}

			if wantRest := test.input[len(test.input)-test.restLen:]; !bytes.Equal(gotRest, wantRest) {
				t.Errorf("%v: gotRest = %v; want %v", test.desc, gotRest, wantRest)
			}
		}
	}
}

func TestAttrView(t *testing.T) {
	tests := []struct {
		desc  string
		input []byte

		// Outputs for ParseFirst.
		hdr     linux.NetlinkAttrHeader
		value   []byte
		restLen int
		ok      bool

		// Outputs for Empty.
		isEmpty bool
	}{
		{
			desc: "valid",
			input: []byte{
				0x06, 0x00, // Length
				0x01, 0x00, // Type
				0x30, 0x31, 0x00, 0x00, // Data with 2 bytes padding
			},
			hdr: linux.NetlinkAttrHeader{
				Length: 6,
				Type:   1,
			},
			value:   []byte{0x30, 0x31},
			restLen: 0,
			ok:      true,
			isEmpty: false,
		},
		{
			desc: "at alignment",
			input: []byte{
				0x08, 0x00, // Length
				0x01, 0x00, // Type
				0x30, 0x31, 0x32, 0x33, // Data
			},
			hdr: linux.NetlinkAttrHeader{
				Length: 8,
				Type:   1,
			},
			value:   []byte{0x30, 0x31, 0x32, 0x33},
			restLen: 0,
			ok:      true,
			isEmpty: false,
		},
		{
			desc: "at alignment with rest data",
			input: []byte{
				0x08, 0x00, // Length
				0x01, 0x00, // Type
				0x30, 0x31, 0x32, 0x33, // Data
				0xFF, 0xFE, // Rest data
			},
			hdr: linux.NetlinkAttrHeader{
				Length: 8,
				Type:   1,
			},
			value:   []byte{0x30, 0x31, 0x32, 0x33},
			restLen: 2,
			ok:      true,
			isEmpty: false,
		},
		{
			desc: "hdr.Length too long",
			input: []byte{
				0xFF, 0x00, // Length
				0x01, 0x00, // Type
				0x30, 0x31, 0x32, 0x33, // Data
			},
			ok:      false,
			isEmpty: false,
		},
		{
			desc: "hdr.Length too short",
			input: []byte{
				0x01, 0x00, // Length
				0x01, 0x00, // Type
				0x30, 0x31, 0x32, 0x33, // Data
			},
			ok:      false,
			isEmpty: false,
		},
		{
			desc:    "empty",
			input:   []byte{},
			ok:      false,
			isEmpty: true,
		},
	}
	for _, test := range tests {
		attrs := netlink.AttrsView(test.input)
		gotHdr, gotValue, gotRest, gotOk := attrs.ParseFirst()
		if gotOk != test.ok {
			t.Errorf("%v: gotOk = %v; want %v", test.desc, gotOk, test.ok)
		} else if test.ok {
			if !reflect.DeepEqual(gotHdr, test.hdr) {
				t.Errorf("%v: gotHdr = %+v; want %+v", test.desc, gotHdr, test.hdr)
			}
			if !bytes.Equal(gotValue, test.value) {
				t.Errorf("%v: gotValue = %v; want %v", test.desc, gotValue, test.value)
			}
			if wantRest := test.input[len(test.input)-test.restLen:]; !bytes.Equal(gotRest, wantRest) {
				t.Errorf("%v: gotRest = %v; want %v", test.desc, gotRest, wantRest)
			}
		}
		if gotEmpty := attrs.Empty(); gotEmpty != test.isEmpty {
			t.Errorf("%v: gotEmpty = %v; want %v", test.desc, gotEmpty, test.isEmpty)
		}
	}
}
