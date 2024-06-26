package ber

import (
	"bytes"
	"io"
	"math"
	"testing"
)

func TestEncodeDecodeInteger(t *testing.T) {
	for _, v := range []int64{0, 10, 128, 1024, math.MaxInt64, -1, -100, -128, -1024, math.MinInt64} {
		enc := encodeInteger(v)
		dec, err := ParseInt64(enc)
		if err != nil {
			t.Fatalf("Error decoding %d : %s", v, err)
		}
		if v != dec {
			t.Errorf("TestEncodeDecodeInteger failed for %d (got %d)", v, dec)
		}
	}
}

func TestBoolean(t *testing.T) {
	packet := NewBoolean(ClassUniversal, TypePrimitive, TagBoolean, true, "first Packet, True")

	newBoolean, ok := packet.Value.(bool)
	if !ok || newBoolean != true {
		t.Error("error during creating packet")
	}

	encodedPacket := packet.Bytes()

	newPacket := DecodePacket(encodedPacket)

	newBoolean, ok = newPacket.Value.(bool)
	if !ok || newBoolean != true {
		t.Error("error during decoding packet")
	}
}

func TestLDAPBoolean(t *testing.T) {
	packet := NewLDAPBoolean(ClassUniversal, TypePrimitive, TagBoolean, true, "first Packet, True")

	newBoolean, ok := packet.Value.(bool)
	if !ok || newBoolean != true {
		t.Error("error during creating packet")
	}

	encodedPacket := packet.Bytes()

	newPacket := DecodePacket(encodedPacket)

	newBoolean, ok = newPacket.Value.(bool)
	if !ok || newBoolean != true {
		t.Error("error during decoding packet")
	}
}

func TestInteger(t *testing.T) {
	var value int64 = 10

	packet := NewInteger(ClassUniversal, TypePrimitive, TagInteger, value, "Integer, 10")

	{
		newInteger, ok := packet.Value.(int64)
		if !ok || newInteger != value {
			t.Error("error creating packet")
		}
	}

	encodedPacket := packet.Bytes()

	newPacket := DecodePacket(encodedPacket)

	{
		newInteger, ok := newPacket.Value.(int64)
		if !ok || newInteger != value {
			t.Error("error decoding packet")
		}
	}
}

func TestString(t *testing.T) {
	value := "Hic sunt dracones"

	packet := NewString(ClassUniversal, TypePrimitive, TagOctetString, value, "String")

	newValue, ok := packet.Value.(string)
	if !ok || newValue != value {
		t.Error("error during creating packet")
	}

	encodedPacket := packet.Bytes()

	newPacket := DecodePacket(encodedPacket)

	newValue, ok = newPacket.Value.(string)
	if !ok || newValue != value {
		t.Error("error during decoding packet")
	}
}

func TestEncodeDecodeOID(t *testing.T) {
	for _, v := range []string{"0.1", "2.981", "2.3", "0.4", "0.4.5.1888", "0.10.5.1888.234.324234"} {
		enc, err := encodeOID(v)
		if err != nil {
			t.Errorf("error on encoding object identifier when encoding %s: %v", v, err)
		}
		parsed, err := parseObjectIdentifier(enc)
		if err != nil {
			t.Errorf("error on parsing object identifier when parsing %s: %v", v, err)
		}
		t.Log(enc)
		t.Log(OIDToString(parsed))
		if v != OIDToString(parsed) {
			t.Error("encoded object identifier did not match parsed")
		}
	}
}

func TestSequenceAndAppendChild(t *testing.T) {
	values := []string{
		"HIC SVNT LEONES",
		"Iñtërnâtiônàlizætiøn",
		"Terra Incognita",
	}

	sequence := NewSequence("a sequence")
	for _, s := range values {
		sequence.AppendChild(NewString(ClassUniversal, TypePrimitive, TagOctetString, s, "String"))
	}

	if len(sequence.Children) != len(values) {
		t.Errorf("wrong length for children array should be %d, got %d", len(values), len(sequence.Children))
	}

	encodedSequence := sequence.Bytes()

	decodedSequence := DecodePacket(encodedSequence)
	if len(decodedSequence.Children) != len(values) {
		t.Errorf("wrong length for children array should be %d => %d", len(values), len(decodedSequence.Children))
	}

	for i, s := range values {
		if decodedSequence.Children[i].Value.(string) != s {
			t.Errorf("expected %d to be %q, got %q", i, s, decodedSequence.Children[i].Value.(string))
		}
	}
}

func TestReadPacket(t *testing.T) {
	packet := NewString(ClassUniversal, TypePrimitive, TagOctetString, "Ad impossibilia nemo tenetur", "string")
	var buffer io.ReadWriter = new(bytes.Buffer)

	if _, err := buffer.Write(packet.Bytes()); err != nil {
		t.Error("error writing packet", err)
	}

	newPacket, err := ReadPacket(buffer)
	if err != nil {
		t.Error("error during ReadPacket", err)
	}
	newPacket.ByteValue = nil
	if !bytes.Equal(newPacket.ByteValue, packet.ByteValue) {
		t.Error("packets should be the same")
	}
}

func TestBinaryInteger(t *testing.T) {
	// data src : http://luca.ntop.org/Teaching/Appunti/asn1.html 5.7
	data := []struct {
		v int64
		e []byte
	}{
		{v: 0, e: []byte{0x02, 0x01, 0x00}},
		{v: 127, e: []byte{0x02, 0x01, 0x7F}},
		{v: 128, e: []byte{0x02, 0x02, 0x00, 0x80}},
		{v: 256, e: []byte{0x02, 0x02, 0x01, 0x00}},
		{v: -128, e: []byte{0x02, 0x01, 0x80}},
		{v: -129, e: []byte{0x02, 0x02, 0xFF, 0x7F}},
		{v: math.MaxInt64, e: []byte{0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{v: math.MinInt64, e: []byte{0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, d := range data {
		if b := NewInteger(ClassUniversal, TypePrimitive, TagInteger, d.v, "").Bytes(); !bytes.Equal(d.e, b) {
			t.Errorf("Wrong binary generated for %d : got % X, expected % X", d.v, b, d.e)
		}
	}
}

func TestBinaryOctetString(t *testing.T) {
	// data src : http://luca.ntop.org/Teaching/Appunti/asn1.html 5.10

	if !bytes.Equal([]byte{0x04, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}, NewString(ClassUniversal, TypePrimitive, TagOctetString, "\x01\x23\x45\x67\x89\xab\xcd\xef", "").Bytes()) {
		t.Error("wrong binary generated")
	}
}

// buff is an alias to build a bytes.Reader from an explicit sequence of bytes
func buff(bs ...byte) *bytes.Reader {
	return bytes.NewReader(bs)
}

func TestEOF(t *testing.T) {
	_, err := ReadPacket(buff())
	if err != io.EOF {
		t.Errorf("empty buffer: expected EOF, got %s", err)
	}

	// testCases for EOF
	testCases := []struct {
		name string
		buf  *bytes.Reader
	}{
		{"primitive", buff(0x04, 0x0a, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9)},
		{"constructed", buff(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)},
		{"constructed indefinite length", buff(0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00)},
	}
	for _, tc := range testCases {
		_, err := ReadPacket(tc.buf)
		if err != nil {
			t.Errorf("%s: expected no error, got %s", tc.name, err)
		}

		_, err = ReadPacket(tc.buf)
		if err != io.EOF {
			t.Errorf("%s: expected EOF, got %s", tc.name, err)
		}
	}

	// testCases for UnexpectedEOF :
	testCases = []struct {
		name string
		buf  *bytes.Reader
	}{
		{"truncated tag", buff(0x1f, 0xff)},
		{"tag and no length", buff(0x04)},
		{"truncated length", buff(0x04, 0x82, 0x02)},
		{"header with no content", buff(0x04, 0x0a)},
		{"header with truncated content", buff(0x04, 0x0a, 0, 1, 2)},

		{"constructed missing content", buff(0x30, 0x06)},
		{"constructed only first child", buff(0x30, 0x06, 0x02, 0x01, 0x01)},
		{"constructed truncated", buff(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01)},

		{"indefinite missing eoc", buff(0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)},
		{"indefinite truncated eoc", buff(0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00)},
	}
	for _, tc := range testCases {
		_, err := ReadPacket(tc.buf)
		if err != io.ErrUnexpectedEOF {
			t.Errorf("%s: expected UnexpectedEOF, got %s", tc.name, err)
		}
	}
}
