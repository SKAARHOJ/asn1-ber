package ber

import (
	"bytes"
	"fmt"
	"math"
)

// This file perfectly matches the ember c sharp library implementation of real parsing, as the asn1-ber package seems to have an internal issue here...

const BitsPerByte int32 = 8
const BitsPerEncodedByte = 7 // Encoded bytes are used for identifiers and subidentifiers
const BytesPerLong = 8
const BytesPerInt = 4
const BitsPerLong = BytesPerLong * BitsPerByte
const BitsPerInt = BytesPerInt * BitsPerByte

const AllBitsSetLong int64 = -1
const AllBitsSetInt int32 = -1

const DoubleSignMask int64 = math.MinInt64
const DoubleMantissaBits int32 = 52
const DoubleExponentMask int64 = (AllBitsSetLong << DoubleMantissaBits) & ^DoubleSignMask
const DoubleExponentBias int64 = 1023
const DoubleMantissaMask int64 = ^(AllBitsSetLong << DoubleMantissaBits)

const StartShift8Bit int32 = BitsPerLong - BitsPerByte

// The main function that reads the real value (as in your original code)
func readReal(readBuffer []byte) (float64, error) {
	length := int32(len(readBuffer))
	position := 0

	firstContentsOctet := readBuffer[0]
	position++
	length--

	signBits := int64(0)
	exponentLength := int32(0)

	// 8.5.3 - 8.5.7, encoding must be base 2, so the bits 6 to 3 must be 0. Moreover, bits 8 to 7 must not
	// both be 0 (which would imply a decimal encoding). This leaves exactly the 12 cases enumerated below.
	switch firstContentsOctet {
	case 0x40:
		return math.Inf(1), nil
	case 0x41:
		return math.Inf(-1), nil
	case 0x42:
		return math.NaN(), nil
	case 0x43:
		return 0, nil

	// 8.5.7.4 a)
	case 0x80:
		signBits = 0
		exponentLength = 1

	case 0xC0:
		signBits = math.MinInt64
		exponentLength = 1

		// 8.5.7.4 b)
	case 0x81:
		signBits = 0
		exponentLength = 2
	case 0xC1:
		signBits = math.MinInt64
		exponentLength = 2

	// 8.5.7.4 c)
	case 0x82:
		signBits = 0
		exponentLength = 3
	case 0xC2:
		signBits = math.MinInt64
		exponentLength = 3

	// 8.5.7.4 d)
	case 0x83:
		signBits = 0
		exponentLength = int32(readBuffer[position])
		position++
		length--
	case 0xC3:
		signBits = math.MinInt
		exponentLength = int32(readBuffer[position])
		position++
		length--
	}

	mantissaLength := length - exponentLength // 8.5.7.5
	if mantissaLength < 1 {
		return 0, fmt.Errorf("Incorrect length for Real at position %d.", position)
	}

	// Fake for now
	exponent, position := read8Bit(readBuffer, position, exponentLength, true)
	mantissa, position := read8Bit(readBuffer, position, mantissaLength, false)

	if exponent == 1024 {
		if mantissa == 0 {
			if signBits == 0 {
				return math.Inf(1), nil
			} else {
				return math.Inf(-1), nil
			}
		} else {
			return math.NaN(), nil
		}
	}

	// https://en.wikipedia.org/wiki/Double-precision_floating-point_format
	if exponent <= -DoubleExponentBias || exponent > DoubleExponentBias {
		return 0, fmt.Errorf("The exponent of the Real at position %d exceeds the expected range.", position)
	}
	if mantissa == 0 {
		return 0, fmt.Errorf("The mantissa of the Real is zero.")
	}

	// Normalization, required for IEEE floating point representation
	for mantissa&(DoubleExponentMask>>int64(BitsPerByte)) == 0 {
		mantissa <<= BitsPerByte
	}

	// In the 64-bit floating point format, the first non-zero binary digit is not stored but only assumed to
	// be bit 53. We therefore shift until we have the 53rd digit == 1 and then mask it out again.
	for mantissa&DoubleExponentMask == 0 {
		mantissa <<= 1
	}

	mantissa &= DoubleMantissaMask

	exponentBits := (exponent + DoubleExponentBias) << DoubleMantissaBits

	result := signBits | exponentBits | mantissa

	return math.Float64frombits(uint64(result)), nil
}

func read8Bit(readBuffer []byte, position int, length int32, isSigned bool) (int64, int) {
	if length <= 0 {
		panic("Unexpected zero length for integer.")
	}

	mostSignificant := readBuffer[position]
	position++

	var result int64
	var leading int64

	// - 1 accounts for the fact that we must not overwrite the sign bit by shifting in bits
	MostSignificantShift := int32(BitsPerLong - BitsPerByte - 1)

	if isSigned && ((mostSignificant & 0x80) != 0) {
		result = (AllBitsSetLong << BitsPerByte) | int64(mostSignificant)
		leading = AllBitsSetLong << MostSignificantShift
	} else {
		result = int64(mostSignificant)
		leading = 0x00
	}

	for length--; length > 0; length-- {
		DiscardBitsMask := int64(AllBitsSetLong << MostSignificantShift)

		if (result & DiscardBitsMask) != leading {
			panic("The integer, length or exponent at position {?} exceeds the expected range.")
		}

		result <<= BitsPerByte
		result |= int64(readBuffer[position])
		position++
	}
	return result, position
}

func writeReal(writeBuffer *bytes.Buffer, value float64) error {
	if math.IsInf(value, 0) {
		v := byte(0x41)
		if value > 0 {
			v = 0x40
		}
		writeBuffer.Write([]byte{v}) // 8.5.6 c) and 8.5.9
		return nil
	}

	if math.IsNaN(value) {
		writeBuffer.Write([]byte{0x42}) // 8.5.9
		return nil
	}

	bits := int64(math.Float64bits(value))

	if bits == -0 {
		writeBuffer.Write([]byte{0x43}) // 8.5.3 and 8.5.9
		return nil
	}

	// 8.5.2
	if bits == 0 {
		return nil
	}

	// 8.5.6 a)
	firstContentsOctet := byte(0x80)

	SignMask := int64(math.MinInt64)

	// 8.5.7.1
	if (bits & SignMask) != 0 {
		firstContentsOctet |= 0x40
	}

	exponent := int64(((bits & DoubleExponentMask) >> DoubleMantissaBits) - DoubleExponentBias)
	exponentShift := get8BitStartShift(exponent, true)

	firstContentsOctet |= byte(getLengthFromShift8Bit(exponentShift) - 1) // 8.5.7.4

	writeBuffer.Write([]byte{firstContentsOctet})
	write8Bit(writeBuffer, exponent, exponentShift)

	MantissaAssumedLeadingOne := int64(int64(1) << DoubleMantissaBits)

	mantissa := (bits & DoubleMantissaMask) | MantissaAssumedLeadingOne

	// CER denormalization 11.3.1 (not required but saves space)
	for (mantissa & 0xFF) == 0 {
		mantissa >>= BitsPerByte
	}

	for (mantissa & 0x01) == 0 {
		mantissa >>= 1
	}

	// TODO: According to 8.5.7.5 we should pass false below, but we pass true to avoid a bug in EmberLib.
	write8Bit(writeBuffer, mantissa, get8BitStartShift(mantissa, true)) // 8.5.6.5

	return nil
}

func get8BitStartShift(value int64, isSigned bool) int32 {
	if (value >= -128) && (value <= 127) {
		return 0
	}

	leading := int64(0)
	if value < 0 {
		leading = 0b110000000000000000000000000000000000000000000000000000000000000
	}
	currentByte := int64(0)

	shift := int32(StartShift8Bit)
	for {
		currentByte = (value >> shift) & 0xFF

		if currentByte == leading && shift > 0 {
			shift -= BitsPerByte
			continue
		}
		break
	}

	if isSigned && ((value > 0) == ((currentByte & 0x80) != 0)) {
		shift += BitsPerByte
	}

	return shift
}

func getLengthFromShift8Bit(shift int32) int32 {
	return (shift / BitsPerByte) + 1
}

func write8Bit(writeBuffer *bytes.Buffer, value int64, shift int32) {
	for ; shift >= 0; shift -= 8 {
		writeBuffer.Write([]byte{byte((value >> shift) & 0xFF)})
	}
}
