package chacha20

// quarterRound function that is described here:
// https://tools.ietf.org/html/rfc7539#section-2.1
func quarterRound(internalState *[16]uint32, a, b, c, d uint32) {
	internalState[a] += internalState[b]
	internalState[d] ^= internalState[a]
	internalState[d] = bitwiseLeftShift(internalState[d], 16)

	internalState[c] += internalState[d]
	internalState[b] ^= internalState[c]
	internalState[b] = bitwiseLeftShift(internalState[b], 12)

	internalState[a] += internalState[b]
	internalState[d] ^= internalState[a]
	internalState[d] = bitwiseLeftShift(internalState[d], 8)

	internalState[c] += internalState[d]
	internalState[b] ^= internalState[c]
	internalState[b] = bitwiseLeftShift(internalState[b], 7)
}

// an n-bit left rotation (towards the high bits)
func bitwiseLeftShift(val uint32, shiftby uint) uint32 {
	return val<<shiftby | val>>(32-shiftby)
}
