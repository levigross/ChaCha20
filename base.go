package chacha20

import (
	"encoding/binary"
)

var (
	initalConstants = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
)

type chachaMatrix struct {
	internalState [64]byte
}

func (cm chachaMatrix) AsUint32() [16]uint32 {
	array := [len(cm.internalState) / 4]uint32{}
	iStatePointer := cm.internalState[:]

	for i := range array {
		array[i] = binary.LittleEndian.Uint32(iStatePointer[:4])
		iStatePointer = iStatePointer[4:]
	}

	return array
}

// FromUint32 creates a chachaMatrix from an array of uint32
func (cm *chachaMatrix) fromUint32(cipherBytes [16]uint32) {
	slicePointer := cm.internalState[:]
	for i := range cipherBytes {
		binary.LittleEndian.PutUint32(slicePointer[:4], cipherBytes[i])
		slicePointer = slicePointer[4:]
	}
}

// createChaCha20Block creates the matrix outlined in the RFC
// https://tools.ietf.org/html/rfc7539#section-2.3
func createChaCha20Block(key [32]byte, blockCount [4]byte, nonce [12]byte) (cm chachaMatrix) {
	slicePointer := cm.internalState[:]
	for i := range initalConstants {
		binary.LittleEndian.PutUint32(slicePointer, initalConstants[i])
		slicePointer = slicePointer[4:]
	}

	keyPointer := key[:]
	for i := 0; i < len(key); i += 4 {
		binary.LittleEndian.PutUint32(slicePointer, binary.LittleEndian.Uint32(keyPointer[:4]))
		keyPointer = keyPointer[4:]
		slicePointer = slicePointer[4:]
	}

	binary.LittleEndian.PutUint32(slicePointer, binary.LittleEndian.Uint32(blockCount[:]))
	slicePointer = slicePointer[4:]

	noncePointer := nonce[:]
	for i := 0; i < len(nonce); i += 4 {
		binary.LittleEndian.PutUint32(slicePointer, binary.LittleEndian.Uint32(noncePointer[:4]))
		noncePointer = noncePointer[4:]
		slicePointer = slicePointer[4:]
	}

	return
}

func applyQuarterRounds(state [16]uint32) (out [16]uint32) {
	for i := 0; i < 10; i++ {
		quarterRound(&state, 0, 4, 8, 12)
		quarterRound(&state, 1, 5, 9, 13)
		quarterRound(&state, 2, 6, 10, 14)
		quarterRound(&state, 3, 7, 11, 15)
		quarterRound(&state, 0, 5, 10, 15)
		quarterRound(&state, 1, 6, 11, 12)
		quarterRound(&state, 2, 7, 8, 13)
		quarterRound(&state, 3, 4, 9, 14)
	}
	return state
}

func core(key [32]byte, blockCount [4]byte, nonce [12]byte) chachaMatrix {
	cm := createChaCha20Block(key, blockCount, nonce)
	old := cm.AsUint32()
	new := applyQuarterRounds(old)
	result := addStates(old, new)
	cm.fromUint32(result)
	return cm
}
