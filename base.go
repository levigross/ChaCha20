package chacha20

import (
	"encoding/binary"
)

var (
	initalConstants = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
)

// createChaCha20Block creates the matrix outlined in the RFC
// https://tools.ietf.org/html/rfc7539#section-2.3
func createChaCha20Block(key [32]byte, blockCount [4]byte, nonce [12]byte) [64]byte {
	chachaMatrix := [64]byte{}
	slicePointer := chachaMatrix[:]
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

	return chachaMatrix
}
