package chacha20

import "testing"

func TestQuarterRound(t *testing.T) {
	foo := [...]uint32{0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
		0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
		0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
		0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320}
	quarterRound(&foo, 2, 7, 8, 13)
	switch {
	case foo[2] != 0xbdb886dc:
		t.Error("Invalid value at index 2", foo)
	case foo[7] != 0xcfacafd2:
		t.Error("Invalid value at index 7", foo)
	case foo[8] != 0xe46bea80:
		t.Error("Invalid value at index 8", foo)
	case foo[13] != 0xccc07c79:
		t.Error("Invalid value at index 13", foo)
	}
}
