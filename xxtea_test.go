// go test -benchmem -cpu 1,2,4,8 -bench . | tee bench_full.txt
// go test -benchmem -cpu 1 -bench . | tee bench_single.txt
//
//xlint:file-ignore U1000 WiP
package xxtea

import (
	"slices"
	"testing"
	// "golang.org/x/crypto/chacha20"
)

const (
	keyBEBE = "0123456789ABCDEF"
	keyBELE = "CDEF89AB45670123"
	keyLEBE = "32107654BA98FEDC"
	keyLELE = "FEDCBA9876543210"
	datLB16 = "1032547698BADCFE"
	datME16 = "1023546798ABDCEF"
	datMX16 = "0132457689BACDFE"

	msgMin = `AbCdEFgH`
	msgMax = `gygedyrtestycsedfdsfsdfdfsfslkdfsdflkjdfjljsdffsdfsdfsdfsjljdfl
gygedyrtestycsedfdsfsdfdfsfslkdfsdflkjdfjljsdffsdfsdfsdfsjljdfl
gygedyrtestycsedfdsfsdfdfsfslkdfsdflkjdfjljsdffsdfsdfsdfsjljdfl
GHTREFDRTRYWERG
` // 208B max
)

// Test if even single position in r, s have the same byte value.
// Returns OK  (false) if bytes on all positions differ.
// Returns FAIL (true) if equal bytes at same index are found.
// Returns FAIL (true) if r, s lengths differ.
func someBytesEqual(r []byte, s string) bool {
	if len(r) != len(s) {
		return true
	}
	for i, b := range []byte(s) {
		if b == r[i] {
			return true
		}
	}
	return false
}

func Test_BitFlip(t *testing.T) {
	msg := []byte(msgMax)
	enc := make([]byte, len(msg))
	dec := make([]byte, len(msg))
	key := NewKey([]byte(keyBEBE))
	key.Encrypt(msg, enc)
	key[2] ^= 1 // flip one bit of the key and try decrypt
	key.Decrypt(enc, dec)
	if someBytesEqual(dec, msgMax) {
		t.Error("Decryption with other key succeeded")
	}
}

func Test_EncDec(t *testing.T) {
	msg := []byte(msgMax)
	enc := make([]byte, len(msg))
	dec := make([]byte, len(msg))
	key := NewKey([]byte(keyBEBE))
	key.Encrypt(msg, enc)
	key.Decrypt(enc, dec)
	if slices.Compare(msg, dec) != 0 {
		t.Error("Decryption failed")
	}
	key = NewKey(AsBELE([]byte(keyBELE)))
	key.Decrypt(enc, dec)
	if slices.Compare(msg, dec) != 0 {
		t.Error("Decryption with BELE key failed")
	}
	key = NewKey(AsLEBE([]byte(keyLEBE)))
	key.Decrypt(enc, dec)
	if slices.Compare(msg, dec) != 0 {
		t.Error("Decryption with LEBE key failed")
	}
	key = NewKey(AsLELE([]byte(keyLELE)))
	key.Decrypt(enc, dec)
	if slices.Compare(msg, dec) != 0 {
		t.Error("Decryption with LELE key failed")
	}
}

func Test_ZeroKeyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("All-zeros key should panic")
		}
	}()
	_ = NewKey(make([]byte, 16))
}

func Test_ShortKeyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Too short key should panic")
		}
	}()
	_ = NewKey([]byte("TooShortKeyGive"))
}

func Test_LongKeyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Too long key should panic")
		}
	}()
	_ = NewKey([]byte("TooLooongKeyGiven"))
}

func Test_Juggles(t *testing.T) {
	if string(AsBELE([]byte(keyBELE))) != keyBEBE {
		t.Error("AsBELE logic is broken")
	}
	if string(AsLEBE([]byte(keyLEBE))) != keyBEBE {
		t.Error("AsLEBE logic is broken")
	}
	if string(AsLELE([]byte(keyLELE))) != keyBEBE {
		t.Error("AsLELE logic is broken")
	}
	/* mid-endian jugglings are now obsolete
	if string(AsLB16([]byte(datLB16))) != keyBEBE {
		t.Error("AsLB16 logic is broken")
	}
	if string(AsME16([]byte(datME16))) != keyBEBE {
		t.Error("AsME16 logic is broken")
	}
	if string(AsMX16([]byte(datMX16))) != keyBEBE {
		t.Error("AsMX16 logic is broken")
	}
	*/
}

func Test_Juggles_min(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Error("min 4B should pass")
		}
	}()
	AsLEBE([]byte("even"))
}

func Test_Juggles_Panics_Short(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("too short argument should panic")
		}
	}()
	AsLEBE([]byte("srt"))
}

func Test_Juggles_Panics_4(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("not integral multiply of 4 should panic")
		}
	}()
	AsLEBE([]byte("uneven"))
}

func Test_Encrypt_Panics_4(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("arguments of not integral multiply of 4 should panic")
		}
	}()
	msg := make([]byte, 9)
	key := NewKey([]byte(keyBEBE))
	key.Encrypt(msg, msg)
}

func Test_Encrypt_Panics_Short(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("arguments shorter than 8 should panic")
		}
	}()
	msg := make([]byte, 4)
	key := NewKey([]byte(keyBEBE))
	key.Encrypt(msg, msg)
}

func Test_Encrypt_Panics_Long(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("arguments longer than 208 should panic")
		}
	}()
	msg := make([]byte, 212)
	key := NewKey([]byte(keyBEBE))
	key.Encrypt(msg, msg)
}

func Test_Encrypt_Panics_Unequal(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("arguments of unequal length should panic")
		}
	}()
	msg := make([]byte, 16)
	out := make([]byte, 32)
	key := NewKey([]byte(keyBEBE))
	key.Encrypt(msg, out)
}

// ///
func Test_Decrypt_Panics_4(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("arguments of not integral multiply of 4 should panic")
		}
	}()
	msg := make([]byte, 9)
	key := NewKey([]byte(keyBEBE))
	key.Decrypt(msg, msg)
}

func Test_Decrypt_Panics_Short(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("arguments shorter than 12 should panic")
		}
	}()
	msg := make([]byte, 8)
	key := NewKey([]byte(keyBEBE))
	key.Decrypt(msg, msg)
}

func Test_Decrypt_Panics_Long(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("arguments longer than 208 should panic")
		}
	}()
	msg := make([]byte, 212)
	key := NewKey([]byte(keyBEBE))
	key.Decrypt(msg, msg)
}

func Test_Decrypt_Panics_Unequal(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("arguments of unequal length should panic")
		}
	}()
	msg := make([]byte, 16)
	out := make([]byte, 20)
	key := NewKey([]byte(keyBEBE))
	key.Decrypt(msg, out)
}

// /
var note int

type bs = []byte

func BenchmarkBytes(b *testing.B) {
	b.Run("NewKey", func(b *testing.B) { benchNewKey(b) })
	b.Run("AsBELE_16", func(b *testing.B) { benchAsBELE(b, 16) })
	b.Run("AsLEBE_16", func(b *testing.B) { benchAsLEBE(b, 16) })
	b.Run("AsLELE_16", func(b *testing.B) { benchAsLELE(b, 16) })
	b.Run("AsBELE_208", func(b *testing.B) { benchAsBELE(b, 208) })
	b.Run("AsLEBE_208", func(b *testing.B) { benchAsLEBE(b, 208) })
	b.Run("AsLELE_208", func(b *testing.B) { benchAsLELE(b, 208) })
}

func benchAsBELE(b *testing.B, bytes int) {
	ks := make([]byte, bytes)
	var r []byte
	b.SetBytes(int64(bytes))
	for n := 0; n < b.N; n++ {
		r = AsBELE(ks)
	}
	note += int(r[0])
}

func benchAsLEBE(b *testing.B, bytes int) {
	ks := make([]byte, bytes)
	var r []byte
	b.SetBytes(int64(bytes))
	for n := 0; n < b.N; n++ {
		r = AsLEBE(ks)
	}
	note += int(r[0])
}

func benchAsLELE(b *testing.B, bytes int) {
	ks := make([]byte, bytes)
	var r []byte
	b.SetBytes(int64(bytes))
	for n := 0; n < b.N; n++ {
		r = AsLELE(ks)
	}
	note += int(r[0])
}

func benchNewKey(b *testing.B) {
	ks := bs(keyBEBE)
	// msg := make([]byte, msglen)
	var k TeaKey
	b.SetBytes(int64(16))
	for n := 0; n < b.N; n++ {
		k = NewKey(ks)
	}
	note += int(k[0])
}

func benchEncrypt(b *testing.B, key TeaKey, msglen int) {
	msg := make([]byte, msglen)
	b.SetBytes(int64(msglen))
	for n := 0; n < b.N; n++ {
		key.Encrypt(msg, msg)
	}
	note += int(msg[0])
}

func benchDecrypt(b *testing.B, key TeaKey, msglen int) {
	msg := make([]byte, msglen)
	b.SetBytes(int64(msglen))
	for n := 0; n < b.N; n++ {
		key.Decrypt(msg, msg)
	}
	note += int(msg[0])
}

func BenchmarkXXTEA(b *testing.B) {
	key := NewKey(bs(keyBEBE))
	b.Run("Encrypt_16", func(b *testing.B) { benchEncrypt(b, key, 16) })
	b.Run("Decrypt_16", func(b *testing.B) { benchDecrypt(b, key, 16) })
	b.Run("Encrypt_32", func(b *testing.B) { benchEncrypt(b, key, 32) })
	b.Run("Decrypt_32", func(b *testing.B) { benchDecrypt(b, key, 32) })
	b.Run("Encrypt_48", func(b *testing.B) { benchEncrypt(b, key, 48) })
	b.Run("Decrypt_48", func(b *testing.B) { benchDecrypt(b, key, 48) })
	b.Run("Encrypt_64", func(b *testing.B) { benchEncrypt(b, key, 64) })
	b.Run("Decrypt_64", func(b *testing.B) { benchDecrypt(b, key, 64) })
	b.Run("Encrypt_96", func(b *testing.B) { benchEncrypt(b, key, 96) })
	b.Run("Decrypt_96", func(b *testing.B) { benchDecrypt(b, key, 96) })
	b.Run("Encrypt_128", func(b *testing.B) { benchEncrypt(b, key, 128) })
	b.Run("Decrypt_128", func(b *testing.B) { benchDecrypt(b, key, 128) })
	b.Run("Encrypt_208", func(b *testing.B) { benchEncrypt(b, key, 208) })
	b.Run("Decrypt_208", func(b *testing.B) { benchDecrypt(b, key, 208) })
}

/* compare with chacha
func BenchmarkChaCha(b *testing.B) {
	b.Run("KstrAnew_16", func(b *testing.B) { benchChaCha(b, 16, true) })
	b.Run("KstrCont_16", func(b *testing.B) { benchChaCha(b, 16, false) })
	b.Run("KstrAnew_32", func(b *testing.B) { benchChaCha(b, 32, true) })
	b.Run("KstrCont_32", func(b *testing.B) { benchChaCha(b, 32, false) })
	b.Run("KstrAnew_48", func(b *testing.B) { benchChaCha(b, 48, true) })
	b.Run("KstrCont_48", func(b *testing.B) { benchChaCha(b, 48, false) })
	b.Run("KstrAnew_64", func(b *testing.B) { benchChaCha(b, 64, true) })
	b.Run("KstrCont_64", func(b *testing.B) { benchChaCha(b, 64, false) })
	b.Run("KstrAnew_80", func(b *testing.B) { benchChaCha(b, 80, true) })
	b.Run("KstrCont_80", func(b *testing.B) { benchChaCha(b, 80, false) })
	b.Run("KstrAnew_96", func(b *testing.B) { benchChaCha(b, 96, true) })
	b.Run("KstrCont_96", func(b *testing.B) { benchChaCha(b, 96, false) })
	b.Run("KstrAnew_128", func(b *testing.B) { benchChaCha(b, 128, true) })
	b.Run("KstrCont_128", func(b *testing.B) { benchChaCha(b, 128, false) })
	b.Run("KstrAnew_208", func(b *testing.B) { benchChaCha(b, 208, true) })
	b.Run("KstrCont_208", func(b *testing.B) { benchChaCha(b, 208, false) })
}

func benchChaCha(b *testing.B, msglen int, withCreate bool) {
	var c *chacha20.Cipher
	msg := make([]byte, msglen)
	b.SetBytes(int64(msglen))
	nce := make([]byte, 12)
	key := make([]byte, 32)
	copy(key[:16], []byte(keyLELE)) // not that it matters ;)
	copy(key[16:], []byte(keyLEBE))
	copy(nce, []byte(keyBELE)[:12])
	for n := 0; n < b.N; n++ {
		// we're timing with key schedule
		if c == nil {
			c, _ = chacha20.NewUnauthenticatedCipher(key, nce)
		}
		c.XORKeyStream(msg, msg)
		if withCreate {
			c = nil // two ifs are neglible comparing to cipher run
		}
	}
	note += int(msg[0])
}
*/
