// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package btea implements low-level primitive of the XXTEA encryption and decryption
// routines defined in Needham and Wheeler's 1997 technical report, "Tea extensions"
// then in errata given in the "Correction to xtea":
// Reference implementation comes from https://en.wikipedia.org/wiki/XXTEA and
// was crosschecked with https://www.movable-type.co.uk/scripts/xxtea.pdf paper
// (Correction to xtea).
//
// This package intentionally does not conform to crypto/cipher interfaces!
//
// XXTEA cipher should NEVER be used as the cipher.Block primitive nor the
// message size should ever exceed 208B (limit enforced by this package).
// See related cryptanalysis papers for XXTEA, XTEA, and TEA.
// Main cryptanalysis paper: https://eprint.iacr.org/2010/254.
//
// Limits: Key must be 16 bytes long. Messages must be at least 8 and no more
// than 208 bytes long.  Message bytes length must be integral multiply of 4.
// Misuse effect in panic.
//
// For small messages encrypted with random keys XXTEA still (in 2024) offers
// 2^126 security with the key alone (no iv-s or nonces).  So it has its uses
// - mostly in the IoT realm.
//
// With desktop CPUs golang.org/x/crypto/chacha20 cipher will be 2 to 3 times
// faster, even with Cipher state instantation:
//
//	[i7-4770HQ CPU @ 2.20GHz]
//	XXTEA/Decrypt_32     365.8 ns/op    87.49 MB/s     0 B/op   0 allocs/op
//	XXTEA/Decrypt_208   1588.0 ns/op   130.98 MB/s     0 B/op   0 allocs/op
//	crypto/ChaCha_32     244.7 ns/op   130.76 MB/s   176 B/op   1 allocs/op
//	crypto/ChaCha_208    662.9 ns/op   313.77 MB/s   176 B/op   1 allocs/op

package xxtea

const (
	em    string = "xxtea: XXTEA cipher misuse! Read teh Docs, Luke!"
	delta uint32 = 0x9e3779b9
)

// TeaKey contains secret key ints
type TeaKey [4]uint32

// XXTEA key size must be 16B of four uint32s serialized to big-endian
// 16 bytes, 128 bits value. Eg. value 0x12345678 to 0x12,0x34,0x56,0x78.
//
// Many IoT software serialize things as cheap as possible - what usually
// means by dumping the raw memory as bytes.  Exchanging keys and data with
// such an implementation usually needs a bit of 4B-chunks and byte-juggling.
// Helper functions AsLELE, AsBELE, or AsLEBE are exported for that:
//
// AsBELE 32107654BA98FEDC <=> 0123456789ABCDEF
//
// AsLEBE CDEF89AB45670123 <=> 0123456789ABCDEF
//
// AsLELE FEDCBA9876543210 <=> 0123456789ABCDEF
func NewKey(key []byte) (k TeaKey) {
	if len(key) != 16 {
		panic(em)
	}
	var c uint32
	for n := 0; n < 16; n += 4 {
		k[n>>2] = uint32(key[n])<<24 | uint32(key[n+1])<<16 | // from bytes
			uint32(key[n+2])<<8 | uint32(key[n+3])
		c |= k[n>>2]
	}
	if c == 0 {
		panic(em) // all-zeros key
	}
	return
}

// AsBELE reverses chunks order, preserves byte order in a 4B chunk.
//
// (BELE) CDEF89AB45670123 <=> 0123456789ABCDEF (BEBE)
//
// Function does its juggling in-place then returns the same 'd' slice.
// It expects len(d) to be at least 4 and divisible by 4.
func AsBELE(d []byte) []byte {
	var i, l int
	l = chk4len(len(d))
	for i < l {
		d[i+0], d[i+1], d[i+2], d[i+3], d[l-3],
			d[l-2], d[l-1], d[l] = d[l-3], d[l-2], d[l-1], d[l],
			d[i+0], d[i+1], d[i+2], d[i+3]
		l -= 4
		i += 4
	}
	return d
}

// AsLEBE reverses byte order in a 4B chunk, preserves chunks order
//
// (LEBE) 32107654BA98FEDC <=> 0123456789ABCDEF (BEBE)
//
// Function does its juggling in-place then returns the same 'd' slice.
// It expects len(d) to be at least 4 and divisible by 4.
func AsLEBE(d []byte) []byte {
	var i int
	for i < chk4len(len(d)) {
		d[i+0], d[i+1], d[i+2], d[i+3] = d[i+3], d[i+2], d[i+1], d[i+0]
		i += 4
	}
	return d
}

// AsLELE reverses byte and chunks order (reverses the slice)
//
// (LELE) FEDCBA9876543210 <=> 0123456789ABCDEF (BEBE)
//
// Function does its juggling in-place then returns the same 'd' slice.
// It expects len(d) to be at least 4 and divisible by 4.
// Limit is imposed for consistency with other As... functions.
func AsLELE(d []byte) []byte {
	var i, l int // uh, now we have slices.Reverse
	l = chk4len(len(d))
	for i < l {
		d[i], d[l] = d[l], d[i]
		l--
		i++
	}
	return d
}

/* mid-endian jugglings are now obsolete
// AsLB16 reverses byte order in a 2B chunk, preserves chunks order
//
// (LB16) 1032547698BADCFE <=> 0123456789ABCDEF (BEBE)
//
// Function does its juggling in-place then returns the same 'd' slice.
// It expects len(d) to be at least 4 and divisible by 4.
// Limit is imposed for consistency with other As... functions.
func AsLB16(d []byte) []byte {
	var i int
	for i < chk4len(len(d)) {
		d[i], d[i+1] = d[i+1], d[i]
		i += 2
	}
	return d
}

// AsME16 reverses byte order in each even 2B chunk
//
// (ME16) 1023546798ABDCEF <=> 0123456789ABCDEF (BEBE)
//
// Function does its juggling in-place then returns the same 'd' slice.
// It expects len(d) to be at least 4 and divisible by 4.
func AsME16(d []byte) []byte {
	var i int // uh, now we have slices.Reverse
	for i < chk4len(len(d)) {
		d[i], d[i+1] = d[i+1], d[i]
		i += 4
	}
	return d
}

// AsMX16 reverses byte order in each odd 2B chunk
//
// (MX16) 0132457689BACDFE <=> 0123456789ABCDEF (BEBE)
//
// Function does its juggling in-place then returns the same 'd' slice.
// It expects len(d) to be at least 4 and divisible by 4.
func AsMX16(d []byte) []byte {
	var i int
	for i < chk4len(len(d)) {
		d[i+2], d[i+3] = d[i+3], d[i+2]
		i += 4
	}
	return d
}
*/
// check4len tests if length is >= 4 and divisible by 4, otherwise it panics.
// It returns index of the last element in a slice if l is slice length.
func chk4len(l int) int {
	if l < 4 || l&3 != 0 {
		panic(em)
	}
	return l - 1
}

// TeaKey.Encrypt does xxtea block rounds over 'in' bytes writing result to the
// 'out' bytes.  It returns the same 'out' slice it has got.
//
// Slices must be the same length in 8..208 range, in multiples of four.
// Both arguments can be the same slice.
func (k TeaKey) Encrypt(in, out []byte) []byte {
	var n, y, z, p, sum, rounds uint32
	var v [52]uint32
	z = uint32(len(in)) // z bytes (temp)
	if z < 12 || z > 208 || z&3 != 0 || z != uint32(len(out)) {
		panic(em)
	}
	for n = 0; n < z; n += 4 {
		v[n>>2] = uint32(in[n])<<24 | uint32(in[n+1])<<16 | // from bytes
			uint32(in[n+2])<<8 | uint32(in[n+3])
	}
	n = z >> 2        // n uint32s
	rounds = 6 + 52/n // rounds = 6 + 52/n;
	/* // reference C ENCRYPT
	    z = v[n-1];
	    sum = 0;
	    do {
	      sum += DELTA;
	      e = (sum >> 2) & 3;
		  for (p=0; p<n-1; p++) {
	        y = v[p+1];
	        z = v[p] += MX;
	      }
	      y = v[0];
	      z = v[n-1] += MX;
	   } while (--rounds);
	*/         // ENCRYPTED
	z = v[n-1] // z = v[n-1];
	for rounds > 0 {
		rounds--            // do ... while (--rounds);
		sum += delta        // sum += DELTA;
		e := (sum >> 2) & 3 // e = (sum >> 2) & 3
		for p = 0; p < n-1; p++ {
			y = v[p+1] // y = v[p+1];
			// z = v[p] += MX;
			v[p] += ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[p&3^e] ^ z))
			z = v[p]
		}
		y = v[0] // y = v[0];
		// z = v[n-1] += MX;
		v[n-1] += ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[p&3^e] ^ z))
		z = v[n-1]
	}
	for n = 0; n < uint32(len(out)); n += 4 {
		k := v[n>>2] // to bytes
		out[n], out[n+1], out[n+2], out[n+3] = byte(k>>24), byte(k>>16), byte(k>>8), byte(k)
	}
	return out
}

// TeaKey.Decrypt does xxtea block rounds over 'in' bytes writing result to the
// 'out' bytes.  It returns the same 'out' slice it has got.
//
// Slices must be the same length in 8..208 range, in multiples of four.
// Both arguments can be the same slice.
func (k TeaKey) Decrypt(in, out []byte) []byte {
	var n, y, z, p, rounds uint32
	var v [52]uint32
	y = uint32(len(in)) // y bytes (temp)
	if y < 12 || y > 208 || y&3 != 0 || y != uint32(len(out)) {
		panic(em)
	}
	for n = 0; n < y; n += 4 {
		v[n>>2] = uint32(in[n])<<24 | uint32(in[n+1])<<16 | // from bytes
			uint32(in[n+2])<<8 | uint32(in[n+3])
	}
	n = y >> 2        // n ints
	rounds = 6 + 52/n // rounds = 6 + 52/n;
	/* // reference C DECRYPT
	   y = v[0];
	   sum = rounds*DELTA;
	   do {
	     e = (sum >> 2) & 3;
	     for (p=n-1; p>0; p--) {
	       z = v[p-1];
	       y = v[p] -= MX;
	     }
	     z = v[n-1];
	     y = v[0] -= MX;
	     sum -= DELTA;
	   } while (--rounds); */
	y = v[0]              // y = v[0];
	sum := rounds * delta // sum = rounds*DELTA;
	for rounds > 0 {
		rounds--            // do ... while (--rounds);
		e := (sum >> 2) & 3 // e = (sum >> 2) & 3;
		// for (p=n-1; p>0; p--) {
		for p = n - 1; p > 0; p-- {
			z = v[p-1] // z = v[p-1];
			// y = v[p] -= MX;
			v[p] -= ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[p&3^e] ^ z))
			y = v[p]
		}
		z = v[n-1] // z = v[n-1];
		// y = v[0] -= MX;
		v[0] -= ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[p&3^e] ^ z))
		y = v[0]
		sum -= delta // sum -= DELTA;
	}
	for n = 0; n < uint32(len(out)); n += 4 {
		k := v[n>>2] // to bytes
		out[n], out[n+1], out[n+2], out[n+3] = byte(k>>24), byte(k>>16), byte(k>>8), byte(k)
	}
	return out
}

/*
Reference C source from https://en.wikipedia.org/wiki/XXTEA
Crosschecked with https://www.movable-type.co.uk/scripts/xxtea.pdf

void btea(uint32_t *v, int n, uint32_t const key[4]) {
uint32_t y, z, sum;
unsigned p, rounds, e;

rounds = 6 + 52/n;

// ENCRYPT
z = v[n-1];
sum = 0;
do {
  sum += DELTA;
  e = (sum >> 2) & 3; for (p=0; p<n-1; p++) {
	y = v[p+1];
    z = v[p] += MX;
  }
  y = v[0];
  z = v[n-1] += MX;
} while (--rounds);
// ENCRYPTED

// DECRYPT
y = v[0];
sum = rounds*DELTA;
do {
  e = (sum >> 2) & 3;
  for (p=n-1; p>0; p--) {
    z = v[p-1];
    y = v[p] -= MX;
  }
  z = v[n-1];
  y = v[0] -= MX;
  sum -= DELTA;
} while (--rounds);
// DECRYPTED
*/
