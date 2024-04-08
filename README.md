# xxtea
Self-contained XXTEA block cipher implementation in Go. 100% tests coverage.  With benchmarks.

XXTEA may protect communication with tiny IoT devices.


### This package intentionally does not conform to the crypto/cipher API!

XXTEA cipher should **NEVER** be used as the `cipher.Block` primitive nor the message size should ever exceed 208B or be less than 12B (limits enforced by this package).  See cryptanalysis papers for XXTEA, XTEA, and TEA.  Start with [XXTEA cryptanalysis](https://eprint.iacr.org/2010/254) paper by _Elias Yarrkov_.


## API
 `import "github.com/ohir/xxtea"`

 - `func NewKey(key []byte) TeaKey    // expects big-endian (0123456789ABCDEF) bytes`
 - `func (k TeaKey) Encrypt(in, out []byte) []byte // in plaintext to out ciphertext`
 - `func (k TeaKey) Decrypt(in, out []byte) []byte // in ciphertext to out plaintext`

Key must be obtained from exactly 16B long byte slice containing a non-zero 128 bits number serialized to big-endian bytes.  See "Interop functions" for possible conversions from other byte layouts.

Decrypt and Encrypt methods on a TeaKey do xxtea block rounds over `in` bytes writing result to the `out` bytes.  Both `in` and `out` can be given the same slice for the in-place operation.  The `out` slice is the one returned.  Both `in` and `out` lengths must be equal, in range of 12 to 208, and must be a multiple of four.

XXTEA originally operates on uint32 values so all functions and methods here expect key and data lengths being an integral multiply of 4.  Possible padding and key extending schemas depends on intended cipher usage or are imposed externally.  None to be imposed by the crypto primitive library.


## INTEROP FUNCTIONS

Many IoT softwares serialise data as cheaply as possible what usually means "by dumping the raw memory".  Exchanging keys (and data) with such an implementation needs some chunk and/or bytes juggling to get at the cannonical big-endian form of a serialized xxtea key.

Helper functions AsLELE, AsBELE, or AsLEBE do such a juggling:

 - `func AsLEBE(d []byte) []byte // CDEF89AB45670123 <=> 0123456789ABCDEF`. AsLEBE reverses byte order in a 4B chunk, preserves chunks order. It returns `d` modified in-place.
 - `func AsBELE(d []byte) []byte // 32107654BA98FEDC <=> 0123456789ABCDEF`. AsBELE reverses chunks order, preserves byte order in a 4B chunk. It returns `d` modified in-place.
 - `func AsLELE(d []byte) []byte // FEDCBA9876543210 <=> 0123456789ABCDEF`. AsLELE reverses byte and chunks order (reverses the slice). It returns `d` modified in-place.

As... functions transform argument slice in-place then return it (for easy composition).
Argument slice should be at least 4 bytes long and with length being multiply of 4.

The old "mid-endian" helpers are now commented-out in the source:

 - `func AsLB16(d []byte) []byte // 1032547698BADCFE <=> 0123456789ABCDEF`. AsLB16 reverses byte order in each 2B chunk, preserving chunks order. It returns `d` modified in-place.
 - `func AsME16(d []byte) []byte // 1023546798ABDCEF <=> 0123456789ABCDEF`. AsME16 reverses byte order in each _even_ 2B chunk. It returns `d` modified in-place.
 - `func AsMX16(d []byte) []byte // 0132457689BACDFE <=> 0123456789ABCDEF`. AsMX16 reverses byte order in each _odd_ 2B chunk. It returns `d` modified in-place.


## ERRORS

No recoverable error conditions may occur, only misuses.  This package functions _panics_ on any possible misuse, ie. wrong argument sizes or key being all zeros.


## INTENDED USAGE

For securing communication with tiny IoT devices using short _indepedent_ messages.

If XXTEA is used with random keys and messages less than 212B it still (2024) offers 2^126 security _with the secret key alone_ (no `iv`-s or `nonce`s needed).

For more powerful CPUs the `golang.org/x/crypto/chacha20` cipher will be 2 to 3 times faster, even with Cipher state instantation per each 32B

```
[i7-4770HQ CPU @ 2.20GHz]
xxtea/Decrypt_32     365.8 ns/op    87.49 MB/s     0 B/op   0 allocs/op
xxtea/Decrypt_208   1588.0 ns/op   130.98 MB/s     0 B/op   0 allocs/op
crypto/ChaCha_32     244.7 ns/op   130.76 MB/s   176 B/op   1 allocs/op
crypto/ChaCha_208    662.9 ns/op   313.77 MB/s   176 B/op   1 allocs/op
```
_Note that ChaCha is a stream cipher - it MUST be used with an authenticator like Poly1305, or a HMAC.  It also uses 32B key and needs 96bit nonce._


## USAGE EXAMPLE

```go
package main

import "github.com/ohir/here"
import "github.com/ohir/xxtea"

func main() {
	key := xxtea.NewKey([]byte("0123456789ABCDEF"))

	plainM := []byte("Some message to encrypt here")
	encMsg := make([]byte, len(plainM))

	key.Encrypt(plainM, encMsg) // encrypt (to other slice)
	here.Dump(plainM, encMsg)

	key.Decrypt(encMsg, encMsg) // decrypt (to the same slice)
	here.Dump(plainM, encMsg)
}
```
```
Result:
-- Here! >>>

 1|b28("Some message to encrypt here")
hex:  53 6F 6D 65 20 6D 65 73 73 61 67 65 20 74 6F 20 65 6E 63 72 79 70 74 20 68 65 72 65
pos: __0__1__2__3__4__5__6__7__8__9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27

 2|b28("\xac\xccʊ6\xbdu\xe3\xe2\xe9Z\x1a\x9a\xfdos\t\x80\x80q\x9e|\xfd\xf3\x05\xc5~\x9a")
hex:  AC CC CA 8A 36 BD 75 E3 E2 E9 5A 1A 9A FD 6F 73 09 80 80 71 9E 7C FD F3 05 C5 7E 9A
pos: __0__1__2__3__4__5__6__7__8__9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27

-- Here! >>>

 1|b28("Some message to encrypt here")
hex:  53 6F 6D 65 20 6D 65 73 73 61 67 65 20 74 6F 20 65 6E 63 72 79 70 74 20 68 65 72 65
pos: __0__1__2__3__4__5__6__7__8__9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27

 2|b28("Some message to encrypt here")
hex:  53 6F 6D 65 20 6D 65 73 73 61 67 65 20 74 6F 20 65 6E 63 72 79 70 74 20 68 65 72 65
pos: __0__1__2__3__4__5__6__7__8__9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27
```
