package blackrock_go

/*
NOTE: The comments in this library are from masscan blackrock module
unless stated otherwise by starting with "STATICFLOW:"
 */

/*
   BlackRock cipher
   (h/t Marsh Ray @marshray for this idea)
   This is a randomization/reshuffling function based on a crypto
   "Feistel network" as describ ed in the paper:
   'Ciphers with Arbitrary Finite Domains'
       by John Black and Phillip Rogaway
       http://www.cs.ucdavis.edu/~rogaway/papers/subset.pdf
   This is a crypto-like construction that encrypts an arbitrary sized
   range. Given a number in the range [0..9999], it'll produce a mapping
   to a distinct different number in the same range (and back again).
   In other words, it randomizes the order of numbers in a sequence.
   For example, it can be used to  randomize the sequence [0..9]:
    0 ->      6
    1 ->      4
    2 ->      8
    3 ->      1
    4 ->      9
    5 ->      3
    6 ->      0
    7 ->      5
    8 ->      2
    9 ->      7
   As you can see on the right hand side, the numbers are in random
   order, and they don't repeaet.
   This is create for port scanning. We can take an index variable
   and increment it during a scan, then use this function to
   randomize it, yet be assured that we've probed every IP and port
   within the range.
   The cryptographic strength of this construction depends upon the
   number of rounds, and the exact nature of the inner "READ()" function.
   Because it's a Feistel network, that "READ()" function can be almost
   anything.
   We don't care about cryptographic strength, just speed, so we are
   using a trivial READ() function.
   This is a class of "format-preserving encryption". There are
   probably better constructions than what I'm using.
*/

import (
	"fmt"
	"math"
	"math/rand"
	"time"
)

/***************************************************************************
 * It's an s-box. You gotta have an s-box
 ***************************************************************************/
var sbox =  [256]byte{
	0x91, 0x58, 0xb3, 0x31, 0x6c, 0x33, 0xda, 0x88,
	0x57, 0xdd, 0x8c, 0xf2, 0x29, 0x5a, 0x08, 0x9f,
	0x49, 0x34, 0xce, 0x99, 0x9e, 0xbf, 0x0f, 0x81,
	0xd4, 0x2f, 0x92, 0x3f, 0x95, 0xf5, 0x23, 0x00,
	0x0d, 0x3e, 0xa8, 0x90, 0x98, 0xdd, 0x20, 0x00,
	0x03, 0x69, 0x0a, 0xca, 0xba, 0x12, 0x08, 0x41,
	0x6e, 0xb9, 0x86, 0xe4, 0x50, 0xf0, 0x84, 0xe2,
	0xb3, 0xb3, 0xc8, 0xb5, 0xb2, 0x2d, 0x18, 0x70,

	0x0a, 0xd7, 0x92, 0x90, 0x9e, 0x1e, 0x0c, 0x1f,
	0x08, 0xe8, 0x06, 0xfd, 0x85, 0x2f, 0xaa, 0x5d,
	0xcf, 0xf9, 0xe3, 0x55, 0xb9, 0xfe, 0xa6, 0x7f,
	0x44, 0x3b, 0x4a, 0x4f, 0xc9, 0x2f, 0xd2, 0xd3,
	0x8e, 0xdc, 0xae, 0xba, 0x4f, 0x02, 0xb4, 0x76,
	0xba, 0x64, 0x2d, 0x07, 0x9e, 0x08, 0xec, 0xbd,
	0x52, 0x29, 0x07, 0xbb, 0x9f, 0xb5, 0x58, 0x6f,
	0x07, 0x55, 0xb0, 0x34, 0x74, 0x9f, 0x05, 0xb2,

	0xdf, 0xa9, 0xc6, 0x2a, 0xa3, 0x5d, 0xff, 0x10,
	0x40, 0xb3, 0xb7, 0xb4, 0x63, 0x6e, 0xf4, 0x3e,
	0xee, 0xf6, 0x49, 0x52, 0xe3, 0x11, 0xb3, 0xf1,
	0xfb, 0x60, 0x48, 0xa1, 0xa4, 0x19, 0x7a, 0x2e,
	0x90, 0x28, 0x90, 0x8d, 0x5e, 0x8c, 0x8c, 0xc4,
	0xf2, 0x4a, 0xf6, 0xb2, 0x19, 0x83, 0xea, 0xed,
	0x6d, 0xba, 0xfe, 0xd8, 0xb6, 0xa3, 0x5a, 0xb4,
	0x48, 0xfa, 0xbe, 0x5c, 0x69, 0xac, 0x3c, 0x8f,

	0x63, 0xaf, 0xa4, 0x42, 0x25, 0x50, 0xab, 0x65,
	0x80, 0x65, 0xb9, 0xfb, 0xc7, 0xf2, 0x2d, 0x5c,
	0xe3, 0x4c, 0xa4, 0xa6, 0x8e, 0x07, 0x9c, 0xeb,
	0x41, 0x93, 0x65, 0x44, 0x4a, 0x86, 0xc1, 0xf6,
	0x2c, 0x97, 0xfd, 0xf4, 0x6c, 0xdc, 0xe1, 0xe0,
	0x28, 0xd9, 0x89, 0x7b, 0x09, 0xe2, 0xa0, 0x38,
	0x74, 0x4a, 0xa6, 0x5e, 0xd2, 0xe2, 0x4d, 0xf3,
	0xf4, 0xc6, 0xbc, 0xa2, 0x51, 0x58, 0xe8, 0xae,
}

/*
STATICFLOW: this type takes the place of rand-blackrock.h since in go we can define the struct in the same file
One noted difference is that this library is missing 4 fields (a_bits, a_mask, b_bits, b_mask). These fields seem
to be used for a secondary version of the blackrock library but they do not effect the operation of the algorithm
so they have been removed here
 */
type BlackRock struct {
	inputSize uint64
	a        uint64
	b        uint64
	seed     uint64
	rounds   int
}

/*
STATICFLOW: This initializes the BlackRock cipher
inputSize : the length of values to be shuffled using BlackRock
seed : random entropy used to make each shuffle unique per run
rounds : how many times the BlackRock cipher shuffles input
 */
func InitBlackrock(inputSize uint64, seed uint64, rounds int) *BlackRock {
	br := &BlackRock{}
	foo := math.Sqrt(float64(inputSize * 1.0))
	/* This algorithm gets very non-random at small numbers, so I'm going
	 * to try to fix some constants here to make it work. It doesn't have
	 * to be good, since it's kinda pointless having ranges this small */
	switch inputSize {
	case 0:
		br.a = 0
		br.b = 0
		break
	case 1 :
		br.a = 1
		br.b = 1
		break
	case 2:
		br.a = 1
		br.b = 2
		break
	case 3:
		br.a = 2
		br.b = 2
		break
	case 4:
	case 5:
	case 6:
		br.a = 2
		br.b = 3
		break
	case 7:
	case 8:
		br.a = 3
		br.b = 3
		break
	default:
		br.inputSize = inputSize
		br.a = uint64(foo - 2)
		br.b = uint64(foo + 3)
		break
	}

	for {
		if br.a * br.b <= inputSize {
			br.b++
		} else {
			break
		}
	}
	br.rounds = rounds
	br.seed = seed
	br.inputSize = inputSize
	return br
}

/***************************************************************************
 * The inner round/mixer function. In DES, it's a series of S-box lookups,
 * which
 ***************************************************************************/
/* STATICFLOW : Here there be dragons. If you're following along with Masscan's C code the GETBYTE inline
	function is below
 */
func (br *BlackRock) read(r uint64, R uint64, seed uint64) uint64{
	var  r0, r1, r2, r3 uint64
	R ^= (seed << r) ^ (seed >> (64 - r))

	r0 = uint64(sbox[br.getByte(R, 0, seed, r)]<<0 | sbox[br.getByte(R, 1, seed, r)]<<8)
	r1 = uint64(sbox[br.getByte(R, 2, seed, r)]<<16 | sbox[br.getByte(R, 3, seed, r)]<<24) & 0x0ffffFFFF
	r2 = uint64(sbox[br.getByte(R,4, seed, r)]<< 0 | sbox[br.getByte(R,5, seed, r)]<< 8)
	r3 = uint64(sbox[br.getByte(R,6, seed, r)]<<16 | sbox[br.getByte(R,7, seed, r)]<<24) & 0x0ffffFFFF

	return r0 ^ r1 ^ r2 << 23 ^ r3 << 33
}

/*
STATICFLOW : This function is inlined within the Masscan C code
 */
func (br *BlackRock) getByte(R uint64, n uint64, seed uint64, r uint64) uint64 {
	return (((R)>>(n*8))^seed^r)&0xFF
}

/***************************************************************************
 *
 * NOTE:
 *  the names in this function are cryptic in order to match as closely
 *  as possible the pseudocode in the following paper:
 *      http://www.cs.ucdavis.edu/~rogaway/papers/subset.pdf
 * Read that paper in order to understand this code.
 ***************************************************************************/
//STATICFLOW: Again.......dragons
func (br *BlackRock) encrypt(r int, a uint64, b uint64, m uint64, seed uint64) uint64 {
	var L, R uint64
	var j int
	var tmp uint64

	L = m % a
	R = m / a

	for j=1; j<= r; j++ {
		if j & 1 == 1 {
			tmp = (L + br.read(uint64(j), R, seed)) % a
		} else {
			tmp = (L + br.read(uint64(j), R, seed)) % b
		}
		L = R
		R = tmp
	}
	if r & 1 == 1 {
		return a * L + R
	} else {
		return a * R + L
	}
}


//STATICFLOW: This will return the encrypted value back to its original value
func (br *BlackRock) unencrypt(r int, a uint64, b uint64, m uint64, seed uint64) uint64 {
	var L, R uint64
	var j int
	var tmp uint64
	if r & 1 == 1 {
		R = m % a
		L = m / a
	} else {
		L = m % a
		R = m / a
	}

	for j=r; j>= 1; j-- {
		if j & 1 == 1 {
			tmp = br.read(uint64(j), L, seed)
			if tmp > R {
				tmp = tmp - R
				tmp = a - (tmp % a)
				if tmp == a {
					tmp = 0
				}
			} else {
				tmp = R - tmp
				tmp %= a
			}
		} else {
			tmp = br.read(uint64(j), L, seed)
			if tmp > R {
				tmp = tmp - R
				tmp = b - (tmp % b)
				if tmp == b {
					tmp = 0
				}
			} else {
				tmp = R - tmp
				tmp %= b
			}
		}
		R = L
		L = tmp
	}
	return a * R + L
}

/*
STATICFLOW: This function is what handles the shuffling of each input. An example of how to use this function
in practice is found on the readme page.
 */
func (br *BlackRock) Shuffle(m uint64) uint64 {
	var c uint64
	c = br.encrypt(br.rounds, br.a, br.b, m, br.seed)
	for {
		if c >= br.inputSize {
			c = br.encrypt(br.rounds, br.a, br.b, c, br.seed)
		} else {
			break
		}
	}
	return c
}

/*
STATICFLOW: This function is what handles the un-shuffling of each input. An example of how to use this function
in practice is found on the readme page.
*/
func (br *BlackRock) Unshuffle(m uint64) uint64 {
	var c uint64

	c = br.unencrypt(br.rounds, br.a, br.b, m, br.seed)
	for {
		if c >= br.inputSize {
			c = br.unencrypt(br.rounds, br.a, br.b,  c, br.seed)
		} else {
			break
		}
	}
	return c
}

func (br *BlackRock) verify(max uint64) bool {
	var list []byte
	var i uint64
	isSuccess := true
	if br.inputSize < max {
		list = make([]byte, br.inputSize)
	} else {
		list = make([]byte, max)
	}

	for i=0; i < br.inputSize; i++ {
		x := br.Shuffle(i)
		if x < max {
			list[x]++
		}
	}

	for i=0; i < max && i < br.inputSize; i++ {
		if list[i] != 1 {
			isSuccess = false
		}
	}

	return isSuccess
}

func Selftest() bool {
	var i uint64
	var inputLength uint64
	/* @marshray
	 * Basic test of decryption. I take the index, encrypt it, then decrypt it,
	 * which means I should get the original index back again. Only, it's not
	 * working. The decryption fails. The reason it's failing is obvious -- I'm
	 * just not seeing it though. The error is probably in the 'UNENCRYPT()'
	 * function above.
	 */

	blackRock := InitBlackrock(1000,0,4)
	for i=0; i<10; i++ {
		var result, result2 uint64
		result = blackRock.Shuffle(i)
		result2 = blackRock.Unshuffle(result)
		if i != result2 {
			return false
		}
	}

	inputLength = 3015 * 3
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i=0; i<5; i++ {
		blackRock = InitBlackrock(inputLength, rng.Uint64(),4)
		if !blackRock.verify(inputLength) {
			fmt.Println("BLACKROCK: randomization failed")
			return  false
		}
	}
	return true
}