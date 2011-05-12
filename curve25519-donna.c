/* Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the frecip function is taken
 * from the sample implementation.
 */

#include <string.h>

#define mul32x32_64(a,b) (((uint64_t)(a))*(b))

#if defined(_MSC_VER)
	#if !defined(_DEBUG)
		#include <intrin.h>
		#undef mul32x32_64
		#define mul32x32_64(a,b) __emulu(a,b)
	#endif
	#undef inline
	#define inline __forceinline
	typedef unsigned char uint8_t;
	typedef unsigned int uint32_t;
	typedef signed int int32_t;
	typedef unsigned __int64 uint64_t;
#else
	#include <stdint.h>
	#undef inline
	#define inline __attribute__((always_inline))
#endif

#define DONNA_INLINE
#if defined(DONNA_INLINE)
  #undef DONNA_INLINE
  #define DONNA_INLINE inline
#else
  #define DONNA_INLINE
#endif

typedef uint8_t u8;
typedef uint32_t felem;
typedef int32_t felemsigned;
typedef felem bignum[10];
typedef uint64_t felemx2;


/* Copy a bignum to another: out = in */
static void DONNA_INLINE
fcopy(bignum out, const bignum in) {
	memcpy(out, in, sizeof(bignum));
}

/* Sum two numbers: out += in */
static void DONNA_INLINE
fsum(bignum out, const bignum in) {
	out[0] += in[0];
	out[1] += in[1];
	out[2] += in[2];
	out[3] += in[3];
	out[4] += in[4];
	out[5] += in[5];
	out[6] += in[6];
	out[7] += in[7];
	out[8] += in[8];
	out[9] += in[9];
}

/* Find the difference of two numbers: out = in - out
 * (note the order of the arguments!)
 */
static void DONNA_INLINE
fdifference_backwards(bignum out, const bignum in) {
	felem r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,c;

	r0 = in[0] - out[0];
	r1 = in[1] - out[1];
	r2 = in[2] - out[2];
	r3 = in[3] - out[3];
	r4 = in[4] - out[4];
	r5 = in[5] - out[5];
	r6 = in[6] - out[6];
	r7 = in[7] - out[7];
	r8 = in[8] - out[8];
	r9 = in[9] - out[9];

	#define carry(i,j) \
		c = r##i >> 31; r##i += c << (26 - (i&1)); r##j -= c;
	#define carry19(i,j) \
		c = r##i >> 31; r##i += c << (26 - (i&1)); r##j -= c * 19;

	carry(0,1)
	carry(1,2)
	carry(2,3)
	carry(3,4)
	carry(4,5)
	carry(5,6)
	carry(6,7)
	carry(7,8)
	carry(8,9)
	carry19(9,0)
	carry(0,1)
	carry(1,2)
	carry(2,3)
	carry(3,4)
	carry(4,5)
	carry(5,6)
	carry(6,7)
	carry(7,8)
	carry(8,9)

	#undef carry
	#undef carry19

    out[0] = r0;
	out[1] = r1;
	out[2] = r2;
	out[3] = r3;
	out[4] = r4;
	out[5] = r5;
	out[6] = r6;
	out[7] = r7;
	out[8] = r8;
	out[9] = r9;
}


/* Multiply a number by a scalar and add: out = (in * scalar) + add */
static void DONNA_INLINE
fscalar_product_sum(bignum out, const bignum in, const felem scalar, const bignum add) {
	felemx2 a;
	felem r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,c;

	a = mul32x32_64(in[0], scalar);     r0 = (felem)a & 0x3ffffff; c = (felem)(a >> 26);
	a = mul32x32_64(in[1], scalar) + c; r1 = (felem)a & 0x1ffffff; c = (felem)(a >> 25);
	a = mul32x32_64(in[2], scalar) + c; r2 = (felem)a & 0x3ffffff; c = (felem)(a >> 26);
	a = mul32x32_64(in[3], scalar) + c; r3 = (felem)a & 0x1ffffff; c = (felem)(a >> 25);
	a = mul32x32_64(in[4], scalar) + c; r4 = (felem)a & 0x3ffffff; c = (felem)(a >> 26);
	a = mul32x32_64(in[5], scalar) + c; r5 = (felem)a & 0x1ffffff; c = (felem)(a >> 25);
	a = mul32x32_64(in[6], scalar) + c; r6 = (felem)a & 0x3ffffff; c = (felem)(a >> 26);
	a = mul32x32_64(in[7], scalar) + c; r7 = (felem)a & 0x1ffffff; c = (felem)(a >> 25);
	a = mul32x32_64(in[8], scalar) + c; r8 = (felem)a & 0x3ffffff; c = (felem)(a >> 26);
	a = mul32x32_64(in[9], scalar) + c; r9 = (felem)a & 0x1ffffff; c = (felem)(a >> 25);
	                                    r0 += c * 19;

	out[0] = r0 + add[0];
	out[1] = r1 + add[1];
	out[2] = r2 + add[2];
	out[3] = r3 + add[3];
	out[4] = r4 + add[4];
	out[5] = r5 + add[5];
	out[6] = r6 + add[6];
	out[7] = r7 + add[7];
	out[8] = r8 + add[8];
	out[9] = r9 + add[9];
}

/* Multiply two numbers: out = in2 * in */
static void DONNA_INLINE
fmul(bignum output, const bignum in2, const bignum in) {
	felem r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
	felem s0,s1,s2,s3,s4,s5,s6,s7,s8,s9;
	felemx2 m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,c;
	felem p;

	r0 = in[0];
	r1 = in[1];
	r2 = in[2];
	r3 = in[3];
	r4 = in[4];
	r5 = in[5];
	r6 = in[6];
	r7 = in[7];
	r8 = in[8];
	r9 = in[9];

	s0 = in2[0];
	s1 = in2[1];
	s2 = in2[2];
	s3 = in2[3];
	s4 = in2[4];
	s5 = in2[5];
	s6 = in2[6];
	s7 = in2[7];
	s8 = in2[8];
	s9 = in2[9];

	m0 = mul32x32_64(r0, s0);
	m1 = mul32x32_64(r0, s1) + mul32x32_64(r1, s0);
	m3 = mul32x32_64(r0, s3) + mul32x32_64(r1, s2) + mul32x32_64(r2, s1) + mul32x32_64(r3, s0);
	m5 = mul32x32_64(r0, s5) + mul32x32_64(r1, s4) + mul32x32_64(r2, s3) + mul32x32_64(r3, s2) + mul32x32_64(r4, s1) + mul32x32_64(r5, s0);
	m7 = mul32x32_64(r0, s7) + mul32x32_64(r1, s6) + mul32x32_64(r2, s5) + mul32x32_64(r3, s4) + mul32x32_64(r4, s3) + mul32x32_64(r5, s2) + mul32x32_64(r6, s1) + mul32x32_64(r7, s0);
	m9 = mul32x32_64(r0, s9) + mul32x32_64(r1, s8) + mul32x32_64(r2, s7) + mul32x32_64(r3, s6) + mul32x32_64(r4, s5) + mul32x32_64(r5, s4) + mul32x32_64(r6, s3) + mul32x32_64(r7, s2) + mul32x32_64(r8, s1) + mul32x32_64(r9, s0);

	r1 *= 2;
	r3 *= 2;
	r5 *= 2;
	r7 *= 2;

	m2 = mul32x32_64(r0, s2) + mul32x32_64(r1, s1) + mul32x32_64(r2, s0);
	m4 = mul32x32_64(r0, s4) + mul32x32_64(r1, s3) + mul32x32_64(r2, s2) + mul32x32_64(r3, s1) + mul32x32_64(r4, s0);
	m6 = mul32x32_64(r0, s6) + mul32x32_64(r1, s5) + mul32x32_64(r2, s4) + mul32x32_64(r3, s3) + mul32x32_64(r4, s2) + mul32x32_64(r5, s1) + mul32x32_64(r6, s0);
	m8 = mul32x32_64(r0, s8) + mul32x32_64(r1, s7) + mul32x32_64(r2, s6) + mul32x32_64(r3, s5) + mul32x32_64(r4, s4) + mul32x32_64(r5, s3) + mul32x32_64(r6, s2) + mul32x32_64(r7, s1) + mul32x32_64(r8, s0);

	r3 = (r3 / 2) * 19;
	r5 = (r5 / 2) * 19;
	r7 = (r7 / 2) * 19;

	r2 *= 19;
	r4 *= 19;
	r6 *= 19;
	r8 *= 19;
	r9 *= 19;

	m1 += (mul32x32_64(r9, s2) + mul32x32_64(r8, s3) + mul32x32_64(r7, s4) + mul32x32_64(r6, s5) + mul32x32_64(r5, s6) + mul32x32_64(r4, s7) + mul32x32_64(r3, s8) + mul32x32_64(r2, s9));
	m3 += (mul32x32_64(r9, s4) + mul32x32_64(r8, s5) + mul32x32_64(r7, s6) + mul32x32_64(r6, s7) + mul32x32_64(r5, s8) + mul32x32_64(r4, s9));
	m5 += (mul32x32_64(r9, s6) + mul32x32_64(r8, s7) + mul32x32_64(r7, s8) + mul32x32_64(r6, s9));
	m7 += (mul32x32_64(r9, s8) + mul32x32_64(r8, s9));

	r1 *= 19;
	r3 *= 2;
	r5 *= 2;
	r7 *= 2;
	r9 *= 2;

	m0 += (mul32x32_64(r9, s1) + mul32x32_64(r8, s2) + mul32x32_64(r7, s3) + mul32x32_64(r6, s4) + mul32x32_64(r5, s5) + mul32x32_64(r4, s6) + mul32x32_64(r3, s7) + mul32x32_64(r2, s8) + mul32x32_64(r1, s9));
	m2 += (mul32x32_64(r9, s3) + mul32x32_64(r8, s4) + mul32x32_64(r7, s5) + mul32x32_64(r6, s6) + mul32x32_64(r5, s7) + mul32x32_64(r4, s8) + mul32x32_64(r3, s9));
	m4 += (mul32x32_64(r9, s5) + mul32x32_64(r8, s6) + mul32x32_64(r7, s7) + mul32x32_64(r6, s8) + mul32x32_64(r5, s9));
	m6 += (mul32x32_64(r9, s7) + mul32x32_64(r8, s8) + mul32x32_64(r7, s9));
	m8 += (mul32x32_64(r9, s9));

	                             r0 = (felem)m0 & 0x3ffffff; c = (m0 >> 26);
	m1 += c;                     r1 = (felem)m1 & 0x1ffffff; c = (m1 >> 25);
	m2 += c;                     r2 = (felem)m2 & 0x3ffffff; c = (m2 >> 26);
	m3 += c;                     r3 = (felem)m3 & 0x1ffffff; c = (m3 >> 25);
	m4 += c;                     r4 = (felem)m4 & 0x3ffffff; c = (m4 >> 26);
	m5 += c;                     r5 = (felem)m5 & 0x1ffffff; c = (m5 >> 25);
	m6 += c;                     r6 = (felem)m6 & 0x3ffffff; c = (m6 >> 26);
	m7 += c;                     r7 = (felem)m7 & 0x1ffffff; c = (m7 >> 25);
	m8 += c;                     r8 = (felem)m8 & 0x3ffffff; c = (m8 >> 26);
	m9 += c;                     r9 = (felem)m9 & 0x1ffffff; p = (felem)(m9 >> 25);
	m0 = r0 + mul32x32_64(p,19); r0 = (felem)m0 & 0x3ffffff; p = (felem)(m0 >> 26);
	r1 += p;      p = r1 >> 25; r1 &= 0x1ffffff;
	r2 += p;      p = r2 >> 26; r2 &= 0x3ffffff;
	r3 += p;      p = r3 >> 25; r3 &= 0x1ffffff;
	r4 += p;      p = r4 >> 26; r4 &= 0x3ffffff;
	r5 += p;      p = r5 >> 25; r5 &= 0x1ffffff;
	r6 += p;      p = r6 >> 26; r6 &= 0x3ffffff;
	r7 += p;      p = r7 >> 25; r7 &= 0x1ffffff;
	r8 += p;      p = r8 >> 26; r8 &= 0x3ffffff;
	r9 += p;      p = r9 >> 25; r9 &= 0x1ffffff;
	r0 += p * 19;

	output[0] = r0;
	output[1] = r1;
	output[2] = r2;
	output[3] = r3;
	output[4] = r4;
	output[5] = r5;
	output[6] = r6;
	output[7] = r7;
	output[8] = r8;
	output[9] = r9;
}


static void DONNA_INLINE
fsquare_times(bignum output, const bignum in, int count) {
	felem r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
	felem d6,d7,d8,d9;
	felemx2 m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,c;
	felem p;

	r0 = in[0];
	r1 = in[1];
	r2 = in[2];
	r3 = in[3];
	r4 = in[4];
	r5 = in[5];
	r6 = in[6];
	r7 = in[7];
	r8 = in[8];
	r9 = in[9];

	do {
		m0 = mul32x32_64(r0, r0);
		r0 *= 2;
		m1 = mul32x32_64(r0, r1);
		m2 = mul32x32_64(r0, r2) + mul32x32_64(r1, r1 * 2);
		r1 *= 2;
		m3 = mul32x32_64(r0, r3) + mul32x32_64(r1, r2    );
		m4 = mul32x32_64(r0, r4) + mul32x32_64(r1, r3 * 2) + mul32x32_64(r2, r2);
		r2 *= 2;
		m5 = mul32x32_64(r0, r5) + mul32x32_64(r1, r4    ) + mul32x32_64(r2, r3);
		m6 = mul32x32_64(r0, r6) + mul32x32_64(r1, r5 * 2) + mul32x32_64(r2, r4) + mul32x32_64(r3, r3 * 2);
		r3 *= 2;
		m7 = mul32x32_64(r0, r7) + mul32x32_64(r1, r6    ) + mul32x32_64(r2, r5) + mul32x32_64(r3, r4    );
		m8 = mul32x32_64(r0, r8) + mul32x32_64(r1, r7 * 2) + mul32x32_64(r2, r6) + mul32x32_64(r3, r5 * 2) + mul32x32_64(r4, r4    );
		m9 = mul32x32_64(r0, r9) + mul32x32_64(r1, r8    ) + mul32x32_64(r2, r7) + mul32x32_64(r3, r6    ) + mul32x32_64(r4, r5 * 2);

		d6 = r6 * 19;
		d7 = r7 * 2 * 19;
		d8 = r8 * 19;
		d9 = r9 * 2 * 19;

		m0 += (mul32x32_64(d9, r1    ) + mul32x32_64(d8, r2    ) + mul32x32_64(d7, r3    ) + mul32x32_64(d6, r4 * 2) + mul32x32_64(r5, r5 * 2 * 19));
		m1 += (mul32x32_64(d9, r2 / 2) + mul32x32_64(d8, r3    ) + mul32x32_64(d7, r4    ) + mul32x32_64(d6, r5 * 2));
		m2 += (mul32x32_64(d9, r3    ) + mul32x32_64(d8, r4 * 2) + mul32x32_64(d7, r5 * 2) + mul32x32_64(d6, r6    ));
		m3 += (mul32x32_64(d9, r4    ) + mul32x32_64(d8, r5 * 2) + mul32x32_64(d7, r6    ));
		m4 += (mul32x32_64(d9, r5 * 2) + mul32x32_64(d8, r6 * 2) + mul32x32_64(d7, r7    ));
		m5 += (mul32x32_64(d9, r6    ) + mul32x32_64(d8, r7 * 2));
		m6 += (mul32x32_64(d9, r7 * 2) + mul32x32_64(d8, r8    ));
		m7 += (mul32x32_64(d9, r8    ));
		m8 += (mul32x32_64(d9, r9    ));

									 r0 = (felem)m0 & 0x3ffffff; c = (m0 >> 26);
		m1 += c;                     r1 = (felem)m1 & 0x1ffffff; c = (m1 >> 25);
		m2 += c;                     r2 = (felem)m2 & 0x3ffffff; c = (m2 >> 26);
		m3 += c;                     r3 = (felem)m3 & 0x1ffffff; c = (m3 >> 25);
		m4 += c;                     r4 = (felem)m4 & 0x3ffffff; c = (m4 >> 26);
		m5 += c;                     r5 = (felem)m5 & 0x1ffffff; c = (m5 >> 25);
		m6 += c;                     r6 = (felem)m6 & 0x3ffffff; c = (m6 >> 26);
		m7 += c;                     r7 = (felem)m7 & 0x1ffffff; c = (m7 >> 25);
		m8 += c;                     r8 = (felem)m8 & 0x3ffffff; c = (m8 >> 26);
		m9 += c;                     r9 = (felem)m9 & 0x1ffffff; p = (felem)(m9 >> 25);
		m0 = r0 + mul32x32_64(p,19); r0 = (felem)m0 & 0x3ffffff; p = (felem)(m0 >> 26);
		r1 += p;      p = r1 >> 25; r1 &= 0x1ffffff;
		r2 += p;      p = r2 >> 26; r2 &= 0x3ffffff;
		r3 += p;      p = r3 >> 25; r3 &= 0x1ffffff;
		r4 += p;      p = r4 >> 26; r4 &= 0x3ffffff;
		r5 += p;      p = r5 >> 25; r5 &= 0x1ffffff;
		r6 += p;      p = r6 >> 26; r6 &= 0x3ffffff;
		r7 += p;      p = r7 >> 25; r7 &= 0x1ffffff;
		r8 += p;      p = r8 >> 26; r8 &= 0x3ffffff;
		r9 += p;      p = r9 >> 25; r9 &= 0x1ffffff;
		r0 += p * 19;
	} while (--count);

	output[0] = r0;
	output[1] = r1;
	output[2] = r2;
	output[3] = r3;
	output[4] = r4;
	output[5] = r5;
	output[6] = r6;
	output[7] = r7;
	output[8] = r8;
	output[9] = r9;
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
static void
fexpand(bignum out, const unsigned char in[32]) {
	#define F(n,start,shift,mask) \
		out[n] = \
			((((felem) in[start + 0]) | \
			((felem) in[start + 1]) << 8 | \
			((felem) in[start + 2]) << 16 | \
			((felem) in[start + 3]) << 24) >> shift) & mask;

	F(0, 0, 0, 0x3ffffff);
	F(1, 3, 2, 0x1ffffff);
	F(2, 6, 3, 0x3ffffff);
	F(3, 9, 5, 0x1ffffff);
	F(4, 12, 6, 0x3ffffff);
	F(5, 16, 0, 0x1ffffff);
	F(6, 19, 1, 0x3ffffff);
	F(7, 22, 3, 0x1ffffff);
	F(8, 25, 4, 0x3ffffff);
	F(9, 28, 6, 0x1ffffff);
	#undef F
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
static void
fcontract(unsigned char out[32], const bignum in) {
	bignum f;
	fcopy(f, in);

	#define carry_pass() \
		f[1] += f[0] >> 26; f[0] &= 0x3ffffff; \
		f[2] += f[1] >> 25; f[1] &= 0x1ffffff; \
		f[3] += f[2] >> 26; f[2] &= 0x3ffffff; \
		f[4] += f[3] >> 25; f[3] &= 0x1ffffff; \
		f[5] += f[4] >> 26; f[4] &= 0x3ffffff; \
		f[6] += f[5] >> 25; f[5] &= 0x1ffffff; \
		f[7] += f[6] >> 26; f[6] &= 0x3ffffff; \
		f[8] += f[7] >> 25; f[7] &= 0x1ffffff; \
		f[9] += f[8] >> 26; f[8] &= 0x3ffffff;

	#define carry_pass_full() \
		carry_pass() \
		f[0] += 19 * (f[9] >> 25); f[9] &= 0x1ffffff;

	#define carry_pass_final() \
		carry_pass() \
		f[9] &= 0x1ffffff;

	carry_pass_full()
	carry_pass_full()

	/* now t is between 0 and 2^255-1, properly carried. */
	/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */
	f[0] += 19;
	carry_pass_full()

	/* now between 19 and 2^255-1 in both cases, and offset by 19. */
	f[0] += (1 << 26) - 19;
	f[1] += (1 << 25) - 1;
	f[2] += (1 << 26) - 1;
	f[3] += (1 << 25) - 1;
	f[4] += (1 << 26) - 1;
	f[5] += (1 << 25) - 1;
	f[6] += (1 << 26) - 1;
	f[7] += (1 << 25) - 1;
	f[8] += (1 << 26) - 1;
	f[9] += (1 << 25) - 1;

	/* now between 2^255 and 2^256-20, and offset by 2^255. */
	carry_pass_final()

	#undef carry_pass
	#undef carry_full
	#undef carry_final

	f[1] <<= 2;
	f[2] <<= 3;
	f[3] <<= 5;
	f[4] <<= 6;
	f[6] <<= 1;
	f[7] <<= 3;
	f[8] <<= 4;
	f[9] <<= 6;

	#define F(i, s) \
		out[s+0] |= (unsigned char )(f[i] & 0xff); \
		out[s+1] = (unsigned char )((f[i] >> 8) & 0xff); \
		out[s+2] = (unsigned char )((f[i] >> 16) & 0xff); \
		out[s+3] = (unsigned char )((f[i] >> 24) & 0xff);

	out[0] = 0;
	out[16] = 0;
	F(0,0);
	F(1,3);
	F(2,6);
	F(3,9);
	F(4,12);
	F(5,16);
	F(6,19);
	F(7,22);
	F(8,25);
	F(9,28);
	#undef F
}

/*
 * Maybe swap the contents of two felem arrays (@a and @b), each 5 elements
 * long. Perform the swap iff @swap is non-zero.
 */
static void DONNA_INLINE
fswap_conditional(bignum a, bignum b, felem iswap) {
	const felem swap = (uint64_t)(-(int64_t)iswap);
	felem x0,x1,x2,x3,x4,x5,x6,x7,x8,x9;

	x0 = swap & (a[0] ^ b[0]); a[0] ^= x0; b[0] ^= x0;
	x1 = swap & (a[1] ^ b[1]); a[1] ^= x1; b[1] ^= x1;
	x2 = swap & (a[2] ^ b[2]); a[2] ^= x2; b[2] ^= x2;
	x3 = swap & (a[3] ^ b[3]); a[3] ^= x3; b[3] ^= x3;
	x4 = swap & (a[4] ^ b[4]); a[4] ^= x4; b[4] ^= x4;
	x5 = swap & (a[5] ^ b[5]); a[5] ^= x5; b[5] ^= x5;
	x6 = swap & (a[6] ^ b[6]); a[6] ^= x6; b[6] ^= x6;
	x7 = swap & (a[7] ^ b[7]); a[7] ^= x7; b[7] ^= x7;
	x8 = swap & (a[8] ^ b[8]); a[8] ^= x8; b[8] ^= x8;
	x9 = swap & (a[9] ^ b[9]); a[9] ^= x9; b[9] ^= x9;
}


/*
 * djb's version, tightened up
 */
static void
frecip(bignum out, const bignum z) {
  bignum a,t0,b,c;

  /* 2 */ fsquare_times(a, z, 1); // a = 2
  /* 8 */ fsquare_times(t0, a, 2);
  /* 9 */ fmul(b, t0, z); // b = 9
  /* 11 */ fmul(a, b, a); // a = 11
  /* 22 */ fsquare_times(t0, a, 1);
  /* 2^5 - 2^0 = 31 */ fmul(b, t0, b);
  /* 2^10 - 2^5 */ fsquare_times(t0, b, 5);
  /* 2^10 - 2^0 */ fmul(b, t0, b);
  /* 2^20 - 2^10 */ fsquare_times(t0, b, 10);
  /* 2^20 - 2^0 */ fmul(c, t0, b);
  /* 2^40 - 2^20 */ fsquare_times(t0, c, 20);
  /* 2^40 - 2^0 */ fmul(t0, t0, c);
  /* 2^50 - 2^10 */ fsquare_times(t0, t0, 10);
  /* 2^50 - 2^0 */ fmul(b, t0, b);
  /* 2^100 - 2^50 */ fsquare_times(t0, b, 50);
  /* 2^100 - 2^0 */ fmul(c, t0, b);
  /* 2^200 - 2^100 */ fsquare_times(t0, c, 100);
  /* 2^200 - 2^0 */ fmul(t0, t0, c);
  /* 2^250 - 2^50 */ fsquare_times(t0, t0, 50);
  /* 2^250 - 2^0 */ fmul(t0, t0, b);
  /* 2^255 - 2^5 */ fsquare_times(t0, t0, 5);
  /* 2^255 - 21 */ fmul(out, t0, a);
}

/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   mypublic: the packed little endian x coordinate of the resulting curve point
 *   n: a little endian, 32-byte number
 *   basepoint: a packed little endian point of the curve
 */
static void
fscalarmult(u8 mypublic[32], const u8 n[32], const u8 basepoint[32]) {
	bignum nqpqx, nqpqz = {1}, nqx = {1}, nqz = {0};
	bignum q, origx, origxprime, zzz, xx, zz, xxprime, zzprime, zzzprime, zmone;
	felem bit, lastbit;
	unsigned i;

	fexpand(q, basepoint);
	fcopy(nqpqx, q);

	i = 255;
	lastbit = 0;

	do {
		bit = (n[i/8] >> (i & 7)) & 1;
		fswap_conditional(nqx, nqpqx, bit ^ lastbit);
		fswap_conditional(nqz, nqpqz, bit ^ lastbit);
		lastbit = bit;

		fcopy(origx, nqx);
		fsum(nqx, nqz);
		fdifference_backwards(nqz, origx); // does x - z
		fcopy(origxprime, nqpqx);
		fsum(nqpqx, nqpqz);
		fdifference_backwards(nqpqz, origxprime);
		fmul(xxprime, nqpqx, nqz);
		fmul(zzprime, nqx, nqpqz);
		fcopy(origxprime, xxprime);
		fsum(xxprime, zzprime);
		fdifference_backwards(zzprime, origxprime);
		fsquare_times(zzzprime, zzprime, 1);
		fsquare_times(nqpqx, xxprime, 1);
		fmul(nqpqz, zzzprime, q);
		fsquare_times(xx, nqx, 1);
		fsquare_times(zz, nqz, 1);
		fmul(nqx, xx, zz);
		fdifference_backwards(zz, xx);  // does zz = xx - zz
		fscalar_product_sum(zzz, zz, 121665, xx); // zzz = (zz * 121665) + xx
		fmul(nqz, zz, zzz);
	} while (i--);

	fswap_conditional(nqx, nqpqx, bit);
	fswap_conditional(nqz, nqpqz, bit);

	frecip(zmone, nqz);
	fmul(nqz, nqx, zmone);
	fcontract(mypublic, nqz);
}


int
curve25519_donna(u8 *mypublic, const u8 *secret, const u8 *basepoint) {
	u8 e[32];
	unsigned i;

	for (i = 0;i < 32;++i)
		e[i] = secret[i];
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;
	fscalarmult(mypublic, e, basepoint);
	return 0;
}
