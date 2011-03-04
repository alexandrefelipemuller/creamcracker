/* sha1sum.c - print SHA-1 Message-Digest Algorithm 
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 * Copyright (C) 2004 g10 Code GmbH
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* SHA-1 coden take from gnupg 1.3.92. 

   Note, that this is a simple tool to be used for MS Windows.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "utils.h"

#undef BIG_ENDIAN_HOST

/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 20 bytes representing the digest.
 */
int HashSumAndCompare(uint32_t *SHA1KEY, unsigned char *inbuf, size_t inlen)
{

	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xefcdab89;
	uint32_t h2 = 0x98badcfe;
	uint32_t h3 = 0x10325476;
	uint32_t h4 = 0xc3d2e1f0;
	uint32_t count = 0;
	unsigned char buf[64];
	while(inlen--)
		buf[count++] = *inbuf++;

	const uint32_t lsb = count << 3;
	/* multiply by 8 to make a bit count */
	unsigned char *p;

	buf[count++] = 0x80; /* pad */
	while( count < 56 )
		buf[count++] = 0;  /* pad */

	/* append the 64 bit count */
	buf[56] = 0;
	buf[57] = 0;
	buf[58] = 0;
	buf[59] = 0;
	buf[60] = count << 21;
	buf[61] = count << 13;
	buf[62] = count <<  5;
	buf[63] = lsb;

	uint32_t a,b,c,d,e,tm;
	uint32_t x[16];

	/* get values from the chaining vars */
	a = h0;
	b = h1;
	c = h2;
	d = h3;
	e = h4;

//#ifdef BIG_ENDIAN_HOST
//	memcpy( x, buf, 64 );
//#else
	{
		unsigned char* data = buf;
		int i;
		unsigned char *p2;
		for(i=0, p2=(unsigned char*)x; i < 16; i++, p2 += 4 ) {
			p2[3] = *data++;
			p2[2] = *data++;
			p2[1] = *data++;
			p2[0] = *data++;
		}
	}
//#endif


#define K1  0x5A827999L
#define K2  0x6ED9EBA1L
#define K3  0x8F1BBCDCL
#define K4  0xCA62C1D6L
#define F1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )
#define F2(x,y,z)   ( x ^ y ^ z )
#define F3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )
#define F4(x,y,z)   ( x ^ y ^ z )


#define M(i) ( tm =   x[i&0x0f] ^ x[(i-14)&0x0f] \
		^ x[(i-8)&0x0f] ^ x[(i-3)&0x0f] \
		, (x[i&0x0f] = ROTATE_LEFT(tm,1)) )

#define R(a,b,c,d,e,f,k,m)  do { e += ROTATE_LEFT( a, 5 )     \
	+ f( b, c, d )  \
	+ k	      \
	+ m;	      \
	b = ROTATE_LEFT( b, 30 );    \
} while(0)
R( a, b, c, d, e, F1, K1, x[ 0] );
R( e, a, b, c, d, F1, K1, x[ 1] );
R( d, e, a, b, c, F1, K1, x[ 2] );
R( c, d, e, a, b, F1, K1, x[ 3] );
R( b, c, d, e, a, F1, K1, x[ 4] );
R( a, b, c, d, e, F1, K1, x[ 5] );
R( e, a, b, c, d, F1, K1, x[ 6] );
R( d, e, a, b, c, F1, K1, x[ 7] );
R( c, d, e, a, b, F1, K1, x[ 8] );
R( b, c, d, e, a, F1, K1, x[ 9] );
R( a, b, c, d, e, F1, K1, x[10] );
R( e, a, b, c, d, F1, K1, x[11] );
R( d, e, a, b, c, F1, K1, x[12] );
R( c, d, e, a, b, F1, K1, x[13] );
R( b, c, d, e, a, F1, K1, x[14] );
R( a, b, c, d, e, F1, K1, x[15] );
R( e, a, b, c, d, F1, K1, M(16) );
R( d, e, a, b, c, F1, K1, M(17) );
R( c, d, e, a, b, F1, K1, M(18) );
R( b, c, d, e, a, F1, K1, M(19) );
R( a, b, c, d, e, F2, K2, M(20) );
R( e, a, b, c, d, F2, K2, M(21) );
R( d, e, a, b, c, F2, K2, M(22) );
R( c, d, e, a, b, F2, K2, M(23) );
R( b, c, d, e, a, F2, K2, M(24) );
R( a, b, c, d, e, F2, K2, M(25) );
R( e, a, b, c, d, F2, K2, M(26) );
R( d, e, a, b, c, F2, K2, M(27) );
R( c, d, e, a, b, F2, K2, M(28) );
R( b, c, d, e, a, F2, K2, M(29) );
R( a, b, c, d, e, F2, K2, M(30) );
R( e, a, b, c, d, F2, K2, M(31) );
R( d, e, a, b, c, F2, K2, M(32) );
R( c, d, e, a, b, F2, K2, M(33) );
R( b, c, d, e, a, F2, K2, M(34) );
R( a, b, c, d, e, F2, K2, M(35) );
R( e, a, b, c, d, F2, K2, M(36) );
R( d, e, a, b, c, F2, K2, M(37) );
R( c, d, e, a, b, F2, K2, M(38) );
R( b, c, d, e, a, F2, K2, M(39) );
R( a, b, c, d, e, F3, K3, M(40) );
R( e, a, b, c, d, F3, K3, M(41) );
R( d, e, a, b, c, F3, K3, M(42) );
R( c, d, e, a, b, F3, K3, M(43) );
R( b, c, d, e, a, F3, K3, M(44) );
R( a, b, c, d, e, F3, K3, M(45) );
R( e, a, b, c, d, F3, K3, M(46) );
R( d, e, a, b, c, F3, K3, M(47) );
R( c, d, e, a, b, F3, K3, M(48) );
R( b, c, d, e, a, F3, K3, M(49) );
R( a, b, c, d, e, F3, K3, M(50) );
R( e, a, b, c, d, F3, K3, M(51) );
R( d, e, a, b, c, F3, K3, M(52) );
R( c, d, e, a, b, F3, K3, M(53) );
R( b, c, d, e, a, F3, K3, M(54) );
R( a, b, c, d, e, F3, K3, M(55) );
R( e, a, b, c, d, F3, K3, M(56) );
R( d, e, a, b, c, F3, K3, M(57) );
R( c, d, e, a, b, F3, K3, M(58) );
R( b, c, d, e, a, F3, K3, M(59) );
R( a, b, c, d, e, F4, K4, M(60) );
R( e, a, b, c, d, F4, K4, M(61) );
R( d, e, a, b, c, F4, K4, M(62) );
R( c, d, e, a, b, F4, K4, M(63) );
R( b, c, d, e, a, F4, K4, M(64) );
R( a, b, c, d, e, F4, K4, M(65) );
R( e, a, b, c, d, F4, K4, M(66) );
R( d, e, a, b, c, F4, K4, M(67) );
R( c, d, e, a, b, F4, K4, M(68) );
R( b, c, d, e, a, F4, K4, M(69) );
R( a, b, c, d, e, F4, K4, M(70) );
R( e, a, b, c, d, F4, K4, M(71) );
R( d, e, a, b, c, F4, K4, M(72) );
R( c, d, e, a, b, F4, K4, M(73) );
R( b, c, d, e, a, F4, K4, M(74) );
R( a, b, c, d, e, F4, K4, M(75) );
R( e, a, b, c, d, F4, K4, M(76) );
R( d, e, a, b, c, F4, K4, M(77) );
R( c, d, e, a, b, F4, K4, M(78) );
R( b, c, d, e, a, F4, K4, M(79) );

/* Update chaining vars */
h0 += a;
h1 += b;
h2 += c;
h3 += d;
h4 += e;

p = buf;
*p++ = h0 >> 24;
if (buf[0] != SHA1KEY[0])
	return false;
*p++ = h0 >> 16;
if (buf[1] != SHA1KEY[1])
	return false;
*p++ = h0 >> 8;
if (buf[2] != SHA1KEY[2])
	return false;
*p++ = h0;
if (buf[3] != SHA1KEY[3])
	return false;
*p++ = h1 >> 24;
*p++ = h1 >> 16;
*p++ = h1 >> 8;
*p++ = h1;
*p++ = h2 >> 24;
*p++ = h2 >> 16;
*p++ = h2 >> 8;
*p++ = h2;
*p++ = h3 >> 24;
*p++ = h3 >> 16;
*p++ = h3 >> 8;
*p++ = h3;
*p++ = h4 >> 24;
*p++ = h4 >> 16;
*p++ = h4 >> 8;
*p++ = h4;

return (buf[4] == SHA1KEY[4] && buf[5] == SHA1KEY[5] && buf[6] == SHA1KEY[6] && buf[7] == SHA1KEY[7]
	&& buf[8] == SHA1KEY[8] && buf[9] == SHA1KEY[9] && buf[10] == SHA1KEY[10] && buf[11] == SHA1KEY[11]
	&& buf[12] == SHA1KEY[12] && buf[13] == SHA1KEY[13] && buf[14] == SHA1KEY[14] && buf[15] == SHA1KEY[15]
	&& buf[16] == SHA1KEY[16] && buf[17] == SHA1KEY[17]  && buf[18] == SHA1KEY[18] && buf[19] == SHA1KEY[19]);
}	

void loadHash(uint32_t *SHA1KEY,char *sha1Key){
	int i;
	char temp[11];
	for (i=0;i<40;i+=2){
		temp[0] = '0';
		temp[1] = 'x';
		temp[2]=sha1Key[i];
		temp[3]=sha1Key[i+1];
		temp[4]='\0';
		SHA1KEY[i/2] = (uint32_t)strtoul(temp,0,0);
	}
}
