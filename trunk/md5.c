/*
 **********************************************************************
 ** md5.h -- Header file for implementation of MD5                   **
 ** RSA Data Security, Inc. MD5 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 12/27/90 SRD,AJ,BSK,JT Reference C version              **
 ** Revised (for MD5): RLR 4/27/91                                   **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     **
 ** Digest Algorithm" in all material mentioning or referencing this **
 ** software or this function.                                       **
 **                                                                  **
 ** License is also granted to make and use derivative works         **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         **
 ** material mentioning or referencing the derived work.             **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

#include "utils.h"
#include <stdint.h>
#include <stdlib.h>

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z))) 

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

/* Basic MD5 step. Transform and compare based on in.
 */
int TransformCompareMd5 (uint32_t *key,uint32_t *in)
{
  register uint32_t a,
	b = (uint32_t)(0xefcdab89),
       	c = (uint32_t)(0x98badcfe),
	d = (uint32_t)(0x10325476);

  /* Round 1 */

  /*a = (uint32_t)7909057655U + in[0]; -> this is bigger than 32 bits */
  a = (uint32_t)3614090359U + in[0];
  a = ROTATE_LEFT (a, 7);
  a += b;
  //FF ( a, b, c, d, in[ 0], 7, 3614090360); /* 1 */
  FF ( d, a, b, c, in[ 1], 12, 3905402710U); /* 2 */
  FF ( c, d, a, b, in[ 2], 17,  606105819U); /* 3 */
  FF ( b, c, d, a, in[ 3], 22, 3250441966U); /* 4 */
  FF ( a, b, c, d, in[ 4], 7, 4118548399U); /* 5 */
  FF ( d, a, b, c, 0, 12, 1200080426U); /* 6 */
  FF ( c, d, a, b, 0, 17, 2821735955U); /* 7 */
  FF ( b, c, d, a, 0, 22, 4249261313U); /* 8 */
  FF ( a, b, c, d, 0, 7, 1770035416U); /* 9 */
  FF ( d, a, b, c, 0, 12, 2336552879U); /* 10 */
  FF ( c, d, a, b, 0, 17, 4294925233U); /* 11 */
  FF ( b, c, d, a, 0, 22, 2304563134U); /* 12 */
  FF ( a, b, c, d, 0, 7, 1804603682U); /* 13 */
  FF ( d, a, b, c, 0, 12, 4254626195U); /* 14 */
  FF ( c, d, a, b, in[5], 17, 2792965006U); /* 15 */
  FF ( b, c, d, a, 0, 22, 1236535329U); /* 16 */

  /* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
  GG ( a, b, c, d, in[ 1], S21, 4129170786U); /* 17 */
  GG ( d, a, b, c, 0, S22, 3225465664U); /* 18 */
  GG ( c, d, a, b, 0, S23,  643717713U); /* 19 */
  GG ( b, c, d, a, in[ 0], S24, 3921069994U); /* 20 */
  GG ( a, b, c, d, 0, S21, 3593408605U); /* 21 */
  GG ( d, a, b, c, 0, S22,   38016083U); /* 22 */
  GG ( c, d, a, b, 0, S23, 3634488961U); /* 23 */
  GG ( b, c, d, a, in[ 4], S24, 3889429448U); /* 24 */
  GG ( a, b, c, d, 0, S21,  568446438U); /* 25 */
  GG ( d, a, b, c, in[5], S22, 3275163606U); /* 26 */
  GG ( c, d, a, b, in[ 3], S23, 4107603335U); /* 27 */
  GG ( b, c, d, a, 0, S24, 1163531501U); /* 28 */
  GG ( a, b, c, d, 0, S21, 2850285829U); /* 29 */
  GG ( d, a, b, c, in[ 2], S22, 4243563512U); /* 30 */
  GG ( c, d, a, b, 0, S23, 1735328473U); /* 31 */
  GG ( b, c, d, a, 0, S24, 2368359562U); /* 32 */

  /* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
  HH ( a, b, c, d, 0, S31, 4294588738U); /* 33 */
  HH ( d, a, b, c, 0, S32, 2272392833U); /* 34 */
  HH ( c, d, a, b, 0, S33, 1839030562U); /* 35 */
  HH ( b, c, d, a, in[5], S34, 4259657740U); /* 36 */
  HH ( a, b, c, d, in[ 1], S31, 2763975236U); /* 37 */
  HH ( d, a, b, c, in[ 4], S32, 1272893353U); /* 38 */
  HH ( c, d, a, b, 0, S33, 4139469664U); /* 39 */
  HH ( b, c, d, a, 0, S34, 3200236656U); /* 40 */
  HH ( a, b, c, d, 0, S31,  681279174U); /* 41 */
  HH ( d, a, b, c, in[ 0], S32, 3936430074U); /* 42 */
  HH ( c, d, a, b, in[ 3], S33, 3572445317U); /* 43 */
  HH ( b, c, d, a, 0, S34,   76029189U); /* 44 */
  HH ( a, b, c, d, 0, S31, 3654602809U); /* 45 */
  HH ( d, a, b, c, 0, S32, 3873151461U); /* 46 */
  HH ( c, d, a, b, 0, S33,  530742520U); /* 47 */
  HH ( b, c, d, a, in[ 2], S34, 3299628645U); /* 48 */

  /* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
  II ( a, b, c, d, in[ 0], S41, 4096336452U); /* 49 */
  II ( d, a, b, c, 0, S42, 1126891415U); /* 50 */
  II ( c, d, a, b, in[5], S43, 2878612391U); /* 51 */
  II ( b, c, d, a, 0, S44, 4237533241U); /* 52 */
  II ( a, b, c, d, 0, S41, 1700485571U); /* 53 */
  II ( d, a, b, c, in[ 3], S42, 2399980690U); /* 54 */
  II ( c, d, a, b, 0, S43, 4293915773U); /* 55 */
  II ( b, c, d, a, in[ 1], S44, 2240044497U); /* 56 */
  II ( a, b, c, d, 0, S41, 1873313359U); /* 57 */
  II ( d, a, b, c, 0, S42, 4264355552U); /* 58 */
  II ( c, d, a, b, 0, S43, 2734768916U); /* 59 */
  II ( b, c, d, a, 0, S44, 1309151649U); /* 60 */ 

  //II ( a, b, c, d, in[ 4], S41, 4149444226U); /* 61 */
  a += I (b, c, d) + in[4] + (uint32_t)4149444226U;
  if (ROTATE_LEFT (a, S41) + b != key[0])
	return false;
  a = ROTATE_LEFT (a, S41);
  a += b;
  II ( d, a, b, c, 0, S42, 3174756917U); /* 62 */

  if(d != key[3])
	return false;
  II ( c, d, a, b, in[ 2], S43,  718787259U); /* 63 */

  if(c != key[2])
	return false;
  //  II ( b, c, d, a, in[ 9], S44, 3951481745); /*Not used, by reversed transform*/ 
  b += I (c, d, a);
  return (b == key[1]);
}

/* This function try to reverse transform MD5, this only economize a little portion of steps */
void loadMd5(uint32_t buf[4],char *md5Key){
	int i;
	char temp[11];
	for (i=0;i<32;i+=8){
		temp[0] = '0';
		temp[1] = 'x';
		temp[2]=md5Key[i+6];
		temp[3]=md5Key[i+7];
		temp[4]=md5Key[i+4];
		temp[5]=md5Key[i+5];
		temp[6]=md5Key[i+2];
		temp[7]=md5Key[i+3];
		temp[8]=md5Key[i];
		temp[9]=md5Key[i+1];
		temp[10]='\0';
		buf[i/8] = (uint32_t)strtoul(temp,0,0);
	}
	// Processing reversed transform
	buf[0] -= (uint32_t)(0x67452301);
	buf[1] -= (uint32_t)(0xefcdab89);
	buf[2] -= (uint32_t)(0x98badcfe);
	buf[3] -= (uint32_t)(0x10325476);
	buf[1] -= buf[2];
	buf[1] = ROTATE_RIGHT(buf[1],21);
	buf[1] -= (uint32_t)3951481745U;
}
