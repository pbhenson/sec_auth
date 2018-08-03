/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Modified by Jeremy Allison 1995.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "byteorder.h"


#define uchar unsigned char
#define uint8 unsigned char
#define int16 short
#define uint16 unsigned short
#define int32 int
#define uint32 unsigned int

static void mdfour(unsigned char *out, unsigned char *in, int n);
void E_P16(unsigned char *p14,unsigned char *p16);

/*******************************************************************
 convert a string to upper case
********************************************************************/
static void strupper(char *s)
{
    while (*s)
      {
	if (islower(*s))
	  *s = toupper(*s);
	s++;
      }
}

/*******************************************************************
 safe string copy into a known length string. maxlength does not
 include the terminating zero.
********************************************************************/
static char *safe_strcpy(char *dest,const char *src, int maxlength)
{
  int len;
  
  if (!dest)
    return 0;
  
  if (!src) {
    *dest = 0;
    return dest;
  }
  
  len = strlen(src);
  
  if (len > maxlength)
    len = maxlength;
  
  memcpy(dest, src, len);
  dest[len] = 0;
  return dest;
}


/* Routines for Windows NT MD4 Hash functions. */
static int _my_wcslen(int16 *str)
{
	int len = 0;
	while(*str++ != 0)
		len++;
	return len;
}

/*
 * Convert a string into an NT UNICODE string.
 * Note that regardless of processor type 
 * this must be in intel (little-endian)
 * format.
 */
 
static int _my_mbstowcs(int16 *dst, uchar *src, int len)
{
	int i;
	int16 val;
 
	for(i = 0; i < len; i++) {
		val = *src;
		SSVAL(dst,0,val);
		dst++;
		src++;
		if(val == 0)
			break;
	}
	return i;
}

/* 
 * Creates the MD4 Hash of the users password in NT UNICODE.
 */
 
static void E_md4hash(uchar *passwd, uchar *p16)
{
	int len;
	int16 wpwd[129];
	
	/* Password cannot be longer than 128 characters */
	len = strlen((char *)passwd);
	if(len > 128)
		len = 128;
	/* Password must be converted to NT unicode */
	_my_mbstowcs(wpwd, passwd, len);
	wpwd[len] = 0; /* Ensure string is null terminated */
	/* Calculate length in bytes */
	len = _my_wcslen(wpwd) * sizeof(int16);

	mdfour(p16, (unsigned char *)wpwd, len);
}

/* Does both the NT and LM owfs of a user's password */
void samba_nt_lm_owf_gen(char *pwd, uchar nt_p16[16], uchar p16[16])
{
	char passwd[130];

	memset(passwd,'\0',130);
	safe_strcpy( passwd, pwd, sizeof(passwd)-1);

	/* Calculate the MD4 hash (NT compatible) of the password */
	memset(nt_p16, '\0', 16);
	E_md4hash((uchar *)passwd, nt_p16);

	/* Mangle the passwords into Lanman format */
	passwd[14] = '\0';
	strupper(passwd);

	/* Calculate the SMB (lanman) hash functions of the password */

	memset(p16, '\0', 16);
	E_P16((uchar *) passwd, (uchar *)p16);

	/* clear out local copy of user's password (just being paranoid). */
	memset(passwd, '\0', sizeof(passwd));
}

/* 
   Unix SMB/Netbios implementation.
   Version 1.9.

   a partial implementation of DES designed for use in the 
   SMB authentication protocol

   Copyright (C) Andrew Tridgell 1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* NOTES: 

   This code makes no attempt to be fast! In fact, it is a very
   slow implementation 

   This code is NOT a complete DES implementation. It implements only
   the minimum necessary for SMB authentication, as used by all SMB
   products (including every copy of Microsoft Windows95 ever sold)

   In particular, it can only do a unchained forward DES pass. This
   means it is not possible to use this code for encryption/decryption
   of data, instead it is only useful as a "hash" algorithm.

   There is no entry point into this code that allows normal DES operation.

   I believe this means that this code does not come under ITAR
   regulations but this is NOT a legal opinion. If you are concerned
   about the applicability of ITAR regulations to this code then you
   should confirm it for yourself (and maybe let me know if you come
   up with a different answer to the one above)
*/

static uchar perm1[56] = {57, 49, 41, 33, 25, 17,  9,
			 1, 58, 50, 42, 34, 26, 18,
			10,  2, 59, 51, 43, 35, 27,
			19, 11,  3, 60, 52, 44, 36,
			63, 55, 47, 39, 31, 23, 15,
			 7, 62, 54, 46, 38, 30, 22,
			14,  6, 61, 53, 45, 37, 29,
			21, 13,  5, 28, 20, 12,  4};

static uchar perm2[48] = {14, 17, 11, 24,  1,  5,
                         3, 28, 15,  6, 21, 10,
                        23, 19, 12,  4, 26,  8,
                        16,  7, 27, 20, 13,  2,
                        41, 52, 31, 37, 47, 55,
                        30, 40, 51, 45, 33, 48,
                        44, 49, 39, 56, 34, 53,
                        46, 42, 50, 36, 29, 32};

static uchar perm3[64] = {58, 50, 42, 34, 26, 18, 10,  2,
			60, 52, 44, 36, 28, 20, 12,  4,
			62, 54, 46, 38, 30, 22, 14,  6,
			64, 56, 48, 40, 32, 24, 16,  8,
			57, 49, 41, 33, 25, 17,  9,  1,
			59, 51, 43, 35, 27, 19, 11,  3,
			61, 53, 45, 37, 29, 21, 13,  5,
			63, 55, 47, 39, 31, 23, 15,  7};

static uchar perm4[48] = {   32,  1,  2,  3,  4,  5,
                            4,  5,  6,  7,  8,  9,
                            8,  9, 10, 11, 12, 13,
                           12, 13, 14, 15, 16, 17,
                           16, 17, 18, 19, 20, 21,
                           20, 21, 22, 23, 24, 25,
                           24, 25, 26, 27, 28, 29,
                           28, 29, 30, 31, 32,  1};

static uchar perm5[32] = {      16,  7, 20, 21,
                              29, 12, 28, 17,
                               1, 15, 23, 26,
                               5, 18, 31, 10,
                               2,  8, 24, 14,
                              32, 27,  3,  9,
                              19, 13, 30,  6,
                              22, 11,  4, 25};


static uchar perm6[64] ={ 40,  8, 48, 16, 56, 24, 64, 32,
                        39,  7, 47, 15, 55, 23, 63, 31,
                        38,  6, 46, 14, 54, 22, 62, 30,
                        37,  5, 45, 13, 53, 21, 61, 29,
                        36,  4, 44, 12, 52, 20, 60, 28,
                        35,  3, 43, 11, 51, 19, 59, 27,
                        34,  2, 42, 10, 50, 18, 58, 26,
                        33,  1, 41,  9, 49, 17, 57, 25};


static uchar sc[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

static uchar sbox[8][4][16] = {
	{{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
	 {0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
	 {4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
	 {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}},

	{{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
	 {3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
	 {0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
	 {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}},

	{{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
	 {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
	 {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
	 {1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}},

	{{7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
	 {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
	 {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
	 {3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}},

	{{2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
	 {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
	 {4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
	 {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}},

	{{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
	 {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
	 {9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
	 {4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}},

	{{4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
	 {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
	 {1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
	 {6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}},

	{{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
	 {1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
	 {7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
	 {2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}}};

static void des_permute(char *out, char *in, uchar *p, int n)
{
	int i;
	for (i=0;i<n;i++)
		out[i] = in[p[i]-1];
}

static void des_lshift(char *d, int count, int n)
{
	char out[64];
	int i;
	for (i=0;i<n;i++)
		out[i] = d[(i+count)%n];
	for (i=0;i<n;i++)
		d[i] = out[i];
}

static void des_concat(char *out, char *in1, char *in2, int l1, int l2)
{
	while (l1--)
		*out++ = *in1++;
	while (l2--)
		*out++ = *in2++;
}

static void des_xor(char *out, char *in1, char *in2, int n)
{
	int i;
	for (i=0;i<n;i++)
		out[i] = in1[i] ^ in2[i];
}

static void dohash(char *out, char *in, char *key, int forw)
{
	int i, j, k;
	char pk1[56];
	char c[28];
	char d[28];
	char cd[56];
	char ki[16][48];
	char pd1[64];
	char l[32], r[32];
	char rl[64];

	des_permute(pk1, key, perm1, 56);

	for (i=0;i<28;i++)
		c[i] = pk1[i];
	for (i=0;i<28;i++)
		d[i] = pk1[i+28];

	for (i=0;i<16;i++) {
		des_lshift(c, sc[i], 28);
		des_lshift(d, sc[i], 28);

		des_concat(cd, c, d, 28, 28); 
		des_permute(ki[i], cd, perm2, 48); 
	}

	des_permute(pd1, in, perm3, 64);

	for (j=0;j<32;j++) {
		l[j] = pd1[j];
		r[j] = pd1[j+32];
	}

	for (i=0;i<16;i++) {
		char er[48];
		char erk[48];
		char b[8][6];
		char cb[32];
		char pcb[32];
		char r2[32];

		des_permute(er, r, perm4, 48);

		des_xor(erk, er, ki[forw ? i : 15 - i], 48);

		for (j=0;j<8;j++)
			for (k=0;k<6;k++)
				b[j][k] = erk[j*6 + k];

		for (j=0;j<8;j++) {
			int m, n;
			m = (b[j][0]<<1) | b[j][5];

			n = (b[j][1]<<3) | (b[j][2]<<2) | (b[j][3]<<1) | b[j][4]; 

			for (k=0;k<4;k++) 
				b[j][k] = (sbox[j][m][n] & (1<<(3-k)))?1:0; 
		}

		for (j=0;j<8;j++)
			for (k=0;k<4;k++)
				cb[j*4+k] = b[j][k];
		des_permute(pcb, cb, perm5, 32);

		des_xor(r2, l, pcb, 32);

		for (j=0;j<32;j++)
			l[j] = r[j];

		for (j=0;j<32;j++)
			r[j] = r2[j];
	}

	des_concat(rl, r, l, 32, 32);

	des_permute(out, rl, perm6, 64);
}

static void str_to_key(unsigned char *str,unsigned char *key)
{
	int i;

	key[0] = str[0]>>1;
	key[1] = ((str[0]&0x01)<<6) | (str[1]>>2);
	key[2] = ((str[1]&0x03)<<5) | (str[2]>>3);
	key[3] = ((str[2]&0x07)<<4) | (str[3]>>4);
	key[4] = ((str[3]&0x0F)<<3) | (str[4]>>5);
	key[5] = ((str[4]&0x1F)<<2) | (str[5]>>6);
	key[6] = ((str[5]&0x3F)<<1) | (str[6]>>7);
	key[7] = str[6]&0x7F;
	for (i=0;i<8;i++) {
		key[i] = (key[i]<<1);
	}
}


static void smbhash(unsigned char *out, unsigned char *in, unsigned char *key, int forw)
{
	int i;
	char outb[64];
	char inb[64];
	char keyb[64];
	unsigned char key2[8];

	str_to_key(key, key2);

	for (i=0;i<64;i++) {
		inb[i] = (in[i/8] & (1<<(7-(i%8)))) ? 1 : 0;
		keyb[i] = (key2[i/8] & (1<<(7-(i%8)))) ? 1 : 0;
		outb[i] = 0;
	}

	dohash(outb, inb, keyb, forw);

	for (i=0;i<8;i++) {
		out[i] = 0;
	}

	for (i=0;i<64;i++) {
		if (outb[i])
			out[i/8] |= (1<<(7-(i%8)));
	}
}

void E_P16(unsigned char *p14,unsigned char *p16)
{
	unsigned char sp8[8] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
	smbhash(p16, sp8, p14, 1);
	smbhash(p16+8, sp8, p14+7, 1);
}

void samba_E_P24(unsigned char *p21, unsigned char *c8, unsigned char *p24)
{
	smbhash(p24, c8, p21, 1);
	smbhash(p24+8, c8, p21+7, 1);
	smbhash(p24+16, c8, p21+14, 1);
}

/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   a implementation of MD4 designed for use in the SMB authentication protocol
   Copyright (C) Andrew Tridgell 1997-1998.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* NOTE: This code makes no attempt to be fast! 

   It assumes that a int is at least 32 bits long
*/

static uint32 A, B, C, D;

static uint32 F(uint32 X, uint32 Y, uint32 Z)
{
	return (X&Y) | ((~X)&Z);
}

static uint32 G(uint32 X, uint32 Y, uint32 Z)
{
	return (X&Y) | (X&Z) | (Y&Z); 
}

static uint32 H(uint32 X, uint32 Y, uint32 Z)
{
	return X^Y^Z;
}

static uint32 lshift(uint32 x, int s)
{
	x &= 0xFFFFFFFF;
	return ((x<<s)&0xFFFFFFFF) | (x>>(32-s));
}

#define ROUND1(a,b,c,d,k,s) a = lshift(a + F(b,c,d) + X[k], s)
#define ROUND2(a,b,c,d,k,s) a = lshift(a + G(b,c,d) + X[k] + (uint32)0x5A827999,s)
#define ROUND3(a,b,c,d,k,s) a = lshift(a + H(b,c,d) + X[k] + (uint32)0x6ED9EBA1,s)

/* this applies md4 to 64 byte chunks */
static void mdfour64(uint32 *M)
{
	int j;
	uint32 AA, BB, CC, DD;
	uint32 X[16];

	for (j=0;j<16;j++)
		X[j] = M[j];

	AA = A; BB = B; CC = C; DD = D;

        ROUND1(A,B,C,D,  0,  3);  ROUND1(D,A,B,C,  1,  7);  
	ROUND1(C,D,A,B,  2, 11);  ROUND1(B,C,D,A,  3, 19);
        ROUND1(A,B,C,D,  4,  3);  ROUND1(D,A,B,C,  5,  7);  
	ROUND1(C,D,A,B,  6, 11);  ROUND1(B,C,D,A,  7, 19);
        ROUND1(A,B,C,D,  8,  3);  ROUND1(D,A,B,C,  9,  7);  
	ROUND1(C,D,A,B, 10, 11);  ROUND1(B,C,D,A, 11, 19);
        ROUND1(A,B,C,D, 12,  3);  ROUND1(D,A,B,C, 13,  7);  
	ROUND1(C,D,A,B, 14, 11);  ROUND1(B,C,D,A, 15, 19);	

        ROUND2(A,B,C,D,  0,  3);  ROUND2(D,A,B,C,  4,  5);  
	ROUND2(C,D,A,B,  8,  9);  ROUND2(B,C,D,A, 12, 13);
        ROUND2(A,B,C,D,  1,  3);  ROUND2(D,A,B,C,  5,  5);  
	ROUND2(C,D,A,B,  9,  9);  ROUND2(B,C,D,A, 13, 13);
        ROUND2(A,B,C,D,  2,  3);  ROUND2(D,A,B,C,  6,  5);  
	ROUND2(C,D,A,B, 10,  9);  ROUND2(B,C,D,A, 14, 13);
        ROUND2(A,B,C,D,  3,  3);  ROUND2(D,A,B,C,  7,  5);  
	ROUND2(C,D,A,B, 11,  9);  ROUND2(B,C,D,A, 15, 13);

	ROUND3(A,B,C,D,  0,  3);  ROUND3(D,A,B,C,  8,  9);  
	ROUND3(C,D,A,B,  4, 11);  ROUND3(B,C,D,A, 12, 15);
        ROUND3(A,B,C,D,  2,  3);  ROUND3(D,A,B,C, 10,  9);  
	ROUND3(C,D,A,B,  6, 11);  ROUND3(B,C,D,A, 14, 15);
        ROUND3(A,B,C,D,  1,  3);  ROUND3(D,A,B,C,  9,  9);  
	ROUND3(C,D,A,B,  5, 11);  ROUND3(B,C,D,A, 13, 15);
        ROUND3(A,B,C,D,  3,  3);  ROUND3(D,A,B,C, 11,  9);  
	ROUND3(C,D,A,B,  7, 11);  ROUND3(B,C,D,A, 15, 15);

	A += AA; B += BB; C += CC; D += DD;
	
	A &= 0xFFFFFFFF; B &= 0xFFFFFFFF;
	C &= 0xFFFFFFFF; D &= 0xFFFFFFFF;

	for (j=0;j<16;j++)
		X[j] = 0;
}

static void copy64(uint32 *M, unsigned char *in)
{
	int i;

	for (i=0;i<16;i++)
		M[i] = (in[i*4+3]<<24) | (in[i*4+2]<<16) |
			(in[i*4+1]<<8) | (in[i*4+0]<<0);
}

static void copy4(unsigned char *out,uint32 x)
{
	out[0] = x&0xFF;
	out[1] = (x>>8)&0xFF;
	out[2] = (x>>16)&0xFF;
	out[3] = (x>>24)&0xFF;
}

/* produce a md4 message digest from data of length n bytes */
static void mdfour(unsigned char *out, unsigned char *in, int n)
{
	unsigned char buf[128];
	uint32 M[16];
	uint32 b = n * 8;
	int i;

	A = 0x67452301;
	B = 0xefcdab89;
	C = 0x98badcfe;
	D = 0x10325476;

	while (n > 64) {
		copy64(M, in);
		mdfour64(M);
		in += 64;
		n -= 64;
	}

	for (i=0;i<128;i++)
		buf[i] = 0;
	memcpy(buf, in, n);
	buf[n] = 0x80;
	
	if (n <= 55) {
		copy4(buf+56, b);
		copy64(M, buf);
		mdfour64(M);
	} else {
		copy4(buf+120, b); 
		copy64(M, buf);
		mdfour64(M);
		copy64(M, buf+64);
		mdfour64(M);
	}

	for (i=0;i<128;i++)
		buf[i] = 0;
	copy64(M, buf);

	copy4(out, A);
	copy4(out+4, B);
	copy4(out+8, C);
	copy4(out+12, D);

	A = B = C = D = 0;
}
