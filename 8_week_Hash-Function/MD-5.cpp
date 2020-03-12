#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 상수 정의 */

#define HASH_BLOCK	64		// 해쉬 블록 크기 (byte)
#define HASH_DATA	16		// 해쉬 값의 크기 (byte)

// 순환 이동 횟수
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* 매크로 함수 */
#define BTOW(a,b,c,d) ( ((a << 24) + (b << 16) + (c << 8) + d) )	// byte를 word로 변환
#define CIR_SHIFT(X,n) ( ((X) << n) | ((X) >> (32-n)) )				// 32비트 왼쪽 순환 이동

// 부울 함수
#define F(X,y,z) ( ((X)&(y)) | ((~X)&(z)) )
#define G(X,y,z) ( ((X)&(z)) | ((y)&(~(z))) )
#define H(X,y,z) ( ((X)^(y)^(z)) )
#define I(X,y,z) ( (y) ^ ((X)|(~(z))) )

/* 타입 정의 */
typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef unsigned __int64 UINT64;

/* 함수 선언 */
void padding( BYTE* in, UINT64 msg_len );								// MD5 패딩 함수
void MD5_init();													// MD5 초기화 함수
void MD5( FILE* fptr, BYTE* result );									// MD5 해쉬 함수
void MD5_digest( BYTE* in );											// MD5 메시지 digest 함수
void FF( UINT* a, UINT b, UINT c, UINT d, UINT M, int s, UINT T );	// F 함수
void GG( UINT* a, UINT b, UINT c, UINT d, UINT M, int s, UINT T );	// G 함수
void HH( UINT* a, UINT b, UINT c, UINT d, UINT M, int s, UINT T );	// H 함수
void II( UINT* a, UINT b, UINT c, UINT d, UINT M, int s, UINT T );	// I 함수
void make_Bit128( BYTE in[16], UINT a, UINT b, UINT c, UINT d );		// word 단위의 해쉬 값을 byte 단위로 변환하는 함수

/* 전역 변수 */
static UINT init_reg[4];		// 초기 레지스터
static BYTE digest[HASH_DATA];	// 해쉬 값
static int isAddpad = 0;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int main()
{
	int i;
	char file_name[32] = { 0, };
	BYTE result[HASH_DATA] = { 0, };
	FILE* fp;

	// 파일 이름 입력
	printf( "* 파일 이름을 입력하세요 : " );
	scanf( "%s", file_name );

	// 파일 열기
	if( ( fp = fopen( file_name, "rb" ) ) == NULL )
	{
		printf( "* File open failed!\n" );
		exit( 1 );
	}

	MD5( fp, result );		// MD5 해쉬

	// 해쉬 결과 출력
	for( i = 0; i < HASH_DATA; i++ )
		printf( "%3X", result[i] );
	printf( "\n" );

	fclose( fp );

	return 0;
}

// 패딩 함수
void padding( BYTE* in, UINT64 msg_len )
{
	int i;
	BYTE* ptr = (BYTE* )& msg_len;

	// 메시지가 448비트 보다 작은 경우와 448비트 보다 큰 경우로 나누어 처리
	// 448비트보다 큰 경우에는 512비트의 블록을 추가하여 패딩을 수행한다
	if( ( msg_len % HASH_BLOCK ) < 56 )
	{
		in[msg_len % HASH_BLOCK] = 0x80;		// 메시지 다음 비트에 1 추가
		msg_len *= 8;							// 메시지 길이 계산

		for( i = 0; i < 8; i++ )
			in[HASH_BLOCK - i - 1] = *( ptr + ( 7 - i ) );	// 블럭 끝의 64bit에 메시지 길이를 저장 
	}
	else
	{
		in[msg_len % HASH_BLOCK] = 0x80;		// 메시지 다음 비트에 1 추가
		msg_len *= 8;							// 메시지 길이 계산
		isAddpad = 1;
		for( i = 0; i < 8; i++ )
			in[HASH_BLOCK * 2 - i - 1] = *( ptr + ( 7 - i ) );	// 블럭 끝의 64bit에 메시지 길이를 저장
	}
}

// 초기 값 설정
void MD5_init()
{
	init_reg[0] = 0x67452301;
	init_reg[1] = 0xefcdab89;
	init_reg[2] = 0x98badcfe;
	init_reg[3] = 0x10325476;
}

// MD5 해쉬 함수
void MD5( FILE* fptr, BYTE* result )
{
	int i, size = 0;
	BYTE msg[HASH_BLOCK * 2] = { 0, };
	UINT64 f_size = 0;

	MD5_init();		// 초기화

	while( ( size = fread( msg, sizeof( BYTE ), HASH_BLOCK, fptr ) ) )
	{
		f_size += size;				// 파일 크기

		if( size < HASH_BLOCK )
			padding( msg, f_size );	// 마지막 블록에서 패딩 수행

		MD5_digest( msg );			// 메시지 digest 수행
		if( isAddpad ) MD5_digest( msg + HASH_BLOCK );
		memset( msg, 0, HASH_BLOCK * 2 );
	}

	for( i = 0; i < HASH_DATA; i++ )
		result[i] = digest[i];
}

// MD5 메시지 digest 함수
void MD5_digest( BYTE* in )
{
	int i;
	UINT a, b, c, d;
	UINT X[16] = { 0, };

	// 512비트 메시지 블록을 32비트 16개의 워드로 변환한다
	for( i = 0; i < HASH_BLOCK;)
	{
		X[i / 4] = BTOW( in[i + 3], in[i + 2], in[i + 1], in[i] );
		i += 4;
	}

	a = init_reg[0]; b = init_reg[1]; c = init_reg[2]; d = init_reg[3];		// 초기 값 설정

	// MD5 라운드 
	// FF/GG/HH/II (레지스터1, 레지스터2, 레지스터3, 레지스터4, 워드 X, 순환 이동 횟수, 라운드 상수)
	/* Round 1 */
	FF( &a, b, c, d, X[0], S11, 0xd76aa478 ); /* 1 */
	FF( &d, a, b, c, X[1], S12, 0xe8c7b756 ); /* 2 */
	FF( &c, d, a, b, X[2], S13, 0x242070db ); /* 3 */
	FF( &b, c, d, a, X[3], S14, 0xc1bdceee ); /* 4 */
	FF( &a, b, c, d, X[4], S11, 0xf57c0faf ); /* 5 */
	FF( &d, a, b, c, X[5], S12, 0x4787c62a ); /* 6 */
	FF( &c, d, a, b, X[6], S13, 0xa8304613 ); /* 7 */
	FF( &b, c, d, a, X[7], S14, 0xfd469501 ); /* 8 */
	FF( &a, b, c, d, X[8], S11, 0x698098d8 ); /* 9 */
	FF( &d, a, b, c, X[9], S12, 0x8b44f7af ); /* 10 */
	FF( &c, d, a, b, X[10], S13, 0xffff5bb1 ); /* 11 */
	FF( &b, c, d, a, X[11], S14, 0x895cd7be ); /* 12 */
	FF( &a, b, c, d, X[12], S11, 0x6b901122 ); /* 13 */
	FF( &d, a, b, c, X[13], S12, 0xfd987193 ); /* 14 */
	FF( &c, d, a, b, X[14], S13, 0xa679438e ); /* 15 */
	FF( &b, c, d, a, X[15], S14, 0x49b40821 ); /* 16 */

	/* Round 2 */
	GG( &a, b, c, d, X[1], S21, 0xf61e2562 ); /* 17 */
	GG( &d, a, b, c, X[6], S22, 0xc040b340 ); /* 18 */
	GG( &c, d, a, b, X[11], S23, 0x265e5a51 ); /* 19 */
	GG( &b, c, d, a, X[0], S24, 0xe9b6c7aa ); /* 20 */
	GG( &a, b, c, d, X[5], S21, 0xd62f105d ); /* 21 */
	GG( &d, a, b, c, X[10], S22, 0x2441453 ); /* 22 */
	GG( &c, d, a, b, X[15], S23, 0xd8a1e681 ); /* 23 */
	GG( &b, c, d, a, X[4], S24, 0xe7d3fbc8 ); /* 24 */
	GG( &a, b, c, d, X[9], S21, 0x21e1cde6 ); /* 25 */
	GG( &d, a, b, c, X[14], S22, 0xc33707d6 ); /* 26 */
	GG( &c, d, a, b, X[3], S23, 0xf4d50d87 ); /* 27 */
	GG( &b, c, d, a, X[8], S24, 0x455a14ed ); /* 28 */
	GG( &a, b, c, d, X[13], S21, 0xa9e3e905 ); /* 29 */
	GG( &d, a, b, c, X[2], S22, 0xfcefa3f8 ); /* 30 */
	GG( &c, d, a, b, X[7], S23, 0x676f02d9 ); /* 31 */
	GG( &b, c, d, a, X[12], S24, 0x8d2a4c8a ); /* 32 */

	/* Round 3 */
	HH( &a, b, c, d, X[5], S31, 0xfffa3942 ); /* 33 */
	HH( &d, a, b, c, X[8], S32, 0x8771f681 ); /* 34 */
	HH( &c, d, a, b, X[11], S33, 0x6d9d6122 ); /* 35 */
	HH( &b, c, d, a, X[14], S34, 0xfde5380c ); /* 36 */
	HH( &a, b, c, d, X[1], S31, 0xa4beea44 ); /* 37 */
	HH( &d, a, b, c, X[4], S32, 0x4bdecfa9 ); /* 38 */
	HH( &c, d, a, b, X[7], S33, 0xf6bb4b60 ); /* 39 */
	HH( &b, c, d, a, X[10], S34, 0xbebfbc70 ); /* 40 */
	HH( &a, b, c, d, X[13], S31, 0x289b7ec6 ); /* 41 */
	HH( &d, a, b, c, X[0], S32, 0xeaa127fa ); /* 42 */
	HH( &c, d, a, b, X[3], S33, 0xd4ef3085 ); /* 43 */
	HH( &b, c, d, a, X[6], S34, 0x4881d05 ); /* 44 */
	HH( &a, b, c, d, X[9], S31, 0xd9d4d039 ); /* 45 */
	HH( &d, a, b, c, X[12], S32, 0xe6db99e5 ); /* 46 */
	HH( &c, d, a, b, X[15], S33, 0x1fa27cf8 ); /* 47 */
	HH( &b, c, d, a, X[2], S34, 0xc4ac5665 ); /* 48 */

	/* Round 4 */
	II( &a, b, c, d, X[0], S41, 0xf4292244 ); /* 49 */
	II( &d, a, b, c, X[7], S42, 0x432aff97 ); /* 50 */
	II( &c, d, a, b, X[14], S43, 0xab9423a7 ); /* 51 */
	II( &b, c, d, a, X[5], S44, 0xfc93a039 ); /* 52 */
	II( &a, b, c, d, X[12], S41, 0x655b59c3 ); /* 53 */
	II( &d, a, b, c, X[3], S42, 0x8f0ccc92 ); /* 54 */
	II( &c, d, a, b, X[10], S43, 0xffeff47d ); /* 55 */
	II( &b, c, d, a, X[1], S44, 0x85845dd1 ); /* 56 */
	II( &a, b, c, d, X[8], S41, 0x6fa87e4f ); /* 57 */
	II( &d, a, b, c, X[15], S42, 0xfe2ce6e0 ); /* 58 */
	II( &c, d, a, b, X[6], S43, 0xa3014314 ); /* 59 */
	II( &b, c, d, a, X[13], S44, 0x4e0811a1 ); /* 60 */
	II( &a, b, c, d, X[4], S41, 0xf7537e82 ); /* 61 */
	II( &d, a, b, c, X[11], S42, 0xbd3af235 ); /* 62 */
	II( &c, d, a, b, X[2], S43, 0x2ad7d2bb ); /* 63 */
	II( &b, c, d, a, X[9], S44, 0xeb86d391 ); /* HASH_BLOCK */

	// 이전 초기 값과 결과 값을 더하여 다음 블록의 해쉬 과정에서 초기 값으로 사용된다
	init_reg[0] += a;
	init_reg[1] += b;
	init_reg[2] += c;
	init_reg[3] += d;

	// word 단위의 결과 값을 byte로 변환한다
	make_Bit128( digest, init_reg[0], init_reg[1], init_reg[2], init_reg[3] );
}

void FF( UINT* a, UINT b, UINT c, UINT d, UINT M, int s, UINT T )
{
	*a = b + CIR_SHIFT( ( *a + F( b, c, d ) + M + T ), s );
}

void GG( UINT* a, UINT b, UINT c, UINT d, UINT M, int s, UINT T )
{
	*a = b + CIR_SHIFT( ( *a + G( b, c, d ) + M + T ), s );
}

void HH( UINT* a, UINT b, UINT c, UINT d, UINT M, int s, UINT T )
{
	*a = b + CIR_SHIFT( ( *a + H( b, c, d ) + M + T ), s );
}

void II( UINT* a, UINT b, UINT c, UINT d, UINT M, int s, UINT T )
{
	*a = b + CIR_SHIFT( ( *a + I( b, c, d ) + M + T ), s );
}

void make_Bit128( BYTE in[16], UINT a, UINT b, UINT c, UINT d )
{
	int i;

	for( i = 0; i < 16; i++ )
	{
		if( i < 4 )
			in[i] = ( ( a & ( (UINT )0x000000FF << ( i * 8 ) ) ) >> ( i * 8 ) );
		else if( i < 8 )
			in[i] = ( ( b & ( (UINT )0x000000FF << ( ( i % 4 ) * 8 ) ) ) >> ( ( i % 4 ) * 8 ) );
		else if( i < 12 )
			in[i] = ( ( c & ( (UINT )0x000000Ff << ( ( i % 4 ) * 8 ) ) ) >> ( ( i % 4 ) * 8 ) );
		else
			in[i] = ( ( d & ( (UINT )0x000000FF << ( ( i % 4 ) * 8 ) ) ) >> ( ( i % 4 ) * 8 ) );
	}
}
