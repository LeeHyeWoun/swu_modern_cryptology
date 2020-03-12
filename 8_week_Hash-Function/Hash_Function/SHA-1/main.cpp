#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 상수 정의 */
#define HASH_BLOCK	64		// 해쉬 블록 크기 (byte)
#define HASH_DATA	20		// 해쉬 값의 크기 (byte)

// 초기 설정 값
#define H0 0x67452301
#define H1 0xefcdab89
#define H2 0x98badcfe
#define H3 0x10325476
#define H4 0xc3d2e1f0

// 라운드 상수
#define K0 0x5a827999
#define K1 0x6ed9eba1
#define K2 0x8f1bbcdc
#define K3 0xca62c1d6

/* 매크로 함수 */
#define BTOW(a,b,c,d) ( ((a << 24) + (b << 16) + (c << 8) + d) )	// byte에서 word로 변환
#define CIR_SHIFT(x,n) ( ((x) << n) | ((x) >> (32-n)) )				// 32비트 왼쪽 순환 이동

// 기약 논리 함수
#define F1(b,c,d) ( ((b)&(c)) | ((~b)&(d)) )
#define F2(b,c,d) ( ((b) ^ (c) ^ (d)) )
#define F3(b,c,d) ( ((b)&(c)) | ((b)&(d)) | ((c)&(d)) )

/* 타입 정의 */
typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef unsigned __int64 UINT64;

/* 함수 선언 */
void SHA_1_init();												// SHA-1 초기화 함수
void padding( BYTE* in, UINT64 msg_len );							// SHA-1 패딩 함수
void SHA_1( FILE* fptr, BYTE* result );							// SHA-1 해쉬 함수
void SHA_1_digest( BYTE* in );									// SHA-1 메시지 digest 함수
void make_Bit160( UINT a, UINT b, UINT c, UINT d, UINT e );		// word 단위의 데이터를 byte 단위로 변환

/* 전역 변수 */
static UINT init_reg[5] = { 0, };				// 초기 레지스터
static BYTE digest[HASH_DATA] = { 0, };		// 해쉬 값
static int isAddpad = 0;

////////////////////////////////////////////////////////////////////////////////////////////////////

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

	SHA_1( fp, result );		// SHA-1 해쉬

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
		in[msg_len % HASH_BLOCK] = 0x80;
		msg_len *= 8;

		for( i = 0; i < 8; i++ )
			in[HASH_BLOCK - i - 1] = *( ptr + i );
	}
	else
	{
		in[msg_len % HASH_BLOCK] = 0x80;
		msg_len *= 8;
		isAddpad = 1;
		for( i = 0; i < 8; i++ )
			in[HASH_BLOCK * 2 - i - 1] = *( ptr + i );
	}
}

// 초기 값 설정
void SHA_1_init()
{
	init_reg[0] = H0;
	init_reg[1] = H1;
	init_reg[2] = H2;
	init_reg[3] = H3;
	init_reg[4] = H4;
}

// SHA-1 해쉬 함수
void SHA_1( FILE* fptr, BYTE* result )
{
	int i, size = 0;
	BYTE msg[HASH_BLOCK * 2] = { 0, };
	UINT64 f_size = 0;

	SHA_1_init();		// 초기화

	while( ( size = fread( msg, sizeof( BYTE ), HASH_BLOCK, fptr ) ) )
	{
		f_size += size;				// 파일 크기

		if( size < HASH_BLOCK )
			padding( msg, f_size );	// 마지막 블록에서 패딩 수행

		SHA_1_digest( msg );			// 메시지 digest 수행
		if( isAddpad ) SHA_1_digest( msg + HASH_BLOCK );
		memset( msg, 0, HASH_BLOCK * 2 );
	}

	for( i = 0; i < HASH_DATA; i++ )
		result[i] = digest[i];
}

// SHA-1 메시지 digest 함수
void SHA_1_digest( BYTE* in )
{
	int i;
	UINT M[16] = { 0, };
	UINT W[80] = { 0, };
	UINT reg[5];

	reg[0] = init_reg[0]; reg[1] = init_reg[1]; reg[2] = init_reg[2]; reg[3] = init_reg[3]; reg[4] = init_reg[4];

	// 512비트 메시지 블록을 32비트 16개의 워드로 변환한다
	for( i = 0; i < HASH_BLOCK;)
	{
		M[i / 4] = BTOW( in[i], in[i + 1], in[i + 2], in[i + 3] );
		i += 4;
	}

	for( i = 0; i < 80; i++ )
		if( i < 16 )
			W[i] = M[i];
		else
			W[i] = CIR_SHIFT( ( W[i - 16] ^ W[i - 14] ^ W[i - 8] ^ W[i - 3] ), 1 );

	// SHA-1 라운드
	for( i = 0; i < 80; i++ )
	{
		UINT temp;
		// Round1
		if( i < 20 )
		{
			temp = CIR_SHIFT( reg[0], 5 ) + F1( reg[1], reg[2], reg[3] ) + reg[4] + W[i] + K0;
			reg[4] = reg[3];
			reg[3] = reg[2];
			reg[2] = CIR_SHIFT( reg[1], 30 );
			reg[1] = reg[0];
			reg[0] = temp;
			//printf("%x %x %x %x %x\n",reg[0],reg[1],reg[2],reg[3],reg[4]);
		}
		// Round2
		else if( i < 40 )
		{
			temp = CIR_SHIFT( reg[0], 5 ) + F2( reg[1], reg[2], reg[3] ) + reg[4] + W[i] + K1;
			reg[4] = reg[3];
			reg[3] = reg[2];
			reg[2] = CIR_SHIFT( reg[1], 30 );
			reg[1] = reg[0];
			reg[0] = temp;
			//printf("%x %x %x %x %x\n",reg[0],reg[1],reg[2],reg[3],reg[4]);
		}
		// Round3
		else if( i < 60 )
		{
			temp = CIR_SHIFT( reg[0], 5 ) + F3( reg[1], reg[2], reg[3] ) + reg[4] + W[i] + K2;
			reg[4] = reg[3];
			reg[3] = reg[2];
			reg[2] = CIR_SHIFT( reg[1], 30 );
			reg[1] = reg[0];
			reg[0] = temp;
			//printf("%x %x %x %x %x\n",reg[0],reg[1],reg[2],reg[3],reg[4]);
		}
		// Round4
		else
		{
			temp = CIR_SHIFT( reg[0], 5 ) + F2( reg[1], reg[2], reg[3] ) + reg[4] + W[i] + K3;
			reg[4] = reg[3];
			reg[3] = reg[2];
			reg[2] = CIR_SHIFT( reg[1], 30 );
			reg[1] = reg[0];
			reg[0] = temp;
			//printf("%x %x %x %x %x\n",reg[0],reg[1],reg[2],reg[3],reg[4]);
		}
	}

	// 다음 블록을 해쉬 하는데 사용할 초기 값을 설정
	init_reg[0] += reg[0];
	init_reg[1] += reg[1];
	init_reg[2] += reg[2];
	init_reg[3] += reg[3];
	init_reg[4] += reg[4];

	// word 단위의 결과 값을 byte 단위로 저장한다
	make_Bit160( init_reg[0], init_reg[1], init_reg[2], init_reg[3], init_reg[4] );
}

// word 단위의 값을 byte 단위로 변환
void make_Bit160( UINT a, UINT b, UINT c, UINT d, UINT e )
{
	int i;
	BYTE* p;

	for( i = 0; i < 20; i++ )
	{
		if( i < 4 )
		{
			p = (BYTE* )& a;
			digest[i] = p[3 - i];
		}
		else if( i < 8 )
		{
			p = (BYTE* )& b;
			digest[i] = p[7 - i];
		}
		else if( i < 12 )
		{
			p = (BYTE* )& c;
			digest[i] = p[11 - i];
		}
		else if( i < 16 )
		{
			p = (BYTE* )& d;
			digest[i] = p[15 - i];
		}
		else
		{
			p = (BYTE* )& e;
			digest[i] = p[19 - i];
		}
	}
}
