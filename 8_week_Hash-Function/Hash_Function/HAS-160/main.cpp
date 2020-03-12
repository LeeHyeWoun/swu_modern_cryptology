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
#define K0 0x00000000
#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc

/* 매크로 함수 */
#define BTOW(a,b,c,d) ( ((a << 24) + (b << 16) + (c << 8) + d) )	// byte에서 word로 변환
#define CIR_SHIFT(x,n) ( ((x) << n) | ((x) >> (32-n)) )				// 32비트 왼쪽 순환 이동

// 기약 논리 함수
#define F1(x,y,z) ( ((x)&(y)) | ((~x)&(z)) )
#define F2(x,y,z) ( ((x) ^ (y) ^ (z)) )
#define F3(x,y,z) ( (y ^ (x | (~z))) )

/* 타입 정의 */
typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef unsigned __int64 UINT64;

/* 함수 선언 */
void HAS_160_init();										// HAS-160 초기화 함수
void padding( BYTE* in, UINT64 msg_len );						// HAS-160 패딩 함수
void HAS_160( FILE* fptr, BYTE* result );						// HAS-160 해쉬 함수
void HAS_160_digest( BYTE* in );								// HAS-160 메시지 digest 함수
void make_Bit160( UINT a, UINT b, UINT c, UINT d, UINT e );	// word 단위의 데이터를 byte 단위로 변환

/* 전역 변수 */
static UINT init_reg[5] = { 0, };			// 초기 레지스터
static BYTE digest[HASH_DATA] = { 0, };	// 해쉬 값
static int isAddpad = 0;
////////////////////////////////////////////////////////////////////////////////////////////////////

void main()
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

	HAS_160( fp, result );		// HAS-160 해쉬

	// 해쉬 결과 출력
	for( i = 0; i < HASH_DATA; i++ )
		printf( "%3X", result[i] );
	printf( "\n" );

	fclose( fp );
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

// HAS-160 초기화 함수
void HAS_160_init()
{
	init_reg[0] = H0;
	init_reg[1] = H1;
	init_reg[2] = H2;
	init_reg[3] = H3;
	init_reg[4] = H4;
}

// HAS-160 해쉬 함수
void HAS_160( FILE* fptr, BYTE* result )
{
	int i, size = 0;
	BYTE msg[HASH_BLOCK * 2] = { 0, };
	UINT64 f_size = 0;

	HAS_160_init();		// 초기화

	while( ( size = fread( msg, sizeof( BYTE ), HASH_BLOCK, fptr ) ) )
	{
		f_size += size;				// 파일 크기

		if( size < HASH_BLOCK )
			padding( msg, f_size );	// 마지막 블록에서 패딩 수행

		HAS_160_digest( msg );			// 메시지 digest 수행
		if( isAddpad ) HAS_160_digest( msg + HASH_BLOCK );
		memset( msg, 0, HASH_BLOCK * 2 );
	}

	for( i = 0; i < HASH_DATA; i++ )
		result[i] = digest[i];
}

static BYTE l[80] =
{
	18, 0, 1, 2, 3, 19, 4, 5, 6, 7, 16, 8 ,9, 10, 11, 17, 12, 13, 14, 15,
	18, 3, 6, 9, 12, 19, 15, 2, 5, 8, 16, 11, 14, 1, 4, 17, 7, 10, 13, 0,
	18, 12, 5, 14, 7, 19, 0, 9, 2, 11, 16, 4, 13, 6, 15, 17, 8, 1, 10, 3,
	18, 7, 2, 13, 8, 19, 3, 14, 9, 4, 16, 15, 10, 5, 0, 17, 11, 6, 1, 12
};

// 순환 이동 횟수
static BYTE S1[20] =
{
	5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13
};

static BYTE S2[4] = { 10, 17, 25, 30 };

// HAS-160 메시지 digest
void HAS_160_digest( BYTE* in )
{
	int i, j, k;
	UINT X[20] = { 0, };
	UINT A, B, C, D, E, T;

	// 초기 값 설정
	A = init_reg[0];
	B = init_reg[1];
	C = init_reg[2];
	D = init_reg[3];
	E = init_reg[4];

	// 512비트 메시지 블록을 32비트 16개의 워드로 변환한다
	for( i = 0; i < HASH_BLOCK;)
	{
		X[i / 4] = BTOW( in[i + 3], in[i + 2], in[i + 1], in[i] );
		i += 4;
	}

	// HAS-160 라운드
	for( i = 0; i < 4; i++ )
	{
		j = i * 20;

		X[16] = X[l[j + 1]] ^ X[l[j + 2]] ^ X[l[j + 3]] ^ X[l[j + 4]];
		X[17] = X[l[j + 6]] ^ X[l[j + 7]] ^ X[l[j + 8]] ^ X[l[j + 9]];
		X[18] = X[l[j + 11]] ^ X[l[j + 12]] ^ X[l[j + 13]] ^ X[l[j + 14]];
		X[19] = X[l[j + 16]] ^ X[l[j + 17]] ^ X[l[j + 18]] ^ X[l[j + 19]];

		//printf("%x %x %x %x\n", X[16], X[17], X[18], X[19]);

		for( k = 0; k < 20; k++ )
		{
			j = 20 * i + k;

			if( i == 0 )
			{
				T = CIR_SHIFT( A, S1[j % 20] ) + F1( B, C, D ) + E + X[l[j]] + K0;
			}
			else if( i == 1 )
			{
				T = CIR_SHIFT( A, S1[j % 20] ) + F2( B, C, D ) + E + X[l[j]] + K1;
			}
			else if( i == 2 )
			{
				T = CIR_SHIFT( A, S1[j % 20] ) + F3( B, C, D ) + E + X[l[j]] + K2;
			}
			else
			{
				T = CIR_SHIFT( A, S1[j % 20] ) + F2( B, C, D ) + E + X[l[j]] + K3;
			}

			E = D;
			D = C;
			C = CIR_SHIFT( B, S2[j / 20] );
			B = A;
			A = T;

			//printf("%x %x %x %x %x\n", A, B, C, D, E);
		}
	}

	// 다음 블록을 해쉬 하는데 사용할 초기 값을 설정
	init_reg[0] += A;
	init_reg[1] += B;
	init_reg[2] += C;
	init_reg[3] += D;
	init_reg[4] += E;

	// word 단위의 결과 값을 byte 단위로 저장한다
	make_Bit160( init_reg[0], init_reg[1], init_reg[2], init_reg[3], init_reg[4] );
}

void make_Bit160( UINT a, UINT b, UINT c, UINT d, UINT e )
{
	int i;
	BYTE* p;

	for( i = 0; i < 20; i++ )
	{
		if( i < 4 )
		{
			p = (BYTE* )& a;
			digest[i] = p[i];
		}
		else if( i < 8 )
		{
			p = (BYTE* )& b;
			digest[i] = p[i % 4];
		}
		else if( i < 12 )
		{
			p = (BYTE* )& c;
			digest[i] = p[i % 4];
		}
		else if( i < 16 )
		{
			p = (BYTE* )& d;
			digest[i] = p[i % 4];
		}
		else
		{
			p = (BYTE* )& e;
			digest[i] = p[i % 4];
		}
	}
}
