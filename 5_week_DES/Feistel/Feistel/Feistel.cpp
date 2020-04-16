//////////////////////////////////////////////
//	블록 길이가 6인 2라운드 Feistel 암호    //
//////////////////////////////////////////////

#include <stdio.h>

/* 상수 정의 */
#define BLOCK_SIZE		6	// 블록 크기(bit)
#define ROUND_NUM		2	// 라운드 수

/* 함수 선언 */
char F1( char input );		// F 함수 1
char F2( char input );		// F 함수 2
char Feistel_Enc( char in );	// Feistel 암호화 함수
char Feistel_Dec( char in );	// Feistel 복호화 함수

////////////////////////////////////////////////////////////////////////////////////////

void main()
{
	char p_bit = 0x2B;
	char c_bit, d_bit;
	int temp = 0, i = 0;

	// 평문 출력
	printf( "* 평문 : " );
	for( i = BLOCK_SIZE - 1; i >= 0; i-- )	// 최하위 한 비트씩 추출
	{
		temp = ( p_bit >> i ) & 0x01;
		printf( "%d ", temp );
	}
	printf( "\n" );

	c_bit = Feistel_Enc( p_bit );		// Feistel 암호화

	// 암호문 출력
	printf( "* 암호문 : " );
	for( i = BLOCK_SIZE - 1; i >= 0; i-- )	// 최하위 한 비트씩 추출
	{
		temp = ( c_bit >> i ) & 0x01;
		printf( "%d ", temp );
	}
	printf( "\n" );

	d_bit = Feistel_Dec( c_bit );		// Feistel 복호화

	// 복호문 출력
	printf( "* 복호문 : " );
	for( i = BLOCK_SIZE - 1; i >= 0; i-- )	// 최하위 한 비트씩 추출
	{
		temp = ( d_bit >> i ) & 0x01;
		printf( "%d ", temp );
	}
	printf( "\n" );
}

// Feistel 암호화
char Feistel_Enc( char in )
{
	int i;
	char temp, left, right;

	left = ( in >> 3 ) & 0x07;	// 왼쪽 3bit
	right = in & 0x07;			// 오른쪽 3bit

	for( i = 0; i < ROUND_NUM; i++ )
	{
		if( i == 0 )
			left = left ^ F1( right );	// 1라운드
		else if( i == 1 )
			left = left ^ F2( right );	// 2라운드

		// 마지막 라운드는 스왑을 하지 않음
		if( i != ROUND_NUM - 1 )
		{
			temp = left;
			left = right;
			right = temp;
		}
	}

	return ( left << 3 ) | right;		// 3bit left와 right를 합쳐 6bit를 만듬
}

// Feistel 복호화
char Feistel_Dec( char in )
{
	int i;
	char temp, left, right;

	left = ( in >> 3 ) & 0x07;	// 왼쪽 3bit
	right = in & 0x07;			// 오른쪽 3bit

	for( i = 0; i < ROUND_NUM; i++ )
	{
		// 복호화에서는 키가 역순으로 적용됨
		if( i == 0 )
			left = left ^ F2( right );	// 1라운드
		else if( i == 1 )
			left = left ^ F1( right );	// 2라운드

		// 마지막 라운드는 스왑을 하지 않음
		if( i != ROUND_NUM - 1 )
		{
			temp = left;
			left = right;
			right = temp;
		}
	}

	return ( left << 3 ) | right;		// 3bit left와 right를 합쳐 6bit를 만듬
}

// F 함수 1
char F1( char input )
{
	if( input == 0x00 )
		return 0x05;
	else if( input == 0x01 )
		return 0x02;
	else if( input == 0x02 )
		return 0x03;
	else if( input == 0x03 )
		return 0x06;
	else if( input == 0x04 )
		return 0x04;
	else if( input == 0x05 )
		return 0x01;
	else if( input == 0x06 )
		return 0x07;
	else if( input == 0x07 )
		return 0x00;

	return 0;
}

// F 함수 2
char F2( char input )
{
	if( input == 0x00 )
		return 0x04;
	else if( input == 0x01 )
		return 0x00;
	else if( input == 0x02 )
		return 0x03;
	else if( input == 0x03 )
		return 0x07;
	else if( input == 0x04 )
		return 0x06;
	else if( input == 0x05 )
		return 0x05;
	else if( input == 0x06 )
		return 0x01;
	else if( input == 0x07 )
		return 0x02;

	return 0;
}