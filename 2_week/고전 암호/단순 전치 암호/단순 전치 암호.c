#include <stdio.h>

#define BLOCK_SIZE	6	// 블록 크기

void main()
{
	int i, j, size, block_num;
	int key[64] = {3, 5, 1, 6, 4, 2};
	char p_text[64], c_text[64], d_text[64];

	printf("* 평문 입력 : ");	// 평문 입력
	scanf("%s", p_text);

	size = strlen(p_text);		// 평문의 길이를 구함

	// 평문이 블록 크기보다 작으면 임의의 문자를 추가한다 (임의의 문자 -> x)
	if(size % BLOCK_SIZE > 0)
	{
		block_num = strlen(p_text) / BLOCK_SIZE + 1;	// 평문의 길이와 블록 크기를 나누어 블록의 개수를 구함
		
		for(i = strlen(p_text) ; i < block_num*BLOCK_SIZE ; i++)	// 임의의 문자를 블록 길이에 맞게 추가
			p_text[i] = 'x';
	}
	else
		block_num = strlen(p_text) / BLOCK_SIZE;	// 평문의 길이와 블록 크기를 나누어 블록의 개수를 구함

	// 암호화
	for(i=0;i<block_num;i++)
		for(j=0;j<BLOCK_SIZE;j++)
			c_text[i*BLOCK_SIZE+j] = p_text[(key[j]-1)+i*BLOCK_SIZE];	

	printf("* 암호문 : ");
	for(i=0 ; i < block_num*BLOCK_SIZE ; i++)			// 암호문 출력
		printf("%c ", c_text[i]);
	printf("\n");

	// 복호화
	for(i=0;i<block_num;i++)
		for(j=0;j<BLOCK_SIZE;j++)
			d_text[(key[j]-1)+i*BLOCK_SIZE] = c_text[i*BLOCK_SIZE+j];

	printf("* 복호문 : ");
	for(i=0 ; i < size ; i++)			// 복호문 출력
		printf("%c ", d_text[i]);
	printf("\n");
}