#include <stdio.h>

#define BLOCK_SIZE	6	// ��� ũ��

void main()
{
	int i, j, size, block_num;
	int key[64] = {3, 5, 1, 6, 4, 2};
	char p_text[64], c_text[64], d_text[64];

	printf("* �� �Է� : ");	// �� �Է�
	scanf("%s", p_text);

	size = strlen(p_text);		// ���� ���̸� ����

	// ���� ��� ũ�⺸�� ������ ������ ���ڸ� �߰��Ѵ� (������ ���� -> x)
	if(size % BLOCK_SIZE > 0)
	{
		block_num = strlen(p_text) / BLOCK_SIZE + 1;	// ���� ���̿� ��� ũ�⸦ ������ ����� ������ ����
		
		for(i = strlen(p_text) ; i < block_num*BLOCK_SIZE ; i++)	// ������ ���ڸ� ��� ���̿� �°� �߰�
			p_text[i] = 'x';
	}
	else
		block_num = strlen(p_text) / BLOCK_SIZE;	// ���� ���̿� ��� ũ�⸦ ������ ����� ������ ����

	// ��ȣȭ
	for(i=0;i<block_num;i++)
		for(j=0;j<BLOCK_SIZE;j++)
			c_text[i*BLOCK_SIZE+j] = p_text[(key[j]-1)+i*BLOCK_SIZE];	

	printf("* ��ȣ�� : ");
	for(i=0 ; i < block_num*BLOCK_SIZE ; i++)			// ��ȣ�� ���
		printf("%c ", c_text[i]);
	printf("\n");

	// ��ȣȭ
	for(i=0;i<block_num;i++)
		for(j=0;j<BLOCK_SIZE;j++)
			d_text[(key[j]-1)+i*BLOCK_SIZE] = c_text[i*BLOCK_SIZE+j];

	printf("* ��ȣ�� : ");
	for(i=0 ; i < size ; i++)			// ��ȣ�� ���
		printf("%c ", d_text[i]);
	printf("\n");
}