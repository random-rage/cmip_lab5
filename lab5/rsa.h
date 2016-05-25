#pragma once

#include "bignum.h"
#include <stdlib.h>
#include <time.h>

typedef unsigned char uchar;
typedef unsigned long ulong;

struct public_key
{
	mpi e;
	mpi n;
};

struct private_key
{
	mpi d;
	mpi n;
};

// ������� ��� ��������� ������� ��� ��������� ������� �����
int myrand(void *rng_state, unsigned char *output, size_t len);

// ������� ��������� ������ � �������� ������������ � ����������� e
int rsa_generate_keys(t_sint exp, public_key &pub, private_key &priv, size_t keylen);

// ������� ���������� �����
// ���������:
//  src - ������� �����
//  srclen - ����� �������� ������
//  dst - �������� �����
//  dstlen - ����� ��������� ������
//  key - �������� ���� ��� ����������
int rsa_encrypt_block(uchar *src, ulong srclen, uchar *dst, ulong dstlen, public_key key);

// ������� ������������ �����
// ���������:
//  src - ������� �����
//  srclen - ����� �������� ������
//  dst - �������� �����
//  dstlen - ����� ��������� ������
//  key - �������� ���� ��� ������������
int rsa_decrypt_block(uchar *src, ulong srclen, uchar *dst, ulong dstlen, private_key key);

// ������� ���������� �����
// ���������:
//  src - ������� �����
//  srclen - ����� �������� ������
//  dst - �������� �����
//  dstlen - ����� ��������� ������
//  key - �������� ���� ��� ����������
int rsa_sign_block(uchar *src, ulong srclen, uchar *dst, ulong dstlen, private_key key);

// ������� �������� ������� �����
// ���������:
//  src - ������� �����
//  srclen - ����� �������� ������
//  dst - �������� �����
//  dstlen - ����� ��������� ������
//  key - �������� ���� ��� �������� �������
int rsa_check_block(uchar *src, ulong srclen, uchar *dst, ulong dstlen, public_key key);