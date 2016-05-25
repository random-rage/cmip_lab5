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

// Функция для получения рандома для генерации простых чисел
int myrand(void *rng_state, unsigned char *output, size_t len);

// Функция генерации ключей с заданной разрядностью и показателем e
int rsa_generate_keys(t_sint exp, public_key &pub, private_key &priv, size_t keylen);

// Функция шифрования блока
// Параметры:
//  src - входной буфер
//  srclen - длина входного буфера
//  dst - выходной буфер
//  dstlen - длина выходного буфера
//  key - открытый ключ для шифрования
int rsa_encrypt_block(uchar *src, ulong srclen, uchar *dst, ulong dstlen, public_key key);

// Функция дешифрования блока
// Параметры:
//  src - входной буфер
//  srclen - длина входного буфера
//  dst - выходной буфер
//  dstlen - длина выходного буфера
//  key - закрытый ключ для дешифрования
int rsa_decrypt_block(uchar *src, ulong srclen, uchar *dst, ulong dstlen, private_key key);

// Функция подписания блока
// Параметры:
//  src - входной буфер
//  srclen - длина входного буфера
//  dst - выходной буфер
//  dstlen - длина выходного буфера
//  key - закрытый ключ для подписания
int rsa_sign_block(uchar *src, ulong srclen, uchar *dst, ulong dstlen, private_key key);

// Функция проверки подписи блока
// Параметры:
//  src - входной буфер
//  srclen - длина входного буфера
//  dst - выходной буфер
//  dstlen - длина выходного буфера
//  key - открытый ключ для проверки подписи
int rsa_check_block(uchar *src, ulong srclen, uchar *dst, ulong dstlen, public_key key);