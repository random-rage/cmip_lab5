#include "rsa.h"

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
	size_t i;

	if (rng_state != NULL)
		rng_state = NULL;

	for (i = 0; i < len; ++i)
		output[i] = rand();

	return(0);
}

int rsa_generate_keys(t_sint exp, public_key &pub, private_key &priv, size_t keylen)
{
	int ret = 0;	// Код возврата
	mpi e, d, 
		p, q, 
		n, f,		// f - значение функции Эйлера от n
		gcd;		// НОД e и f
	
	srand(time(0));

	// Инициализируем длинные числа
	mpi_init(&e);	mpi_init(&d);
	mpi_init(&p);	mpi_init(&q);
	mpi_init(&n);	mpi_init(&f);
	mpi_init(&gcd);

	// Устанавливаем e
	MPI_CHK(mpi_lset(&e, exp));

	do
	{
		// Генерируем p и q
		MPI_CHK(mpi_gen_prime(&p, keylen / 2, 0, myrand, NULL));
		MPI_CHK(mpi_gen_prime(&q, keylen / 2, 0, myrand, NULL));

		// Если они равны, ещё раз генерируем
		if (mpi_cmp_mpi(&p, &q) == 0)
			continue;

		// Вычисляем n
		MPI_CHK(mpi_mul_mpi(&n, &p, &q));

		// Вычисляем (p-1) и (q-1)
		MPI_CHK(mpi_sub_int(&p, &p, 1));
		MPI_CHK(mpi_sub_int(&q, &q, 1));

		// Вычисляем значение функции Эйлера от n
		MPI_CHK(mpi_mul_mpi(&f, &p, &q));

		// Вычисляем НОД(e, f)
		MPI_CHK(mpi_gcd(&gcd, &e, &f));
	} 
	// Если общих делителей у e и f (кроме 1) нет, завершаем генерацию
	while (mpi_cmp_int(&gcd, 1) != 0);		

	// Вычисляем d
	MPI_CHK(mpi_inv_mod(&d, &e, &f));
	
	// Записываем числа в открытый и закрытый ключи
	pub = { e, n };
	priv = { d, n };

cleanup:	// Освобождаем ненужные ресурсы

	if (ret != 0)
	{
		mpi_free(&e);	
		mpi_free(&d);
		mpi_free(&n);
	}
	
	mpi_free(&p);	
	mpi_free(&q);
	mpi_free(&f);
	mpi_free(&gcd);

	return ret;
}

int rsa_encrypt_block(uchar *src, ulong srclen, uchar *dst, ulong dstlen, public_key key)
{
	int ret = 0;	// Код возврата

	mpi msg;		// Число-сообщение

	mpi_init(&msg);	// Инициализируем число-сообщение

	// Считываем его из буфера
	MPI_CHK(mpi_read_binary(&msg, src, srclen));

	// Если оно меньше n, шифруем
	if (mpi_cmp_mpi(&msg, &key.n) < 0)
	{
		MPI_CHK(mpi_exp_mod(&msg, &msg, &key.e, &key.n, NULL));

		// Записываем зашифрованное сообщение в выходной буфер
		MPI_CHK(mpi_write_binary(&msg, dst, dstlen));
	}
	// Иначе - выдаём исключение
	else
		throw "Source block is too long";

cleanup:	// Освобождаем ненужные ресурсы

	mpi_free(&msg);

	return ret;
}

int rsa_decrypt_block(uchar *src, ulong srclen, uchar *dst, ulong dstlen, private_key key)
{
	int ret = 0;	// Код возврата

	mpi msg;		// Число-сообщение

	mpi_init(&msg);	// Инициализируем число-сообщение

					// Считываем его из буфера
	MPI_CHK(mpi_read_binary(&msg, src, srclen));

	// Если оно меньше n, расшифровываем
	if (mpi_cmp_mpi(&msg, &key.n) < 0)
	{
		MPI_CHK(mpi_exp_mod(&msg, &msg, &key.d, &key.n, NULL));

		// Записываем расшифрованное сообщение в выходной буфер
		MPI_CHK(mpi_write_binary(&msg, dst, dstlen));
	}
	// Иначе - выдаём исключение
	else
		throw "Source block is too long";

cleanup:	// Освобождаем ненужные ресурсы

	mpi_free(&msg);

	return ret;
}

int rsa_sign_block(uchar *src, ulong srclen, uchar *dst, ulong dstlen, private_key key)
{
	int ret = 0;	// Код возврата

	mpi msg;		// Число-сообщение

	mpi_init(&msg);	// Инициализируем число-сообщение

					// Считываем его из буфера
	MPI_CHK(mpi_read_binary(&msg, src, srclen));

	// Если оно меньше n, подписываем
	if (mpi_cmp_mpi(&msg, &key.n) < 0)
	{
		MPI_CHK(mpi_exp_mod(&msg, &msg, &key.d, &key.n, NULL));

		// Записываем подпись в выходной буфер
		MPI_CHK(mpi_write_binary(&msg, dst, dstlen));
	}
	// Иначе - выдаём исключение
	else
		throw "Source block is too long";

cleanup:	// Освобождаем ненужные ресурсы

	mpi_free(&msg);

	return ret;
}

int rsa_check_block(uchar *src, ulong srclen, uchar *dst, ulong dstlen, public_key key)
{
	int ret = 0;	// Код возврата

	mpi msg;		// Число-сообщение

	mpi_init(&msg);	// Инициализируем число-сообщение

					// Считываем его из буфера
	MPI_CHK(mpi_read_binary(&msg, src, srclen));

	// Если оно меньше n, проверяем подпись
	if (mpi_cmp_mpi(&msg, &key.n) < 0)
	{
		MPI_CHK(mpi_exp_mod(&msg, &msg, &key.e, &key.n, NULL));

		// Записываем прообраз в выходной буфер
		MPI_CHK(mpi_write_binary(&msg, dst, dstlen));
	}
	// Иначе - выдаём исключение
	else
		throw "Source block is too long";

cleanup:	// Освобождаем ненужные ресурсы

	mpi_free(&msg);

	return ret;
}