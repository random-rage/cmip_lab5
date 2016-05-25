// lab5.cpp: определяет точку входа для консольного приложения.
//

#include <stdio.h>
#include "bignum.h"
#include "rsa.h"

#define STR_LEN 1024
#define MSG_LEN 256

void test_prime_num_gen()
{
	mpi p;
	mpi_init(&p);
	clock_t start, end;
	float diff;
	
	srand(time(0));

	for (size_t i = 256; i <= 2048; i <<= 1)
	{
		start = clock();
		mpi_gen_prime(&p, i, 0, myrand, NULL);
		end = clock();

		diff = ((float)(end - start)) / CLOCKS_PER_SEC;

		printf("%d-bit prime number generation time: %f seconds\n", i, diff);
	}

	mpi_free(&p);
}

uchar InvertBit(uchar byte, int pos)
{
	return byte ^ (1 << pos);
}

void print_buffer(const char *format, uchar *buf, size_t len)
{
	for (size_t i = 0; i < len; i++)
		if (buf[i] != 0)
		{
			printf("%s:\n%.*s\n\n", format, len - i, buf + i);
			break;
		}
}

int main()
{
	int ret = 0;

	size_t len = STR_LEN;
	char E[STR_LEN], D[STR_LEN], N[STR_LEN];

	uchar source[MSG_LEN];
	uchar encrypted[MSG_LEN], decrypted[MSG_LEN];		// Buffers

	public_key pub;
	private_key priv;

	MPI_CHK(rsa_generate_keys(65537, pub, priv, 1024));

	MPI_CHK(mpi_write_string(&pub.e, 10, E, &len));
	len = STR_LEN;

	MPI_CHK(mpi_write_string(&pub.n, 10, N, &len));
	len = STR_LEN;

	MPI_CHK(mpi_write_string(&priv.d, 10, D, &len));

	printf("e = %s\nd = %s\nn = %s\n", E, D, N);

	printf("Enter message to encrypt:\n");
	scanf("%[^\n]", source);

	len = strnlen((const char *)source, MSG_LEN) + 1;			// Length of string + zero-char

	try
	{
		MPI_CHK(rsa_encrypt_block(source, len, encrypted, MSG_LEN, pub));
		print_buffer("Encrypted", encrypted, MSG_LEN);

		MPI_CHK(rsa_decrypt_block(encrypted, MSG_LEN, decrypted, MSG_LEN, priv));
		print_buffer("Decrypted", decrypted, MSG_LEN);

		MPI_CHK(rsa_sign_block(source, len, encrypted, MSG_LEN, priv));
		print_buffer("Signature", encrypted, MSG_LEN);

		MPI_CHK(rsa_check_block(encrypted, MSG_LEN, decrypted, MSG_LEN, pub));
		print_buffer("Preimage", decrypted, MSG_LEN);

		source[0] = InvertBit(source[0], 2);
		printf("Corrupted:\n%s\n\n", source);

		MPI_CHK(rsa_sign_block(source, len, encrypted, MSG_LEN, priv));
		print_buffer("Signature of corrupted", encrypted, MSG_LEN);
	}
	catch (char *e)
	{
		printf("Error: %s\n", e);
	}

cleanup:
	mpi_free(&pub.e);
	mpi_free(&priv.d);
	mpi_free(&priv.n);

	return ret;
}

