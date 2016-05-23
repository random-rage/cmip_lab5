// lab5.cpp: определяет точку входа для консольного приложения.
//

#include <stdio.h>
#include "rsa.h"
#include "bignum.h"

#define STR_LEN 1024
#define MSG_LEN 256

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

	MPI_CHK(rsa_generate_keys(65537, pub, priv, STR_LEN));

	MPI_CHK(mpi_write_string(&pub.e, 10, E, &len));
	len = STR_LEN;

	MPI_CHK(mpi_write_string(&pub.n, 10, N, &len));
	len = STR_LEN;

	MPI_CHK(mpi_write_string(&priv.d, 10, D, &len));

	printf("e = %s\nd = %s\nn = %s\n", E, D, N);

	printf("Enter message to encrypt:\n");
	scanf("%[^\n]", source);

	len = strnlen((const char *)source, MSG_LEN) + 1;			// Length of string + zero-char

	MPI_CHK(rsa_encrypt_block(source, len, encrypted, MSG_LEN, pub));
	
	print_buffer("Encrypted", encrypted, MSG_LEN);

	MPI_CHK(rsa_decrypt_block(encrypted, MSG_LEN, decrypted, MSG_LEN, priv));

	print_buffer("Decrypted", decrypted, MSG_LEN);

	MPI_CHK(rsa_sign_block(source, len, encrypted, MSG_LEN, priv));

	print_buffer("Signed", encrypted, MSG_LEN);

	MPI_CHK(rsa_check_block(encrypted, MSG_LEN, decrypted, MSG_LEN, pub));

	print_buffer("Checked", decrypted, MSG_LEN);

	cleanup:

	return ret;
}

