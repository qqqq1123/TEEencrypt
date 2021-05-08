/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define BUF_SIZE 1024

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,    	TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	
	int fd;

	char plain[BUF_SIZE] ={0};
	char cipher[BUF_SIZE+2] = {0};

	op.params[0].tmpref.buffer = plain;
	op.params[0].tmpref.size = BUF_SIZE;
	op.params[1].tmpref.buffer = cipher;
	op.params[1].tmpref.size = BUF_SIZE+2;

	if(strcmp(argv[1], "-e") == 0 ){
		fd = open(argv[2], O_RDONLY);
		read(fd, plain, BUF_SIZE);
		close(fd);

		memcpy(op.params[0].tmpref.buffer, plain, BUF_SIZE);
		memcpy(op.params[1].tmpref.buffer, plain, BUF_SIZE);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

		fd = open("/root/ciphertext.txt", O_CREAT|O_RDWR);
		write(fd,op.params[1].tmpref.buffer, BUF_SIZE+2);
//		write(fd,op.params[1].tmpref.buffer, BUF_SIZE);
		close(fd);

	}else if(strcmp(argv[1], "-d") == 0 ){
		op.params[0].tmpref.buffer = cipher;
		fd = open(argv[2], O_RDONLY);
		read(fd,cipher, BUF_SIZE+2);
		close(fd);

		memcpy(op.params[0].tmpref.buffer, cipher, BUF_SIZE+2);
		memcpy(op.params[1].tmpref.buffer, cipher, BUF_SIZE+2);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		
		fd = open("/root/decryptedText.txt", O_CREAT|O_RDWR);
		write(fd, op.params[1].tmpref.buffer, BUF_SIZE);
		close(fd);
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);
	

	return 0;
}
