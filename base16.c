//
// Created by jvlk on 11.11.22.
//

#include "base16.h"


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *tobase16(const char *in, int len)
{
	char alph[] = "abcdefghijklmnop";

	char *out = malloc(len * 2 + 1);

	for (int i = 0; i < len; i++) {
		out[i * 2] = alph[in[i] >> 4];
		out[i * 2 + 1] = alph[in[i] & 0x0F];
	}
	out[len * 2] = '\0';
	return out;

}

char *frombase16(const char *in, int len)
{
	char *out = malloc(len / 2 + 1);
	int l = 0;
	for (int i = 0; i < len; i += 2) {
		out[l++] = ((in[i] - 'a') * 16) + in[i + 1] - 'a';
	}
	out[len / 2 + 1] = '\0';
	return out;
}