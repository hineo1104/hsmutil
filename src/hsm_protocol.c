#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hsm_protocol.h"

int hsm_pack_packet(hsm_command_t *hc, char* b, int* len) {
	int off = 0;

	memcpy(b + off, hc->ch, 8); off += 8;
	memcpy(b + off, hc->cmd, 2); off += 2;
	memcpy(b + off, hc->data, hc->data_len); off += hc->data_len;

	*len = off;
	return 0;
}

int hsm_unpack_packet(hsm_command_t *hc, char* b, int len) {
	int off = 0;

	if (memcmp(b + off, hc->ch, 8) != 0) {
		return -1;
	}
	off += 8;
	memcpy(hc->rc, b + off, 2); off += 2;
	memcpy(hc->ec, b + off, 2); off += 2;
	if (memcmp(hc->ec, "00", 2) != 0) {
		printf("hsm return error [%s]\n", hc->ec);
		return -1;
	}
	memset(hc->data, 0, sizeof(hc->data));
	memcpy(hc->data, b + off, len - off);
	hc->data_len = len - off;
	return 0;
}
