#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

#include "hsm_protocol.h"
#include "hsm_socket.h"


#define HSM_COMMAND_COMMON		"COMMON"
#define HSM_COMMAND_GENZMK		"GENZMK"
#define HSM_COMMAND_GENZEK		"GENZEK"
#define HSM_COMMAND_GENZPK		"GENZPK"
#define HSM_COMMAND_GENZAK		"GENZAK"
#define HSM_COMMAND_GENKEY		"GENKEY"
#define HSM_COMMAND_ENCRYPT		"ENCRYPT"
#define HSM_COMMAND_DECEYPT		"DECRYPT"
#define HSM_COMMAND_ECBMAC		"ECBMAC"
#define HSM_COMMAND_ZMK2LMK		"ZMK2LMK"


static void hsm_help();
static int hsm_parse_option(int argc, char** argv);
static void hsm_genzmk();
static void hsm_genkey();
static void hsm_genzek();
static void hsm_genzpk();
static void hsm_genzak();
static void hsm_zmk2lmk();
static void hsm_encrypt_data();
static void hsm_decrypt_data();
static void hsm_calc_ecb_mac();
static hsm_socket_t hsm_connect_server();
static int hsm_send_handler(hsm_socket_t s, hsm_command_t *hc);
static int hsm_recv_handler(hsm_socket_t s, hsm_command_t *hc);
static void hsm_gen_hsm_cmd_header(hsm_command_t* hc);
static char* hsm_get_option(char* optname);
static int crypt_data(char mode, char* key, const char* in, char* out);

typedef void (*hsm_cmd_proc)();

typedef struct {
		char* 	     	name;		//所属指令
		hsm_cmd_proc 	proc;		//指令处理函数
}hsm_cmd_t;


typedef struct {
	char* optname;				//短选项名称
	char* optnamel;				//长选项名称
	char* cmd;					//所属指令 (COMMON代表通用选项)
	int   flag;					//选项属性     0不带参数, 1带参数
	char* value;				//选项默认值			
}hsm_cmd_option_t;

static hsm_cmd_t* cmd = NULL;		//命令

//选项配置表
static hsm_cmd_option_t cmd_option[] = {

						{"a", "addr", 	 HSM_COMMAND_COMMON,  1,  "192.168.13.109"},
						{"p", "port", 	 HSM_COMMAND_COMMON,  1,  "8"},
						{"t", "timedout",HSM_COMMAND_COMMON,  1,  "10"},
					    {"h", "help", 	 HSM_COMMAND_COMMON,  0,  NULL},
					  	{"",  "zmk1",  	 HSM_COMMAND_GENZMK,  1,  NULL},
					 	{"",  "zmk2",  	 HSM_COMMAND_GENZMK,  1,  NULL},
					 	{"",  "zmk", 	 HSM_COMMAND_COMMON,  1,  NULL},
					 	{"",  "zek",	 HSM_COMMAND_COMMON,  1,  NULL},
					 	{"",  "data",	 HSM_COMMAND_COMMON,  1,  NULL},
					 	{"",  "key", 	 HSM_COMMAND_COMMON,  1,  NULL},
					 	{"",  "key-type",HSM_COMMAND_GENKEY,  1,  NULL},
					 	{NULL, NULL, NULL, 0, NULL}

							};
//命名表
static hsm_cmd_t cmd_table[] = {

						{HSM_COMMAND_GENZMK,	hsm_genzmk},
						{HSM_COMMAND_GENZEK,	hsm_genzek},
						{HSM_COMMAND_GENZPK,	hsm_genzpk},
						{HSM_COMMAND_GENZAK,	hsm_genzak},
						{HSM_COMMAND_GENKEY,	hsm_genkey},
						{HSM_COMMAND_ENCRYPT, 	hsm_encrypt_data},
						{HSM_COMMAND_DECEYPT,   hsm_decrypt_data},
						{HSM_COMMAND_ECBMAC,    hsm_calc_ecb_mac},
						{HSM_COMMAND_ZMK2LMK,   hsm_zmk2lmk},
						{NULL, NULL}

							};

static void hsm_help() {
	printf("Usage: hsmutil [COMMON OPTIONS] COMMAND [COMMAND OPTIONS]\n");
	return;
}

static char* hsm_get_option(char* optname) {
	int i;
	hsm_cmd_option_t *opt;

	for (i = 0; ;i++) {
		opt = &cmd_option[i];
		if (opt->cmd == NULL) {
			break;
		}
		if (
			(strcmp(opt->optname, optname) == 0) ||
			(strcmp(opt->optnamel, optname) == 0)
			) {
			return opt->value;
		}
	}
	return NULL;
}

static hsm_socket_t hsm_connect_server() {
	hsm_socket_t s;
	char *addr, *port, *timedout;
	struct sockaddr_in sa;
	int socklen;
	int err; 

	addr = hsm_get_option("a");
	port = hsm_get_option("p");
	timedout = hsm_get_option("t");
	s = hsm_socket(AF_INET, SOCK_STREAM, 0);
	if (s == (hsm_socket_t) -1) {
		err = errno;
		printf("create socket error %d\n", err);
		return;
	}
	if (hsm_socket_reuseaddr(s) != 0) {
		if (hsm_close_socket(s) != 0) {
		}
		return;
	}
	if (hsm_socket_timedout(s, atoi(timedout) * 1000) != 0) {
		if (hsm_close_socket(s) != 0) {
		}
		return;
	}
	sa.sin_family = AF_INET;    
	sa.sin_port   = htons(atoi(port));
	sa.sin_addr.s_addr = inet_addr(addr);
	socklen = sizeof(struct sockaddr_in);
	if (hsm_connect_peer(s, (struct sockaddr*)&sa, socklen) != 0) {
		return -1;
	}
	return s;
}


static int hsm_send_handler(hsm_socket_t s, hsm_command_t *hc) {
	char buf[1024] = {0};
	int len;
	ssize_t size;

	if (hsm_pack_packet(hc, buf + 2, &len) != 0) {
		return;
	}
	int_to_c2(buf, len);

	printf("%*.*s\n", len, len, buf + 2);


	size = hsm_send(s, buf, len + 2);
	if (size <= 0 || size != (len + 2)) {//链接已经被关闭
		return -1;
	}
	return 0;
}
static int hsm_recv_handler(hsm_socket_t s, hsm_command_t *hc) {
	char buf[1024] = {0};
	ssize_t size;

	size = hsm_recv(s, buf, sizeof(buf));
	if (size <= 0) {//说明连接被关闭
		return -1;
	}
	if (hsm_unpack_packet(hc, buf + 2, size - 2) != 0) {
		return -1;
	}
	return 0;
}
static void hsm_gen_hsm_cmd_header(hsm_command_t* hc) {
	char ch[14 + 1] = {0};
	get_datetime(ch);
	memcpy(hc->ch, ch + 6, 8);
}
static int crypt_data(char mode, char* key, const char* in, char* out) {
	hsm_command_t hc;
	int off;
	hsm_socket_t s;

	memset(&hc, 0, sizeof(hc));
	hsm_gen_hsm_cmd_header(&hc);
	memcpy(hc.cmd, HSM_CMD_CRYPT, HSM_CMD_LEN);
	hc.data[0] = '0';			//一次性传入数据
	hc.data[1] = mode;			//进行数据加密
	hc.data[2] = '1';			//CBC加密
	hc.data[3] = '0';			//使用的密钥为zek
	off = 4;
	hc.data[off] = HSM_KEYPLAN_2DES; off += 1;
	memcpy(hc.data + off, key, strlen(key)); off += strlen(key);
	hc.data[off] = '1';	off += 1;						//输入数据为扩展的asc格式，方便进行输入
	hc.data[off] = '1'; off += 1;						//输出数据为扩展asc格式，方便进行输出显示
	hc.data[off] = '0'; off += 1;						//填充模式
	memcpy(hc.data + off, "0000", 4); off += 4;			//填充字符	
	hc.data[off] = '0'; off += 1;						//填充类型
	sprintf(hc.data + off, "%03x", strlen(in) / 2);
	toupper_str(hc.data + off, 3); off += 3;
	memcpy(hc.data + off, in, strlen(in)); off += strlen(in);
	hc.data_len = off;
	s = hsm_connect_server();
	if (s < 0) {
		return - 1;
	}
	if (hsm_send_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return - 1;
	}
	if (hsm_recv_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return - 1;
	}
	hsm_close_socket(s);
	off = hatoi(hc.data + 1, 3);
	if (off <= 0) {
		return -1;
	}
	memcpy(out, hc.data + 4, off * 2);
	return 0;
}

static void hsm_encrypt_data() {
	char* zek;
	char* d;
	char r[512] = {0};

	if ((zek = hsm_get_option("zek")) == NULL) {
		printf("COMMAND:%s must have zek option\n", HSM_COMMAND_ENCRYPT);
		return;			
	}
	if (strlen(zek) != 32) {
		printf("zmk option argument length error\n");
		return;	
	}
	if ((d = hsm_get_option("data")) == NULL) {
		printf("COMMAND:%s must have data option\n", HSM_COMMAND_ENCRYPT);
		return;	
	}
	if (strlen(d) % 2 != 0) {
		printf("data option argument must be even long\n");
		return;
	}
	if (crypt_data('0', zek, d, r) < 0) {
		return;
	}
	printf("encrypt result:\n%s\n", r);
}

static void hsm_decrypt_data() {
	char* zek;
	char* d;
	char r[512] = {0};

	if ((zek = hsm_get_option("zek")) == NULL) {
		printf("COMMAND:%s must have zek option\n", HSM_COMMAND_GENKEY);
		return;			
	}
	if (strlen(zek) != 32) {
		printf("zmk option argument length error\n");
		return;	
	}
	if ((d = hsm_get_option("data")) == NULL) {
		printf("COMMAND:%s must have data option\n", HSM_COMMAND_GENKEY);
		return;	
	}
	if (strlen(d) % 2 != 0) {
		printf("data option argument must be even long\n");
		return;
	}
	if (crypt_data('1', zek, d, r) < 0) {
		return;
	}
	printf("decrypt result:\n%s\n", r);
}

static void hsm_genkey() {
	char* keytype, *kt;
	char* zmk;
	char key[32 + 1] = {0}, key1[32 + 1] = {0}, kcv[8] = {0};
	hsm_command_t hc;
	int off;
	hsm_socket_t s;

	if ((kt = hsm_get_option("key-type")) == NULL) {
		printf("COMMAND:%s must have key-type option\n", HSM_COMMAND_GENKEY);
		return;		
	}
	if (strcmp(kt, "zpk") == 0) {
		keytype = HSM_KEYTYPE_ZPK;
	}
	else if (strcmp(kt, "zak") == 0) {
		keytype = HSM_KEYTYPE_ZAK;
	}
	else if (strcmp(kt, "zek") == 0) {
		keytype = HSM_KEYTYPE_ZEK;
	}
	else {
		printf("key-type option argument error\n");
		return;			
	}
	if ((zmk = hsm_get_option("zmk")) == NULL) {
		printf("COMMAND:%s must have zmk option\n", HSM_COMMAND_GENKEY);
		return;		
	}
	if (strlen(zmk) != 32) {
		printf("zmk option argument length error\n");
		return;
	}
	memset(&hc, 0, sizeof(hc));
	hsm_gen_hsm_cmd_header(&hc);
	memcpy(hc.cmd, HSM_CMD_GENKEY, HSM_CMD_LEN);
	hc.data[0] = '1';	//生成密钥，并在指定的zmk下加密
	memcpy(hc.data + 1, keytype, HSM_KEYTYPE_LEN);
	hc.data[1 + HSM_KEYTYPE_LEN] = HSM_KEYPLAN_2DES;	//3DES加密
	off =  2 + HSM_KEYTYPE_LEN;
	hc.data[off] = HSM_KEYPLAN_2DES; off += 1;
	memcpy(hc.data + off, zmk, strlen(zmk)); off += strlen(zmk);	
	hc.data[off] = HSM_KEYPLAN_2DES; off += 1;
	hc.data_len = off;
	s = hsm_connect_server();
	if (s < 0) {
		return;
	}
	if (hsm_send_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	if (hsm_recv_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	hsm_close_socket(s);
	memcpy(key,  hc.data + 1, 32);
	memcpy(key1, hc.data + 34, 32);
	memcpy(kcv,  hc.data + 66, 8);
	printf("hsm gen %s [%s] encrypted by lmk\n", kt, key);
	printf("hsm gen %s [%s] encrypted by zmk\n", kt, key1);
	printf("hem gen %s kcv [%s]\n", kt, kcv);
	return;
}

static void hsm_genzmk() {
	char *zmk1, *zmk2;
	hsm_command_t hc;
	int off;
	hsm_socket_t s;

	if ((zmk1 = hsm_get_option("zmk1")) == NULL) {
		printf("COMMAND:%s must have zmk1 option\n", HSM_COMMAND_GENZMK);
		return;
	}
	if ((zmk2 = hsm_get_option("zmk2")) == NULL) {
		printf("COMMAND:%s must have zmk2 option\n", HSM_COMMAND_GENZMK);
		return;
	}
	if (strlen(zmk1) != 32 || strlen(zmk2) != 32) {
		printf("zmk length error\n");
		return;
	}
	memset(&hc, 0, sizeof(hc));
	hsm_gen_hsm_cmd_header(&hc);
	memcpy(hc.cmd, HSM_CMD_GENZMK, HSM_CMD_LEN);
	hc.data[0] = '2';		//分量数
	memcpy(hc.data + 1, HSM_KEYTYPE_ZMK, HSM_KEYTYPE_LEN);
	hc.data[1 + HSM_KEYTYPE_LEN] = HSM_KEYPLAN_2DES;
	off = 2 + HSM_KEYTYPE_LEN;
	memcpy(hc.data + off, zmk1, strlen(zmk1)); off += strlen(zmk1);
	memcpy(hc.data + off, zmk2, strlen(zmk2)); off += strlen(zmk2);
	hc.data_len = off;

	s = hsm_connect_server();
	if (s < 0) {
		return;
	}
	if (hsm_send_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	if (hsm_recv_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	hsm_close_socket(s);
	printf("hsm gen zmk [%32.32s]\nthe zmk kcv [%16.16s]\n", hc.data + 1, hc.data + 33);
	return;
}

static void hsm_genzek() {
	char *zmk1, *zmk2;
	hsm_command_t hc;
	int off;
	hsm_socket_t s;

	if ((zmk1 = hsm_get_option("zmk1")) == NULL) {
		printf("COMMAND:%s must have zmk1 option\n", HSM_COMMAND_GENZMK);
		return;
	}
	if ((zmk2 = hsm_get_option("zmk2")) == NULL) {
		printf("COMMAND:%s must have zmk2 option\n", HSM_COMMAND_GENZMK);
		return;
	}
	if (strlen(zmk1) != 32 || strlen(zmk2) != 32) {
		printf("zmk length error\n");
		return;
	}
	memset(&hc, 0, sizeof(hc));
	hsm_gen_hsm_cmd_header(&hc);
	memcpy(hc.cmd, HSM_CMD_GENZMK, HSM_CMD_LEN);
	hc.data[0] = '2';		//分量数
	memcpy(hc.data + 1, HSM_KEYTYPE_ZEK, HSM_KEYTYPE_LEN);
	hc.data[1 + HSM_KEYTYPE_LEN] = HSM_KEYPLAN_2DES;
	off = 2 + HSM_KEYTYPE_LEN;
	memcpy(hc.data + off, zmk1, strlen(zmk1)); off += strlen(zmk1);
	memcpy(hc.data + off, zmk2, strlen(zmk2)); off += strlen(zmk2);
	hc.data_len = off;

	s = hsm_connect_server();
	if (s < 0) {
		return;
	}
	if (hsm_send_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	if (hsm_recv_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	hsm_close_socket(s);
	printf("hsm gen zmk [%32.32s]\nthe zmk kcv [%16.16s]\n", hc.data + 1, hc.data + 33);
	return;
}

static void hsm_genzpk() {
	char *zmk1, *zmk2;
	hsm_command_t hc;
	int off;
	hsm_socket_t s;

	if ((zmk1 = hsm_get_option("zmk1")) == NULL) {
		printf("COMMAND:%s must have zmk1 option\n", HSM_COMMAND_GENZMK);
		return;
	}
	if ((zmk2 = hsm_get_option("zmk2")) == NULL) {
		printf("COMMAND:%s must have zmk2 option\n", HSM_COMMAND_GENZMK);
		return;
	}
	if (strlen(zmk1) != 32 || strlen(zmk2) != 32) {
		printf("zmk length error\n");
		return;
	}
	memset(&hc, 0, sizeof(hc));
	hsm_gen_hsm_cmd_header(&hc);
	memcpy(hc.cmd, HSM_CMD_GENZMK, HSM_CMD_LEN);
	hc.data[0] = '2';		//分量数
	memcpy(hc.data + 1, HSM_KEYTYPE_ZPK, HSM_KEYTYPE_LEN);
	hc.data[1 + HSM_KEYTYPE_LEN] = HSM_KEYPLAN_2DES;
	off = 2 + HSM_KEYTYPE_LEN;
	memcpy(hc.data + off, zmk1, strlen(zmk1)); off += strlen(zmk1);
	memcpy(hc.data + off, zmk2, strlen(zmk2)); off += strlen(zmk2);
	hc.data_len = off;

	s = hsm_connect_server();
	if (s < 0) {
		return;
	}
	if (hsm_send_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	if (hsm_recv_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	hsm_close_socket(s);
	printf("hsm gen zmk [%32.32s]\nthe zmk kcv [%16.16s]\n", hc.data + 1, hc.data + 33);
	return;
}

static void hsm_genzak() {
	char *zmk1, *zmk2;
	hsm_command_t hc;
	int off;
	hsm_socket_t s;

	if ((zmk1 = hsm_get_option("zmk1")) == NULL) {
		printf("COMMAND:%s must have zmk1 option\n", HSM_COMMAND_GENZMK);
		return;
	}
	if ((zmk2 = hsm_get_option("zmk2")) == NULL) {
		printf("COMMAND:%s must have zmk2 option\n", HSM_COMMAND_GENZMK);
		return;
	}
	if (strlen(zmk1) != 32 || strlen(zmk2) != 32) {
		printf("zmk length error\n");
		return;
	}
	memset(&hc, 0, sizeof(hc));
	hsm_gen_hsm_cmd_header(&hc);
	memcpy(hc.cmd, HSM_CMD_GENZMK, HSM_CMD_LEN);
	hc.data[0] = '2';		//分量数
	memcpy(hc.data + 1, HSM_KEYTYPE_ZAK, HSM_KEYTYPE_LEN);
	hc.data[1 + HSM_KEYTYPE_LEN] = HSM_KEYPLAN_2DES;
	off = 2 + HSM_KEYTYPE_LEN;
	memcpy(hc.data + off, zmk1, strlen(zmk1)); off += strlen(zmk1);
	memcpy(hc.data + off, zmk2, strlen(zmk2)); off += strlen(zmk2);
	hc.data_len = off;

	s = hsm_connect_server();
	if (s < 0) {
		return;
	}
	if (hsm_send_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	if (hsm_recv_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	hsm_close_socket(s);
	printf("hsm gen zmk [%32.32s]\nthe zmk kcv [%16.16s]\n", hc.data + 1, hc.data + 33);
	return;
}


static void hsm_zmk2lmk() {
	char* zmk, *key, *type;
	hsm_command_t hc;
	int off;
	hsm_socket_t s;

	if ((zmk = hsm_get_option("zmk")) == NULL) {
		printf("COMMAND:%s must have zmk1 option\n", HSM_COMMAND_ZMK2LMK);
		return;
	}
	if ((key = hsm_get_option("key")) == NULL) {
		printf("COMMAND:%s must have zmk2 option\n", HSM_COMMAND_ZMK2LMK);
		return;
	}
	if ((type = hsm_get_option("key-type")) == NULL) {
		printf("COMMAND:%s must have key-type option\n", HSM_COMMAND_ZMK2LMK);
		return;
	}
	if (strlen(zmk) != 32) {
		printf("zmk leng error\n");
		return;
	}
	if (strlen(key) != 16 && strlen(key) != 32) {
		printf("key length error");
		return;
	}
	memset(&hc, 0, sizeof(hc));
	hsm_gen_hsm_cmd_header(&hc);
	off  = 0;
	memcpy(hc.cmd, HSM_CMD_ZMK2LMK, HSM_CMD_LEN);

	if (strcmp(type, "zmk") == 0) {
		memcpy(hc.data + off, HSM_KEYTYPE_ZMK, HSM_KEYTYPE_LEN);
	}
	else if (strcmp(type, "zpk") == 0) {
		memcpy(hc.data + off, HSM_KEYTYPE_ZPK, HSM_KEYTYPE_LEN);
	}
	else if (strcmp(type, "zak") == 0) {
		memcpy(hc.data + off, HSM_KEYTYPE_ZAK, HSM_KEYTYPE_LEN);
	}
	else if (strcmp(type, "zek") == 0) {
		memcpy(hc.data + off, HSM_KEYTYPE_ZEK, HSM_KEYTYPE_LEN);
	}
	else {
		printf("key-type option value error\n");
		return;
	}
	off += HSM_KEYTYPE_LEN;
	hc.data[off] = HSM_KEYPLAN_2DES; off += 1;
	memcpy(hc.data + off, zmk, strlen(zmk)); off += strlen(zmk);

	if (strlen(key) == 16) {
		memcpy(hc.data + off, key, strlen(key));
		off += strlen(key);
		hc.data[off] = HSM_KEYPLAN_DES;
		off += 1;
	}
	else {
		hc.data[off] = HSM_KEYPLAN_2DES; off += 1;
		memcpy(hc.data + off, key, strlen(key));
		off += strlen(key);
		hc.data[off] = HSM_KEYPLAN_2DES;
		off += 1;
	}
	hc.data_len = off;

	s = hsm_connect_server();
	if (s < 0) {
		return;
	}
	if (hsm_send_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	if (hsm_recv_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	hsm_close_socket(s);
	if (strlen(key) == 16) {
		printf("key by lmk:%16.16s\n", hc.data);
		printf("kcv:%s\n", hc.data + 16);
	}
	else {
		printf("key by lmk:%32.32s\n", hc.data + 1);
		printf("kcv:%s\n", hc.data + 33);
	}
	return;
}


static calc_x99_mac(char* zmk, char* d, int len, char* out) {
	hsm_command_t hc;
	int off;
	hsm_socket_t s;

	memset(&hc, 0, sizeof(hc));
	hsm_gen_hsm_cmd_header(&hc);
	memcpy(hc.cmd, HSM_CMD_CALCECBMAC, HSM_CMD_LEN);
	off = 0;
	hc.data[0] = '0';	//一次性传入数据
	off += 1;
	hc.data[off] = '1';		//ZAK
	off += 1;
	hc.data[off] = '1';		//2DES
	off += 1;
	hc.data[off] = '0';		//2进制数据
	off += 1;
	memcpy(hc.data + off, zmk, strlen(zmk));
	off += strlen(zmk);
	sprintf(hc.data + off, "%04x", len);
	toupper_str(hc.data + off, 4);	//这里全部转换为大写
	off += 4;
	memcpy(hc.data + off, d, len);
	off += len;
	hc.data_len = off;
	
	s = hsm_connect_server();
	if (s < 0) {
		return;
	}
	if (hsm_send_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	if (hsm_recv_handler(s, &hc) != 0) {
		hsm_close_socket(s);
		return;
	}
	hsm_close_socket(s);
	//printf("out[%16.16s]\n", hc.data);
	asc2hex(hc.data, 16, 0, out);
	return;

}


static void hsm_calc_ecb_mac() {
	char *zmk, *d;
	char data[8] = {0}, mb[16 + 1] = {0};
	char out[8] = {0};
	char mac[16 + 1] = {0};
	int i;

	if ((zmk = hsm_get_option("zmk")) == NULL) {
		printf("COMMAND:%s must have zmk option\n", HSM_COMMAND_GENZMK);
		return;
	}

	if ((d = hsm_get_option("data")) == NULL) {
		printf("COMMAND:%s must have data option\n", HSM_COMMAND_GENKEY);
		return;
	}
	for (i = 0; i < 8; i++) {
		data[(i&0x07)] ^= d[i];
	}
	hex2asc(data, 16, 0, mb);
	memcpy(data, mb, 8);
	calc_x99_mac(zmk, data, 8, out);
	memcpy(data, out, 8);
	for (i = 0; i < 8; i++) {
		data[i] ^= mb[8 + i];
	}
	calc_x99_mac(zmk, data, 8, out);
	hex2asc(out, 16, 0, mb);
	hex2asc(mb, 16, 0, mac);
	printf("mac[%16.16s]\n", mac);
}

static int hsm_parse_option(int argc, char** argv) {
	int i, n, flag = 0;
	char *p, *arg;
	hsm_cmd_option_t* opt;
	hsm_cmd_t *c;


	if (argc == 1) {	//表明不带任何选项命令
		hsm_help();
		exit(1);
	}
	for (i = 1; i < argc; i++) {
		p = argv[i];
		if (*p != '-') {//非选项
			//查找对应的命令
			for (n = 0; ;n++) {
				c = &cmd_table[n];
				if (c->name == NULL) {
					break;
				}
				if (strcmp(p, c->name) == 0) {
					break;
				}
			}
			if (c->name == NULL) {
				printf("undefined command %s \n", argv[i]);
				exit(1);
			}
			cmd = c;
		}
		else if (*p == '-') {//选项
			if (*(p + 1) == '-') {
				p = p + 2;	//长选项
				flag = 1;
			}
			else {
				p =  p + 1;//短选项
			}
			for (n = 0; ;n++) {	//查找选项配置
				opt = &cmd_option[n];
				if (opt->cmd == NULL) {
					break;
				}
				if (flag == 1) {
					if (strcmp(p, opt->optnamel) == 0) {
						//找到对应长选项
						break;
					}
				}
				else {
					if (strcmp(p, opt->optname) == 0) {
						//找到对应短选项
						break;
					}
				}
			}
			//没有找到都应的选项配置
			if (opt->cmd == NULL) {
				printf("undefined options: %s\n", argv[i]);
				exit(1);
			}
			if (strcmp(opt->optname, "h") == 0) {
				hsm_help();
				exit(0);
			}		
			//判断该选项是否需要参数
			if (opt->flag == 0) {	//该选项不带参数
				opt->value = "1";	//表明在命令行上设置过该选项
				break;
			}
			i = i + 1;
			if (i >=  argc || argv[i] == NULL) {
				printf("option %s must have arg\n", argv[i - 1]);
				exit(1);
			}
			opt->value = argv[i];
		}
	}
	if (cmd == NULL) {
		printf("have no command found\n");
		exit(1);
	}
	return 0;
}
int main(int argc, char** argv) {
	
	if (hsm_parse_option(argc, argv) != 0) {
		return -1;
	}
	if (cmd != NULL) {
		cmd->proc();		
	}	
	return 0;
}