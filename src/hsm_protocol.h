#ifndef _HSM_PROTOCOL_H_
#define _HSM_PROTOCOL_H_

#define HSM_KEYTYPE_LEN		3
#define HSM_KEYTYPE_ZMK		"000"
#define HSM_KEYTYPE_ZPK		"001"
#define HSM_KEYTYPE_ZAK		"008"
#define HSM_KEYTYPE_ZEK		"00A"

#define HSM_KEYPLAN_DES		'Z'
#define HSM_KEYPLAN_2DES	'X'
#define HSM_KEYPLAN_3DES	'Y'

#define HSM_CMD_LEN			2
#define HSM_CMD_GENKEY		"A0"
#define HSM_CMD_GENZMK		"A5"
#define HSM_CMD_ZMK2LMK		"A6"
#define HSM_CMD_SWITCHZPK	"GC"
#define HSM_CMD_CALCMAC		"MQ"
#define HSM_CMD_TRANSFERPIN	"CC"
#define HSM_CMD_CRYPT		"E0"
#define HSM_CMD_CALCECBMAC	"MU"

#define HSM_PINCODE_LEN		2	
#define HSM_PINCODE_ISO		"01"


typedef struct {
	char ch[8 + 1];			//命令头
	char cmd[2 + 1];		//命令字
	char em[32 + 1];		//命令尾
	char rc[2 + 1];			//响应码
	char ec[2 + 1];			//错误码
	char data[1024];		//命令数据
	int data_len;   	//数据长度
}hsm_command_t;

int hsm_pack_packet(hsm_command_t *hc, char* b, int* len);
int hsm_unpack_packet(hsm_command_t *hc, char* b, int len);

#endif