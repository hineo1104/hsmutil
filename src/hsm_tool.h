#ifndef _HSM_TOOL_H_
#define _HSM_TOOL_H_

void get_datetime(char* dt);
void int_to_c2 (u_char* hex, int n);
int toupper_str(char* str, int len);
int hatoi(const char* str, size_t n);

int asc2hex(const u_char* asc, int len, u_char type, u_char* hex);
int hex2asc(const u_char* hex, int len, u_char type, u_char* asc);

#endif