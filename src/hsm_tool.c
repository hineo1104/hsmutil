#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


void get_datetime(char* dt) {
    time_t tt;
    struct tm* t;

    tt = time(NULL);
    t = localtime(&tt);
    strftime(dt, 15, "%Y%m%d%H%M%S", t);
	return;
}

void int_to_c2 (u_char* hex, int n) {
    int tmp = n;
    if (tmp <= 65535) {
        *(hex + 1) = n % 256;
        *hex = tmp >>8;
    }
    return;
}

int toupper_str(char* str, int len) {
    int i;

    for (i = 0; i < len; i++) {
        if (str[i] >= 'a' && str[i] <= 'z') {
            str[i] = toupper(str[i]);
        }        
    }
    return 0;
}

int hatoi(const char* str, size_t n) {
   int value;
    if (n == 0) {
        return -1;
    }
    for (value = 0; n--; str++) {
        if (*str >= '0' && *str <= '9') {
            value = value * 16 + (*str - '0');
        }
        else if (*str >= 'a' && *str <= 'f') {
            value = value * 16 + (*str - 'a' + 10);
        }
        else if (*str >= 'A' && *str <= 'F') {
            value = value * 16 + (*str - 'A' + 10);
        }
        else {
            return -1;
        }
    }
    if (value < 0) {
        return -1;
    }
    return value;
}

int asc2hex(const u_char* asc, int len, u_char type, u_char* hex) {
    int i = 0;
    char tmp, tmp1;

    if (asc == NULL || hex == NULL || len <= 0) {
        return -1;
    }

    if (len & 0x01 && type)/*判别是否为奇数以及往那边对齐*/ {
        tmp1 = 0 ;
    }
    else {
        tmp1 = 0x55 ;
    }

    for (i = 0; i < len; asc++, i++) {
        if ( *asc >= 'a' ) {
            tmp = *asc - 'a' + 10 ;
        }
        else if ( *asc >= 'A' ) {
            tmp = *asc - 'A' + 10 ;
        }
        else if ( *asc >= '0' ) {
            tmp = *asc - '0' ;
        }
        else {
            tmp = *asc;
            tmp&=0x0f;
         }

        if ( tmp1 == 0x55 ) {
            tmp1 = tmp;
        }
        else {
            *hex ++ = tmp1 << 4 | tmp;
            tmp1 = 0x55;
        }
    }
    if (tmp1 != 0x55) {
        *hex = tmp1 << 4;
    }
    return 0;
}


int hex2asc(const u_char* hex, int len, u_char type, u_char* asc) {
    int i = 0;

    if (hex == NULL) {
        return -1;
    }
    if (len & 0x01 && type) /*判别是否为奇数以及往那边对齐,0:左，1:右*/ {
        i = 1;
        len++;
    }
    else {
        i = 0;
    }
    for (; i < len; i++, asc++) {
        if (i & 0x01) {
            *asc = *hex++ & 0x0f;
        }
        else {
            *asc = *hex >> 4;
        }
        if (*asc > 9) {
            *asc += 'A' - 10;
        }
        else {
            *asc += '0';
        }
    }
    *asc = 0;
    return 0;
}
