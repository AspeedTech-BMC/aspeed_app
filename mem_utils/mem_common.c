/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include "mem_common.h"
#include "compiler.h"

int cmd_get_data_size(char *arg, int default_size)
{
	/* Check for a size specification .b, .w .l or .q.
	 */
	int len = strlen(arg);
	if (len > 2 && arg[len - 2] == '.') {
		switch (arg[len - 1]) {
		case 'b':
			return 1;
		case 'w':
			return 2;
		case 'l':
			return 4;
		case 's':
			return -2;
		case 'q':
			if (MEM_SUPPORT_64BIT_DATA)
				return 8;
			/* no break */
		default:
			return -1;
		}
	}
	return default_size;
}

unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base)
{
	unsigned long result = 0,value;

	if (*cp == '0') {
		cp++;
		if ((*cp == 'x') && isxdigit(cp[1])) {
			base = 16;
			cp++;
		}
		if (!base) {
			base = 8;
		}
	}
	if (!base) {
		base = 10;
	}
	while (isxdigit(*cp) && (value = isdigit(*cp) ? *cp-'0' : (islower(*cp)
		? toupper(*cp) : *cp)-'A'+10) < base) {
/*		printf("result = %x %s \n",result, cp); */
		result = result*base + value;
		cp++;
	}
	if (endp)
		*endp = (char *)cp;
	return result;
}

long simple_strtol(const char *cp,char **endp,unsigned int base)
{
	if(*cp=='-')
		return -simple_strtoul(cp+1,endp,base);
	return simple_strtoul(cp,endp,base);
}
