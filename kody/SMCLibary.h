#ifndef _MYLIB_H_
#define _MYLIB_H_

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <signal.h>

	void CipherCode(char * outFileName);
	long injectCodeFreePlace();
	void clearInjectedSpace(void * injectedSpaceAddress, size_t injectedCodeSize);
#endif
