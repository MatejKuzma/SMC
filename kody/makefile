make: SMCCode.c SMCLibary.o
	gcc SMCCode.c SMCLibary.o -o SMCCode;

libary: SMCLibary.c SMCLibary.h
	gcc -o SMCLibary.o -c SMCLibary.c

no-stack-protection: SMCCode.c
	gcc SMCCode.c -o SMCCode

clear: SMCCode.c
	rm SMCCode
