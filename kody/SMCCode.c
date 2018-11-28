#include <stdio.h>
#include "SMCLibary.h"


//dynamically injected linear function in form y = a*x + b
int linearFunction(int a, int b, int x)
{
	long injectSize = 0;
	long jumpAddress = injectCodeFreePlace("linearFunctionCode", &injectSize);
	int output = 0;

	//input handling for injected code
	/*
	a -> edi
	x -> edx
	b -> esi
	*/
	__asm__("mov   0x0(%0),%%edi\n\t":: "r" (&a): );
	__asm__("mov   0x0(%0),%%edx\n\t":: "r" (&x): );
	__asm__("mov   0x0(%0),%%esi\n\t":: "r" (&b): );

	//execute code
	__asm__(
		"callq *%0"
    :
    : "r" ((void *)jumpAddress)
    : );

	//output handling for injected code
	//return value expected in register eax
	__asm__(
		"mov %%eax, 0x0(%0)"
		:
		: "r" (&output)
		: "rax");

	printf("%d * %d + %d = %d\n", a, x, b, output);

	//clear injection place
	clearInjectedSpace((void *)jumpAddress, injectSize);

	return output;
}

//inject euclidean algorith code dynamically and get output
void euclideanAlgo(int a, int b)
{
	//inject code given in file to free place and return it's address
	long injectSize = 0;
	long jumpAddress = injectCodeFreePlace("euclideanCode", &injectSize);
	int output = 0;

	//input handling for injected code
	/*
	a parameter -> esi, b parameter -> edi 
	(for this case register - parameter mapping order does not matter)
	*/
	__asm__("mov   0x0(%0),%%esi\n\t":: "r" (&a): );
	__asm__("mov   0x0(%0),%%edi\n\t":: "r" (&b): );

	//execute code
	__asm__(
		"callq *%0"
    :
    : "r" ((void *)jumpAddress)
    : );
	
	//output handling for injected code
	__asm__(
		"mov %%eax, 0x0(%0)"
	:
    : "r" (&output)
    : "rax");

	//clear injection place
	clearInjectedSpace((void *)jumpAddress, injectSize);

	printf("GCD of %d and %d is %d\n", a, b, output);
}

//inject deciphering algorithm dynamically and print result
void decipherCode(char * inFileName)
{
	//load ciphered code from file
	FILE * file = fopen(inFileName, "r");

	//error state treatment
	if(file == NULL){
		perror("DECIPHER FILE INJECTION");
		return;
	}
	int key = 3;
	long fileSize;

	//get file size
	fseek(file, 0, SEEK_END);
	fileSize = ftell(file);
	fseek(file, 0, SEEK_SET);

	char text[fileSize];

	//read file contents
	fread(text, fileSize, 1, file);

	//inject code given in file to free place and return it's address
	long injectSize = 0;
	long jumpAddress = injectCodeFreePlace("decipherCode", &injectSize);
	//input handling for injected code
	/*
	char array address 	-> rdi
	codeSize 			-> esi
	key 				-> edx
	(for this case register - parameter mapping order does not matter)
	*/
	__asm__("lea   0x0(%0),%%rdi\n\t":: "r" (&text): );
	__asm__("mov   0x0(%0),%%rsi\n\t":: "r" (&fileSize): );
	__asm__("mov   0x0(%0),%%edx\n\t":: "r" (&key): );

	//execute code
	__asm__(
		"callq *%0"
    :
    : "r" ((void *)jumpAddress)
    : );

	//clear injection place
	clearInjectedSpace((void *)jumpAddress, injectSize);

	printf("DECIPHERED CONTENT OF FILE %s:\n", inFileName);
	fflush(stdout); //force output to std
    write(1,text,fileSize);
	printf("\n");
}

//injected euclidean algorithm with input from user
void gcdInput()
{
	int a, b;
	char input[256];

	//input handling
	printf("Enter first number for gcd: ");
	scanf("%s", input);
	a = atoi(input);
	if(a == 0){
		printf("%s is not valid argument\n", input);
		return;
	}
	printf("Enter second number for gcd: ");
	scanf("%s", input);
	b = atoi(input);
	if(b == 0){
		printf("%s is not valid argument\n", input);
		return;
	}
	euclideanAlgo( a, b);
}

// injected linear function with input from user
void linearFunctionInput()
{
	int a, b, x;
	char input[256];

	printf("Format of function: a * x + b\n");
	//input handling
	printf("Enter a: ");
	scanf("%s", input);
	a = atoi(input);
	if(a == 0){
		printf("%s is not valid argument\n", input);
		return;
	}
	printf("Enter b: ");
	scanf("%s", input);
	b = atoi(input);
	if(b == 0){
		printf("%s is not valid argument\n", input);
		return;
	}

	printf("Enter x: ");
	scanf("%s", input);
	x = atoi(input);
	if(x == 0){
		printf("%s is not valid argument\n", input);
		return;
	}

	linearFunction(a,b,x);
}

//Function computes linear function test
void Test(){
	//function a*x + b
	int a = 3; int b = 11;
	//10x linear function
    for (int idx = 0; idx < 10; idx++){	
		//trap process
		linearFunction(a,b,idx);
    }
	//10x gcd function
	int number = 354;
	for (int idx = 1; idx <= 17; idx++){	
		//trap process
		euclideanAlgo(number,idx);
    }
	//decipher all codes files
	decipherCode("testCipherFile");
	decipherCode("linearFunctionCode");
	decipherCode("euclideanCode");
	decipherCode("decipherCode");

	printf("\nTest successful!\n");
}

//code to be modified
int main(int argc, char ** argv){	
	//input from command line parsing
	int opt;
	while ((opt = getopt (argc, argv, "ed:ac:xt")) != -1)
    		switch (opt){
			//injected euclidean algorithm code
			case 'e':
				gcdInput();
			break;
			//injected decipher algorithm code
			case 'd':
				decipherCode(optarg);
			break;
			//injected linear function
			case 'x':
				linearFunctionInput();
			break;
			//cipher given file with binary code
			case 'c':
				CipherCode(optarg);
			break;
			//test injection
			case 't':
				Test();	
      		default:
        		break;
	}
	if(argc == 1)
		printf("Use -h for help\n");
		
	return 0;
}
