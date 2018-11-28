#include "SMCLibary.h"

//find free process space in virtual memory of process
long getProcessFreeSpace(pid_t PID, long * retAddr)
{
	char filePath[32];

	//open file to read process info
	sprintf(filePath, "/%s/%d/%s","proc", PID, "maps");
	FILE * file = fopen(filePath, "r");

	//error state treatment
	if(file == NULL){
		perror("OPENING /proc/PID/maps");
		return 0;
	}

	ssize_t lineLen = 0;
	ssize_t readLen = 0;
	long processFreeSpace = 0;
	long startFrameAddr, endFrameAddr;
    char usage[256];
	char * lineBuff;

	//read /proc/PID/maps line by line and seek for not used frames
	while( readLen = (getline(&lineBuff, &lineLen, file)) != -1 ){
		sscanf(lineBuff, "%lx-%lx %s %s %s %s %s", &startFrameAddr, &endFrameAddr, usage, usage, usage, usage, usage);

        if(strcmp(usage, "0") == 0){
			//compute free space size
			processFreeSpace = endFrameAddr - startFrameAddr;
			*retAddr = startFrameAddr;
            break;
		}
	}

	//close file
	fclose(file);

	return processFreeSpace;
}

//simple shift cipher, mode TRUE == cipher FALSE == decipher
char * cipherAlgorithm(char * ct, size_t ctLen, int key, bool mode){
	//plain text container
	char * pt = malloc (sizeof(char)*ctLen);

	int modeSwitch = (mode)? 1 : (-1);
	//decipher process
	for(int idx = 0; idx < ctLen; idx++)
		pt[idx] = (ct[idx] + key*modeSwitch) % 255;

	return pt;
}

//hex char to dec conversion
int hex_to_dec(char input){
	if(input >= '0' && input <= '9' )
		return input-48;
	else if(input >= 'a' && input <= 'f')
		return input-97+10;
	else if(input >= 'A' && input <= 'F')
		return input-65+10;
	else
		return -1;
}

//decipher code given by filename
unsigned char * DecipherCode(char * inFileName, size_t * codeSize)
{
	//open file to read ciphered text
	FILE * file = fopen(inFileName, "r");

	//error state treatment
	if(file == NULL){
		perror("DECIPHER FILE");
		return NULL;
	}

	//get file size
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	fseek(file, 0, SEEK_SET);

	unsigned char fileBuff[fileSize];
	//read file contents
	fread(fileBuff, fileSize, 1, file);
	unsigned char * ft = cipherAlgorithm(fileBuff, (size_t)fileSize, 3, false);

	//parse string to bytecode		
	unsigned char * byteCode = malloc(fileSize/4*sizeof(unsigned char));
	*codeSize = fileSize/4;
	for(int idx = 0; idx < fileSize/4; idx++)
		byteCode[idx] = hex_to_dec(ft[idx*4 + 2])*16 + hex_to_dec(ft[idx*4 + 3]);

	//close file
	fclose(file);

	//free deciphered ascii code
	free(ft);

	return byteCode;
}

//cipher code in file
void CipherCode(char * outFileName)
{
	//open file to read ciphered text
	FILE * file = fopen(outFileName, "r");
	//error state treatment
	if(file == NULL){
		perror("CIPHER FILE");
		return;
	}

	//get file size
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	fseek(file, 0, SEEK_SET);

	//read file contents
	char * fileBuff = malloc(sizeof(char)*fileSize);
	fread(fileBuff, fileSize, 1, file);

	//close file
	fclose(file); 

	char * ct = cipherAlgorithm(fileBuff, fileSize, 3, true);

	//open file for write ciphered text
	FILE * wfile = fopen(outFileName, "w");
	fwrite(ct, 1, fileSize, wfile);

	//close file
	fclose(wfile);

	//free buffer
	free(ct);
}

//modify code
long injectCodeFreePlace(char * codeFile, long * codeSize)
{
	//get process PID
	pid_t PID = getpid();

	//get stack write, execute, read permissions
	long pageSize = getpagesize();
	long stackAddress = (long)&pageSize;
	stackAddress = stackAddress & ~(pageSize - 1);

	if(mprotect((void *)stackAddress, 1, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
		printf("ERRNO: %d\n", errno);
		perror("STACK PRIVILEGES NOT GAINED");
		return 0;
	}

    //get space where is possible to safely inject code
    long freeSpaceAddr = 0, freeSpaceSize = 0;
	if((freeSpaceSize = getProcessFreeSpace(PID, &freeSpaceAddr)) == 0){
		printf("NO FREE SPACE FOUND\n");
		return 0;
	}

    //set permissions to read, write, execute on free address place
    if(mprotect((void *)freeSpaceAddr, freeSpaceSize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("FREE PLACE PRIVILEGE NOT GAINED\n");
        return 0;
    }

	//decipher code
	unsigned char * codeMemory = DecipherCode(codeFile, codeSize);

	//if injected code is bigger than size of injection space exit
	if(*codeSize > freeSpaceSize){
		printf("CANNOT INJECT CODE TO VIRTUAL SPACE, NOT ENOUGH PLACE FOR CODE!\n");
		return 0;
	}

    //copy code to free space
    memcpy((void *)freeSpaceAddr, codeMemory, *codeSize);

	//deallocate code buffer
	free(codeMemory);

	return freeSpaceAddr;
}

//clear injected memory
void clearInjectedSpace(void * injectedSpaceAddress, size_t injectedCodeSize)
{
	memset(injectedSpaceAddress, 0, injectedCodeSize);
}