#include <unistd.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <string.h>
#include <signal.h>

#include "SMCLibary.h"

const size_t wordSize = sizeof(long);

//get free place in virtual space of process, using /proc/PID/maps
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
	long startAddr, endAddr;
    char device[20];
	char * lineBuff;

	//read /proc/PID/maps line by line and seek for not used frames
	while( readLen = (getline(&lineBuff, &lineLen, file)) != -1 ){
		sscanf(lineBuff, "%lx-%lx %s %s %s", &startAddr, &endAddr, device, device, device);
        if(strcmp(device, "08:02") == 0){ //00:00
			//count free space size
			processFreeSpace = endAddr - startAddr;
			*retAddr = startAddr;
            break;
		}
	}

	//close file
	fclose(file);

	return processFreeSpace;
}

/*get chosen chunk of memory of tracee process,
 *return size is padded in order to final size be multiply of word size */
unsigned char * getTraceeMemory(pid_t TPID, long beginAddr, size_t size)
{
	const int wordSize = sizeof(long);
	int readNum = size / wordSize;
	const int readLeftover = size % wordSize;
	readNum = ( (size % wordSize) > 0)? readNum + 1 : readNum;
	unsigned char * outBuffer = malloc(size + readLeftover *sizeof(unsigned char));

	//eazy access to data from ptrace PTRACE_PEEKDATA call
	union uni{
		long intData;
		unsigned char charData[wordSize];
	}rData;

	// PEEKDATA reads one word size per call
	size_t bytesToRead = wordSize;
        size_t actualSize = size;	
	for(int idx = 0; idx < readNum; idx += 1){
		//read data from tracee memory, return value is chunk of 8 bytes of data
		rData.intData = ptrace(PTRACE_PEEKDATA, TPID, beginAddr + idx * wordSize, NULL);
		if(rData.intData == -1){
			perror("PTRACE TRACEE READ");
			return NULL;
		}

		//copy data to buffer
		actualSize -= wordSize;
		bytesToRead = (actualSize >= wordSize)? wordSize : actualSize;
		memcpy(outBuffer + idx * wordSize, rData.charData, bytesToRead);
	}

	return outBuffer;
}

// memory set is without padding, it is important for input codes to be in form of multiply of word size
void setTraceeMemory(pid_t TPID, unsigned char * code, long beginAddr, size_t size)
{
	const int wordSize = sizeof(long);
	int writeNum = size / wordSize;
	int writeLeftover = size % wordSize;

	//eazy access to data for ptrace PTRACE_POKEDATA call
	union uni{
		long intData;
		unsigned char charData[wordSize];
	}wData;
	union uni2{
		long intData;
		unsigned char charData[wordSize];
	}rData;

	for(int idx = 0; idx < writeNum; idx += 1){
		memcpy(wData.charData, code + idx * wordSize, wordSize);
		//write data to tracee's memory
		wData.intData = ptrace(PTRACE_POKEDATA, TPID, beginAddr + idx * wordSize, wData.intData);
		if(wData.intData == -1){
			perror("PTRACE TRACEE READ");
			return;
		}
	}
	//missaligment
	if(writeLeftover){
printf("JE LEFTOVER\n");
		//read block of data first
		rData.intData = ptrace(PTRACE_PEEKDATA, TPID, beginAddr + writeNum*wordSize, wData.intData);
		//modify block with code to be injected
printf("PRED %s\n", rData.charData);
for(int idx = 0; idx < 8; idx ++)
	printf("[%d]%x ", idx, rData.charData[idx]);
printf("\n");

		memcpy(rData.charData, code + writeNum * wordSize, writeLeftover);
printf("PO %s\n", rData.charData);
for(int idx = 0; idx < 8; idx ++)
	printf("[%d]%x ", idx, rData.charData[idx]);
printf("\n");

		//inject modified code
		ptrace(PTRACE_POKEDATA, TPID, beginAddr+writeNum*wordSize, rData.intData);
	}
}

void analyseStack(pid_t PID, long stackAddr)
{
	size_t bytesNum = 400;
	long startStackAddr = stackAddr - bytesNum;

	//read stack memory
	char * stackMemory = getTraceeMemory(PID, startStackAddr, bytesNum);

	printf("STACK ANALYSIS FROM ADDRES: %lx TO %lx\n",startStackAddr, stackAddr );
	for(int idx = 0; idx < bytesNum; idx += 4){
		char charNum[4] = {stackMemory[idx], stackMemory[idx+1], stackMemory[idx+2], stackMemory[idx+3] };
		int val = atoi(charNum);
		//sscanf(charNum, "%d", &val);
		printf("%lx holds value [-%ld]: %d -> 0[%d]\t1[%d]\t2[%d]\t3[%d]\n",startStackAddr+idx, bytesNum-idx, val, stackMemory[idx],
		stackMemory[idx+1], stackMemory[idx+2], stackMemory[idx+3] );
	}
}

void processInjectToFreeSpace(pid_t TPID, char * codeFileName)
{
	printf("Trying to inject code to process %d\n", TPID);

	//attach to process, make proces child process of yours, send SIGSTOP
	if(ptrace(PTRACE_ATTACH, TPID, NULL, NULL) == -1){
		perror("PTRACE ATTACH ERROR");
		return;
	}

	//wait child process to change state to stopped
	wait(NULL);

	//find free space and size of free space found
	long freeSpaceAddr = 0;
	long freeSpaceSize = getProcessFreeSpace(TPID, &freeSpaceAddr);
	if(freeSpaceSize == 0) return;

printf("Tracee process stopped\n Free place found: %lx (%ld B free)\n",freeSpaceAddr, freeSpaceSize);

	//read code from file
	char tmpCode[] =
	"\x89\x7d\xec"
	"\x8b\x45\xec"
	"\x83\xc0\x01"
	"\x89\x45\xfc"
	"\x8b\x45\xfc"
	"\xcc";

	//save content of memory
	char * oldMemory = getTraceeMemory(TPID, freeSpaceAddr, sizeof(tmpCode) - 1);

	//set memory of tracee to injection code on free space
	setTraceeMemory(TPID, tmpCode, freeSpaceAddr, sizeof(tmpCode) - 1);

	//get registers of attached process

	//get registers of attached process & set them to free space place
	struct user_regs_struct writeRegisters, readRegisters;
	ptrace(PTRACE_GETREGS, TPID, NULL, &readRegisters);
	writeRegisters = readRegisters;
	writeRegisters.rip = freeSpaceAddr;
	ptrace(PTRACE_SETREGS, TPID, NULL, &writeRegisters);

	analyseStack(TPID, readRegisters.rsp);

	//detach from process
	ptrace(PTRACE_DETACH, TPID, NULL, NULL);
	
	//let tracee process continue
	kill(TPID, SIGCONT);

	//attach to process, make proces child process of yours, send SIGSTOP
	if(ptrace(PTRACE_ATTACH, TPID, NULL, NULL) == -1){
		perror("PTRACE ATTACH ERROR");
		return;
	}

	//wait child process to change state to stopped
	wait(NULL);

	//restore memory and registers
	setTraceeMemory(TPID, oldMemory, freeSpaceAddr, sizeof(tmpCode) - 1);
	//restore registers
	readRegisters.rip++;
	readRegisters.rax = writeRegisters.rax;
	ptrace(PTRACE_GETREGS, TPID, NULL, &writeRegisters);
	ptrace(PTRACE_SETREGS, TPID, NULL, &readRegisters);

	//detach from process
	ptrace(PTRACE_DETACH, TPID, NULL, NULL);
	
	//let tracee process continue
	kill(TPID, SIGCONT);

return;
/*
	//wait child process to change state to stopped
	wait(NULL);

	//find free space and size of free space found
	long freeSpaceAddr = 0;
	long freeSpaceSize = getProcessFreeSpace(TPID, &freeSpaceAddr);

	//read code from file to buffer
	char * codeString;
	size_t codeFileSize = 0;
	if((codeString = ReadPlainCode(codeFileName, &codeFileSize, freeSpaceSize)) == NULL)
		return;

printf("voalnie dokonce velkost %lu codeString '%s'\n", codeFileSize, codeString);
	//parse code to char form
	for(int idx = 0; idx < (codeFileSize/4); idx++){
		printf("[%d]%c %c %c %c\n", idx, codeString[idx*4], codeString[idx*4+1], codeString[idx*4+2], codeString[idx*4+3]);
	}

	char tmpCode[] =
	"\x89\x7d\xec"
	"\x8b\x45\xec"
	"\x83\xc0\x01"
	"\x89\x45\xfc"
	"\x8b\x45\xfc"
	"\xcc";

	//set memory of tracee to injection code on free space
	setTraceeMemory(TPID, tmpCode, freeSpaceAddr, sizeof(tmpCode) - 1);

	struct user_regs_struct readRegisters, writeRegisters, tmpRegs;

	//get registers of attached process
	ptrace(PTRACE_GETREGS, TPID, NULL, &readRegisters);
printf("Instruction pointer:\t%llx\nInjecting to address:\t%lx <- %ld B free\n", readRegisters.rip, (long)freeSpaceAddr, freeSpaceSize);

		//set instruction pointer to injected process
		writeRegisters = readRegisters;
		writeRegisters.rip = freeSpaceAddr;
		ptrace(PTRACE_SETREGS, TPID, NULL, &writeRegisters);

ptrace(PTRACE_GETREGS, TPID, NULL, &tmpRegs);
printf("Proces spusteny dalej s RIP registrom : %llx\n", tmpRegs.rip);

		//let tracee process continue
		ptrace(PTRACE_DETACH, TPID, NULL, NULL);


printf("Proces spustil modifikovany kod\n");

	//attach to process again
	if(ptrace(PTRACE_ATTACH, TPID, NULL, NULL) == -1){
		perror("PTRACE ATTACH ERROR");
		return;
	}

	sleep(2);
printf("Proces sa znova attachol na child\n");
ptrace(PTRACE_GETREGS, TPID, NULL, &tmpRegs);
printf("Instruction pointer po znovu attachnuti:\t%llx\n", tmpRegs.rip);

/*
		//set registers back
		readRegisters.rip++;
		ptrace(PTRACE_SETREGS, TPID, NULL, &readRegisters);
printf("Pustam proces dalej\n");
		//let tracee process continue
		kill(TPID, SIGCONT);

	//detach from process
	ptrace(PTRACE_DETACH, TPID, NULL, NULL);*/
}


int main(int argc, char ** argv)
{
	//parameter parsing
	int opt;
	while ((opt = getopt (argc, argv, "i:")) != -1)
    		switch (opt){
			//inject code to process with ptrace
			case 'i':
				processInjectToFreeSpace(atoi(optarg), "helloWorld-code"); //"helloWorld-code" TEMPORARY
			break;
      		default:
        		return 1;
	}

//	CipherCode(FILE_NAME, "\x70\x71\x72\x73", 4);

//	DecipherCode(FILE_NAME);

	return 0;
}
