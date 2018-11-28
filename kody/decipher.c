//simple shift cipher, mode TRUE == cipher FALSE == decipher
void decipherAlgorithm(char * ct, int ctLen){
	//decipher process
	for(int idx = 0; idx < ctLen; idx++)
		ct[idx] = (ct[idx] - 3) % 255;
}
