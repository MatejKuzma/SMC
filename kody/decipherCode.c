void decipherCode(char * codeAddress, long codeSize, int key)
{
    for(int idx = 0; idx < codeSize; idx++)
        codeAddress[idx] = (codeAddress[idx] - key) % 255;
}