#include <stdint.h>
#include <stdio.h>
#include <execinfo.h>
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

void guardMe(const unsigned int address, const unsigned int length, const unsigned int expectedHash, const unsigned int uid, int *reported_tamper){

	const unsigned char  *beginAddress = (const unsigned char *)address;
	unsigned int visited = 0;
	unsigned char hash = 0;

	#pragma clang loop vectorize(disable)
	while (visited < length) {
		hash ^= *beginAddress++;
		++visited;
	}
	if (*reported_tamper == 0 && hash !=(unsigned char)expectedHash) {
		printf("%sTampered binary (id = %u)!, expected != computed (%#x != %#hhx) \n",
			KNRM, uid, expectedHash, hash);
		*reported_tamper = 1;
	}
}

void logHash() {
	//printf("final hash: %ld\n", hash);
}
