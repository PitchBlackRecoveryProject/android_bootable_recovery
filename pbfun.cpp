#include <sys/types.h>
#include <stdint.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <sys/mman.h>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include "twrp-functions.hpp"

#define MAGIC "AVBf"
#define MAGIC_PATCH "AVBe"

using namespace std;

static char hexMap[]={
	'0','1','2','3','4','5','6','7',
	'8','9','A','B','C','D','E','F'
	};

std::string str2hex(const char *str)
{
	int l=strlen(str);
	string hexStr = "";
	for (int index=0; index < l; index++) {
		for (int ch=str[index]; ch > 0; ch/=16) {
			hexStr+= hexMap[ch/16];
			if (ch%16 != 0)
				hexStr += hexMap[ch%16];
			ch /= 16;

		}
		if (strlen(hexStr.c_str()) == 1)
			hexStr += "0";
	}
	return hexStr;
}

static void hex2byte(uint8_t *hex, uint8_t *str) {
	char high, low;
	for (int i = 0, length = strlen((char *) hex); i < length; i += 2) {
		high = toupper(hex[i]) - '0';
		low = toupper(hex[i + 1]) - '0';
		str[i / 2] = ((high > 9 ? high - 7 : high) << 4) + (low > 9 ? low - 7 : low);
	}
}

int PBFunc::patchAVB(const char *image) {
	string hexMagic, hexMagicPatch;
	hexMagic = str2hex(MAGIC);
	hexMagicPatch = str2hex(MAGIC_PATCH);
	int patternsize = strlen(hexMagic.c_str()) / 2, patchsize = strlen(hexMagicPatch.c_str()) / 2;
	int patched = 1;
	size_t filesize;
	uint8_t *file, *pattern, *patch;
	struct stat st;
	printf ("%s\n", image);
	int fd = open(image, O_RDWR | O_CLOEXEC);
	fstat(fd, &st);
	if (S_ISBLK(st.st_mode))
		ioctl(fd, BLKGETSIZE64, &filesize);
	else
		filesize = st.st_size;
	file = (uint8_t*)(filesize > 0 ? mmap(nullptr, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) : nullptr);
	if (file == nullptr) {
		fprintf(stderr, "Invalid File [%s] \n", image);
		exit(1);
	}
	close(fd);
	pattern = new uint8_t[patternsize];
	patch = new uint8_t[patchsize];
	hex2byte((uint8_t *) hexMagic.c_str(), pattern);
	hex2byte((uint8_t *) hexMagicPatch.c_str(), patch);
	for (size_t i = 0; i < filesize - patternsize; ++i) {
		if (memcmp(file + i, pattern, patternsize) == 0) {
			memset(file + i, 0, patternsize);
			memcpy(file + i, patch, patchsize);
			i += patternsize - 1;
			patched = 0;
		}
	}
	munmap(file, filesize);
	delete pattern;
	delete patch;

	return patched;
}
