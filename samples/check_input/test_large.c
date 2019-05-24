#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char org_serial[] = "this_be_da_serial";
char serial[] = "vjkq]`g]fc]qgpkcn";

// __attribute__((noinline))
// __attribute__((annotate("sc_virtualize")))
inline static int check_input(const char *s) {
  int result = 0;
  for (int i = 0; i < sizeof(serial); ++i) {
    int shift = (s[i] - serial[i]) != 0;
    result |= ((int)shift) << i;
  }
  return result;
}

// __attribute__((noinline))
inline static int transform_input(char *s) {
  int len = strlen(s);
	if (len == 0)
		return -1;

  for (int i = 0; i < len; ++i)
    s[i] ^= 0x02;

  return 0;
}

__attribute__((annotate("sc_virtualize")))
int main(int argc, const char **argv) {
  char buf[21];
  scanf("%20s", buf);
  buf[20] = 0;

  char *input = (char*)calloc(21, 1);
  if (!input) {
    printf("Could not allocate memory\n");
    return -2;
  }

  strncpy(input, buf, 21);
  transform_input(input);

  int ret = check_input(input);
  if (ret == 0) {
    printf("success\n");
    return 0;
  } else {
    printf("failed\n");
    return -1;
  }
}
