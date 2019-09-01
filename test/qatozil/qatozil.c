#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>

/* "0." +  39 digits in UINT128_MAX + '\0' */
#define MAX_BUF_LEN 42

#define QA_ZIL_SHIFT 12
#define LI_ZIL_SHIFT 6

/* Filter out leading zero's and non-digit characters in a null terminated string. */
void cleanse_input(char *buf) {
  int len = strlen(buf);
  assert (len < MAX_BUF_LEN);
  int nextpos = 0;
  bool seen_nonzero = false;

  for (int i = 0; i < len; i++) {
    char c = buf[i];
    if (c == '0' && !seen_nonzero) {
      continue;
    }
    if (isdigit(c)) {
      seen_nonzero = true;
      buf[nextpos++] = c;
    }
  }
  assert (nextpos <= len);

  if (nextpos == 0)
    buf[nextpos++] = '0';

  buf[nextpos] = '\0';
}

/* Removing trailing 0s and ".". */
void remove_trailing_zeroes(char *buf)
{
  int len = strlen(buf);
  assert(len < MAX_BUF_LEN);

  for (int i = len-1; i >= 0; i--) {
    if (buf[i] == '0')
      buf[i] = '\0';
    else if (buf[i] == '.') {
      buf[i] = '\0';
      break;
    } else {
      break;
    }
  }
}

/* Given a null terminated sequence of digits (value < UINT128_MAX),
 * divide it by "shift" and pretty print the result. */
void ToZil(char *input, char *output, int shift)
{
  int len = strlen(input);
  assert(len > 0 && len < MAX_BUF_LEN);
  assert(shift == QA_ZIL_SHIFT || shift == LI_ZIL_SHIFT);

  if (len <= shift) {
    strcpy(output, "0.");
    /* Insert (shift - len) 0s. */
    for (int i = 0; i < (shift - len); i++) {
      /* A bit inefficient, but it's ok, at most shift iterations. */
      strcat(output, "0");
    }
    strcat(output, input);
    remove_trailing_zeroes(output);
    return;
  }

  /* len >= shift+1. Copy the first len-shift characters. */
  strncpy(output, input, len - shift);
  /* append a decimal point. */
  strcpy(output + len - shift, ".");
  /* copy the remaining characters in input. */
  strcat(output, input + len - shift);
  /* Remove trailing zeroes (after the decimal point). */
  remove_trailing_zeroes(output);
}


int main(int argc, char *argv[])
{
  char qabuf[MAX_BUF_LEN], zilbuf[MAX_BUF_LEN];

  if (argc != 2 || strlen(argv[1]) > 39) {
    fprintf(stderr, "Usage: ./qatozil Qa [length of Qa <= 39 digits]\n");
    exit(1);
  }

  /* Copy to a local buffer. */
  strcpy(qabuf, argv[1]);
  /* Cleanse the input. */
  cleanse_input(qabuf);
  /* Convert Qa to Zil. */
  ToZil(qabuf, zilbuf, QA_ZIL_SHIFT);
  /* Print output. */
  printf("%s\n", zilbuf);

  return 0;
}
