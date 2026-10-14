#include <stdio.h>

/* A tiny, self-contained program we fully own, used to prove the patcher
 * rewrites bytes correctly and the result still runs. main() prints one of
 * two strings depending on a value the test will patch. */
int decide(void) { return 0; }

int main(void) {
    if (decide())
        printf("PATCHED\n");
    else
        printf("ORIGINAL\n");
    return 0;
}
