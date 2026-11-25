/*
 * EmberScan dynamic-analysis ground-truth sample.
 *
 * Deliberately vulnerable. Each marked line is reachable under emulation after
 * a single `read(0, ...)` taints `line`, and should produce exactly one finding
 * from the corresponding detector. Build with tests/build_test_binaries.sh.
 *
 * Expected findings from `emberscan analyze`:
 *   strcpy(buf, input)  -> taint      : buffer overflow            (CWE-120)
 *   printf(input)       -> info_leak  : format string             (CWE-134)
 *   system(input)       -> taint      : command injection         (CWE-78)
 *   srand(time(NULL))   -> weak_code  : predictable PRNG seed      (CWE-337)
 *   rand()              -> weak_code  : insecure PRNG              (CWE-338)
 *
 * NOTE: compiled -fno-stack-protector so a stack canary does not abort the run
 * before the sinks are reached. Not for production — a test fixture only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

void handle(char *input)
{
    char buf[64];
    strcpy(buf, input);   /* taint: tainted -> unbounded copy  (CWE-120) */
    printf(input);        /* info_leak: tainted format string  (CWE-134) */
    system(input);        /* taint: tainted -> command exec    (CWE-78)  */
    (void)buf;
}

int main(void)
{
    char line[256];

    /* taint source: the backend/detector marks `line` tainted on this call */
    read(0, line, sizeof(line));

    srand(time(NULL));    /* weak_code: predictable seed (CWE-337) */
    (void)rand();         /* weak_code: insecure PRNG    (CWE-338) */

    handle(line);
    return 0;
}
