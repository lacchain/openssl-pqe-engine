// This writes entropy to the Linux /dev/random pool using ioctl, so that entropy increases.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/random.h>
#include "libibrand.h"

#define SIZE_PROC_FILENAME "/proc/sys/kernel/random/poolsize"
#define FILL_PROC_FILENAME "/proc/sys/kernel/random/write_wakeup_threshold"

static struct pollfd pfd;
static uint32_t inmFillWatermark;
static struct rand_pool_info *inmPoolInfo;

// Find the entropy pool size.
static uint32_t readNumberFromFile(char *fileName)
{
    FILE *file = fopen(fileName, "r");
    if(file == NULL)
    {
        app_tracef("[ibrand_lib] FATAL: Unable to open %s\n", fileName);
        exit(455);
    }

    uint32_t value = 0u;
    char c;
    while( ((c = getc(file)) != EOF) && ('0' <= c) && (c <= '9') )
    {
        value *= 10;
        value += c - '0';
    }
    fclose(file);
    return value;
}

// Open /dev/random
void inmWriteEntropyStart(uint32_t bufLen, bool debug)
{
    pfd.events = POLLOUT;

    //pfd.fd = open("/dev/random", O_WRONLY);
    pfd.fd = open("/dev/random", O_RDWR);
    if(pfd.fd < 0)
    {
        app_tracef("[ibrand_lib] FATAL: Unable to open /dev/random\n");
        exit(456);
    }

    inmPoolInfo = calloc(1, sizeof(struct rand_pool_info) + bufLen);
    if(inmPoolInfo == NULL)
    {
        app_tracef("[ibrand_lib] FATAL: Unable to allocate memory\n");
        exit(457);
    }

    inmFillWatermark = readNumberFromFile(FILL_PROC_FILENAME);
        app_tracef("[ibrand_lib] FATAL: readNumberFromFile failed\n");
    if(debug)
    {
        app_tracef("Entropy pool size:%u, fill watermark:%u\n", readNumberFromFile(SIZE_PROC_FILENAME), inmFillWatermark);
    }
}

void inmWriteEntropyEnd()
{
    free( inmPoolInfo );
}

// Block until either the entropy pool has room, or 1 minute has passed.
void inmWaitForPoolToHaveRoom()
{
    int ent_count;

    if (ioctl(pfd.fd, RNDGETENTCNT, &ent_count) == 0 && (uint32_t)ent_count < inmFillWatermark)
    {
        return;
    }
    poll(&pfd, 1, -1); // waits until /dev/random is in usage
}

// Add the bytes to the entropy pool.  This can be unwhitenened, but the estimated bits of
// entropy needs to be accurate or pessimistic.  Return false if the Linux entropy pool is
// full after writing.
void inmWriteEntropyToPool(uint8_t *bytes, uint32_t length, uint32_t entropy)
{
    inmPoolInfo->entropy_count = entropy;
    inmPoolInfo->buf_size = length;
    memcpy(inmPoolInfo->buf, bytes, length);
    //app_tracef("Writing %u bytes with %u bits of entropy to /dev/random\n", length, entropy);
    ioctl(pfd.fd, RNDADDENTROPY, inmPoolInfo);
}
