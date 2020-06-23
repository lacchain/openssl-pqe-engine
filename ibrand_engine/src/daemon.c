// Functions used when running in the background

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>

#include "ibrand.h"

// Write PID in a file
static bool writePid(int32_t pid, char *fileName)
{
    FILE *pidFile;
    int ret;

    pidFile = fopen(fileName, "w");
    if (pidFile == NULL)
    {
        return false;
    }
    ret = fprintf(pidFile, "%d\n", pid);
    fclose(pidFile);
    return (ret >= 0);
}

void startDaemon(struct opt_struct* opts)
{
    int32_t pid;
    if (!opts->daemon)
    {
        // No backgrounding, optionally write current PID
        if (opts->pidFileName != NULL)
        {
            writePid(getpid(), opts->pidFileName);
        }
        return;
    }
    pid = fork();
    if (pid < 0)
    {
        fputs("fork() failed\n", stderr);
        exit(1);
    }
    if (pid > 0)
    {
        // Parent
        exit(opts->pidFileName != NULL && !writePid(pid, opts->pidFileName));
    }
    // Child
}
