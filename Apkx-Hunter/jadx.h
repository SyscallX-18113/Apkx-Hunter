#ifndef JADX_H
#define JADX_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "define.h"
#include "file_making.h"

int run_jadx(char *argv[], char *output_dir, int argc)
{

    char cmd[8192];
    char full_path[2048];
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    char Half_path[2048];

    snprintf(full_path, sizeof(full_path), "%s/%s", cwd, argv[1]);
    snprintf(Half_path, sizeof(Half_path), "%s", cwd);

    check_apk(full_path);

    if (argv[2] == NULL)
    {
        snprintf(cmd, sizeof(cmd), "jadx -d %s/%s %s", Half_path, output_dir, full_path);

        system(cmd);
    }

    else if (argc >= 4 && strcmp(argv[2], DEEP) == 0 && strcmp(argv[3], DECOMPILE) == 0)
    {

        snprintf(cmd, sizeof(cmd), "jadx -d %s/%s --deobf --deobf-min 3 --show-bad-code --escape-unicode --respect-bytecode-access-modifiers --threads-count 8 %s", Half_path, output_dir, full_path);

        system(cmd);
        printf(HACKER_WHITE "\nDecompilation successful\n" COLOR_RESET);
        return 0;
    }

    else if (argc >= 4 && strcmp(argv[2], FAST) == 0 && strcmp(argv[3], DECOMPILE) == 0)
    {

        snprintf(cmd, sizeof(cmd), "jadx -d %s/%s  %s", Half_path, output_dir, full_path);

        system(cmd);
        printf(HACKER_WHITE "\nDecompilation successful\n" COLOR_RESET);
        return 0;
    }

    else if (strcmp(argv[2], DEEP) == 0)
    {

        snprintf(cmd, sizeof(cmd), "jadx -d %s/%s --deobf --deobf-min 3 --show-bad-code --escape-unicode --respect-bytecode-access-modifiers --threads-count 8 %s", Half_path, output_dir, full_path);

        system(cmd);
    }

    else if (strcmp(argv[2], FAST) == 0)
    {

        snprintf(cmd, sizeof(cmd), "jadx -d %s/%s  %s", Half_path, output_dir, full_path);

        system(cmd);
    }

    file_making(output_dir, argv, argc);
    return 0;
}

#endif