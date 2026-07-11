#ifndef EXTRACT_H
#define EXTRACT_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <sys/types.h>

int extract_apk(char *argv[], char *output_dir)
{
    printf(HACKER_WHITE "\n[#] Extracting APK....\n\n");
    sleep(2);

    char cmd[8192];
    char full_path[2048];
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    char Half_path[2048];

    snprintf(full_path, sizeof(full_path), "%s/%s", cwd, argv[1]);
    snprintf(Half_path, sizeof(Half_path), "%s", cwd);

    snprintf(cmd, sizeof(cmd), "unzip %s -d %s/%s", full_path, Half_path, output_dir);
    system(cmd);

    printf("\n[#] APK Extracted And Saved\n");
    printf(COLOR_RESET);
    return 0;
}

#endif