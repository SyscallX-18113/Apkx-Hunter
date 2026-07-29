/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef EXTRACT_H
#define EXTRACT_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <limits.h>
#include <sys/types.h>
#include "multi_apk.h"



int folder(const char *path)
{
    struct stat statbuf;
    if (stat(path, &statbuf) == 0)
    {
        return S_ISDIR(statbuf.st_mode);
    }
    return 0;
}

void count_apks(const char *folder)
{
    DIR *dir = opendir(folder);

    if (dir == NULL)
        return;

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char path[2048];
        snprintf(path, sizeof(path), "%s/%s", folder, entry->d_name);

        struct stat st;

        if (stat(path, &st) == 0)
        {
            if (S_ISDIR(st.st_mode))
            {
                
                count_apks(path);
            }
            else if (S_ISREG(st.st_mode))
            {
                const char *ext = strrchr(entry->d_name, '.');

                if (ext && strcmp(ext, ".apk") == 0)
                {
                    apk_count++;
                }
            }
        }
    }

    closedir(dir);
}

int extract_apk(char *argv[], char *output_dir)
{
    printf(HACKER_WHITE "\n[#] Extracting APK....\n\n");
    sleep(4);

    char cmd[10240];
    char full_path[4096];
    char cwd[2048];
    getcwd(cwd, sizeof(cwd));
    char Half_path[4096];
    char Path[8192];
    snprintf(full_path, sizeof(full_path), "%s/%s", cwd, argv[1]);
    snprintf(Half_path, sizeof(Half_path), "%s", cwd);
    snprintf(Path, sizeof(Path), "%s/%s", Half_path, output_dir);

    if (folder(Path))
    {
        printf("\n[#] Folder Already Exist!\n");
        return 1;
    }

    snprintf(cmd, sizeof(cmd), "unzip %s -d %s/%s > /dev/null 2>&1", full_path, Half_path, output_dir);
    system(cmd);
    

    if (folder(Path))
    {
        printf("\n[#] APK Extracted And Saved\n");
    }
    else
    {
        printf("File doesn's Exist");
    }
    
    
    printf(COLOR_RESET);
    return 0;
}

int extract_apk_1(int argc, char *argv[], char *output_dir)
{
    printf(HACKER_WHITE "\n[#] Extracting APK....\n\n");
    sleep(2);

    char cmd[10240];
    char full_path[4096];
    char cwd[2048];
    getcwd(cwd, sizeof(cwd));
    char Half_path[4096];
    char Path[8192];
    char folder_path[6000];
    char ch;

    
    snprintf(full_path, sizeof(full_path), "%s/%s", cwd, argv[1]);
    snprintf(Half_path, sizeof(Half_path), "%s", cwd);
    snprintf(folder_path, sizeof(folder_path), "%s/%s", Half_path, output_dir);
    snprintf(Path, sizeof(Path), "%s/%s", Half_path, output_dir);



    if (folder(Path))
    {
        printf("\n[#] Folder Already Exist\n");
        return 1;
    }
    
    snprintf(cmd, sizeof(cmd), "unzip %s -d %s/%s > /dev/null 2>&1", full_path, Half_path, output_dir);
    system(cmd);

    if (folder(Path))
    {
        printf("\n[#] APK Extracted Starting Scanning...\n");
        sleep(2);
    }
    else
    {
        printf("File doesn's Exist");
        return 1;
    }

    count_apks(folder_path);
    printf("\nApks Detected: %d APK(s).\n", apk_count);
    printf("Do you want to scan them? [Y/N]: ");
    scanf("%c", &ch);

    if (ch == 'y' || ch == 'Y')
    {
    scan_multi_apk(folder_path, argc, argv);
    }
    else
    {
        printf("Scan Terminated.");
        return 0;
    }

    
    
    
    printf(COLOR_RESET);

}

#endif
