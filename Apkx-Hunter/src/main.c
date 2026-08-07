/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <sys/types.h>
#include <stddef.h>
#include "define.h"
#include "banner.h"
#include "patterns.h"
#include "functions.h"
#include "jadx.h"
#include "scan_secrets.h"
#include "apktool.h"
#include "extract.h"
#include "multi_apk.h"
#include "masvs.h"
#define MODEL_PATH "/usr/share/apkx-hunter/model.bin"
#define MODEL_PATH_1 "model/model.bin"

int main(int argc, char *argv[])
{

    for (int i = 2; i < argc; i++)
    {
        int found = 0;

        for (int j = 0; j < valid_flag_count; j++)
        {
            if (strcmp(argv[i], valid_flags[j]) == 0)
            {
                found = 1;
                break;
            }
        }

        if (!found)
        {
            printf(HACKER_WHITE "Error: Unknown option '%s'\n" COLOR_RESET, argv[i]);
            printf(HACKER_WHITE "Use --help to see available options.\n" COLOR_RESET);
            return 1;
        }
    }

    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], DEEP) == 0)
            deep_2 = 1;

        else if (strcmp(argv[i], FAST) == 0)
            fast_2 = 1;

        else if (strcmp(argv[i], EXTRACT_MULTI_APK) == 0)
            extract_multi_apk_2 = 1;

        else if (strcmp(argv[i], SECRETS) == 0)
            secrets_2 = 1;

        else if (strcmp(argv[i], FOLDER_SCAN) == 0)
            folder_scan_2 = 1;

        else if (strcmp(argv[i], PERMISSIONS) == 0)
            permissions_2 = 1;

        else if (strcmp(argv[i], PATTERNS) == 0)
            patterns_2 = 1;

        else if (strcmp(argv[i], DECOMPILE) == 0)
            decompile_2 = 1;

        else if (strcmp(argv[i], FILE_SCAN) == 0)
            file_scan_2 = 1;

        else if (strcmp(argv[i], APKTOOL) == 0)
            apktool_2 = 1;

        else if (strcmp(argv[i], APKTOOL_SCAN) == 0)
            apktool_scan_2 = 1;

        else if (strcmp(argv[i], MULTI_APK) == 0)
            multi_apk_2 = 1;

        else if (strcmp(argv[i], EXTRACT) == 0)
            extract_2 = 1;

        else if (strcmp(argv[i], MASVS) == 0)
            masvs_2 = 1;

        else if (strcmp(argv[i], INSTALL) == 0)
            install = 1;    
    }

    if (multi_apk_2)
    {
        silent_mode = 2;
    }

    init_bucket_regexes();
    print_banner();

    if (access(MODEL_PATH, F_OK) != 0 &&
        access(MODEL_PATH_1, F_OK) != 0)
    {
        printf(HACKER_WHITE);
        printf("\n[ERROR] AI model not found!\n");
        printf("Expected location:\n");
        printf("%s\n", MODEL_PATH);
        printf("Or the current working directory.\n");
        printf("Secret Detection cannot run without model.bin.\n\n");
        printf(COLOR_RESET);

        return 1;
    }

    if (argc == 1)
    {
        printf(HACKER_WHITE "Usage: %s <apk|folder> --deep | --fast | --folder-scan OR %s --help \n" COLOR_RESET, argv[0], argv[0]);
        return 0;
    }

    if (strcmp(argv[1], HELP) == 0)
    {
        help_func();
        return 0;
    }

    
    if (strcmp(argv[1], INSTALL) == 0)
    {
        install_missing_dependencies();
        return 0;
    }

    if ((strstr(argv[1], ".apk") == NULL) && (multi_apk_2 == 1))
    {
        char full_path[3000];
        char cwd[1024];
        getcwd(cwd, sizeof(cwd));

        snprintf(full_path, sizeof(full_path), "%s/%s", cwd, argv[1]);

        struct stat st;

        if (stat(full_path, &st) != 0)
        {
            printf("Not a directory.\n");
            return 0;
        }

        scan_multi_apk(full_path, argc, argv);

        return 0;
    }

    if (argc >= 3 && (extract_multi_apk_2 == 1) && (strstr(argv[1], ".apkm") != NULL || strstr(argv[1], ".xapk") != NULL || strstr(argv[1], ".apks") != NULL || strstr(argv[1], ".zip") != NULL))
    {
        char output_dir[512];

        char *apk_name = argv[1];
        char *dot = strstr(apk_name, ".apk");

        char *dot_1 = strstr(apk_name, ".zip");

        if (dot || dot_1)
        {
            ptrdiff_t len = dot - apk_name;
            snprintf(output_dir, sizeof(output_dir),
                     "EXTRACTED_MULTI_APK_%.*s", (int)len, apk_name);
        }
        else
        {
            snprintf(output_dir, sizeof(output_dir),
                     "output_default");
        }
        extract_apk_1(argc, argv, output_dir);
        return 0;
    }

    if (argc >= 3 && (extract_2 == 1) && (strstr(argv[1], ".apkm") != NULL || strstr(argv[1], ".xapk") != NULL || strstr(argv[1], ".apks") != NULL || strstr(argv[1], ".zip") != NULL))
    {
        char output_dir[256];

        char *apk_name = argv[1];
        char *dot = strstr(apk_name, ".apk");
        char *dot_1 = strstr(apk_name, ".zip");

        if (dot || dot_1)
        {
            ptrdiff_t len = dot - apk_name;
            snprintf(output_dir, sizeof(output_dir),
                     "extracted_output_%.*s", (int)len, apk_name);
        }
        else
        {
            snprintf(output_dir, sizeof(output_dir),
                     "output_default");
        }
        extract_apk(argv, output_dir);
        return 0;
    }

    if ((strstr(argv[1], ".apk") == NULL) && (folder_scan_2 == 1))
    {
        file_making(argv[1], argv, argc);
        cleanup_bucket_regexes();
        return 0;
    }

    if ((strstr(argv[1], ".apk") == NULL) && (apktool_scan_2 == 1))
    {
        file_making_for_apktool(argv[1], argv, argc);
        cleanup_bucket_regexes();
        return 0;
    }

    if ((strstr(argv[1], ".apk") != NULL) && (apktool_2 == 1))
    {

        char output_dir[256];

        char *apk_name = argv[1];
        char *dot = strstr(apk_name, ".apk");

        if (dot)
        {
            ptrdiff_t len = dot - apk_name;
            snprintf(output_dir, sizeof(output_dir),
                     "Apktool_output_%.*s", (int)len, apk_name);
        }
        else
        {
            snprintf(output_dir, sizeof(output_dir),
                     "output_default");
        }
        run_apktool(argv, output_dir, argc);
        cleanup_bucket_regexes();
        return 0;
    }

    if (strstr(argv[1], ".apk") != NULL && !extract_2)
    {

        char output_dir[256];

        char *apk_name = argv[1];
        char *dot = strstr(apk_name, ".apk");

        if (dot)
        {
            ptrdiff_t len = dot - apk_name;
            snprintf(output_dir, sizeof(output_dir),
                     "Jadx_output_%.*s", (int)len, apk_name);
        }
        else
        {
            snprintf(output_dir, sizeof(output_dir),
                     "output_default");
        }

        run_jadx(argv, output_dir, argc);
        cleanup_bucket_regexes();
        return 0;
    }

    printf(HACKER_WHITE "Invalid input\n" COLOR_RESET);
    cleanup_bucket_regexes();

    return 0;
}