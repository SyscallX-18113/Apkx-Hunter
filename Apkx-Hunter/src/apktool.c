/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#include "apktool.h"

int run_apktool(char *argv[], char *output_dir, int argc)
{

    char cmd[10240];
    char full_path[4096];
    char cwd[3072];
    getcwd(cwd, sizeof(cwd));
    char Half_path[4096];
    char gd[5000];

    snprintf(full_path, sizeof(full_path), "%s/%s", cwd, argv[1]);
    snprintf(Half_path, sizeof(Half_path), "%s", cwd);
    snprintf(gd, sizeof(gd), "%s/%s", Half_path, output_dir);

    check_apk(full_path);
    compute_hashes(full_path);

    if (not_valid_apk == 0)
    {

        if (argc == 3)
        {

            snprintf(cmd, sizeof(cmd), "apktool d -f %s -o %s/%s", full_path, Half_path, output_dir);

            int ret = system(cmd);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "\n[ERROR] Failed to execute APKTOOL.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] APKTOOL did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }
            if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0)
            {
                printf(HACKER_WHITE "\n[WARNING] APKTOOL completed with warnings (Exit Code %d).\n" COLOR_RESET, WEXITSTATUS(ret));
            }

            printf(HACKER_WHITE "[OK] APKTOOL decompiled successfully. Starting the Scanning Process\n" COLOR_RESET);
            stats.apks_scanned++;
        }

        else if (argc == 4 && ((secrets_2 == 1) || (permissions_2 == 1) || (patterns_2 == 1) || (extract_2 == 1) || (masvs_2 == 1) || (file_scan_2 == 1)))
        {

            snprintf(cmd, sizeof(cmd), "apktool d -f %s -o %s/%s", full_path, Half_path, output_dir);

            int ret = system(cmd);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "\n[ERROR] Failed to execute APKTOOL.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] APKTOOL did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }
            if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0)
            {
                printf(HACKER_WHITE "\n[WARNING] APKTOOL completed with warnings (Exit Code %d).\n" COLOR_RESET, WEXITSTATUS(ret));
            }

            printf(HACKER_WHITE "[OK] APKTOOL decompiled successfully. Starting the Scanning Process\n" COLOR_RESET);
            stats.apks_scanned++;
        }

        else if (argc == 4 && (decompile_2 == 1))
        {

            snprintf(cmd, sizeof(cmd), "apktool d -f %s -o %s/%s", full_path, Half_path, output_dir);

            int ret = system(cmd);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "\n[ERROR] Failed to execute APKTOOL.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] APKTOOL did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }
            if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0)
            {
                printf(HACKER_WHITE "\n[WARNING] APKTOOL completed with warnings (Exit Code %d).\n" COLOR_RESET, WEXITSTATUS(ret));
            }

            printf(HACKER_WHITE "\nDecompilation successful. Result Saved\n" COLOR_RESET);
            stats.apks_scanned++;
            return 0;
        }
    }
    else
    {
        return 1;
    }

    file_making_for_apktool(output_dir, argv, argc);
    return 0;
}

int run_apktool_1(char *argv[], char *full_path, char *output_dir, int argc)
{

    char cmd[10240];
    char cwd[3072];
    getcwd(cwd, sizeof(cwd));
    char Half_path[4096];
    char gd[5000];

    snprintf(Half_path, sizeof(Half_path), "%s", cwd);
    snprintf(gd, sizeof(gd), "%s/%s", Half_path, output_dir);

    check_apk(full_path);
    compute_hashes(full_path);

    if (not_valid_apk == 0)
    {
        if ((secrets_2 == 1) || (permissions_2 == 1) || (patterns_2 == 1) || (extract_2 == 1) || (masvs_2 == 1) || (file_scan_2 == 1) || (multi_apk_2 == 1) || (extract_multi_apk_2 == 1))
        {

            snprintf(cmd, sizeof(cmd), "apktool d -f %s -o %s/%s", full_path, Half_path, output_dir);

            int ret = system(cmd);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "\n[ERROR] Failed to execute APKTOOL.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] APKTOOL did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }
            if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0)
            {
                printf(HACKER_WHITE "\n[WARNING] APKTOOL completed with warnings (Exit Code %d).\n" COLOR_RESET, WEXITSTATUS(ret));
            }

            printf(HACKER_WHITE "[OK] APKTOOL decompiled successfully. Starting the Scanning Process\n" COLOR_RESET);
            stats.apks_scanned++;
        }

        else if (argc == 4 && ((decompile_2 == 1) || (multi_apk_2 == 1 || extract_multi_apk_2 == 1)))
        {

            snprintf(cmd, sizeof(cmd), "apktool d -f %s -o %s/%s", full_path, Half_path, output_dir);

            int ret = system(cmd);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "\n[ERROR] Failed to execute APKTOOL.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] APKTOOL did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }
            if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0)
            {
                printf(HACKER_WHITE "\n[WARNING] APKTOOL completed with warnings (Exit Code %d).\n" COLOR_RESET, WEXITSTATUS(ret));
            }

            printf(HACKER_WHITE "\nDecompilation successful. Result Saved\n" COLOR_RESET);
            stats.apks_scanned++;
            return 0;
        }
    }
    else
    {
        return 1;
    }

    file_making_for_apktool(output_dir, argv, argc);
    return 0;
}
