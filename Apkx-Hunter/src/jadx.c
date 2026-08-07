/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#include "jadx.h"

int directory_exists(const char *path)
{
    struct stat st;

    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
    {
        return 1;
    }

    return 0;
}

int run_jadx(char *argv[], char *output_dir, int argc)
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

        if (argv[2] == NULL)
        {
            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s %s ", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }
            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }

            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "[OK] JADX decompiled successfully. Continuing analysis...\n" COLOR_RESET);
            stats.apks_scanned++;
            sleep(4);
        }

        else if ((secrets_2 == 1) || (permissions_2 == 1) || (patterns_2 == 1) || (masvs_2 == 1) || (file_scan_2 == 1))
        {
            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s %s ", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }

            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "[OK] JADX decompiled successfully. Continuing analysis...\n" COLOR_RESET);
            stats.apks_scanned++;
            sleep(4);
        }

        else if (decompile_2 == 1)
        {

            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s --deobf --deobf-min 3 --show-bad-code --escape-unicode --respect-bytecode-access-modifiers --threads-count 8 %s", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }
            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "\nDecompilation successful. Result Saved\n" COLOR_RESET);
            stats.apks_scanned++;
            return 0;
        }

        else if ((deep_2 == 1) && (decompile_2 == 1))
        {

            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s --deobf --deobf-min 3 --show-bad-code --escape-unicode --respect-bytecode-access-modifiers --threads-count 8 %s", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }

            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "\nDecompilation successful. Result Saved\n" COLOR_RESET);
            stats.apks_scanned++;
            return 0;
        }

        else if ((fast_2 == 1) && (decompile_2 == 1))
        {

            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s  %s", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }
            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "\nDecompilation successful. Result Saved\n" COLOR_RESET);
            stats.apks_scanned++;
            return 0;
        }

        else if ((deep_2 == 1))
        {

            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s --deobf --deobf-min 3 --show-bad-code --escape-unicode --respect-bytecode-access-modifiers --threads-count 8 %s", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }
            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "[OK] JADX decompiled successfully. Continuing analysis...\n" COLOR_RESET);
            stats.apks_scanned++;
            sleep(4);
        }

        else if ((fast_2 == 1))
        {

            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s  %s", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }

            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "[OK] JADX decompiled successfully. Continuing analysis...\n" COLOR_RESET);
            stats.apks_scanned++;
            sleep(4);
        }
    }
    else
    {
        return 1;
    }

    file_making(output_dir, argv, argc);
    return 0;
}

int run_jadx_1(char *argv[], char *full_path, char *output_dir, int argc)
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

        if (argv[2] == NULL || (multi_apk_2 == 1) || (extract_multi_apk_2 == 1))
        {
            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s %s ", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }
            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }

            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "[OK] JADX decompiled successfully. Continuing analysis...\n" COLOR_RESET);
            stats.apks_scanned++;
            sleep(4);
        }

        else if ((secrets_2 == 1) || (permissions_2 == 1) || (patterns_2 == 1) || (masvs_2 == 1) || (file_scan_2 == 1))
        {
            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s %s ", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }

            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "[OK] JADX decompiled successfully. Continuing analysis...\n" COLOR_RESET);
            stats.apks_scanned++;
            sleep(4);
        }

        else if (decompile_2 == 1)
        {

            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s --deobf --deobf-min 3 --show-bad-code --escape-unicode --respect-bytecode-access-modifiers --threads-count 8 %s", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }
            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "\nDecompilation successful. Result Saved\n" COLOR_RESET);
            stats.apks_scanned++;
            return 0;
        }

        else if ((deep_2 == 1) && (decompile_2 == 1))
        {

            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s --deobf --deobf-min 3 --show-bad-code --escape-unicode --respect-bytecode-access-modifiers --threads-count 8 %s", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }

            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "\nDecompilation successful. Result Saved\n" COLOR_RESET);
            stats.apks_scanned++;
            return 0;
        }

        else if ((fast_2 == 1) && (decompile_2 == 1))
        {

            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s  %s", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }
            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "\nDecompilation successful. Result Saved\n" COLOR_RESET);
            stats.apks_scanned++;
            return 0;
        }

        else if (deep_2 == 1)
        {

            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s --deobf --deobf-min 3 --show-bad-code --escape-unicode --respect-bytecode-access-modifiers --threads-count 8 %s", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }
            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "[OK] JADX decompiled successfully. Continuing analysis...\n" COLOR_RESET);
            stats.apks_scanned++;
            sleep(4);
        }

        else if (fast_2 == 1)
        {

            snprintf(cmd, sizeof(cmd), "jadx -d %s/%s  %s", Half_path, output_dir, full_path);

            int ret = system(cmd);
            int exit_code = WEXITSTATUS(ret);

            if (WIFSIGNALED(ret))
            {
                printf(HACKER_WHITE "\nKilled by signal = %d JADX Failed\n" COLOR_RESET, WTERMSIG(ret));
                return 1;
            }

            if (ret == -1)
            {
                printf(HACKER_WHITE "[ERROR] Unable to execute JADX.\n" COLOR_RESET);
                return 1;
            }

            if (!directory_exists(gd))
            {
                printf(HACKER_WHITE "[ERROR] JADX did not create the sources directory.\n" COLOR_RESET);
                return 1;
            }

            if (exit_code != 0)
            {
                printf(HACKER_WHITE "[WARNING] JADX completed with warnings (exit code %d).\n" COLOR_RESET, exit_code);
            }

            printf(HACKER_WHITE "[OK] JADX decompiled successfully. Continuing analysis...\n" COLOR_RESET);
            stats.apks_scanned++;
            sleep(4);
        }
    }
    else
    {
        return 1;
    }

    file_making(output_dir, argv, argc);
    return 0;
}


