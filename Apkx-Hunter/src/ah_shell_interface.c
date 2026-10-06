
/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#include "ah_shell_interface.h"

int run_command(int shell_argc, char *shell_argv[])
{

    if ((strstr(shell_argv[1], ".apk") == NULL) && (multi_apk_2 == 1))
    {
        char full_path[3000];
        char cwd[1024];
        getcwd(cwd, sizeof(cwd));

        snprintf(full_path, sizeof(full_path), "%s/%s", cwd, shell_argv[1]);

        struct stat st;

        if (stat(full_path, &st) != 0)
        {
            printf(HACKER_WHITE "Not a directory ):\n" COLOR_RESET);
            return 0;
        }
        model_init();

        scan_multi_apk(full_path, shell_argc, shell_argv);

        return 0;
    }

    if (shell_argc >= 3 && (extract_multi_apk_2 == 1) && (strstr(shell_argv[1], ".apkm") != NULL || strstr(shell_argv[1], ".xapk") != NULL || strstr(shell_argv[1], ".apks") != NULL || strstr(shell_argv[1], ".zip") != NULL))
    {
        char output_dir[512];

        char *apk_name = shell_argv[1];
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
        model_init();
        extract_apk_1(shell_argc, shell_argv, output_dir);
        return 0;
    }

    if (shell_argc >= 3 && (extract_2 == 1) && (strstr(shell_argv[1], ".apkm") != NULL || strstr(shell_argv[1], ".xapk") != NULL || strstr(shell_argv[1], ".apks") != NULL || strstr(shell_argv[1], ".zip") != NULL))
    {
        char output_dir[256];

        char *apk_name = shell_argv[1];
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
        model_init();
        extract_apk(shell_argv, output_dir);
        return 0;
    }

    if ((strstr(shell_argv[1], ".apk") == NULL) && (folder_scan_2 == 1))
    {

        char full_path[3000];
        char cwd[1024];
        getcwd(cwd, sizeof(cwd));

        snprintf(full_path, sizeof(full_path), "%s/%s", cwd, shell_argv[1]);

        struct stat st;

        if (stat(full_path, &st) != 0)
        {
            printf(HACKER_WHITE "Directory not found ):\n" COLOR_RESET);
            return 0;
        }
        model_init();
        file_making(shell_argv[1], shell_argv, shell_argc);
        cleanup_bucket_regexes();
        return 0;
    }

    if ((strstr(shell_argv[1], ".apk") == NULL) && (apktool_scan_2 == 1))
    {
        char full_path[3000];
        char cwd[1024];
        getcwd(cwd, sizeof(cwd));

        snprintf(full_path, sizeof(full_path), "%s/%s", cwd, shell_argv[1]);

        struct stat st;

        if (stat(full_path, &st) != 0)
        {
            printf(HACKER_WHITE "Directory not found ):\n" COLOR_RESET);
            return 0;
        }

        model_init();
        file_making_for_apktool(shell_argv[1], shell_argv, shell_argc);
        cleanup_bucket_regexes();
        return 0;
    }

    if ((strstr(shell_argv[1], ".apk") != NULL) && (apktool_2 == 1))
    {

        char output_dir[256];

        char *apk_name = shell_argv[1];
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
        model_init();
        run_apktool(shell_argv, output_dir, shell_argc);
        cleanup_bucket_regexes();
        return 0;
    }

    if (strstr(shell_argv[1], ".apk") != NULL && !extract_2)
    {

        char output_dir[256];

        char *apk_name = shell_argv[1];
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

        model_init();

        run_jadx(shell_argv, output_dir, shell_argc);
        cleanup_bucket_regexes();
        return 0;
    }
}

int parse_shell_args(char *command, char **shell_argv)
{
    int shell_argc = 0;

    char *token = strtok(command, " \t");

    while (token != NULL && shell_argc < MAX_SHELL_ARGS)
    {
        shell_argv[shell_argc] = token;
        shell_argc++;

        token = strtok(NULL, " \t");
    }

    return shell_argc;
}

int command_line()
{

    printf(HACKER_WHITE);

    char command[500];

    while (1)
    {
        init_bucket_regexes();
        reset_command_state();

        printf("\n");
        char *input = readline(COLOR_BLUE "Apkx-Hunter--> " COLOR_RESET);

        if (input == NULL)
            break;

        if (strlen(input) == 0)
        {
            free(input);
            continue;
        }

        add_history(input);

        strncpy(command, input, sizeof(command) - 1);
        command[sizeof(command) - 1] = '\0';

        free(input);

        char *shell_argv[MAX_SHELL_ARGS];

        int shell_argc = parse_shell_args(command, shell_argv);

        if (shell_argc == 0)
            continue;

        for (int i = 1; i < shell_argc; i++)
        {
            if (strcmp(shell_argv[i], DEEP) == 0)
                deep_2 = 1;

            else if (strcmp(shell_argv[i], FAST) == 0)
                fast_2 = 1;

            else if (strcmp(shell_argv[i], SEARCH) == 0)
                search_2 = 1;

            else if (strcmp(shell_argv[i], BANNER) == 0)
                banner_2 = 1;

            else if (strcmp(shell_argv[i], QUIET) == 0)
                quiet_2 = 1;

            else if (strcmp(shell_argv[i], RUN) == 0)
                run_2 = 1;

            else if (strcmp(shell_argv[i], EXIT) == 0)
                exit_2 = 1;

            else if (strcmp(shell_argv[i], EXTRACT_MULTI_APK) == 0)
                extract_multi_apk_2 = 1;

            else if (strcmp(shell_argv[i], SECRETS) == 0)
                secrets_2 = 1;

            else if (strcmp(shell_argv[i], FOLDER_SCAN) == 0)
                folder_scan_2 = 1;

            else if (strcmp(shell_argv[i], PERMISSIONS) == 0)
                permissions_2 = 1;

            else if (strcmp(shell_argv[i], PATTERNS) == 0)
                patterns_2 = 1;

            else if (strcmp(shell_argv[i], DECOMPILE) == 0)
                decompile_2 = 1;

            else if (strcmp(shell_argv[i], FILE_SCAN) == 0)
                file_scan_2 = 1;

            else if (strcmp(shell_argv[i], APKTOOL) == 0)
                apktool_2 = 1;

            else if (strcmp(shell_argv[i], APKTOOL_SCAN) == 0)
                apktool_scan_2 = 1;

            else if (strcmp(shell_argv[i], MULTI_APK) == 0)
                multi_apk_2 = 1;

            else if (strcmp(shell_argv[i], EXTRACT) == 0)
                extract_2 = 1;

            else if (strcmp(shell_argv[i], MASVS) == 0)
                masvs_2 = 1;

            else if (strcmp(shell_argv[i], INSTALL) == 0)
                install = 1;
        }

        if (multi_apk_2 == 1 || quiet_2 == 1)
            silent_mode = 2;

        if (strcmp(shell_argv[0], EXIT) == 0)
        {
            break;
        }

        else if (strcmp(shell_argv[0], HELP) == 0)
        {
            help_func();
            continue;
        }

        else if (strcmp(shell_argv[0], BANNER) == 0)
        {
            print_banner();
            continue;
        }

        else if (shell_argc >= 2 &&
                 strcmp(shell_argv[0], RUN) == 0 &&
                 strcmp(shell_argv[1], INSTALL) == 0)
        {
            install_missing_dependencies();
            continue;
        }

        else if (shell_argc >= 2 &&
         strcmp(shell_argv[0], RUN) == 0 &&
         strcmp(shell_argv[1], SEARCH) == 0)
{
    if (shell_argc < 3)
    {
        printf(HACKER_WHITE "Error: Search folder required.\n" COLOR_RESET);
        continue;
    }

    if (shell_argc < 4)
    {
        printf(HACKER_WHITE "Error: Search term required.\n" COLOR_RESET);
        continue;
    }

    char search_string[8192] = {0};

    for (int i = 3; i < shell_argc; i++)
    {
        if (i > 3)
            strcat(search_string, " ");

        strcat(search_string, shell_argv[i]);
    }

    search_folder(shell_argv[2], search_string);
}

        else if (strcmp(shell_argv[0], RUN) == 0)
        {

            if (shell_argc < 2)
            {
                printf(HACKER_WHITE
                       "Error: No target specified.\n" COLOR_RESET);
                continue;
            }

            int invalid_option = 0;

            for (int i = 2; i < shell_argc; i++)
            {
                int found = 0;

                for (int j = 0; j < valid_flag_count; j++)
                {
                    if (strcmp(shell_argv[i], valid_flags[j]) == 0)
                    {
                        found = 1;
                        break;
                    }
                }

                if (!found)
                {
                    printf(
                        HACKER_WHITE
                        "Error: Unknown option '%s'\n" COLOR_RESET,
                        shell_argv[i]);

                    invalid_option = 1;
                }
            }

            if (invalid_option)
            {
                printf(
                    HACKER_WHITE
                    "Use 'help' to see available options.\n" COLOR_RESET);

                continue;
            }

            if (multi_apk_2 == 1 ||
                apktool_2 == 1 ||
                deep_2 == 1 ||
                fast_2 == 1 ||
                strstr(shell_argv[1], ".apk") != NULL)
            {
                check_apktool_jadx_versions(shell_argv);
            }

            run_command(shell_argc, shell_argv);

            continue;
        }

        else
        {
            if (strcmp(shell_argv[0], "cd") == 0)
            {
                if (shell_argc < 2)
                {
                    printf("cd: missing operand\n");
                }
                else if (chdir(shell_argv[1]) != 0)
                {
                    perror("cd");
                }

                continue;
            }

            system(command);
        }

        cleanup_bucket_regexes();
    }

    return 0;
}
