#ifndef FILE_MAKING_H
#define FILE_MAKING_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <sys/types.h>
#include "patterns.h"
#include "define.h"
#include "main_ai.h"
#include "functions.h"
#include "scan_dir_func.h"

int file_making(char *output_dir, char *argv[], int argc)
{
    char name_output_dir[256];
    snprintf(name_output_dir, sizeof(name_output_dir), "Result_%s", output_dir);

    char secrets_file[512];
    snprintf(secrets_file, sizeof(secrets_file), "%s/secrets_findings.txt", name_output_dir);

    char files_file[512];
    snprintf(files_file, sizeof(files_file), "%s/files.txt", name_output_dir);

    char patterns_file[512];
    snprintf(patterns_file, sizeof(patterns_file), "%s/pattern_findings.txt", name_output_dir);

    char permissions_file[512];
    snprintf(permissions_file, sizeof(permissions_file), "%s/permissions_findings.txt", name_output_dir);

    char native_lib_file[512];
    snprintf(native_lib_file, sizeof(native_lib_file), "%s/native_library_files.txt", name_output_dir);

    char masvs_file[512];
    snprintf(masvs_file, sizeof(masvs_file), "%s/masvs_findings.txt", name_output_dir);

    //

    char name_output_dir_folder[256];
    snprintf(name_output_dir_folder, sizeof(name_output_dir_folder), "Folder-Scan_Result_%s", output_dir);

    char secrets_file_folder[512];
    snprintf(secrets_file_folder, sizeof(secrets_file_folder), "%s/secrets_findings.txt", name_output_dir_folder);

    char files_file_folder[512];
    snprintf(files_file_folder, sizeof(files_file_folder), "%s/files.txt", name_output_dir_folder);

    char patterns_file_folder[512];
    snprintf(patterns_file_folder, sizeof(patterns_file_folder), "%s/pattern_findings.txt", name_output_dir_folder);

    char permissions_file_folder[512];
    snprintf(permissions_file_folder, sizeof(permissions_file_folder), "%s/permissions_findings.txt", name_output_dir_folder);

    char native_lib_file_folder[512];
    snprintf(native_lib_file_folder, sizeof(native_lib_file_folder), "%s/native_library_files.txt", name_output_dir_folder);

    char masvs_file_folder[512];
    snprintf(masvs_file_folder, sizeof(masvs_file_folder), "%s/masvs_findings.txt", name_output_dir_folder);

    struct stat st;

    if (stat(output_dir, &st) == 0 && S_ISDIR(st.st_mode))
    {

        if (strstr(argv[1], ".apk") != NULL)
        {
            if (mkdir(name_output_dir, 0755) == 0)
            {
                printf(HACKER_WHITE "\nDirectory created successfully.\n\n" COLOR_RESET);
            }
            else
            {
                printf(HACKER_WHITE);
                perror("mkdir");
                printf(COLOR_RESET);
                return 1;
            }

            if (argc == 2 || (argc == 3 && strcmp(argv[2], FAST) == 0) || (argc == 3 && strcmp(argv[2], DEEP) == 0))
            {
                printf(HACKER_WHITE);

                FILE *for_patterns = fopen(patterns_file, "w");

                if (!for_patterns)
                {

                    printf("Cannot create output file for pattern findings\n");
                    return 1;
                }

                FILE *for_regex = fopen(secrets_file, "w");

                if (!for_regex)
                {

                    printf("Cannot create output file for secrets findings\n");
                    return 1;
                }

                FILE *for_permissions = fopen(permissions_file, "w");

                if (!for_permissions)
                {

                    printf("cannot create output file for permissions findings\n");
                    return 1;
                }

                FILE *for_masvs = fopen(masvs_file, "w");
                if (!for_masvs)
                {

                    printf("Cannot create output file for MASVS findings\n");
                    return 1;
                }

                printf(COLOR_RESET);

                scan_dir(output_dir, for_patterns, for_regex, for_permissions, argv, argc, output_dir, for_masvs);
                printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt, permissions.txt, masvs_findings.txt or secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);
                fclose(for_patterns);
                fclose(for_regex);
                fclose(for_permissions);
            }
            else if (argc >= 4 && strcmp(argv[3], SECRETS) == 0)
            {
                printf(HACKER_WHITE);
                FILE *for_regex = fopen(secrets_file, "w");

                if (!for_regex)
                {

                    printf("Cannot create output file for secrets findings\n");
                    return 1;
                }

                printf(COLOR_RESET);

                scan_dir_sec(output_dir, for_regex, argv, argc, output_dir);
                printf(HACKER_WHITE "Scan completed. Results in secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);

                fclose(for_regex);
            }

            else if (argc >= 4 && strcmp(argv[3], MASVS) == 0)
            {
                printf(HACKER_WHITE);
                FILE *for_masvs = fopen(masvs_file, "w");

                if (!for_masvs)
                {

                    printf("Cannot create output file for MASVS findings\n");
                    return 1;
                }
                printf(COLOR_RESET);
                

                scan_dir_masvs(output_dir, for_masvs, argv, argc, output_dir);
                printf(HACKER_WHITE "Scan completed. Results in masvs_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);

                fclose(for_masvs);
            }

            else if (argc >= 4 && strcmp(argv[3], PERMISSIONS) == 0)
            {
                printf(HACKER_WHITE);
                FILE *for_permissions = fopen(permissions_file, "w");

                if (!for_permissions)
                {

                    printf("cannot create output file for permissions findings\n");
                    return 1;
                }
                printf(COLOR_RESET);

                scan_dir_per(output_dir, for_permissions, argv, argc, output_dir);
                printf(HACKER_WHITE "\nScan completed. Results in permissions.txt in %s folder\n" COLOR_RESET, name_output_dir);

                fclose(for_permissions);
            }

            else if (argc >= 4 && strcmp(argv[3], PATTERNS) == 0)
            {
                printf(HACKER_WHITE);
                FILE *for_patterns = fopen(patterns_file, "w");

                if (!for_patterns)
                {

                    printf("Cannot create output file for pattern findings\n");
                    return 1;
                }

                printf(COLOR_RESET);

                scan_dir_pat(output_dir, for_patterns, argv, argc, output_dir);
                printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);
                fclose(for_patterns);
            }
            else if (argc >= 4 && strcmp(argv[3], FILE_SCAN) == 0)
            {
                printf(HACKER_WHITE);
                FILE *scan_files = fopen(files_file, "w");

                if (!scan_files)
                {

                    printf("Cannot create output file for printing files\n");
                    return 1;
                }
                FILE *for_native_lib = fopen(native_lib_file, "w");

                if (!for_native_lib)
                {

                    printf("cannot create output file for .so files findings\n");
                    return 1;
                }
                printf(COLOR_RESET);
                scan_dir_files(output_dir, scan_files, for_native_lib);
                printf(HACKER_WHITE "\nScan completed. Results in files.txt or native_library_files.txt in %s folder\n" COLOR_RESET, name_output_dir);
                fclose(scan_files);
            }
        }

        else
        {

            if (mkdir(name_output_dir_folder, 0755) == 0)
            {
                printf(HACKER_WHITE "\nDirectory created successfully.\n\n" COLOR_RESET);

                if (argc == 3 && strcmp(argv[2], FOLDER_SCAN) == 0)
                {
                    printf(HACKER_WHITE);

                    FILE *for_patterns = fopen(patterns_file_folder, "w");

                    if (!for_patterns)
                    {

                        printf("Cannot create output file for pattern findings in %s folder\n", name_output_dir_folder);
                        return 1;
                    }

                    FILE *for_regex = fopen(secrets_file_folder, "w");

                    if (!for_regex)
                    {

                        printf("Cannot create output file for secrets findings in %s folder\n", name_output_dir_folder);
                        return 1;
                    }

                    FILE *for_permissions = fopen(permissions_file_folder, "w");

                    if (!for_permissions)
                    {

                        printf("cannot create output file for permissions findings\n");
                        return 1;
                    }

                    FILE *for_masvs = fopen(masvs_file_folder, "w");

                    if (!for_masvs)
                    {

                        printf("Cannot create output file for MASVS findings\n");
                        return 1;
                    }
                    printf(COLOR_RESET);

                    printf(COLOR_RESET);

                    scan_dir(output_dir, for_patterns, for_regex, for_permissions, argv, argc, output_dir, for_masvs);
                    printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt, permissions.txt, masvs_findings.txt or secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                    fclose(for_patterns);
                    fclose(for_regex);
                    fclose(for_permissions);
                }

                else if (argc >= 4 && strcmp(argv[3], SECRETS) == 0)
                {
                    printf(HACKER_WHITE);
                    FILE *for_regex = fopen(secrets_file_folder, "w");

                    if (!for_regex)
                    {

                        printf("Cannot create output file for secrets findings\n");
                        return 1;
                    }
                    printf(COLOR_RESET);
                    scan_dir_sec(output_dir, for_regex, argv, argc, output_dir);
                    printf(HACKER_WHITE "Scan completed. Results in secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);

                    fclose(for_regex);
                }

                else if (argc >= 4 && strcmp(argv[3], MASVS) == 0)
                {
                    printf(HACKER_WHITE);
                    FILE *for_masvs = fopen(masvs_file_folder, "w");

                    if (!for_masvs)
                    {

                        printf("Cannot create output file for MASVS findings\n");
                        return 1;
                    }
                    printf(COLOR_RESET);

                    scan_dir_masvs(output_dir, for_masvs, argv, argc, output_dir);
                    printf(HACKER_WHITE "Scan completed. Results in masvs_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);

                    fclose(for_masvs);
                }

                else if (argc >= 4 && strcmp(argv[3], PERMISSIONS) == 0)
                {
                    printf(HACKER_WHITE);
                    FILE *for_permissions = fopen(permissions_file_folder, "w");

                    if (!for_permissions)
                    {

                        printf("cannot create output file for permissions findings \n");
                        return 1;
                    }
                    printf(COLOR_RESET);
                    scan_dir_per(output_dir, for_permissions, argv, argc, output_dir);
                    printf(HACKER_WHITE "\nScan completed. Results in permissions.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);

                    fclose(for_permissions);
                }

                else if (argc >= 4 && strcmp(argv[3], PATTERNS) == 0)
                {
                    printf(HACKER_WHITE);
                    FILE *for_patterns = fopen(patterns_file_folder, "w");

                    if (!for_patterns)
                    {

                        printf("Cannot create output file for pattern findings\n");
                        return 1;
                    }

                    printf(COLOR_RESET);
                    scan_dir_pat(output_dir, for_patterns, argv, argc, output_dir);
                    printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                    fclose(for_patterns);
                }

                else if (argc >= 4 && strcmp(argv[3], FILE_SCAN) == 0)
                {
                    printf(HACKER_WHITE);
                    FILE *scan_files = fopen(files_file_folder, "w");

                    if (!scan_files)
                    {

                        printf("Cannot create output file for printing files\n");
                        return 1;
                    }
                    FILE *for_native_lib_folder = fopen(native_lib_file_folder, "w");

                    if (!for_native_lib_folder)
                    {

                        printf("cannot create output file for .so files findings\n");
                        return 1;
                    }
                    printf(COLOR_RESET);
                    scan_dir_files(output_dir, scan_files, for_native_lib_folder);
                    printf(HACKER_WHITE "\nScan completed. Results in files.txt or native_library_files.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                    fclose(scan_files);
                }
            }

            else
            {
                printf(HACKER_WHITE);
                perror("mkdir");
                printf(COLOR_RESET);
                return 1;
            }
        }

        return 1;
    }
}

int file_making_for_apktool(char *output_dir, char *argv[], int argc)
{

    char *result_folder_name = output_dir;
    char *prefix = "Apktool_";

    char *output_dir_1 = result_folder_name + strlen(prefix);

    char name_output_dir[256];
    snprintf(name_output_dir, sizeof(name_output_dir), "Apktool_Result_%s", output_dir_1);

    char secrets_file[512];
    snprintf(secrets_file, sizeof(secrets_file), "%s/secrets_findings.txt", name_output_dir);

    char files_file[512];
    snprintf(files_file, sizeof(files_file), "%s/files.txt", name_output_dir);

    char patterns_file[512];
    snprintf(patterns_file, sizeof(patterns_file), "%s/pattern_findings.txt", name_output_dir);

    char permissions_file[512];
    snprintf(permissions_file, sizeof(permissions_file), "%s/permissions_findings.txt", name_output_dir);

    char native_lib_file[512];
    snprintf(native_lib_file, sizeof(native_lib_file), "%s/native_library_files.txt", name_output_dir);

    char masvs_file[512];
    snprintf(masvs_file, sizeof(masvs_file), "%s/masvs_findings.txt", name_output_dir);

    //

    char name_output_dir_folder[256];
    snprintf(name_output_dir_folder, sizeof(name_output_dir_folder), "Apktool-Folder-scan_Result_%s", output_dir_1);

    char secrets_file_folder[512];
    snprintf(secrets_file_folder, sizeof(secrets_file_folder), "%s/secrets_findings.txt", name_output_dir);

    char files_file_folder[512];
    snprintf(files_file_folder, sizeof(files_file_folder), "%s/files.txt", name_output_dir_folder);

    char patterns_file_folder[512];
    snprintf(patterns_file_folder, sizeof(patterns_file_folder), "%s/pattern_findings.txt", name_output_dir_folder);

    char permissions_file_folder[512];
    snprintf(permissions_file_folder, sizeof(permissions_file_folder), "%s/permissions_findings.txt", name_output_dir_folder);

    char native_lib_file_folder[512];
    snprintf(native_lib_file_folder, sizeof(native_lib_file_folder), "%s/native_library_files.txt", name_output_dir_folder);

    char masvs_file_folder[512];
    snprintf(masvs_file_folder, sizeof(masvs_file_folder), "%s/masvs_findings.txt", name_output_dir_folder);

    struct stat st;

    if (stat(output_dir, &st) == 0 && S_ISDIR(st.st_mode))
    {

        if (strstr(argv[1], ".apk") != NULL)
        {

            if (argv[3] == NULL)
            {

                if (mkdir(name_output_dir, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n" COLOR_RESET);
                }
                else
                {
                    printf(HACKER_WHITE);
                    perror("mkdir");
                    printf(COLOR_RESET);
                    return 1;
                }
                printf(HACKER_WHITE);

                FILE *for_patterns = fopen(patterns_file, "w");

                if (!for_patterns)
                {

                    printf("Cannot create output file for pattern findings\n");
                    return 1;
                }

                FILE *for_regex = fopen(secrets_file, "w");

                if (!for_regex)
                {

                    printf("Cannot create output file for secrets findings\n");
                    return 1;
                }

                FILE *for_permissions = fopen(permissions_file, "w");

                if (!for_permissions)
                {

                    printf("cannot create output file for permissions findings\n");
                    return 1;
                }

                FILE *scan_files = fopen(files_file, "w");

                if (!scan_files)
                {

                    printf("Cannot create output file for printing files\n");
                    return 1;
                }

                FILE *for_masvs = fopen(masvs_file, "w");

                if (!for_masvs)
                {

                    printf("Cannot create output file for MASVS findings\n");
                    return 1;
                }
                
                printf(COLOR_RESET);

                scan_dir_for_apktool(scan_files, output_dir, for_patterns, for_regex, for_permissions, argv, argc, output_dir, for_masvs);
                printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt, permissions.txt, masvs_findings.txt or secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);
                fclose(for_patterns);
                fclose(for_regex);
                fclose(for_permissions);
            }

            else if (argc >= 4 && strcmp(argv[3], SECRETS) == 0)
            {

                if (mkdir(name_output_dir, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n\n" COLOR_RESET);
                }
                else
                {
                    printf(HACKER_WHITE);
                    perror("mkdir");
                    printf(COLOR_RESET);
                    return 1;
                }
                printf(HACKER_WHITE);
                FILE *for_regex = fopen(secrets_file, "w");

                if (!for_regex)
                {

                    printf("Cannot create output file for secrets findings\n");
                    return 1;
                }
                printf(COLOR_RESET);

                scan_dir_for_apktool_sec(output_dir, for_regex, argv, argc, output_dir);
                printf(HACKER_WHITE "Scan completed. Results in secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);

                fclose(for_regex);
            }

            else if (argc >= 4 && strcmp(argv[3], MASVS) == 0)
            {

                if (mkdir(name_output_dir, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n\n" COLOR_RESET);
                }
                else
                {
                    printf(HACKER_WHITE);
                    perror("mkdir");
                    printf(COLOR_RESET);
                    return 1;
                }
                printf(HACKER_WHITE);
                FILE *for_masvs = fopen(masvs_file, "w");

                if (!for_masvs)
                {

                    printf("Cannot create output file for MASVS findings\n");
                    return 1;
                }
                printf(COLOR_RESET);

                scan_dir_for_apktool_masvs(output_dir, for_masvs, argv, argc, output_dir);
                printf(HACKER_WHITE "Scan completed. Results in masvs_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);

                fclose(for_masvs);
            }

            else if (argc >= 4 && strcmp(argv[3], PERMISSIONS) == 0)
            {
                if (mkdir(name_output_dir, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n" COLOR_RESET);
                }
                else
                {
                    printf(HACKER_WHITE);
                    perror("mkdir");
                    printf(COLOR_RESET);
                    return 1;
                }
                printf(HACKER_WHITE);
                FILE *for_permissions = fopen(permissions_file, "w");

                if (!for_permissions)
                {

                    printf("cannot create output file for permissions findings\n");
                    return 1;
                }
                printf(COLOR_RESET);

                scan_dir_for_apktool_per(output_dir, for_permissions, argv, argc, output_dir);
                printf(HACKER_WHITE "\nScan completed. Results in permissions.txt in %s folder\n" COLOR_RESET, name_output_dir);

                fclose(for_permissions);
            }

            else if (argc >= 4 && strcmp(argv[3], PATTERNS) == 0)
            {
                if (mkdir(name_output_dir, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n" COLOR_RESET);
                }
                else
                {
                    printf(HACKER_WHITE);
                    perror("mkdir");
                    printf(COLOR_RESET);
                    return 1;
                }
                printf(HACKER_WHITE);
                FILE *for_patterns = fopen(patterns_file, "w");

                if (!for_patterns)
                {

                    printf("Cannot create output file for pattern findings\n");
                    return 1;
                }
                printf(COLOR_RESET);

                scan_dir_for_apktool_pat(output_dir, for_patterns, argv, argc, output_dir);
                printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);
                fclose(for_patterns);
            }
            else if (argc >= 4 && strcmp(argv[3], FILE_SCAN) == 0)
            {
                if (mkdir(name_output_dir, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n" COLOR_RESET);
                }
                else
                {
                    printf(HACKER_WHITE);
                    perror("mkdir");
                    printf(COLOR_RESET);
                    return 1;
                }
                printf(HACKER_WHITE);
                FILE *scan_files = fopen(files_file, "w");

                if (!scan_files)
                {

                    printf("Cannot create output file for printing files\n");
                    return 1;
                }
                FILE *for_native_lib_file = fopen(native_lib_file, "w");

                if (!for_native_lib_file)
                {

                    printf("cannot create output file for .so files findings\n");
                    return 1;
                }
                printf(COLOR_RESET);
                scan_dir_for_apktool_files(output_dir, scan_files, for_native_lib_file);
                printf(HACKER_WHITE "\nScan completed. Results in files.txt or native_library_files.txt in %s folder\n" COLOR_RESET, name_output_dir);
                fclose(scan_files);
            }
        }

        else
        {
            if (argv[3] == NULL)
            {
                if (mkdir(name_output_dir_folder, 0755) == 0)
                {
                    printf("\nDirectory created successfully.\n\n");
                }
                else
                {
                    printf(HACKER_WHITE);
                    perror("mkdir");
                    printf(COLOR_RESET);
                    return 1;
                }
                printf(HACKER_WHITE);

                FILE *for_patterns = fopen(patterns_file_folder, "w");

                if (!for_patterns)
                {

                    printf("Cannot create output file for pattern findings\n");
                    return 1;
                }

                FILE *for_regex = fopen(secrets_file_folder, "w");

                if (!for_regex)
                {

                    printf("Cannot create output file for secrets findings\n");
                    return 1;
                }

                FILE *for_permissions = fopen(permissions_file_folder, "w");

                if (!for_permissions)
                {

                    printf("cannot create output file for permissions findings\n");
                    return 1;
                }

                FILE *scan_files = fopen(files_file_folder, "w");

                if (!scan_files)
                {

                    printf("Cannot create output file for printing files\n");
                    return 1;
                }

                FILE *for_masvs = fopen(masvs_file_folder, "w");

                if (!for_masvs)
                {

                    printf("Cannot create output file for MASVS findings\n");
                    return 1;
                }
                printf(COLOR_RESET);

                scan_dir_for_apktool(scan_files, output_dir, for_patterns, for_regex, for_permissions, argv, argc, output_dir, for_masvs);
                printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt, permissions.txt, masvs_findings.txt or secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                fclose(for_patterns);
                fclose(for_regex);
                fclose(for_permissions);
            }
            else if (argc >= 4 && strcmp(argv[3], SECRETS) == 0)
            {

                if (mkdir(name_output_dir_folder, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n\n" COLOR_RESET);
                }
                else
                {
                    printf(HACKER_WHITE);
                    perror("mkdir");
                    printf(COLOR_RESET);
                    return 1;
                }
                printf(HACKER_WHITE);
                FILE *for_regex = fopen(secrets_file_folder, "w");

                if (!for_regex)
                {

                    printf("Cannot create output file for secrets findings\n");
                    return 1;
                }
                printf(COLOR_RESET);

                scan_dir_for_apktool_sec(output_dir, for_regex, argv, argc, output_dir);
                printf(HACKER_WHITE "Scan completed. Results in secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);

                fclose(for_regex);
            }

            else if (argc >= 4 && strcmp(argv[3], MASVS) == 0)
            {

                if (mkdir(name_output_dir_folder, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n\n" COLOR_RESET);
                }
                else
                {
                    printf(HACKER_WHITE);
                    perror("mkdir");
                    printf(COLOR_RESET);
                    return 1;
                }
                printf(HACKER_WHITE);
                FILE *for_masvs = fopen(masvs_file_folder, "w");

                if (!for_masvs)
                {

                    printf("Cannot create output file for MASVS findings\n");
                    return 1;
                }
                printf(COLOR_RESET);

                scan_dir_for_apktool_masvs(output_dir, for_masvs, argv, argc, output_dir);
                printf(HACKER_WHITE "Scan completed. Results in masvs_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);

                fclose(for_masvs);
            }

            else if (argc >= 4 && strcmp(argv[3], PERMISSIONS) == 0)
            {
                if (mkdir(name_output_dir_folder, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n" COLOR_RESET);
                }
                else
                {
                    printf(HACKER_WHITE);
                    perror("mkdir");
                    printf(COLOR_RESET);
                    return 1;
                }
                printf(HACKER_WHITE);
                FILE *for_permissions = fopen(permissions_file_folder, "w");

                if (!for_permissions)
                {

                    printf("cannot create output file for permissions findings\n");
                    return 1;
                }
                printf(COLOR_RESET);

                scan_dir_for_apktool_per(output_dir, for_permissions, argv, argc, output_dir);
                printf(HACKER_WHITE "\nScan completed. Results in permissions.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);

                fclose(for_permissions);
            }

            else if (argc >= 4 && strcmp(argv[3], PATTERNS) == 0)
            {
                if (mkdir(name_output_dir_folder, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n" COLOR_RESET);
                }
                else
                {
                    printf(HACKER_WHITE);
                    perror("mkdir");
                    printf(COLOR_RESET);
                    return 1;
                }

                printf(HACKER_WHITE);
                FILE *for_patterns = fopen(patterns_file_folder, "w");

                if (!for_patterns)
                {

                    printf("Cannot create output file for pattern findings\n");
                    return 1;
                }
                printf(COLOR_RESET);

                scan_dir_for_apktool_pat(output_dir, for_patterns, argv, argc, output_dir);
                printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                fclose(for_patterns);
            }
            else if (argc >= 4 && strcmp(argv[3], FILE_SCAN) == 0)
            {
                if (mkdir(name_output_dir_folder, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n" COLOR_RESET);
                }
                else
                {
                    printf(HACKER_WHITE);
                    perror("mkdir");
                    printf(COLOR_RESET);
                    return 1;
                }
                printf(HACKER_WHITE);
                FILE *scan_files = fopen(files_file_folder, "w");

                if (!scan_files)
                {

                    printf("Cannot create output file for printing files\n");
                    return 1;
                }
                FILE *for_native_lib_folder = fopen(native_lib_file_folder, "w");

                if (!for_native_lib_folder)
                {

                    printf("cannot create output file for .so files findings\n");
                    return 1;
                }
                printf(COLOR_RESET);
                scan_dir_for_apktool_files(output_dir, scan_files, for_native_lib_folder);
                printf(HACKER_WHITE "\nScan completed. Results in files.txt or native_library_files.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                fclose(scan_files);
            }
        }
    }
}

#endif
