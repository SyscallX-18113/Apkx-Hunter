/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */


#include "file_making.h"


int file_making(char *output_dir, char *argv[], int argc)
{
    char name_output_dir[512];
    snprintf(name_output_dir, sizeof(name_output_dir), "Result_%s", output_dir);

    char secrets_file[800];
    snprintf(secrets_file, sizeof(secrets_file), "%s/secrets_findings.txt", name_output_dir);

    char files_file[800];
    snprintf(files_file, sizeof(files_file), "%s/files.txt", name_output_dir);

    char patterns_file[800];
    snprintf(patterns_file, sizeof(patterns_file), "%s/patterns_findings.txt", name_output_dir);

    char permissions_file[800];
    snprintf(permissions_file, sizeof(permissions_file), "%s/permissions_findings.txt", name_output_dir);

    char native_lib_file[800];
    snprintf(native_lib_file, sizeof(native_lib_file), "%s/native_library_files.txt", name_output_dir);

    char masvs_file[800];
    snprintf(masvs_file, sizeof(masvs_file), "%s/masvs_findings.txt", name_output_dir);

    //

    char name_output_dir_folder[512];
    snprintf(name_output_dir_folder, sizeof(name_output_dir_folder), "Folder-Scan_Result_%s", output_dir);

    char secrets_file_folder[800];
    snprintf(secrets_file_folder, sizeof(secrets_file_folder), "%s/secrets_findings.txt", name_output_dir_folder);

    char files_file_folder[800];
    snprintf(files_file_folder, sizeof(files_file_folder), "%s/files.txt", name_output_dir_folder);

    char patterns_file_folder[800];
    snprintf(patterns_file_folder, sizeof(patterns_file_folder), "%s/pattern_findings.txt", name_output_dir_folder);

    char permissions_file_folder[800];
    snprintf(permissions_file_folder, sizeof(permissions_file_folder), "%s/permissions_findings.txt", name_output_dir_folder);

    char native_lib_file_folder[8000];
    snprintf(native_lib_file_folder, sizeof(native_lib_file_folder), "%s/native_library_files.txt", name_output_dir_folder);

    char masvs_file_folder[800];
    snprintf(masvs_file_folder, sizeof(masvs_file_folder), "%s/masvs_findings.txt", name_output_dir_folder);

    struct stat st;

    if (stat(output_dir, &st) == 0 && S_ISDIR(st.st_mode))
    {

        if ((strstr(argv[1], ".apk") != NULL || strstr(argv[1], ".apkm") != NULL || strstr(argv[1], ".aab") != NULL || strstr(argv[1], ".xapk") != NULL || strstr(argv[1], ".apks") != NULL) || ((multi_apk_2 == 1) && opendir(argv[1]) != NULL) || extract_multi_apk_2 == 1)
        {

            if (mkdir(name_output_dir, 0755) == 0)
            {
                printf(HACKER_WHITE "\nDirectory created successfully.\n\n" COLOR_RESET);
            }
            else
            {
                printf(HACKER_WHITE);

                if (errno == EEXIST)
                {
                    printf("Directory '%s' already exists.\n" COLOR_RESET, name_output_dir);
                }
                else if (errno == EACCES)
                {
                    printf("Permission denied to create directory '%s'.\n" COLOR_RESET, name_output_dir);
                }
                else
                {
                    perror("mkdir");
                    printf(COLOR_RESET);
                }
                return 1;
            }

            if ((argc == 3 && (extract_multi_apk_2 == 1 || multi_apk_2 == 1)) || (argc == 2 || (fast_2 == 1) || (deep_2 == 1) || (((fast_2 == 1) || (deep_2 == 1)) && (extract_multi_apk_2 == 1 || multi_apk_2 == 1))) && (!secrets_2 && !permissions_2 && !masvs_2 && !patterns_2 && !file_scan_2))
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
                printf("Running Full Scan...\n\n");
                sleep(5);

                printf(COLOR_RESET);

                scan_dir(output_dir, for_patterns, for_regex, for_permissions, argv, argc, output_dir, for_masvs);
                printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt, permissions.txt, masvs_findings.txt or secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                fclose(for_patterns);
                fclose(for_regex);
                fclose(for_permissions);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }

            else if (secrets_2 == 1)
            {
                printf(HACKER_WHITE);
                FILE *for_regex = fopen(secrets_file, "w");

                if (!for_regex)
                {

                    printf("Cannot create output file for secrets findings\n");
                    return 1;
                }
                printf("Running Secrets Scan...\n\n");
                sleep(5);

                printf(COLOR_RESET);

                scan_dir_sec(output_dir, for_regex, argv, argc, output_dir);
                printf(HACKER_WHITE "Scan completed. Results in secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);

                fclose(for_regex);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }

            else if (masvs_2 == 1)
            {
                printf(HACKER_WHITE);
                FILE *for_masvs = fopen(masvs_file, "w");

                if (!for_masvs)
                {

                    printf("Cannot create output file for MASVS findings\n");
                    return 1;
                }
                printf("Running OWASP MASVS Scan...\n\n");
                sleep(5);
                printf(COLOR_RESET);

                scan_dir_masvs(output_dir, for_masvs, argv, argc, output_dir);
                printf(HACKER_WHITE "Scan completed. Results in masvs_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);

                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                fclose(for_masvs);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }

            else if (permissions_2 == 1)
            {
                printf(HACKER_WHITE);
                FILE *for_permissions = fopen(permissions_file, "w");

                if (!for_permissions)
                {

                    printf("cannot create output file for permissions findings\n");
                    return 1;
                }
                printf("Running Exported Activity Or Permissions Scan...\n\n");
                sleep(5);
                printf(COLOR_RESET);

                scan_dir_per(output_dir, for_permissions, argv, argc, output_dir);
                printf(HACKER_WHITE "\nScan completed. Results in permissions.txt in %s folder\n" COLOR_RESET, name_output_dir);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);

                fclose(for_permissions);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }

            else if (patterns_2 == 1)
            {
                printf(HACKER_WHITE);
                FILE *for_patterns = fopen(patterns_file, "w");

                if (!for_patterns)
                {

                    printf("Cannot create output file for pattern findings\n");
                    return 1;
                }

                printf("Running Patterns Scan...\n\n");
                sleep(5);
                printf(COLOR_RESET);

                scan_dir_pat(output_dir, for_patterns, argv, argc, output_dir);
                printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                fclose(for_patterns);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }
            else if (file_scan_2 == 1)
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
                printf("Saving Files...\n\n");
                sleep(5);
                printf(COLOR_RESET);
                scan_dir_files(output_dir, scan_files, for_native_lib);
                printf(HACKER_WHITE "\nScan completed. Results in files.txt or native_library_files.txt in %s folder\n" COLOR_RESET, name_output_dir);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                fclose(scan_files);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }
            else
            {

                printf(HACKER_WHITE "Wrong Command" COLOR_RESET);
            }
        }

        else
        {

            if (mkdir(name_output_dir_folder, 0755) == 0)
            {
                printf(HACKER_WHITE "\nDirectory created successfully.\n\n" COLOR_RESET);

                if (argc == 3 && (folder_scan_2 == 1))
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
                    printf("Running Full Scan...\n\n");
                    sleep(5);
                    printf(COLOR_RESET);

                    scan_dir(output_dir, for_patterns, for_regex, for_permissions, argv, argc, output_dir, for_masvs);
                    printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt, permissions.txt, masvs_findings.txt or secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                    printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                    printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                    fclose(for_patterns);
                    fclose(for_regex);
                    fclose(for_permissions);
                    if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                    {
                        statics();
                    }
                }

                else if ((secrets_2 == 1) || ((secrets_2 == 1) && (folder_scan_2 == 1)))
                {
                    printf(HACKER_WHITE);
                    FILE *for_regex = fopen(secrets_file_folder, "w");

                    if (!for_regex)
                    {

                        printf("Cannot create output file for secrets findings\n");
                        return 1;
                    }
                    printf("Running Secrets Scan...\n\n");
                    sleep(5);
                    printf(COLOR_RESET);
                    scan_dir_sec(output_dir, for_regex, argv, argc, output_dir);
                    printf(HACKER_WHITE "Scan completed. Results in secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);

                    printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                    printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                    fclose(for_regex);
                    if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                    {
                        statics();
                    }
                }

                else if ((masvs_2 == 1) || ((masvs_2 == 1) && (folder_scan_2 == 1)))
                {
                    printf(HACKER_WHITE);
                    FILE *for_masvs = fopen(masvs_file_folder, "w");

                    if (!for_masvs)
                    {

                        printf("Cannot create output file for MASVS findings\n");
                        return 1;
                    }
                    printf("Running OWASP MASVS Scan...\n\n");
                    sleep(5);
                    printf(COLOR_RESET);

                    scan_dir_masvs(output_dir, for_masvs, argv, argc, output_dir);
                    printf(HACKER_WHITE "Scan completed. Results in masvs_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);

                    printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                    printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                    fclose(for_masvs);
                    if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                    {
                        statics();
                    }
                }

                else if ((permissions_2 == 1) || ((permissions_2 == 1) && (folder_scan_2 == 1)))
                {
                    printf(HACKER_WHITE);
                    FILE *for_permissions = fopen(permissions_file_folder, "w");

                    if (!for_permissions)
                    {

                        printf("cannot create output file for permissions findings \n");
                        return 1;
                    }
                    printf("Running Exported Activity Or Permissions Scan...\n\n");
                    sleep(5);
                    printf(COLOR_RESET);
                    scan_dir_per(output_dir, for_permissions, argv, argc, output_dir);
                    printf(HACKER_WHITE "\nScan completed. Results in permissions.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                    printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                    printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);

                    fclose(for_permissions);
                    if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                    {
                        statics();
                    }
                }

                else if ((patterns_2 == 1) || ((patterns_2 == 1) && (folder_scan_2 == 1)))
                {
                    printf(HACKER_WHITE);
                    FILE *for_patterns = fopen(patterns_file_folder, "w");

                    if (!for_patterns)
                    {

                        printf("Cannot create output file for pattern findings\n");
                        return 1;
                    }
                    printf("Running Patterns Scan...\n\n");
                    sleep(5);

                    printf(COLOR_RESET);
                    scan_dir_pat(output_dir, for_patterns, argv, argc, output_dir);
                    printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                    printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                    printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                    fclose(for_patterns);
                    if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                    {
                        statics();
                    }
                }

                else if ((file_scan_2 == 1) || ((file_scan_2 == 1) && (folder_scan_2 == 1)))
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
                    printf("Saving Files...\n\n");
                    sleep(5);
                    printf(COLOR_RESET);
                    scan_dir_files(output_dir, scan_files, for_native_lib_folder);
                    printf(HACKER_WHITE "\nScan completed. Results in files.txt or native_library_files.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                    printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                    printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                    fclose(scan_files);
                    if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                    {
                        statics();
                    }
                }
                else
                {

                    printf(HACKER_WHITE "Wrong Command" COLOR_RESET);
                }
            }

            else
            {
                printf(HACKER_WHITE);

                if (errno == EEXIST)
                {
                    printf("Directory '%s' already exists.\n" COLOR_RESET, name_output_dir_folder);
                }
                else if (errno == EACCES)
                {
                    printf("Permission denied to create directory '%s'.\n" COLOR_RESET, name_output_dir_folder);
                }
                else
                {
                    perror("mkdir");
                    printf(COLOR_RESET);
                }
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

    char name_output_dir[512];
    snprintf(name_output_dir, sizeof(name_output_dir), "Apktool_Result_%s", output_dir_1);

    char secrets_file[800];
    snprintf(secrets_file, sizeof(secrets_file), "%s/secrets_findings.txt", name_output_dir);

    char files_file[800];
    snprintf(files_file, sizeof(files_file), "%s/files.txt", name_output_dir);

    char patterns_file[800];
    snprintf(patterns_file, sizeof(patterns_file), "%s/pattern_findings.txt", name_output_dir);

    char permissions_file[800];
    snprintf(permissions_file, sizeof(permissions_file), "%s/permissions_findings.txt", name_output_dir);

    char native_lib_file[800];
    snprintf(native_lib_file, sizeof(native_lib_file), "%s/native_library_files.txt", name_output_dir);

    char masvs_file[800];
    snprintf(masvs_file, sizeof(masvs_file), "%s/masvs_findings.txt", name_output_dir);

    //

    char name_output_dir_folder[512];
    snprintf(name_output_dir_folder, sizeof(name_output_dir_folder), "Apktool-Folder-scan_Result_%s", output_dir_1);

    char secrets_file_folder[800];
    snprintf(secrets_file_folder, sizeof(secrets_file_folder), "%s/secrets_findings.txt", name_output_dir_folder);

    char files_file_folder[800];
    snprintf(files_file_folder, sizeof(files_file_folder), "%s/files.txt", name_output_dir_folder);

    char patterns_file_folder[800];
    snprintf(patterns_file_folder, sizeof(patterns_file_folder), "%s/pattern_findings.txt", name_output_dir_folder);

    char permissions_file_folder[800];
    snprintf(permissions_file_folder, sizeof(permissions_file_folder), "%s/permissions_findings.txt", name_output_dir_folder);

    char native_lib_file_folder[800];
    snprintf(native_lib_file_folder, sizeof(native_lib_file_folder), "%s/native_library_files.txt", name_output_dir_folder);

    char masvs_file_folder[800];
    snprintf(masvs_file_folder, sizeof(masvs_file_folder), "%s/masvs_findings.txt", name_output_dir_folder);

    struct stat st;

    if (stat(output_dir, &st) == 0 && S_ISDIR(st.st_mode))
    {

        if ((strstr(argv[1], ".apk") != NULL || strstr(argv[1], ".apkm") != NULL || strstr(argv[1], ".aab") != NULL || strstr(argv[1], ".xapk") != NULL || strstr(argv[1], ".apks") != NULL) || ((multi_apk_2 == 1) && opendir(argv[1]) != NULL) || extract_multi_apk_2 == 1)
        {

            if ((argv[3] == NULL || (apktool_2) || (multi_apk_2)) && (!secrets_2 && !permissions_2 && !masvs_2 && !patterns_2 && !file_scan_2))
            {

                if (mkdir(name_output_dir, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n" COLOR_RESET);
                }
                else
                {
                    printf(HACKER_WHITE);

                    if (errno == EEXIST)
                    {
                        printf(HACKER_WHITE "Directory '%s' already exists.\n" COLOR_RESET, name_output_dir);
                    }

                    else if (errno == EACCES)
                {
                    printf("Permission denied to create directory '%s'.\n" COLOR_RESET, name_output_dir);
                }
                
                    else
                    {
                        perror("mkdir");
                        printf(COLOR_RESET);
                    }
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
                printf("Running Full Scan...\n\n");
                sleep(5);

                printf(COLOR_RESET);

                scan_dir_for_apktool(scan_files, output_dir, for_patterns, for_regex, for_permissions, argv, argc, output_dir, for_masvs);
                printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt, permissions.txt, masvs_findings.txt or secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                fclose(for_patterns);
                fclose(for_regex);
                fclose(for_permissions);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }

            else if (secrets_2 == 1)
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
                printf("Running Secrets Scan...\n\n");
                sleep(5);

                FILE *for_regex = fopen(secrets_file, "w");

                if (!for_regex)
                {

                    printf("Cannot create output file for secrets findings\n");
                    return 1;
                }
                printf(COLOR_RESET);

                scan_dir_for_apktool_sec(output_dir, for_regex, argv, argc, output_dir);
                printf(HACKER_WHITE "Scan completed. Results in secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);

                fclose(for_regex);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }

            else if (masvs_2 == 1)
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
                printf("Running OWASP MASVS Scan...\n\n");
                sleep(5);
                printf(COLOR_RESET);

                scan_dir_for_apktool_masvs(output_dir, for_masvs, argv, argc, output_dir);
                printf(HACKER_WHITE "Scan completed. Results in masvs_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);

                fclose(for_masvs);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }

            else if (permissions_2 == 1)
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
                printf("Running Exported Activity Or Permissions Scan...\n\n");
                sleep(5);
                printf(COLOR_RESET);

                scan_dir_for_apktool_per(output_dir, for_permissions, argv, argc, output_dir);
                printf(HACKER_WHITE "\nScan completed. Results in permissions.txt in %s folder\n" COLOR_RESET, name_output_dir);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);

                fclose(for_permissions);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }

            else if (patterns_2 == 1)
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
                printf("Running Patterns Scan...\n\n");
                sleep(5);
                printf(COLOR_RESET);

                scan_dir_for_apktool_pat(output_dir, for_patterns, argv, argc, output_dir);
                printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt in %s folder\n" COLOR_RESET, name_output_dir);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                fclose(for_patterns);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }
            else if (file_scan_2 == 1)
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

                printf("Saving Files...\n\n");
                sleep(5);
                printf(COLOR_RESET);
                scan_dir_for_apktool_files(output_dir, scan_files, for_native_lib_file);
                printf(HACKER_WHITE "\nScan completed. Results in files.txt or native_library_files.txt in %s folder\n" COLOR_RESET, name_output_dir);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                fclose(scan_files);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }
        }

        else
        {
            if (argv[3] == NULL)
            {
                if (mkdir(name_output_dir_folder, 0755) == 0)
                {
                    printf(HACKER_WHITE "\nDirectory created successfully.\n\n" HACKER_WHITE);
                }
                else
                {
                    printf(HACKER_WHITE);

                    if (errno == EEXIST)
                    {
                        printf("Directory '%s' already exists.\n" COLOR_RESET, name_output_dir_folder);
                    }
                    else if (errno == EACCES)
                    {
                        printf("Permission denied to create directory '%s'.\n" COLOR_RESET, name_output_dir_folder);
                    }
                    else
                    {
                        perror("mkdir");
                        printf(COLOR_RESET);
                    }
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
                printf("Running Full Scan...\n\n");
                sleep(5);
                printf(COLOR_RESET);

                scan_dir_for_apktool(scan_files, output_dir, for_patterns, for_regex, for_permissions, argv, argc, output_dir, for_masvs);
                printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt, permissions.txt, masvs_findings.txt or secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                fclose(for_patterns);
                fclose(for_regex);
                fclose(for_permissions);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }
            else if ((secrets_2 == 1) || ((secrets_2 == 1) && apktool_scan_2 == 1))
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
                printf("Running Secrets Scan...\n\n");
                sleep(5);
                printf(COLOR_RESET);

                scan_dir_for_apktool_sec(output_dir, for_regex, argv, argc, output_dir);
                printf(HACKER_WHITE "Scan completed. Results in secrets_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);

                fclose(for_regex);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }

            else if ((masvs_2 == 1) || ((masvs_2 == 1) && apktool_scan_2 == 1))
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
                printf("Running OWASP MASVS Scan...\n\n");
                sleep(5);
                printf(COLOR_RESET);

                scan_dir_for_apktool_masvs(output_dir, for_masvs, argv, argc, output_dir);
                printf(HACKER_WHITE "Scan completed. Results in masvs_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);

                fclose(for_masvs);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }

            else if ((permissions_2 == 1) || ((permissions_2 == 1) && apktool_scan_2 == 1))
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
                printf("Running Exported Activity Or Permissions Scan...\n\n");
                sleep(5);
                printf(COLOR_RESET);

                scan_dir_for_apktool_per(output_dir, for_permissions, argv, argc, output_dir);
                printf(HACKER_WHITE "\nScan completed. Results in permissions.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);

                fclose(for_permissions);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }

            else if ((patterns_2 == 1) || ((patterns_2 == 1) && apktool_scan_2 == 1))
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
                printf("Running Patterns Scan...\n\n");
                sleep(5);
                printf(COLOR_RESET);

                scan_dir_for_apktool_pat(output_dir, for_patterns, argv, argc, output_dir);
                printf(HACKER_WHITE "\nScan completed. Results in pattern_findings.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                fclose(for_patterns);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }
            else if ((file_scan_2 == 1) || ((file_scan_2 == 1) && apktool_scan_2 == 1))
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
                printf("Saving Files...\n\n");
                sleep(5);
                printf(COLOR_RESET);
                scan_dir_for_apktool_files(output_dir, scan_files, for_native_lib_folder);
                printf(HACKER_WHITE "\nScan completed. Results in files.txt or native_library_files.txt in %s folder\n" COLOR_RESET, name_output_dir_folder);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                printf(HACKER_WHITE "════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" COLOR_RESET);
                fclose(scan_files);
                if (multi_apk_2 != 1 && extract_multi_apk_2 != 1)
                {
                    statics();
                }
            }
        }
    }
}

